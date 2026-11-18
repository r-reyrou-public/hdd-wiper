//! 再開用の進捗ファイル(JobState)と、不良セクタ範囲の管理。

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

pub const PHASE_COUNT: usize = 4; // 0,1,2 = 書込みパス / 3 = 検証読込み
pub const PHASE_DONE: u8 = 4;

pub fn phase_label(p: u8) -> &'static str {
    match p {
        0 => "ゼロ書込み(1回目)",
        1 => "乱数書込み",
        2 => "ゼロ書込み(最終)",
        3 => "検証(ゼロ確認)",
        _ => "完了",
    }
}

/// 消去の方式(周回数と検証方法のプリセット)
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum EraseMode {
    /// ゼロ → 乱数 → ゼロ + 全域検証
    #[default]
    Standard,
    /// ゼロ → 乱数 → ゼロ + 抽出検証
    FastVerify,
    /// 乱数 → ゼロ + 抽出検証
    TwoPass,
    /// ゼロ + 抽出検証
    OnePass,
}

impl EraseMode {
    pub const ALL: [EraseMode; 4] = [EraseMode::Standard, EraseMode::FastVerify, EraseMode::TwoPass, EraseMode::OnePass];

    pub fn label(self) -> &'static str {
        match self {
            EraseMode::Standard => "標準: ゼロ → 乱数 → ゼロ + 全域検証",
            EraseMode::FastVerify => "高速: ゼロ → 乱数 → ゼロ + 抽出検証",
            EraseMode::TwoPass => "簡易2周: 乱数 → ゼロ + 抽出検証",
            EraseMode::OnePass => "簡易1周: ゼロ + 抽出検証",
        }
    }

    pub fn short(self) -> &'static str {
        match self {
            EraseMode::Standard => "標準(3回書込み+全域検証)",
            EraseMode::FastVerify => "高速(3回書込み+抽出検証)",
            EraseMode::TwoPass => "簡易2周(2回書込み+抽出検証)",
            EraseMode::OnePass => "簡易1周(1回書込み+抽出検証)",
        }
    }

    /// 書込み・検証の各工程を実行するか
    pub fn slot_enabled(self, slot: u8) -> bool {
        match self {
            EraseMode::Standard | EraseMode::FastVerify => slot <= 3,
            EraseMode::TwoPass => (1..=3).contains(&slot),
            EraseMode::OnePass => slot >= 2 && slot <= 3,
        }
    }

    pub fn sample_verify(self) -> bool {
        self != EraseMode::Standard
    }

    pub fn step_count(self) -> usize {
        (0..4u8).filter(|&p| self.slot_enabled(p)).count()
    }

    /// 工程番号(1始まり)
    pub fn step_no(self, slot: u8) -> usize {
        (0..=slot.min(3)).filter(|&p| self.slot_enabled(p)).count()
    }
}

/// 抽出検証の1区間の大きさ
pub const SAMPLE_CHUNK: u64 = 1 << 20;

fn splitmix64(x: &mut u64) -> u64 {
    *x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// 抽出検証で読む区間 (開始バイト, 長さ) を、ディスク位置の昇順で返す。
/// 先頭256MiB・末尾256MiB・乱数で選んだ2048か所(各1MiB)。小さいディスクは全域。
/// seed が同じなら常に同じ結果(再開時に同じ区間を使うため)。
pub fn sample_ranges(size: u64, ss: u64, seed: u64) -> Vec<(u64, u64)> {
    let chunk = SAMPLE_CHUNK.max(ss) / ss * ss;
    let mut starts: Vec<u64> = Vec::new();
    let nchunks = size.div_ceil(chunk);
    if size <= (3u64 << 30) {
        starts.extend((0..nchunks).map(|i| i * chunk));
    } else {
        let edge = 256u64 << 20;
        starts.extend((0..edge / chunk).map(|i| i * chunk));
        let tail0 = (size - edge) / chunk * chunk;
        starts.extend((0..edge / chunk + 1).map(|i| tail0 + i * chunk).filter(|&s| s < size));
        let mut x = seed ^ size;
        for _ in 0..2048 {
            starts.push(splitmix64(&mut x) % nchunks * chunk);
        }
        starts.sort_unstable();
        starts.dedup();
    }
    starts.into_iter().map(|st| (st, chunk.min(size - st))).collect()
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DiskIdentity {
    pub vendor: String,
    pub model: String,
    pub serial: String,
    pub size: u64,
    pub sector_size: u32,
    pub bus: String,
}

impl DiskIdentity {
    /// 再開ファイル名に使うキー
    pub fn key(&self) -> String {
        let raw = format!("{}_{}_{}_{}", self.vendor, self.model, self.serial, self.size);
        raw.chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' })
            .collect()
    }
    pub fn same_disk(&self, other: &DiskIdentity) -> bool {
        self.model == other.model
            && self.vendor == other.vendor
            && self.serial == other.serial
            && self.size == other.size
            && self.sector_size == other.sector_size
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum BadKind {
    /// 書込み不可・読込み不可
    Unreadable,
    /// 書込み不可だが読込み可(元データが残っている可能性)
    Residual,
    /// 検証で0以外が残っていた(再書込みでも直らない)
    VerifyMismatch,
}

pub const CLASS_ZERO: u8 = 1;
pub const CLASS_TEXT: u8 = 2;
pub const CLASS_SIGNATURE: u8 = 4;
pub const CLASS_ENTROPY: u8 = 8;
pub const CLASS_OTHER: u8 = 16;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BadRun {
    pub start: u64,
    pub len: u64,
    pub kind: BadKind,
    pub classes: u8,
    pub sigs: Vec<String>,
    pub phase: u8,
}

impl BadRun {
    pub fn end(&self) -> u64 {
        self.start + self.len
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Event {
    pub time: String,
    pub what: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JobState {
    pub version: u32,
    pub identity: DiskIdentity,
    pub last_disk_number: u32,
    pub started: String,
    pub phase: u8,
    pub offset: u64,
    pub phase_ok: [u64; PHASE_COUNT],
    pub phase_err: [u64; PHASE_COUNT],
    pub phase_skip: [u64; PHASE_COUNT],
    pub phase_secs: [f64; PHASE_COUNT],
    pub write_retries: u64,
    pub read_retries: u64,
    pub verify_fixed: u64,
    pub bad_runs: Vec<BadRun>,
    pub events: Vec<Event>,
    /// 書込みエラーの種類別の回数(原因の切り分け用)
    #[serde(default)]
    pub write_errors: BTreeMap<String, u64>,
    /// 消去方式(再開時も同じ方式を使う)
    #[serde(default)]
    pub mode: EraseMode,
    /// 抽出検証の区間を決める種
    #[serde(default)]
    pub sample_seed: u64,
    /// 自動調整で選ばれた (ブロックバイト数, 同時発行数)
    #[serde(default)]
    pub tuned: Option<(u32, u32)>,
    /// 通常の工程から外し、最後に消す先頭・末尾の合計バイト数(0なら従来どおり全域を工程で処理)
    #[serde(default)]
    pub deferred: u64,
}

/// 最後に消す先頭・末尾の大きさ。ディスクが小さいときは使わない(0, 0)。
/// ボリュームデータ(ドライブの割り当てを決めるパーティション表)だけを対象にする最小限の範囲。
/// 先頭: MBR と GPT(ヘッダ+パーティション表)。末尾: GPTの控え。
/// ファイル名などの管理領域(ファイルシステム内)は、通常どおり各工程で消す。
pub fn deferred_sizes(disk_size: u64) -> (u64, u64) {
    const HEAD: u64 = 1 << 20;
    const TAIL: u64 = 1 << 20;
    if disk_size < 1 << 30 {
        (0, 0)
    } else {
        (HEAD, TAIL)
    }
}

pub fn now_str() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

impl JobState {
    pub fn new(identity: DiskIdentity, disk_number: u32) -> Self {
        Self::new_with_mode(identity, disk_number, EraseMode::Standard)
    }

    pub fn new_with_mode(identity: DiskIdentity, disk_number: u32, mode: EraseMode) -> Self {
        let mut seed = [0u8; 8];
        let _ = getrandom::fill(&mut seed);
        JobState {
            version: 2,
            identity,
            last_disk_number: disk_number,
            started: now_str(),
            phase: 0,
            offset: 0,
            phase_ok: [0; PHASE_COUNT],
            phase_err: [0; PHASE_COUNT],
            phase_skip: [0; PHASE_COUNT],
            phase_secs: [0.0; PHASE_COUNT],
            write_retries: 0,
            read_retries: 0,
            verify_fixed: 0,
            bad_runs: Vec::new(),
            events: Vec::new(),
            write_errors: BTreeMap::new(),
            mode,
            sample_seed: u64::from_le_bytes(seed),
            tuned: None,
            deferred: 0,
        }
    }

    pub fn event(&mut self, what: impl Into<String>) {
        self.events.push(Event { time: now_str(), what: what.into() });
    }

    /// 不良セクタ範囲を追加(隣接かつ同種なら結合)
    pub fn add_bad(&mut self, lba: u64, kind: BadKind, classes: u8, sig: Option<&str>) {
        let idx = self.bad_runs.partition_point(|r| r.start < lba);
        // 既に含まれている場合
        if idx > 0 && self.bad_runs[idx - 1].end() > lba {
            return;
        }
        if idx < self.bad_runs.len() && self.bad_runs[idx].start == lba {
            return;
        }
        let phase = self.phase;
        let mut merged = false;
        if idx > 0 {
            let p = &mut self.bad_runs[idx - 1];
            if p.end() == lba && p.kind == kind {
                p.len += 1;
                p.classes |= classes;
                if let Some(s) = sig {
                    if p.sigs.len() < 8 && !p.sigs.iter().any(|x| x == s) {
                        p.sigs.push(s.to_string());
                    }
                }
                merged = true;
            }
        }
        if merged {
            // 次の範囲との結合
            let i = idx - 1;
            if i + 1 < self.bad_runs.len()
                && self.bad_runs[i].end() == self.bad_runs[i + 1].start
                && self.bad_runs[i].kind == self.bad_runs[i + 1].kind
            {
                let n = self.bad_runs.remove(i + 1);
                let p = &mut self.bad_runs[i];
                p.len += n.len;
                p.classes |= n.classes;
                for s in n.sigs {
                    if p.sigs.len() < 8 && !p.sigs.contains(&s) {
                        p.sigs.push(s);
                    }
                }
            }
            return;
        }
        if idx < self.bad_runs.len()
            && lba + 1 == self.bad_runs[idx].start
            && self.bad_runs[idx].kind == kind
        {
            let n = &mut self.bad_runs[idx];
            n.start = lba;
            n.len += 1;
            n.classes |= classes;
            if let Some(s) = sig {
                if n.sigs.len() < 8 && !n.sigs.iter().any(|x| x == s) {
                    n.sigs.push(s.to_string());
                }
            }
            return;
        }
        self.bad_runs.insert(
            idx,
            BadRun {
                start: lba,
                len: 1,
                kind,
                classes,
                sigs: sig.map(|s| vec![s.to_string()]).unwrap_or_default(),
                phase,
            },
        );
    }

    /// [cur, end) のうち、先頭から見て最初の「処理すべき区間」と「スキップ区間」を返す。
    /// 戻り値: (処理区間の終端, 次の開始位置)
    pub fn next_segment(&self, cur: u64, end: u64) -> (u64, u64) {
        let i = self.bad_runs.partition_point(|r| r.end() <= cur);
        if i >= self.bad_runs.len() {
            return (end, end);
        }
        let r = &self.bad_runs[i];
        if r.start <= cur {
            (cur, r.end().min(end))
        } else {
            let e = r.start.min(end);
            (e, e)
        }
    }

    /// 書き込めるようになったセクタを不良の記録から外す(範囲の分割・縮小に対応)
    pub fn clear_bad(&mut self, lba: u64) -> bool {
        let i = self.bad_runs.partition_point(|r| r.end() <= lba);
        let Some(r) = self.bad_runs.get(i) else { return false };
        if r.start > lba {
            return false;
        }
        if r.len == 1 {
            self.bad_runs.remove(i);
        } else if lba == r.start {
            let r = &mut self.bad_runs[i];
            r.start += 1;
            r.len -= 1;
        } else if lba == r.end() - 1 {
            self.bad_runs[i].len -= 1;
        } else {
            let mut tail = self.bad_runs[i].clone();
            tail.start = lba + 1;
            tail.len = self.bad_runs[i].end() - (lba + 1);
            self.bad_runs[i].len = lba - self.bad_runs[i].start;
            self.bad_runs.insert(i + 1, tail);
        }
        true
    }

    pub fn total_bad_sectors(&self) -> u64 {
        self.bad_runs.iter().map(|r| r.len).sum()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let tmp = path.with_extension("json.tmp");
        let data = serde_json::to_vec(self).map_err(std::io::Error::other)?;
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&data)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)
    }

    pub fn load(path: &Path) -> std::io::Result<JobState> {
        let data = std::fs::read(path)?;
        let mut st: JobState = serde_json::from_slice(&data).map_err(std::io::Error::other)?;
        if st.version < 2 {
            // 旧版は、書込みが全て失敗していても「不良セクタ」として先へ進んでいた。
            // 1セクタも書けていない記録は誤りなので、進捗ごと破棄してやり直す。
            if st.phase_ok.iter().sum::<u64>() == 0 && !st.bad_runs.is_empty() {
                st.phase = 0;
                st.offset = 0;
                st.phase_ok = [0; PHASE_COUNT];
                st.phase_err = [0; PHASE_COUNT];
                st.phase_skip = [0; PHASE_COUNT];
                st.phase_secs = [0.0; PHASE_COUNT];
                st.write_retries = 0;
                st.read_retries = 0;
                st.bad_runs.clear();
                st.event("旧版で全セクタの書込みに失敗していた記録を破棄し、最初からやり直します");
            }
            st.version = 2;
        }
        Ok(st)
    }

    /// 各工程で処理するバイト数(実行しない工程は0)
    pub fn slot_lens(&self) -> [u64; PHASE_COUNT] {
        let size = self.identity.size.saturating_sub(self.deferred);
        let mut v = [0u64; PHASE_COUNT];
        for (slot, len) in v.iter_mut().enumerate().take(3) {
            if self.mode.slot_enabled(slot as u8) {
                *len = size;
            }
        }
        v[3] = if self.mode.sample_verify() {
            sample_ranges(size, self.identity.sector_size as u64, self.sample_seed).iter().map(|r| r.1).sum()
        } else {
            size
        };
        v
    }

    /// 通算の処理済みバイト数(実行する工程の合計)
    pub fn progress_bytes(&self, _size: u64) -> u64 {
        let l = self.slot_lens();
        let done: u64 = l[..(self.phase as usize).min(PHASE_COUNT)].iter().sum();
        done + if self.phase < PHASE_DONE { self.offset } else { 0 }
    }

    pub fn total_bytes(&self) -> u64 {
        self.slot_lens().iter().sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident() -> DiskIdentity {
        DiskIdentity {
            vendor: "V".into(),
            model: "M".into(),
            serial: "S".into(),
            size: 1 << 20,
            sector_size: 512,
            bus: "SATA".into(),
        }
    }

    #[test]
    fn add_bad_merges_adjacent() {
        let mut s = JobState::new(ident(), 1);
        for l in [10, 12, 11, 20] {
            s.add_bad(l, BadKind::Unreadable, 0, None);
        }
        assert_eq!(s.bad_runs.len(), 2);
        assert_eq!(s.bad_runs[0].start, 10);
        assert_eq!(s.bad_runs[0].len, 3);
        assert_eq!(s.total_bad_sectors(), 4);
    }

    #[test]
    fn next_segment_splits() {
        let mut s = JobState::new(ident(), 1);
        s.add_bad(5, BadKind::Unreadable, 0, None);
        s.add_bad(6, BadKind::Unreadable, 0, None);
        assert_eq!(s.next_segment(0, 20), (5, 5));
        assert_eq!(s.next_segment(5, 20), (5, 7));
        assert_eq!(s.next_segment(7, 20), (20, 20));
        assert_eq!(s.next_segment(0, 3), (3, 3));
    }

    #[test]
    fn legacy_all_failed_state_is_reset() {
        let dir = std::env::temp_dir().join(format!("hddwiper_legacy_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut s = JobState::new(ident(), 1);
        s.version = 1;
        s.offset = 1 << 20;
        s.phase_err[0] = 2048;
        s.add_bad(0, BadKind::Residual, CLASS_OTHER, None);
        let p = dir.join("legacy.json");
        s.save(&p).unwrap();
        let l = JobState::load(&p).unwrap();
        assert_eq!(l.offset, 0);
        assert!(l.bad_runs.is_empty());
        assert_eq!(l.version, 2);
        // 1セクタでも書けていた旧版の記録は残す
        let mut s2 = JobState::new(ident(), 1);
        s2.version = 1;
        s2.offset = 4096;
        s2.phase_ok[0] = 8;
        s2.add_bad(100, BadKind::Unreadable, 0, None);
        s2.save(&p).unwrap();
        let l2 = JobState::load(&p).unwrap();
        assert_eq!(l2.offset, 4096);
        assert_eq!(l2.bad_runs.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sample_ranges_are_deterministic_and_bounded() {
        let size = 6_001_175_126_016u64;
        let a = sample_ranges(size, 512, 42);
        let b = sample_ranges(size, 512, 42);
        let c = sample_ranges(size, 512, 43);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.windows(2).all(|w| w[0].0 < w[1].0), "昇順で重複なし");
        assert!(a.iter().all(|&(s, l)| l > 0 && s + l <= size && s % 512 == 0 && l % 512 == 0));
        let total: u64 = a.iter().map(|r| r.1).sum();
        assert!(total < 3 << 30, "抽出は数GiB程度: {total}");
        assert_eq!(a[0].0, 0);
        assert_eq!(a.last().map(|r| r.0 + r.1), Some(size - size % SAMPLE_CHUNK + (size % SAMPLE_CHUNK)).filter(|_| true));
        // 小さいディスクは全域
        let small = sample_ranges(8 << 20, 512, 1);
        assert_eq!(small.iter().map(|r| r.1).sum::<u64>(), 8 << 20);
    }

    #[test]
    fn mode_steps() {
        assert_eq!(EraseMode::Standard.step_count(), 4);
        assert_eq!(EraseMode::TwoPass.step_count(), 3);
        assert_eq!(EraseMode::OnePass.step_count(), 2);
        assert!(!EraseMode::OnePass.slot_enabled(0) && !EraseMode::OnePass.slot_enabled(1));
        assert!(EraseMode::OnePass.slot_enabled(2) && EraseMode::OnePass.slot_enabled(3));
        assert_eq!(EraseMode::TwoPass.step_no(2), 2);
        let mut s = JobState::new_with_mode(ident(), 1, EraseMode::OnePass);
        s.phase = 2;
        s.offset = 100;
        assert_eq!(s.progress_bytes(0), 100);
    }
}
