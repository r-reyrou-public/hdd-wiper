//! 消去エンジン: 書込み工程(ゼロ/乱数/ゼロ)と検証。方式プリセット・中断・再開に対応。

use crate::classify::classify;
use crate::dev::{AlignedBuf, BlockDev, StallAbort};
use crate::report;
use crate::state::*;
use crate::util::secure_erase_file;
use rand_chacha::ChaCha8Rng;
use rand_core::{Rng, SeedableRng};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const CMD_RUN: u8 = 0;
pub const CMD_PAUSE: u8 = 1;
pub const CMD_STOP: u8 = 2;

/// 一時停止の理由(表示とイベント記録用)
pub const REASON_QUEUE: u8 = 0; // スケジューラの待機(記録しない)
pub const REASON_USER: u8 = 1;
pub const REASON_BANDWIDTH: u8 = 2;

pub const CELLS: usize = 4096;

/// 書込みに1度も成功しないまま、これだけ連続して失敗したら系統的な失敗とみなして中止する
pub const SYSTEMIC_FAIL_BYTES: u64 = 64 << 20;

#[derive(Clone, Debug, PartialEq)]
pub enum Status {
    Preparing,
    Running,
    Paused,
    Finished,
    Stopped,
    Failed(String),
}

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub status: Status,
    pub phase: u8,
    pub offset: u64,
    pub size: u64,
    pub sector_size: u32,
    pub total_done: u64,
    /// 実行する全工程の合計バイト数
    pub total_all: u64,
    /// 現在の工程で処理するバイト数
    pub phase_len: u64,
    pub step: usize,
    pub steps: usize,
    pub sample_verify: bool,
    pub samples: VecDeque<(Instant, u64)>,
    pub ok: u64,
    pub err: u64,
    pub skip: u64,
    pub write_retries: u64,
    pub read_retries: u64,
    pub bad_sectors: u64,
    pub unerased_sectors: u64,
    pub report_path: Option<PathBuf>,
    pub message: String,
    /// 直近の書込みエラー(OSのエラーコードつき)
    pub last_error: String,
    /// 自動調整の結果や書込みキャッシュの状態などの説明
    pub notes: String,
}

impl Snapshot {
    pub fn new(size: u64, sector_size: u32) -> Self {
        Snapshot {
            status: Status::Preparing,
            phase: 0,
            offset: 0,
            size,
            sector_size,
            total_done: 0,
            total_all: size * PHASE_COUNT as u64,
            phase_len: size,
            step: 1,
            steps: PHASE_COUNT,
            sample_verify: false,
            samples: VecDeque::new(),
            ok: 0,
            err: 0,
            skip: 0,
            write_retries: 0,
            read_retries: 0,
            bad_sectors: 0,
            unerased_sectors: 0,
            report_path: None,
            message: String::new(),
            last_error: String::new(),
            notes: String::new(),
        }
    }

    /// 直近 window の平均速度(bytes/sec)。不足していれば None
    pub fn speed(&self, window: Duration) -> Option<f64> {
        let (t1, b1) = *self.samples.back()?;
        let mut first = *self.samples.front()?;
        for &(t, b) in self.samples.iter() {
            if t1.duration_since(t) <= window {
                first = (t, b);
                break;
            }
        }
        let dt = t1.duration_since(first.0).as_secs_f64();
        if dt < 1.0 {
            return None;
        }
        Some((b1 - first.1) as f64 / dt)
    }

    pub fn total_bytes_all(&self) -> u64 {
        self.total_all
    }
}

#[derive(Default)]
pub struct LatStats {
    pub wait_n: AtomicU64,
    pub wait_sum: AtomicU64,
    pub wait_max: AtomicU64,
    pub flush_n: AtomicU64,
    pub flush_sum: AtomicU64,
    pub flush_max: AtomicU64,
}

impl LatStats {
    fn add(n: &AtomicU64, sum: &AtomicU64, max: &AtomicU64, d: Duration) {
        let us = d.as_micros() as u64;
        n.fetch_add(1, Ordering::Relaxed);
        sum.fetch_add(us, Ordering::Relaxed);
        max.fetch_max(us, Ordering::Relaxed);
    }
    pub fn add_wait(&self, d: Duration) {
        Self::add(&self.wait_n, &self.wait_sum, &self.wait_max, d)
    }
    pub fn add_flush(&self, d: Duration) {
        Self::add(&self.flush_n, &self.flush_sum, &self.flush_max, d)
    }
    /// (回数, 平均ms, 最大ms) を読み出して0に戻す: (待ち, flush)
    pub fn take(&self) -> ((u64, f64, f64), (u64, f64, f64)) {
        let f = |n: &AtomicU64, sum: &AtomicU64, max: &AtomicU64| {
            let c = n.swap(0, Ordering::Relaxed);
            let s = sum.swap(0, Ordering::Relaxed);
            let m = max.swap(0, Ordering::Relaxed);
            (c, if c > 0 { s as f64 / c as f64 / 1000.0 } else { 0.0 }, m as f64 / 1000.0)
        };
        (f(&self.wait_n, &self.wait_sum, &self.wait_max), f(&self.flush_n, &self.flush_sum, &self.flush_max))
    }
}

pub struct JobShared {
    pub cmd: AtomicU8,
    pub reason: AtomicU8,
    /// 発行済みのI/Oが完了せずに待っている秒数(0なら正常)
    pub stall_secs: AtomicU64,
    /// 未消去セクタの書き直しが済んでいない(スケジューラはこのジョブを1本ずつ先に動かす)
    pub refill_pending: AtomicBool,
    /// 待ち時間の統計(原因調査用。スケジューラが定期的に読み出して0に戻す)。
    /// 書込み完了待ち(最古のI/Oを回収するまでに待った時間)と flush の回数・合計・最大(マイクロ秒)
    pub lat: LatStats,
    pub snap: Mutex<Snapshot>,
    pub map: Mutex<Vec<u8>>,
}

impl JobShared {
    pub fn new(size: u64, sector_size: u32) -> Arc<Self> {
        Arc::new(JobShared {
            cmd: AtomicU8::new(CMD_PAUSE),
            reason: AtomicU8::new(REASON_QUEUE),
            stall_secs: AtomicU64::new(0),
            refill_pending: AtomicBool::new(false),
            lat: LatStats::default(),
            snap: Mutex::new(Snapshot::new(size, sector_size)),
            map: Mutex::new(vec![0; CELLS]),
        })
    }
    pub fn set_cmd(&self, cmd: u8, reason: u8) {
        self.reason.store(reason, Ordering::SeqCst);
        self.cmd.store(cmd, Ordering::SeqCst);
    }
    pub fn snapshot(&self) -> Snapshot {
        self.snap.lock().unwrap().clone()
    }
    pub fn set_status(&self, s: Status) {
        self.snap.lock().unwrap().status = s;
    }
}

#[derive(Clone)]
pub struct EngineCfg {
    /// 1回の転送の最大サイズ(バッファの大きさ)
    pub block: usize,
    pub retries: u32,
    /// 進捗の保存(と書込みキャッシュの flush)の間隔
    pub checkpoint_bytes: u64,
    pub checkpoint_secs: u64,
    /// 連続してこの数のセクタが失敗したら、以降の再試行を省略して高速にスキップする
    pub fast_skip_after: u32,
    /// 同時に発行する書込み・読込みの数(重ね書き)。1なら逐次
    pub queue_depth: usize,
    /// 確保するバッファの最大数(自動調整の上限)
    pub max_depth: usize,
    /// 書込みスルーで開いているか(ログ表示用。ディスクを開く側で実際に設定する)
    pub write_through: bool,
    /// 開始直後に、ブロックサイズと同時発行数を実測して最適な組を選ぶ
    pub autotune: bool,
    /// 自動調整を行う最小のディスク容量
    pub tune_min_size: u64,
    pub tune_warmup_ms: u64,
    pub tune_probe_ms: u64,
}

impl Default for EngineCfg {
    fn default() -> Self {
        EngineCfg {
            block: 16 << 20,
            retries: 3,
            checkpoint_bytes: 4 << 30,
            checkpoint_secs: 90,
            fast_skip_after: 256,
            queue_depth: 3,
            max_depth: 4,
            write_through: false,
            autotune: true,
            tune_min_size: 64 << 30,
            tune_warmup_ms: 3000,
            tune_probe_ms: 8000,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Finished,
    Stopped,
}

enum Wp {
    Done,
    Stopped,
    Deadline,
}

struct Inflight {
    slot: usize,
    off: u64,
    len: usize,
    /// 発行時点で結果が分かっている場合(同期I/O・発行失敗)
    early: Option<std::io::Result<()>>,
}

pub struct Engine {
    dev: Box<dyn BlockDev>,
    shared: Arc<JobShared>,
    pub st: JobState,
    state_path: PathBuf,
    log_dir: PathBuf,
    cfg: EngineCfg,
    bufs: Vec<AlignedBuf>,
    cur: usize,
    /// 現在のブロックサイズと同時発行数
    blk: usize,
    dep: usize,
    async_ok: bool,
    inflight: VecDeque<Inflight>,
    free_slots: Vec<usize>,
    submit_off: u64,
    scratch: AlignedBuf,
    rng: ChaCha8Rng,
    ss: u64,
    size: u64,
    slot_lens: [u64; PHASE_COUNT],
    sample: Vec<(u64, u64)>,
    since_ckpt: u64,
    last_ckpt: Instant,
    last_sample: Instant,
    consec_fail: u32,
    last_tick: Instant,
    paused_logged: bool,
    /// 直近のチェックポイント時点の工程内オフセットと件数
    ckpt_offset: u64,
    ckpt_counts: [u64; 3],
    /// このオフセットまでは、ブロックごとに flush して確実に書込みを確認する(キャッシュ書込み失敗の切り分け)
    careful_until: u64,
    careful_now: bool,
    last_err: String,
    /// 実行開始以降に書込みに成功したセクタ数
    run_ok: u64,
    /// 系統的な書込み失敗を検出したときの中止理由
    fatal: Option<String>,
    run_start: Option<JobState>,
    notes: Vec<String>,
    /// 応答しないI/Oを取り消した直後(不良セクタとして記録しない)
    aborted: bool,
    /// 取り消しにも応じず、I/Oがカーネルに残っている(バッファを解放してはいけない)
    hung: bool,
    /// 応答停止のため書込みキャッシュの確認(flush)ができない。最後に確認済みの位置へ戻して保存する
    unsafe_flush: bool,
    /// 実行中に応答停止で自動的に取り消した回数(成功すると0に戻る)
    auto_aborts: u32,
    /// 自動の取り消し・やり直しを繰り返しても進まないので、あきらめて中断する
    giveup: bool,
    /// 長い応答待ちを再開ログに記録した回数(記録しすぎないための上限用)
    slow_events: u32,
    /// 再開ファイルを保存できていない(空き容量不足など)。定期的に再試行する
    save_pending: bool,
    last_save_try: Instant,
    /// 応答が遅いときの縮退: 0=通常 1=4MiB×2 2=1MiB×1
    slow_level: u8,
    slow_base: (usize, usize),
    slow_hits: u32,
    fast_hits: u32,
    slow_notes: u32,
}

impl Drop for Engine {
    fn drop(&mut self) {
        // 発行済みのI/Oが残っている状態でバッファを解放しない
        while let Some(e) = self.inflight.pop_front() {
            if e.early.is_none() {
                let _ = self.dev.finish_write(e.slot);
            }
        }
    }
}

impl Engine {
    pub fn new(
        dev: Box<dyn BlockDev>,
        shared: Arc<JobShared>,
        st: JobState,
        state_path: PathBuf,
        log_dir: PathBuf,
        cfg: EngineCfg,
    ) -> Self {
        let mut dev = dev;
        dev.attach(shared.clone());
        let ss = dev.sector_size() as u64;
        let size = dev.total_bytes();
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("OSの乱数源を取得できません");
        let block = (cfg.block / ss as usize).max(1) * ss as usize;
        let mut cfg = cfg;
        cfg.block = block;
        let slots = dev.async_slots();
        let async_ok = cfg.queue_depth > 1 && slots > 1;
        let nbuf = if async_ok { cfg.max_depth.max(cfg.queue_depth).min(slots) } else { 1 };
        let dep = if async_ok { cfg.queue_depth.min(nbuf) } else { 1 };
        let slot_lens = st.slot_lens();
        let sample = if st.mode.sample_verify() { sample_ranges(size, ss, st.sample_seed) } else { Vec::new() };
        let mut e = Engine {
            dev,
            shared,
            st,
            state_path,
            log_dir,
            bufs: (0..nbuf).map(|_| AlignedBuf::new(block)).collect(),
            cur: 0,
            blk: block,
            dep,
            async_ok,
            inflight: VecDeque::new(),
            free_slots: (0..nbuf).rev().collect(),
            submit_off: 0,
            scratch: AlignedBuf::new((ss as usize).max(4096)),
            cfg,
            rng: ChaCha8Rng::from_seed(seed),
            ss,
            size,
            slot_lens,
            sample,
            since_ckpt: 0,
            last_ckpt: Instant::now(),
            last_sample: Instant::now(),
            consec_fail: 0,
            last_tick: Instant::now(),
            paused_logged: false,
            ckpt_offset: 0,
            ckpt_counts: [0; 3],
            careful_until: 0,
            careful_now: false,
            last_err: String::new(),
            run_ok: 0,
            fatal: None,
            run_start: None,
            notes: Vec::new(),
            aborted: false,
            hung: false,
            unsafe_flush: false,
            auto_aborts: 0,
            giveup: false,
            slow_events: 0,
            save_pending: false,
            last_save_try: Instant::now(),
            slow_level: 0,
            slow_base: (block, dep),
            slow_hits: 0,
            fast_hits: 0,
            slow_notes: 0,
        };
        if let Some((b, d)) = e.st.tuned {
            e.apply_tuning(b as usize, d as usize);
        }
        e
    }

    /// 取り消しに応じないI/Oが残っているか。true ならこの Engine を drop せず leak させること
    pub fn is_hung(&self) -> bool {
        self.hung
    }

    /// 開始前に分かっている説明(書込みキャッシュの状態など)を記録に残す
    pub fn add_note(&mut self, note: impl Into<String>) {
        let n = note.into();
        self.st.event(n.clone());
        self.notes.push(n);
    }

    /// I/O の完了待ちが長い(領域不良や接続の不調で遅い)ときは、転送を小さく・同時発行を減らして、
    /// 経路(USBブリッジ・ハブ)ごと止まるのを防ぐ。回復したら元に戻す。
    fn note_latency(&mut self, w: Duration) {
        const SLOW: Duration = Duration::from_millis(1000);
        const FAST: Duration = Duration::from_millis(100);
        if w >= SLOW {
            self.fast_hits = 0;
            self.slow_hits += 1;
            if self.slow_hits >= 2 && self.slow_level < 2 {
                self.slow_hits = 0;
                if self.slow_level == 0 {
                    self.slow_base = (self.blk, self.dep);
                }
                self.slow_level += 1;
                self.set_slow_level(w);
            }
        } else if self.slow_level > 0 {
            self.slow_hits = 0;
            if w < FAST {
                self.fast_hits += 1;
                if self.fast_hits >= 300 {
                    self.fast_hits = 0;
                    self.slow_level -= 1;
                    self.set_slow_level(w);
                }
            } else {
                self.fast_hits = 0;
            }
        } else {
            self.slow_hits = 0;
        }
    }

    fn set_slow_level(&mut self, w: Duration) {
        let ss = self.ss as usize;
        let (bb, bd) = self.slow_base;
        let (blk, dep) = match self.slow_level {
            0 => (bb, bd),
            1 => (bb.min(4 << 20), bd.min(2)),
            _ => (bb.min(1 << 20), 1),
        };
        self.blk = (blk / ss).max(1) * ss;
        self.dep = dep.clamp(1, self.bufs.len());
        if !self.async_ok {
            self.dep = 1;
        }
        if self.slow_notes < 20 {
            self.slow_notes += 1;
            let msg = if self.slow_level == 0 {
                format!("応答が回復したため、転送を元に戻しました: {}MiB×{}", self.blk >> 20, self.dep)
            } else {
                format!(
                    "ディスクの応答が遅い({} ms)ため、転送を小さくしました: {}KiB×{} (レベル{})",
                    w.as_millis(), self.blk >> 10, self.dep, self.slow_level
                )
            };
            self.st.event(msg);
        }
    }

    fn apply_tuning(&mut self, block: usize, depth: usize) {
        let ss = self.ss as usize;
        self.blk = (block.min(self.cfg.block) / ss).max(1) * ss;
        self.dep = depth.clamp(1, self.bufs.len());
        if !self.async_ok {
            self.dep = 1;
        }
        self.slow_level = 0;
        self.slow_base = (self.blk, self.dep);
    }

    // ------------------------------------------------------------ 補助

    fn cell(&self, byte: u64) -> usize {
        ((byte as u128 * CELLS as u128 / self.size as u128) as usize).min(CELLS - 1)
    }

    fn mark_range(&self, b0: u64, b1: u64, val: u8) {
        if b1 <= b0 {
            return;
        }
        let (c0, c1) = (self.cell(b0), self.cell(b1 - 1));
        let mut m = self.shared.map.lock().unwrap();
        for c in c0..=c1 {
            if m[c] != 2 {
                m[c] = val;
            }
        }
    }

    fn mark_bad(&self, lba: u64) {
        let c = self.cell(lba * self.ss);
        self.shared.map.lock().unwrap()[c] = 2;
    }

    fn rebuild_map(&self) {
        let mut m = self.shared.map.lock().unwrap();
        m.iter_mut().for_each(|c| *c = 0);
        drop(m);
        if self.st.phase < PHASE_DONE {
            if self.st.phase == 3 && self.st.mode.sample_verify() {
                let mut cum = 0u64;
                for &(pos, len) in &self.sample {
                    if cum + len > self.st.offset {
                        break;
                    }
                    self.mark_range(pos, pos + len, 1);
                    cum += len;
                }
            } else {
                self.mark_range(0, self.st.offset, 1);
            }
        }
        for r in &self.st.bad_runs {
            let c0 = self.cell(r.start * self.ss);
            let c1 = self.cell((r.end() - 1) * self.ss);
            let mut m = self.shared.map.lock().unwrap();
            for c in c0..=c1 {
                m[c] = 2;
            }
        }
    }

    fn record_err(&mut self, e: &std::io::Error) {
        let label = os_label(e);
        if self.st.write_errors.len() < 20 || self.st.write_errors.contains_key(&label) {
            *self.st.write_errors.entry(label.clone()).or_insert(0) += 1;
        }
        self.last_err = label;
    }

    /// 系統的な書込み失敗: この実行で積んだ「不良セクタ」は誤りなので、実行開始時点の状態に戻して中止する
    fn abort_systemic(&mut self, msg: String) -> String {
        self.reap_all_quiet();
        let events = std::mem::take(&mut self.st.events);
        let errs = std::mem::take(&mut self.st.write_errors);
        if let Some(rs) = self.run_start.take() {
            self.st = rs;
        }
        self.st.events = events;
        self.st.write_errors = errs;
        self.st.event(format!("中止: {msg}"));
        self.ckpt_offset = self.st.offset;
        let _ = self.st.save(&self.state_path);
        msg
    }

    fn counts(&self, ph: usize) -> [u64; 3] {
        [self.st.phase_ok[ph], self.st.phase_err[ph], self.st.phase_skip[ph]]
    }

    /// 進捗を保存する。書込み工程では、ディスクの書込みキャッシュも flush する。
    /// `drain` が true なら、発行済みの書込みを全て回収してから行う(false なら書込みを止めずに flush)。
    /// flush に失敗した場合は、直近のチェックポイントまで巻き戻して(再実行は1ブロックずつ確認する)
    /// false を返す。
    fn checkpoint(&mut self, drain: bool) -> bool {
        if drain {
            self.reap_all_quiet();
        }
        let mut clean = true;
        let mut skip_flush = self.unsafe_flush;
        let mut flush_failed = false;
        if self.st.phase < 3 && !skip_flush {
            let t_fl = Instant::now();
            let fr = self.dev.flush();
            self.shared.lat.add_flush(t_fl.elapsed());
            if let Err(e) = fr {
                flush_failed = true;
                if let Some(sa) = e.get_ref().and_then(|x| x.downcast_ref::<StallAbort>()) {
                    // 応答しないflush: 書込みキャッシュの状態が分からないので、確認済みの位置まで戻す
                    skip_flush = true;
                    self.unsafe_flush = true;
                    if sa.hung {
                        self.hung = true;
                    }
                }
            }
        }
        if self.st.phase < 3 && (skip_flush || flush_failed) {
            clean = false;
            self.reap_all_quiet();
            let ph = self.st.phase as usize;
            let failed_at = self.st.offset;
            if skip_flush {
                self.st.event(format!(
                    "ディスクの応答停止のため書込みキャッシュを確認できません。最後に確認済みのオフセット {} まで戻して保存します(進んでいた {} までは再開後に書き直します)",
                    self.ckpt_offset, failed_at
                ));
            } else {
                self.st.event(format!(
                    "書込みキャッシュの吐き出しに失敗。オフセット {} から {} の範囲を1ブロックずつ確認しながら書き直します",
                    self.ckpt_offset, failed_at
                ));
                self.careful_until = self.careful_until.max(failed_at);
            }
            self.st.offset = self.ckpt_offset;
            self.submit_off = self.ckpt_offset;
            self.st.phase_ok[ph] = self.ckpt_counts[0];
            self.st.phase_err[ph] = self.ckpt_counts[1];
            self.st.phase_skip[ph] = self.ckpt_counts[2];
            self.rebuild_map();
        }
        self.try_save();
        if clean {
            self.ckpt_offset = self.st.offset;
            if self.st.phase < 3 {
                self.ckpt_counts = self.counts(self.st.phase as usize);
            }
        }
        self.since_ckpt = 0;
        self.last_ckpt = Instant::now();
        clean
    }

    /// 再開ファイルを保存する。失敗(空き容量不足など)したら画面に出し、あとで再試行する。
    /// 保存できたら表示を消し、保存できなかった期間があれば記録に残す。
    fn try_save(&mut self) -> bool {
        self.last_save_try = Instant::now();
        match self.st.save(&self.state_path) {
            Ok(()) => {
                if self.save_pending {
                    self.save_pending = false;
                    self.st.event("再開ファイルを保存できました(空き容量が確保されました)");
                    let _ = self.st.save(&self.state_path);
                }
                let mut s = self.shared.snap.lock().unwrap();
                if s.message.starts_with("再開ファイルの保存に失敗") {
                    s.message.clear();
                }
                true
            }
            Err(e) => {
                if !self.save_pending {
                    self.save_pending = true;
                    // 保存できないので、イベントは(次に保存できたときに)メモリ上の記録として残る
                    self.st.event(format!("再開ファイルを保存できません: {e}。空き容量ができ次第、10秒ごとに再試行します"));
                }
                self.shared.snap.lock().unwrap().message = format!(
                    "再開ファイルの保存に失敗: {e} (空き容量ができ次第、10秒ごとに自動で再試行します。書込みは続けますが、この間に中断すると続きから再開できない可能性があります)"
                );
                false
            }
        }
    }

    fn done_before(&self, phase: usize) -> u64 {
        self.slot_lens[..phase.min(PHASE_COUNT)].iter().sum()
    }

    fn publish(&mut self, force_sample: bool) {
        let ph = (self.st.phase as usize).min(PHASE_COUNT - 1);
        let mut s = self.shared.snap.lock().unwrap();
        s.phase = self.st.phase;
        s.offset = self.st.offset;
        s.total_done = self.done_before(self.st.phase as usize) + if self.st.phase < PHASE_DONE { self.st.offset } else { 0 };
        s.total_all = self.slot_lens.iter().sum();
        s.phase_len = self.slot_lens[ph];
        s.step = self.st.mode.step_no(self.st.phase);
        s.steps = self.st.mode.step_count();
        s.sample_verify = self.st.mode.sample_verify();
        s.ok = self.st.phase_ok[ph];
        s.err = self.st.phase_err[ph];
        s.skip = self.st.phase_skip[ph];
        s.write_retries = self.st.write_retries;
        s.read_retries = self.st.read_retries;
        s.bad_sectors = self.st.total_bad_sectors();
        s.unerased_sectors = self.st.total_bad_sectors();
        if s.last_error != self.last_err {
            s.last_error = self.last_err.clone();
        }
        if s.notes.is_empty() && !self.notes.is_empty() {
            s.notes = self.notes.join(" / ");
        }
        let now = Instant::now();
        if force_sample || now.duration_since(self.last_sample) >= Duration::from_millis(250) {
            let done = s.total_done;
            s.samples.push_back((now, done));
            while let Some(&(t, _)) = s.samples.front() {
                if now.duration_since(t) > Duration::from_secs(120) {
                    s.samples.pop_front();
                } else {
                    break;
                }
            }
            self.last_sample = now;
        }
    }

    /// 一時停止/中断の指示を処理する。false を返したら中断。
    /// 呼ぶ前に発行済みのI/Oを回収しておくこと。
    fn poll_control(&mut self) -> bool {
        loop {
            match self.shared.cmd.load(Ordering::SeqCst) {
                CMD_RUN => {
                    if self.paused_logged {
                        self.st.event("再開");
                        self.paused_logged = false;
                    }
                    {
                        let mut s = self.shared.snap.lock().unwrap();
                        if s.status != Status::Running {
                            s.status = Status::Running;
                            s.samples.clear();
                        }
                    }
                    return true;
                }
                CMD_STOP => {
                    self.st.event("中断(再開可能)");
                    self.checkpoint(true);
                    // 空き容量不足で再開ファイルを保存できていないときは、空きができるまで(最長30分)待つ
                    let t0 = Instant::now();
                    while self.save_pending && t0.elapsed() < Duration::from_secs(1800) {
                        std::thread::sleep(Duration::from_secs(5));
                        self.try_save();
                    }
                    return false;
                }
                _ => {
                    let reason = self.shared.reason.load(Ordering::SeqCst);
                    let already = self.shared.snapshot().status == Status::Paused;
                    if !already {
                        if reason != REASON_QUEUE && !self.paused_logged {
                            let why = if reason == REASON_BANDWIDTH {
                                "一時停止(帯域不足のため台数を絞った)"
                            } else {
                                "一時停止"
                            };
                            self.st.event(why);
                            self.paused_logged = true;
                        }
                        self.checkpoint(true);
                        self.shared.set_status(Status::Paused);
                    }
                    std::thread::sleep(Duration::from_millis(100));
                    self.last_tick = Instant::now();
                }
            }
        }
    }

    /// 現在の制御指示を確認する(実行中なら true)。呼ぶ前に発行済みI/Oは回収済みであること
    fn control_ok(&mut self) -> bool {
        if self.shared.cmd.load(Ordering::SeqCst) != CMD_RUN {
            return self.poll_control();
        }
        if self.shared.snap.lock().unwrap().status != Status::Running {
            // 初回の RUN 受付(状態表示の更新)
            return self.poll_control();
        }
        true
    }

    // ------------------------------------------------------------ メイン

    pub fn run(&mut self) -> Result<Outcome, String> {
        let resumed = self.st.phase > 0 || self.st.offset > 0;
        self.run_start = Some(self.st.clone());
        self.run_ok = 0;
        self.fatal = None;
        self.st.event(if resumed { "再開処理を開始" } else { "消去を開始" });
        self.st.event(format!("消去方式: {}", self.st.mode.short()));
        self.st.event(format!(
            "書込み設定: 最大ブロック {} MiB / 同時発行 最大{} / 書込みスルー {} / 進捗保存 {}秒ごと",
            self.cfg.block >> 20,
            self.bufs.len(),
            if self.cfg.write_through { "ON" } else { "OFF(チェックポイントごとにflush)" },
            self.cfg.checkpoint_secs
        ));
        self.rebuild_map();
        self.publish(true);
        self.last_tick = Instant::now();
        let mut tuned_this_run = false;
        let mut refilled_this_run = false;
        let mut verified_bad_first = false;
        while self.st.phase < PHASE_DONE {
            let ph = self.st.phase;
            if !self.st.mode.slot_enabled(ph) {
                self.st.phase += 1;
                self.st.offset = 0;
                continue;
            }
            let step = format!("工程 {}/{}: {}", self.st.mode.step_no(ph), self.st.mode.step_count(), phase_label(ph));
            if self.st.offset == 0 {
                self.st.event(format!("{step} 開始"));
                self.rebuild_map();
            }
            self.ckpt_offset = self.st.offset;
            if ph < 3 {
                self.ckpt_counts = self.counts(ph as usize);
            }
            self.submit_off = self.st.offset;
            self.careful_until = 0;
            if ph < 3 && (self.st.offset == 0 || !refilled_this_run) {
                // 本編の前に、前回までに書けなかったセクタを優先して書き直す
                refilled_this_run = true;
                let ok = self.refill_bad(ph);
                self.shared.refill_pending.store(false, Ordering::SeqCst);
                if !ok {
                    return self.stopped_outcome();
                }
            }
            if ph < 3 {
                if !tuned_this_run && self.should_tune() {
                    tuned_this_run = true;
                    if !self.autotune(ph) {
                        return self.stopped_outcome();
                    }
                }
                loop {
                    match self.write_phase_until(ph, None) {
                        Wp::Stopped => return self.stopped_outcome(),
                        Wp::Done | Wp::Deadline => {}
                    }
                    // 工程の最後に、書けなかったセクタをもう一度書き直してから flush する
                    if self.st.offset >= self.size && !self.refill_bad(ph) {
                        return self.stopped_outcome();
                    }
                    // 工程の最後に flush。失敗したら巻き戻されるので、もう一度書き直す
                    if self.checkpoint(true) {
                        break;
                    }
                }
            } else {
                if self.st.offset == 0 || !verified_bad_first {
                    verified_bad_first = true;
                    if !self.verify_bad_first() {
                        return self.stopped_outcome();
                    }
                }
                let ok = if self.st.mode.sample_verify() { self.verify_sample_phase() } else { self.verify_full_phase() };
                if !ok {
                    return self.stopped_outcome();
                }
            }
            self.st.event(format!("{step} 完了"));
            self.st.phase += 1;
            self.st.offset = 0;
            self.checkpoint(true);
            self.publish(true);
        }
        // 最後に、後回しにしていた先頭・末尾(パーティション情報・ドライブの割り当て)を消す。
        // 中断→再開しても、ここに来るまでは先頭が残っているので、ディスクを同じドライブとして扱える。
        if let Err(e) = self.wipe_deferred() {
            self.st.event(format!("中止: {e}"));
            let _ = self.st.save(&self.state_path);
            return Err(e);
        }
        self.st.event("全工程が完了");
        let _ = self.dev.flush();
        let note = self.dev.finish_wipe();
        if !note.is_empty() {
            self.st.event(note);
        }
        self.finish()
    }

    /// 通常の工程から外した範囲(先頭・末尾)を、工程と同じパターン(ゼロ→乱数→ゼロ)で消し、ゼロを確認する。
    /// 再開時は最初からやり直す(短い処理なので、やり直しても問題ない)。
    fn wipe_deferred(&mut self) -> Result<(), String> {
        let ranges = self.dev.deferred_ranges();
        if ranges.is_empty() {
            return Ok(());
        }
        let total: u64 = ranges.iter().map(|r| r.1).sum();
        self.st.event(format!(
            "最後に、先頭・末尾の合計 {} MiB(ボリュームデータ: パーティション表・ドライブの割り当て)を消去します",
            total >> 20
        ));
        self.publish(true);
        let chunk = self.bufs[0].as_slice().len();
        let mut layout_removed = false;
        for ph in 0..3u8 {
            if !self.st.mode.slot_enabled(ph) {
                continue;
            }
            for &(start, len) in &ranges {
                let end = start + len;
                let mut off = start;
                while off < end {
                    let n = ((end - off) as usize).min(chunk);
                    self.fill_block(0, ph, n);
                    let mut r = self.dev.write_raw(off, &self.bufs[0].as_slice()[..n]);
                    if r.is_err() && !layout_removed {
                        // パーティション情報が残っていて書けない場合は、先に削除してやり直す
                        layout_removed = true;
                        let note = self.dev.finish_wipe();
                        self.st.event(format!("先頭・末尾に書けなかったため、パーティション情報を先に削除して再試行します: {note}"));
                        r = self.dev.write_raw(off, &self.bufs[0].as_slice()[..n]);
                    }
                    r.map_err(|e| format!("先頭・末尾の消去に失敗しました(オフセット {off}): {e}"))?;
                    off += n as u64;
                }
            }
            self.dev.flush().map_err(|e| format!("先頭・末尾の消去の確認(flush)に失敗しました: {e}"))?;
        }
        // 最終工程はゼロなので、ゼロになっていることを読み戻して確認する
        for &(start, len) in &ranges {
            let end = start + len;
            let mut off = start;
            while off < end {
                let n = ((end - off) as usize).min(chunk);
                self.dev
                    .read_raw(off, &mut self.bufs[0].as_mut_slice()[..n])
                    .map_err(|e| format!("先頭・末尾の読み戻しに失敗しました(オフセット {off}): {e}"))?;
                if self.bufs[0].as_slice()[..n].iter().any(|&b| b != 0) {
                    return Err(format!("先頭・末尾の消去を確認できませんでした(オフセット {off} 付近にゼロでないデータが残っています)"));
                }
                off += n as u64;
            }
        }
        self.st.event("先頭・末尾の消去を確認しました");
        Ok(())
    }

    fn stopped_outcome(&mut self) -> Result<Outcome, String> {
        if self.giveup && !self.hung {
            self.unsafe_flush = true;
            self.st.event("応答停止による取り消しとやり直しを3回繰り返しても進まないため、中断します");
            self.checkpoint(false);
            return Err("ディスクが長時間応答せず、取り消してやり直しても進みませんでした。ケースの電源・USB接続を確認(必要なら電源を入れ直して)から、ツールを起動し直してください。進捗は最後に確認済みの位置まで保存済みで、続きから再開できます。".into());
        }
        if self.hung {
            self.unsafe_flush = true;
            self.st.event("ディスクが応答せず、I/Oの取り消しにも応じませんでした。最後に確認済みの位置を保存して中断します");
            self.checkpoint(false);
            return Err("ディスクが応答しません(I/Oの取り消しにも応じませんでした)。ケースの電源・USB接続を確認し、ディスクを接続し直してからツールを起動し直してください。進捗は最後に確認済みの位置まで保存済みで、続きから再開できます。".into());
        }
        if let Some(msg) = self.fatal.take() {
            return Err(self.abort_systemic(msg));
        }
        Ok(Outcome::Stopped)
    }

    fn finish(&mut self) -> Result<Outcome, String> {
        let report_path = report::write_report(&self.st, &self.log_dir)
            .map_err(|e| format!("結果ログの書き出しに失敗: {e}"))?;
        // 再開用ログは消し込んでから削除する
        secure_erase_file(&self.state_path);
        secure_erase_file(&self.state_path.with_extension("json.tmp"));
        let mut s = self.shared.snap.lock().unwrap();
        s.report_path = Some(report_path);
        s.status = Status::Finished;
        Ok(Outcome::Finished)
    }

    /// 1ブロック分の完了を記録する(オフセットは必ず連続して進む)
    fn account_done(&mut self, off: u64, len: usize) {
        debug_assert_eq!(off, self.st.offset);
        let ph = self.st.phase as usize;
        self.mark_range(off, off + len as u64, 1);
        self.st.offset += len as u64;
        self.tick_time(ph, len as u64);
    }

    fn tick_time(&mut self, ph: usize, len: u64) {
        let now = Instant::now();
        self.st.phase_secs[ph] += now.duration_since(self.last_tick).as_secs_f64();
        self.last_tick = now;
        self.since_ckpt += len;
    }

    fn checkpoint_due(&self) -> bool {
        self.since_ckpt >= self.cfg.checkpoint_bytes
            || Instant::now().duration_since(self.last_ckpt).as_secs() >= self.cfg.checkpoint_secs
            || (self.save_pending && self.last_save_try.elapsed() >= Duration::from_secs(10))
    }

    // ------------------------------------------------------------ 自動調整

    fn should_tune(&self) -> bool {
        self.cfg.autotune
            && self.async_ok
            && self.st.tuned.is_none()
            && self.size >= self.cfg.tune_min_size
            && self.careful_until == 0
    }

    /// ブロックサイズと同時発行数の組を、実際の書込みで測って選ぶ(測定中の書込みも消去として有効)。
    /// false なら中断された。
    fn autotune(&mut self, ph: u8) -> bool {
        let mib = 1usize << 20;
        let maxb = self.cfg.block;
        let maxd = self.bufs.len();
        let mut cands: Vec<(usize, usize)> =
            vec![(4 * mib, 2), (8 * mib, 3), (16 * mib, 4), (32 * mib, 4)]
                .into_iter()
                .map(|(b, d)| (b.min(maxb), d.min(maxd)))
                .collect();
        cands.dedup();
        let mut seen = Vec::new();
        cands.retain(|c| {
            let new = !seen.contains(c);
            seen.push(*c);
            new
        });
        // 慣らし運転(ディスクの書込みキャッシュが空の状態の影響を避ける)
        let warm = Duration::from_millis(self.cfg.tune_warmup_ms);
        let probe = Duration::from_millis(self.cfg.tune_probe_ms);
        self.apply_tuning(maxb.min(16 * mib), self.cfg.queue_depth);
        match self.write_phase_until(ph, Some(Instant::now() + warm)) {
            Wp::Stopped => return false,
            Wp::Done => return true,
            Wp::Deadline => {}
        }
        let mut results: Vec<((usize, usize), f64)> = Vec::new();
        for &(b, d) in &cands {
            self.apply_tuning(b, d);
            let o0 = self.st.offset;
            let t0 = Instant::now();
            match self.write_phase_until(ph, Some(t0 + probe)) {
                Wp::Stopped => return false,
                Wp::Done => return true,
                Wp::Deadline => {}
            }
            let dt = t0.elapsed().as_secs_f64().max(0.001);
            results.push(((b, d), (self.st.offset - o0) as f64 / dt));
        }
        // 最速の組を採用。差が3%未満なら、より小さい(メモリが少なく安全な)組を選ぶ
        let best = results.iter().map(|r| r.1).fold(0.0f64, f64::max);
        let pick = results.iter().find(|r| r.1 >= best * 0.97).map(|r| r.0).unwrap_or((maxb.min(16 * mib), self.cfg.queue_depth));
        self.apply_tuning(pick.0, pick.1);
        self.st.tuned = Some((self.blk as u32, self.dep as u32));
        let detail: Vec<String> = results
            .iter()
            .map(|((b, d), v)| format!("{}MiB×{}={:.0}MB/s", b >> 20, d, v / 1e6))
            .collect();
        let msg = format!("自動調整: {} → 採用 {}MiB×{}", detail.join(", "), self.blk >> 20, self.dep);
        self.add_note(msg);
        true
    }

    // ------------------------------------------------------------ 書込み(重ね書き)

    fn fill_block(&mut self, slot: usize, ph: u8, len: usize) {
        let b = &mut self.bufs[slot].as_mut_slice()[..len];
        if ph == 1 {
            self.rng.fill_bytes(b);
        } else {
            b.fill(0);
        }
    }

    fn has_known_bad(&self, off: u64, len: usize) -> bool {
        let lba0 = off / self.ss;
        let end = lba0 + len as u64 / self.ss;
        self.st.next_segment(lba0, end) != (end, end)
    }

    fn needs_slow(&self, off: u64, len: usize) -> bool {
        off < self.careful_until || self.has_known_bad(off, len)
    }

    fn submit(&mut self, slot: usize, off: u64, len: usize, write: bool) {
        let early = if self.async_ok {
            let r = if write {
                let p = self.bufs[slot].ptr();
                unsafe { self.dev.begin_write(slot, off, p, len) }
            } else {
                let p = self.bufs[slot].ptr() as *mut u8;
                unsafe { self.dev.begin_read(slot, off, p, len) }
            };
            match r {
                Ok(()) => None,
                Err(e) => Some(Err(e)),
            }
        } else if write {
            Some(self.dev.write_at(off, &self.bufs[slot].as_slice()[..len]))
        } else {
            Some(self.dev.read_at(off, &mut self.bufs[slot].as_mut_slice()[..len]))
        };
        self.inflight.push_back(Inflight { slot, off, len, early });
    }

    fn take_result(&mut self, e: &mut Inflight, write: bool) -> std::io::Result<()> {
        let t0 = Instant::now();
        let r = match e.early.take() {
            Some(r) => r,
            None if write => self.dev.finish_write(e.slot),
            None => self.dev.finish_read(e.slot),
        };
        self.note_latency(t0.elapsed());
        let waited = t0.elapsed().as_secs();
        if waited >= 20 && self.slow_events < 40 {
            // 後から原因を調べられるように、応答が止まった時刻と長さを残す
            self.slow_events += 1;
            self.st.event(format!(
                "ディスクの応答が {waited} 秒間止まりました(オフセット {} 付近{})",
                e.off,
                if r.is_err() { "・取り消し/エラーで終了" } else { "・その後回復" }
            ));
        }
        if let Err(err) = &r {
            if let Some(s) = err.get_ref().and_then(|x| x.downcast_ref::<StallAbort>()) {
                self.aborted = true;
                self.unsafe_flush = true;
                if s.hung {
                    self.hung = true;
                }
            }
        }
        r
    }

    /// 応答しないI/Oを取り消した後始末。完了を確認できていないブロックは記録せず、同じ位置からやり直す
    fn finish_abort(&mut self, slots: Vec<usize>) {
        if !self.hung {
            self.free_slots.extend(slots);
        }
        self.submit_off = self.st.offset;
        self.aborted = false;
        if self.shared.cmd.load(Ordering::SeqCst) == CMD_RUN {
            // 指示によらず、応答停止のため自動で取り消した。何度も続くなら、あきらめて中断する
            self.auto_aborts += 1;
            if self.auto_aborts >= 3 {
                self.giveup = true;
            }
        }
        self.st.event(if self.hung {
            "ディスクが応答せず、取り消しにも応じませんでした"
        } else {
            "ディスクが応答しないため、発行済みのI/Oを取り消しました(完了を確認できていない範囲はやり直します)"
        });
    }

    /// 最も古い発行済み書込みを回収する。失敗があれば残りも回収し、順番に処理する
    fn reap_one(&mut self, ph: u8) {
        let Some(mut e) = self.inflight.pop_front() else { return };
        let t_w = Instant::now();
        let r = self.take_result(&mut e, true);
        self.shared.lat.add_wait(t_w.elapsed());
        if r.is_ok() {
            self.free_slots.push(e.slot);
            self.account_fast(ph, e.off, e.len);
            return;
        }
        let mut rest = vec![(e, r)];
        while let Some(mut n) = self.inflight.pop_front() {
            let r = self.take_result(&mut n, true);
            rest.push((n, r));
        }
        if self.aborted {
            self.finish_abort(rest.iter().map(|(e, _)| e.slot).collect());
            return;
        }
        let errs: Vec<String> = rest.iter().filter_map(|(_, r)| r.as_ref().err().map(os_label)).collect();
        for label in errs {
            if self.st.write_errors.len() < 20 || self.st.write_errors.contains_key(&label) {
                *self.st.write_errors.entry(label.clone()).or_insert(0) += 1;
            }
            self.last_err = label;
        }
        for (e, r) in rest {
            if r.is_ok() {
                self.account_fast(ph, e.off, e.len);
            } else {
                // 失敗ブロック: セクタ単位に切り分けて書き直す(バッファには元のデータが残っている)
                self.cur = e.slot;
                self.write_block_slow(ph, e.off, e.len);
                self.account_done(e.off, e.len);
            }
            self.free_slots.push(e.slot);
        }
    }

    fn reap_all(&mut self, ph: u8) {
        while !self.inflight.is_empty() {
            self.reap_one(ph);
        }
    }

    /// 工程の種類に関わらず、発行済みの書込みを回収する(checkpoint用)
    fn reap_all_quiet(&mut self) {
        if self.inflight.is_empty() {
            return;
        }
        let ph = self.st.phase.min(2);
        self.reap_all(ph);
    }

    fn account_fast(&mut self, ph: u8, off: u64, len: usize) {
        self.st.phase_ok[ph as usize] += len as u64 / self.ss;
        self.run_ok += len as u64 / self.ss;
        self.consec_fail = 0;
        self.unsafe_flush = false;
        self.auto_aborts = 0;
        self.account_done(off, len);
    }

    /// 書込み工程。`deadline` を過ぎたら、発行済みを回収して Deadline を返す(自動調整の測定用)
    /// 未消去として記録されたセクタ(書込み不可だったもの)を、優先して書き直す。
    /// 各範囲の先頭を1回だけ試し、書けなければその範囲は飛ばす(時間を使いすぎないため)。
    /// 書けた範囲は、書けなくなるまで先へ進める。確認で不一致だった範囲(VerifyMismatch)は対象外。
    /// 呼ぶ前に発行済みのI/Oが無いこと。
    /// false を返したら中断(停止指示・応答停止など)。
    fn refill_bad(&mut self, ph: u8) -> bool {
        if self.hung || self.giveup || self.fatal.is_some() {
            return false;
        }
        if self.st.bad_runs.iter().all(|r| r.kind == BadKind::VerifyMismatch) {
            return true;
        }
        // 開始直後はスケジューラの待機中(一時停止)のことがある。実行の指示が出るまで待つ
        if self.shared.cmd.load(Ordering::SeqCst) != CMD_RUN && !self.poll_control() {
            return false;
        }
        let ss = self.ss;
        let slot = self.free_slots.last().copied().unwrap_or(0);
        self.cur = slot;
        let saved_consec = self.consec_fail;
        self.consec_fail = self.cfg.fast_skip_after; // 失敗時は再試行せず1回で諦める
        let before = self.st.total_bad_sectors();
        // 書ける範囲は最後まで書き直す(以前は 1<<22 セクタ=2 GiB で打ち切っていたため、大きな範囲が残った)。
        // 書けない範囲は先頭の1回で諦めるので、時間はかからない
        let mut budget: u64 = u64::MAX / 2;
        let mut idx = 0usize;
        let mut last_map = Instant::now();
        'runs: while idx < self.st.bad_runs.len() && budget > 0 {
            if self.hung || self.giveup || self.fatal.is_some() {
                break;
            }
            if !self.priority_tick("未消去セクタを優先して書き直し中", &mut last_map) {
                self.consec_fail = saved_consec;
                return false;
            }
            let r = self.st.bad_runs[idx].clone();
            if r.kind == BadKind::VerifyMismatch {
                idx += 1;
                continue;
            }
            let mut lba = r.start;
            let mut progressed = false;
            while lba < r.end() && budget > 0 {
                if !self.priority_tick("未消去セクタを優先して書き直し中", &mut last_map) {
                    self.consec_fail = saved_consec;
                    return false;
                }
                let n = ((r.end() - lba) * ss).min(self.blk as u64).min(self.bufs[slot].as_slice().len() as u64) as usize;
                let n = n / ss as usize * ss as usize;
                if n == 0 {
                    break;
                }
                self.fill_block(slot, ph, n);
                if self.raw_write(lba * ss, 0, n).is_ok() {
                    let secs = n as u64 / ss;
                    for l in lba..lba + secs {
                        self.st.clear_bad(l);
                    }
                    lba += secs;
                    budget = budget.saturating_sub(secs);
                    progressed = true;
                    continue;
                }
                // ブロックで失敗: 先頭1セクタだけ試して、書けなければこの範囲は諦める
                self.fill_block(slot, ph, ss as usize);
                if self.raw_write(lba * ss, 0, ss as usize).is_ok() {
                    self.st.clear_bad(lba);
                    lba += 1;
                    budget = budget.saturating_sub(1);
                    progressed = true;
                    continue;
                }
                break;
            }
            // lba は「まだ書けていない最初のセクタ」。そこを含む範囲が残っていれば次の範囲へ、無ければその位置が次の範囲
            let _ = progressed;
            let i = self.st.bad_runs.partition_point(|x| x.end() <= lba);
            idx = match self.st.bad_runs.get(i) {
                Some(x) if x.start <= lba => i + 1,
                _ => i,
            };
            if self.fatal.is_some() {
                break 'runs;
            }
        }
        self.consec_fail = saved_consec;
        self.clear_priority_message();
        let after = self.st.total_bad_sectors();
        if before != after {
            self.st.event(format!(
                "未消去セクタを優先して書き直し: {} セクタを解消(残り {} セクタ / {})",
                before - after,
                after,
                phase_label(ph)
            ));
            let _ = self.dev.flush();
            self.rebuild_map();
        }
        !(self.hung || self.giveup || self.fatal.is_some())
    }

    /// 優先処理(書き直し・読み直し)の最中に、画面の状態・進捗・セクタマップを更新し、
    /// 一時停止/中断の指示を受け付ける。false なら中断。
    fn priority_tick(&mut self, label: &str, last_map: &mut Instant) -> bool {
        if !self.control_ok() {
            return false;
        }
        if self.checkpoint_due() {
            self.checkpoint(false);
        }
        if last_map.elapsed() >= Duration::from_secs(5) {
            *last_map = Instant::now();
            self.rebuild_map();
        }
        self.publish(false);
        let left = self.st.total_bad_sectors();
        self.shared.snap.lock().unwrap().message = format!("{label}(対象の残り {left} セクタ)");
        true
    }

    fn clear_priority_message(&self) {
        let mut s = self.shared.snap.lock().unwrap();
        if s.message.contains("優先") {
            s.message.clear();
        }
    }

    /// 読み取り確認(最終工程)の最初に、これまで確認できていない範囲(不良として記録済みで、
    /// 通常の確認では飛ばされる範囲)を優先して読み直す。
    /// 読めて全て0なら確認済みにする。0以外が残っていれば0を書き直して確かめる。読めない範囲は1回で諦める。
    /// 戻り値 false は中断。
    fn verify_bad_first(&mut self) -> bool {
        if self.hung || self.giveup || self.fatal.is_some() {
            return false;
        }
        if self.st.bad_runs.is_empty() {
            return true;
        }
        if self.shared.cmd.load(Ordering::SeqCst) != CMD_RUN && !self.poll_control() {
            return false;
        }
        let ss = self.ss;
        let ssz = ss as usize;
        let slot = self.free_slots.last().copied().unwrap_or(0);
        self.cur = slot;
        let saved_consec = self.consec_fail;
        self.consec_fail = self.cfg.fast_skip_after; // 読めないときは再試行せず1回で諦める
        let before = self.st.total_bad_sectors();
        let mut idx = 0usize;
        let mut last_map = Instant::now();
        while idx < self.st.bad_runs.len() {
            if self.hung || self.giveup || self.fatal.is_some() {
                break;
            }
            if !self.priority_tick("読み取り確認を優先: これまで確認できていない範囲を読み直し中", &mut last_map) {
                self.consec_fail = saved_consec;
                return false;
            }
            let r = self.st.bad_runs[idx].clone();
            let mut lba = r.start;
            'run: while lba < r.end() {
                if !self.priority_tick("読み取り確認を優先: これまで確認できていない範囲を読み直し中", &mut last_map) {
                    self.consec_fail = saved_consec;
                    return false;
                }
                let n = ((r.end() - lba) * ss).min(self.blk as u64).min(self.bufs[slot].as_slice().len() as u64) as usize;
                let n = n / ssz * ssz;
                if n == 0 {
                    break;
                }
                let secs = n as u64 / ss;
                let rr = self.dev.read_at(lba * ss, &mut self.bufs[slot].as_mut_slice()[..n]);
                if let Err(e) = &rr {
                    if self.mark_disconnect(e) {
                        break;
                    }
                }
                if rr.is_ok() {
                    if self.bufs[slot].as_slice()[..n].iter().all(|&b| b == 0) {
                        for l in lba..lba + secs {
                            self.st.clear_bad(l);
                        }
                        self.st.phase_ok[3] += secs;
                        lba += secs;
                        continue;
                    }
                    // 0以外が含まれる: セクタごとに、0を書き直して確かめる
                    for k in 0..secs {
                        let l = lba + k;
                        let so = (k * ss) as usize;
                        if self.bufs[slot].as_slice()[so..so + ssz].iter().all(|&b| b == 0) {
                            self.st.clear_bad(l);
                            self.st.phase_ok[3] += 1;
                            continue;
                        }
                        self.scratch.as_mut_slice()[..ssz].fill(0);
                        let wrote = self.dev.write_at(l * ss, &self.scratch.as_slice()[..ssz]).is_ok() && self.dev.flush().is_ok();
                        if wrote && self.dev.read_at(l * ss, &mut self.scratch.as_mut_slice()[..ssz]).is_ok()
                            && self.scratch.as_slice()[..ssz].iter().all(|&b| b == 0)
                        {
                            self.st.clear_bad(l);
                            self.st.verify_fixed += 1;
                            self.st.phase_ok[3] += 1;
                        } else {
                            // 書き直せない: この範囲は諦めて次へ
                            lba = l + 1;
                            break 'run;
                        }
                    }
                    lba += secs;
                    continue;
                }
                // ブロックが読めない: 先頭1セクタだけ試し、読めなければこの範囲は諦める
                if self.dev.read_at(lba * ss, &mut self.bufs[slot].as_mut_slice()[..ssz]).is_ok()
                    && self.bufs[slot].as_slice()[..ssz].iter().all(|&b| b == 0)
                {
                    self.st.clear_bad(lba);
                    self.st.phase_ok[3] += 1;
                    lba += 1;
                    continue;
                }
                break;
            }
            let i = self.st.bad_runs.partition_point(|x| x.end() <= lba);
            idx = match self.st.bad_runs.get(i) {
                Some(x) if x.start <= lba => i + 1,
                _ => i,
            };
        }
        self.consec_fail = saved_consec;
        let after = self.st.total_bad_sectors();
        self.st.event(format!(
            "読み取り確認を優先して実施(これまで確認できていない範囲): {} セクタを確認して解消 / 確認できず残り {} セクタ",
            before - after,
            after
        ));
        self.rebuild_map();
        self.clear_priority_message();
        !(self.hung || self.giveup || self.fatal.is_some())
    }

    fn write_phase_until(&mut self, ph: u8, deadline: Option<Instant>) -> Wp {
        loop {
            if self.hung || self.giveup {
                return Wp::Stopped;
            }
            if self.fatal.is_some() {
                self.reap_all(ph);
                return Wp::Stopped;
            }
            if self.shared.cmd.load(Ordering::SeqCst) != CMD_RUN {
                self.reap_all(ph);
                if !self.poll_control() {
                    return Wp::Stopped;
                }
            } else if !self.control_ok() {
                return Wp::Stopped;
            }
            if let Some(d) = deadline {
                if Instant::now() >= d {
                    self.reap_all(ph);
                    return Wp::Deadline;
                }
            }
            if self.st.offset >= self.size {
                return Wp::Done;
            }
            // 発行できるだけ発行する(次のデータの生成中も、ディスクは前のブロックを書いている)
            while self.inflight.len() < self.dep && self.submit_off < self.size {
                let off = self.submit_off;
                let len = (self.size - off).min(self.blk as u64) as usize;
                if self.needs_slow(off, len) {
                    break;
                }
                let Some(slot) = self.free_slots.pop() else { break };
                self.fill_block(slot, ph, len);
                self.submit(slot, off, len, true);
                self.submit_off += len as u64;
            }
            if self.inflight.is_empty() {
                // 既知の不良セクタを含む / 確認モードのブロックは、同期でセクタ単位に処理
                let off = self.st.offset;
                let len = (self.size - off).min(self.blk as u64) as usize;
                let slot = self.free_slots.pop().unwrap_or(0);
                self.cur = slot;
                self.fill_block(slot, ph, len);
                self.write_block_slow(ph, off, len);
                self.account_done(off, len);
                self.submit_off = off + len as u64;
                if !self.free_slots.contains(&slot) {
                    self.free_slots.push(slot);
                }
            } else {
                self.reap_one(ph);
            }
            if self.checkpoint_due() {
                // 書込みを止めずに flush する(止めるのは flush に失敗したときだけ)
                self.checkpoint(false);
            }
            self.publish(false);
        }
    }

    fn raw_write(&mut self, byte_off: u64, boff: usize, blen: usize) -> std::io::Result<()> {
        let cur = self.cur;
        let mut r = self.dev.write_at(byte_off, &self.bufs[cur].as_slice()[boff..boff + blen]);
        if r.is_ok() && self.careful_now {
            r = self.dev.flush();
        }
        if let Err(e) = &r {
            self.record_err(e);
            // ディスクが切断された(OSエラー 21/55/433/1167)ときは、不良セクタにせず、応答停止と同じ扱いで中断する
            // (切断中の失敗を不良セクタとして記録すると、数百万セクタが「未消去」になってしまう)
            let code = e.raw_os_error();
            let label = os_label(e);
            self.mark_disconnect_code(code, &label);
        }
        r
    }

    /// OSエラーが「ディスクが消えた/切断された」ものなら、不良セクタにせず、応答停止と同じ扱いで中断する。
    /// (切断中の失敗を不良セクタとして記録すると、広い範囲が「未消去・読込み不可」になってしまう)
    fn mark_disconnect_code(&mut self, code: Option<i32>, label: &str) -> bool {
        if self.hung {
            return true;
        }
        if matches!(code, Some(21 | 55 | 433 | 1167 | 6)) {
            self.hung = true;
            self.st.event(format!("ディスクとの接続が切れました({label})。不良セクタとしては記録せず、中断します"));
            return true;
        }
        false
    }

    fn mark_disconnect(&mut self, e: &std::io::Error) -> bool {
        let label = os_label(e);
        self.mark_disconnect_code(e.raw_os_error(), &label)
    }

    /// 失敗が続いているとき、ディスクがまだ存在するかを先頭セクタの読み込みで確かめる。
    /// 読めなければ(アンマウント・切断など)、不良セクタではなく切断として中断する。
    fn check_gone(&mut self) -> bool {
        if self.hung {
            return true;
        }
        let ss = self.ss as usize;
        match self.dev.read_at(0, &mut self.scratch.as_mut_slice()[..ss]) {
            Ok(()) => false,
            Err(e) => {
                self.hung = true;
                self.st.event(format!(
                    "ディスクが応答しなくなりました(先頭セクタも読めません: {})。不良セクタとしては記録せず、中断します",
                    os_label(&e)
                ));
                true
            }
        }
    }

    /// 同期・セクタ単位切り分けつきの書込み(self.cur のバッファに書込み内容が入っていること)
    fn write_block_slow(&mut self, ph: u8, off: u64, len: usize) {
        self.careful_now = off < self.careful_until;
        let ss = self.ss;
        let lba0 = off / ss;
        let end = lba0 + len as u64 / ss;
        let mut cur = lba0;
        while cur < end {
            let (seg_end, next) = self.st.next_segment(cur, end);
            if seg_end > cur {
                self.write_segment(ph, cur, seg_end, lba0);
            }
            if next > seg_end {
                self.st.phase_skip[ph as usize] += next - seg_end;
            }
            cur = next;
        }
        self.careful_now = false;
    }

    fn write_segment(&mut self, ph: u8, from: u64, to: u64, lba0: u64) {
        let ss = self.ss;
        let boff = ((from - lba0) * ss) as usize;
        let blen = ((to - from) * ss) as usize;
        for attempt in 0..2 {
            if attempt > 0 {
                self.st.write_retries += 1;
            }
            if self.raw_write(from * ss, boff, blen).is_ok() {
                self.st.phase_ok[ph as usize] += to - from;
                self.run_ok += to - from;
                self.consec_fail = 0;
                return;
            }
        }
        // ブロック書込みに失敗 → セクタ単位で切り分ける
        for lba in from..to {
            if self.fatal.is_some() || self.hung {
                return;
            }
            let so = ((lba - lba0) * ss) as usize;
            if self.write_sector(lba, so) {
                self.st.phase_ok[ph as usize] += 1;
                self.run_ok += 1;
                self.consec_fail = 0;
                continue;
            }
            // 失敗の最初と、続く間は8セクタごとに、ディスクが消えていないか確かめる(消えていれば不良として記録しない)
            if self.consec_fail % 8 == 0 && self.check_gone() {
                return;
            }
            let (kind, classes, sig) = if self.read_sector_retry(lba) {
                let ssz = ss as usize;
                let c = classify(&self.scratch.as_slice()[..ssz]);
                (BadKind::Residual, c.classes, c.sig)
            } else {
                (BadKind::Unreadable, 0, None)
            };
            self.st.add_bad(lba, kind, classes, sig);
            self.st.phase_err[ph as usize] += 1;
            self.mark_bad(lba);
            self.consec_fail = self.consec_fail.saturating_add(1);
            // 実行開始から1セクタも書けないまま、連続して大量に失敗している = 不良セクタではなく系統的な失敗
            if self.run_ok < 2048 && (self.consec_fail as u64) * ss >= SYSTEMIC_FAIL_BYTES {
                self.fatal = Some(format!(
                    "このディスクにほとんど書き込めません(連続 {} MiB 以上失敗)。最後のエラー: {}。書込み保護・アクセス拒否・接続不良・ディスク故障のいずれかが考えられます。",
                    SYSTEMIC_FAIL_BYTES >> 20,
                    self.last_err
                ));
                return;
            }
        }
    }

    fn attempts(&self) -> u32 {
        if self.consec_fail >= self.cfg.fast_skip_after { 1 } else { 1 + self.cfg.retries }
    }

    fn write_sector(&mut self, lba: u64, boff: usize) -> bool {
        let ss = self.ss as usize;
        for a in 0..self.attempts() {
            if a > 0 {
                self.st.write_retries += 1;
            }
            if self.raw_write(lba * self.ss, boff, ss).is_ok() {
                return true;
            }
        }
        false
    }

    /// scratch に1セクタ読み込む
    fn read_sector_retry(&mut self, lba: u64) -> bool {
        let ss = self.ss as usize;
        for a in 0..self.attempts() {
            if a > 0 {
                self.st.read_retries += 1;
            }
            match self.dev.read_at(lba * self.ss, &mut self.scratch.as_mut_slice()[..ss]) {
                Ok(()) => return true,
                Err(e) => {
                    if self.mark_disconnect(&e) {
                        return false;
                    }
                }
            }
        }
        false
    }

    // ------------------------------------------------------------ 検証

    fn reap_reads(&mut self) {
        while !self.inflight.is_empty() {
            self.reap_one_read();
        }
    }

    /// 最も古い発行済み読込みを回収して確認する。失敗・不一致はセクタ単位で詳しく調べる
    fn reap_one_read(&mut self) {
        let Some(mut e) = self.inflight.pop_front() else { return };
        let r = self.take_result(&mut e, false);
        if self.aborted {
            let mut slots = vec![e.slot];
            while let Some(mut n) = self.inflight.pop_front() {
                let _ = self.take_result(&mut n, false);
                slots.push(n.slot);
            }
            self.finish_abort(slots);
            return;
        }
        let ok = r.is_ok() && self.bufs[e.slot].as_slice()[..e.len].iter().all(|&b| b == 0);
        if ok {
            self.st.phase_ok[3] += e.len as u64 / self.ss;
            self.consec_fail = 0;
            self.unsafe_flush = false;
            self.auto_aborts = 0;
        } else {
            self.cur = e.slot;
            self.verify_block(e.off, e.len);
        }
        self.free_slots.push(e.slot);
        self.account_done(e.off, e.len);
    }

    /// 全域検証(重ね読み)。false なら中断された
    fn verify_full_phase(&mut self) -> bool {
        self.submit_off = self.st.offset;
        loop {
            if self.hung || self.giveup {
                return false;
            }
            if self.shared.cmd.load(Ordering::SeqCst) != CMD_RUN {
                self.reap_reads();
                if !self.poll_control() {
                    return false;
                }
            } else if !self.control_ok() {
                return false;
            }
            if self.st.offset >= self.size {
                return true;
            }
            while self.inflight.len() < self.dep && self.submit_off < self.size {
                let off = self.submit_off;
                let len = (self.size - off).min(self.blk as u64) as usize;
                if self.has_known_bad(off, len) {
                    break;
                }
                let Some(slot) = self.free_slots.pop() else { break };
                self.submit(slot, off, len, false);
                self.submit_off += len as u64;
            }
            if self.inflight.is_empty() {
                let off = self.st.offset;
                let len = (self.size - off).min(self.blk as u64) as usize;
                let slot = self.free_slots.pop().unwrap_or(0);
                self.cur = slot;
                self.verify_block(off, len);
                self.account_done(off, len);
                self.submit_off = off + len as u64;
                if !self.free_slots.contains(&slot) {
                    self.free_slots.push(slot);
                }
            } else {
                self.reap_one_read();
            }
            if self.checkpoint_due() {
                self.checkpoint(false);
            }
            self.publish(false);
        }
    }

    /// 抽出検証(先頭・末尾・乱数で選んだ区間だけ読む)。false なら中断された
    fn verify_sample_phase(&mut self) -> bool {
        self.cur = 0;
        let ranges = self.sample.clone();
        let mut cum = 0u64;
        for (pos, len) in ranges {
            if cum + len <= self.st.offset {
                cum += len;
                continue;
            }
            if !self.poll_control() {
                return false;
            }
            let mut o = pos;
            while o < pos + len {
                let l = (pos + len - o).min(self.cfg.block as u64) as usize;
                self.verify_block(o, l);
                o += l as u64;
            }
            self.mark_range(pos, pos + len, 1);
            self.st.offset += len;
            self.tick_time(3, len);
            cum += len;
            if self.checkpoint_due() {
                self.checkpoint(false);
            }
            self.publish(false);
        }
        true
    }

    fn verify_block(&mut self, off: u64, len: usize) {
        let ss = self.ss;
        let lba0 = off / ss;
        let end = lba0 + len as u64 / ss;
        let mut cur = lba0;
        while cur < end {
            let (seg_end, next) = self.st.next_segment(cur, end);
            if seg_end > cur {
                self.verify_segment(cur, seg_end, lba0);
            }
            if next > seg_end {
                self.st.phase_skip[3] += next - seg_end;
            }
            cur = next;
        }
    }

    fn verify_segment(&mut self, from: u64, to: u64, lba0: u64) {
        let ss = self.ss;
        let ssz = ss as usize;
        let c = self.cur;
        let boff = ((from - lba0) * ss) as usize;
        let blen = ((to - from) * ss) as usize;
        let mut block_ok = false;
        for attempt in 0..2 {
            if attempt > 0 {
                self.st.read_retries += 1;
            }
            match self.dev.read_at(from * ss, &mut self.bufs[c].as_mut_slice()[boff..boff + blen]) {
                Ok(()) => {
                    block_ok = true;
                    break;
                }
                Err(e) => {
                    if self.mark_disconnect(&e) {
                        return;
                    }
                }
            }
        }
        if block_ok {
            if self.bufs[c].as_slice()[boff..boff + blen].iter().all(|&b| b == 0) {
                self.st.phase_ok[3] += to - from;
                self.consec_fail = 0;
                return;
            }
            for lba in from..to {
                let so = boff + ((lba - from) * ss) as usize;
                if self.bufs[c].as_slice()[so..so + ssz].iter().all(|&b| b == 0) {
                    self.st.phase_ok[3] += 1;
                } else {
                    self.handle_mismatch(lba, so);
                }
            }
            return;
        }
        // 読込み不能 → セクタ単位
        for lba in from..to {
            if self.hung || self.fatal.is_some() {
                return;
            }
            let so = boff + ((lba - from) * ss) as usize;
            let mut got = false;
            for a in 0..self.attempts() {
                if a > 0 {
                    self.st.read_retries += 1;
                }
                match self.dev.read_at(lba * ss, &mut self.bufs[c].as_mut_slice()[so..so + ssz]) {
                    Ok(()) => {
                        got = true;
                        break;
                    }
                    Err(e) => {
                        if self.mark_disconnect(&e) {
                            return;
                        }
                    }
                }
            }
            if !got {
                if self.consec_fail % 8 == 0 && self.check_gone() {
                    return;
                }
                self.st.add_bad(lba, BadKind::Unreadable, 0, None);
                self.st.phase_err[3] += 1;
                self.mark_bad(lba);
                self.consec_fail = self.consec_fail.saturating_add(1);
                continue;
            }
            self.consec_fail = 0;
            if self.bufs[c].as_slice()[so..so + ssz].iter().all(|&b| b == 0) {
                self.st.phase_ok[3] += 1;
            } else {
                self.handle_mismatch(lba, so);
            }
        }
    }

    /// 検証で0以外が見つかったセクタ: 内容を分類 → ゼロを再書込み → 再読込みで確認
    fn handle_mismatch(&mut self, lba: u64, so: usize) {
        let ssz = self.ss as usize;
        let c = self.cur;
        let cl = classify(&self.bufs[c].as_slice()[so..so + ssz]);
        self.scratch.as_mut_slice()[..ssz].fill(0);
        let mut written = false;
        for a in 0..self.attempts() {
            if a > 0 {
                self.st.write_retries += 1;
            }
            let ok = self.dev.write_at(lba * self.ss, &self.scratch.as_slice()[..ssz]).is_ok()
                && self.dev.flush().is_ok();
            if ok {
                written = true;
                break;
            }
        }
        if written && self.read_sector_retry(lba) && self.scratch.as_slice()[..ssz].iter().all(|&b| b == 0) {
            self.st.verify_fixed += 1;
            self.st.phase_ok[3] += 1;
        } else {
            self.st.add_bad(lba, BadKind::VerifyMismatch, cl.classes, cl.sig);
            self.st.phase_err[3] += 1;
            self.mark_bad(lba);
        }
    }
}

/// 書込みテスト: 先頭・中央・末尾の1セクタと1MiBを「読んで同じ内容を書き戻す」ことで、
/// データを変えずに、このディスクへ実際に書き込めるかを確かめる。
pub fn preflight(dev: &mut dyn BlockDev) -> Result<(), String> {
    let ss = dev.sector_size() as usize;
    let size = dev.total_bytes();
    let chunk = ((1usize << 20).min((size / 4) as usize) / ss).max(1) * ss;
    let mut buf = AlignedBuf::new(chunk.max(4096));
    let mid = (size / 2) / chunk as u64 * chunk as u64;
    let last = size.saturating_sub(chunk as u64) / ss as u64 * ss as u64;
    for off in [0u64, mid, last] {
        for len in [ss, chunk] {
            let b = &mut buf.as_mut_slice()[..len];
            dev.read_at(off, b)
                .map_err(|e| format!("オフセット {off} の {len} バイト読込みに失敗: {}", os_label(&e)))?;
            let b = &buf.as_slice()[..len];
            dev.write_at(off, b)
                .map_err(|e| format!("オフセット {off} の {len} バイト書込みに失敗: {}", os_label(&e)))?;
        }
    }
    dev.flush().map_err(|e| format!("書込み後の flush に失敗: {}", os_label(&e)))?;
    Ok(())
}

pub fn os_label(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(c) => format!("OSエラー {c}: {e}"),
        None => e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev::fake::FakeDev;

    fn ident(size: u64, ss: u32) -> DiskIdentity {
        DiskIdentity {
            vendor: "T".into(),
            model: "FAKE".into(),
            serial: "SER12345".into(),
            size,
            sector_size: ss,
            bus: "SATA".into(),
        }
    }

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("hddwiper_test_{}_{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn small_cfg() -> EngineCfg {
        EngineCfg {
            block: 64 * 1024,
            retries: 3,
            checkpoint_bytes: 128 * 1024,
            checkpoint_secs: 1,
            fast_skip_after: 256,
            queue_depth: 3,
            max_depth: 4,
            write_through: false,
            autotune: false,
            tune_min_size: 0,
            tune_warmup_ms: 20,
            tune_probe_ms: 30,
        }
    }

    fn make_with(dev: FakeDev, dir: &PathBuf, st: Option<JobState>, cfg: EngineCfg) -> (Engine, Arc<JobShared>) {
        let size = dev.total_bytes();
        let ss = dev.sector_size();
        let shared = JobShared::new(size, ss);
        shared.set_cmd(CMD_RUN, REASON_USER);
        let st = st.unwrap_or_else(|| JobState::new(ident(size, ss), 1));
        let e = Engine::new(Box::new(dev), shared.clone(), st, dir.join("resume.json"), dir.clone(), cfg);
        (e, shared)
    }

    fn make(dev: FakeDev, dir: &PathBuf, st: Option<JobState>) -> (Engine, Arc<JobShared>) {
        make_with(dev, dir, st, small_cfg())
    }

    /// N回目の finish_write で「応答しないI/Oを取り消した」エラーを返す模擬デバイス
    struct StallDev {
        inner: FakeDev,
        calls: u32,
        stall_at: u32,
        hung: bool,
    }

    impl BlockDev for StallDev {
        fn sector_size(&self) -> u32 {
            self.inner.sector_size()
        }
        fn total_bytes(&self) -> u64 {
            self.inner.total_bytes()
        }
        fn write_at(&mut self, off: u64, buf: &[u8]) -> std::io::Result<()> {
            self.inner.write_at(off, buf)
        }
        fn read_at(&mut self, off: u64, buf: &mut [u8]) -> std::io::Result<()> {
            self.inner.read_at(off, buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
        fn async_slots(&self) -> usize {
            self.inner.async_slots()
        }
        unsafe fn begin_write(&mut self, slot: usize, off: u64, ptr: *const u8, len: usize) -> std::io::Result<()> {
            unsafe { self.inner.begin_write(slot, off, ptr, len) }
        }
        fn finish_write(&mut self, slot: usize) -> std::io::Result<()> {
            self.calls += 1;
            if self.calls >= self.stall_at {
                let _ = self.inner.finish_write(slot);
                return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, StallAbort { hung: self.hung }));
            }
            self.inner.finish_write(slot)
        }
    }

    #[test]
    fn stall_abort_is_not_recorded_as_bad_sector() {
        let dir = tmpdir("stall");
        let fake = FakeDev::new(1 << 20, 512);
        let dev = StallDev { inner: fake.clone(), calls: 0, stall_at: 5, hung: false };
        let size = fake.total_bytes();
        let shared = JobShared::new(size, 512);
        shared.set_cmd(CMD_RUN, REASON_USER);
        let st = JobState::new(ident(size, 512), 1);
        let mut e = Engine::new(Box::new(dev), shared.clone(), st, dir.join("resume.json"), dir.clone(), small_cfg());
        // 取り消しが起きたら中断指示を出す(実機ではユーザーの「中断」)
        fake.0.lock().unwrap().stop_after = Some((6, shared.clone()));
        assert_eq!(e.run().unwrap(), Outcome::Stopped);
        assert!(e.st.bad_runs.is_empty(), "取り消されたI/Oを不良セクタにしない");
        assert_eq!(e.st.total_bad_sectors(), 0);
        assert!(!e.is_hung());
        let saved = JobState::load(&dir.join("resume.json")).unwrap();
        assert!(saved.offset <= e.st.offset);
        assert!(saved.events.iter().any(|ev| ev.what.contains("取り消し")));
    }

    #[test]
    fn repeated_auto_abort_gives_up_with_error() {
        let dir = tmpdir("giveup");
        let fake = FakeDev::new(1 << 20, 512);
        // 5回目以降は毎回「応答しないため取り消した」(実行中のまま = 自動取り消し)
        let dev = StallDev { inner: fake.clone(), calls: 0, stall_at: 5, hung: false };
        let size = fake.total_bytes();
        let shared = JobShared::new(size, 512);
        shared.set_cmd(CMD_RUN, REASON_USER);
        let st = JobState::new(ident(size, 512), 1);
        let mut e = Engine::new(Box::new(dev), shared.clone(), st, dir.join("resume.json"), dir.clone(), small_cfg());
        let r = e.run();
        assert!(r.is_err(), "進まないままなら、あきらめてエラーで終了する");
        assert!(!e.is_hung());
        assert_eq!(e.st.total_bad_sectors(), 0, "不良セクタにしない");
        assert!(dir.join("resume.json").exists());
        let n = e.st.events.iter().filter(|ev| ev.what.contains("取り消しました")).count();
        assert_eq!(n, 3);
    }

    #[test]
    fn hung_device_stops_with_error_and_keeps_progress() {
        let dir = tmpdir("hung");
        let fake = FakeDev::new(1 << 20, 512);
        let dev = StallDev { inner: fake.clone(), calls: 0, stall_at: 5, hung: true };
        let size = fake.total_bytes();
        let shared = JobShared::new(size, 512);
        shared.set_cmd(CMD_RUN, REASON_USER);
        let st = JobState::new(ident(size, 512), 1);
        let mut e = Engine::new(Box::new(dev), shared.clone(), st, dir.join("resume.json"), dir.clone(), small_cfg());
        let r = e.run();
        assert!(r.is_err(), "応答しないディスクはエラーで終了する");
        assert!(e.is_hung());
        assert_eq!(e.st.total_bad_sectors(), 0);
        assert!(dir.join("resume.json").exists(), "進捗は保存される");
        std::mem::forget(e);
    }

    #[test]
    fn full_run_leaves_all_zero() {
        let dir = tmpdir("full");
        let dev = FakeDev::new(1 << 20, 512);
        let (mut e, shared) = make(dev.clone(), &dir, None);
        assert_eq!(e.run().unwrap(), Outcome::Finished);
        assert!(dev.0.lock().unwrap().data.iter().all(|&b| b == 0));
        let s = shared.snapshot();
        assert_eq!(s.status, Status::Finished);
        assert!(s.report_path.unwrap().exists());
        assert!(!dir.join("resume.json").exists(), "再開用ログは削除される");
        assert_eq!(e.st.phase_ok[0], (1 << 20) / 512);
        assert_eq!(e.st.phase_ok[3], (1 << 20) / 512);
    }

    #[test]
    fn random_pass_really_writes_random() {
        let dir = tmpdir("rand");
        let dev = FakeDev::new(256 * 1024, 512);
        let size = dev.total_bytes();
        let mut st = JobState::new(ident(size, 512), 1);
        st.phase = 1; // 乱数パスから開始
        let (mut e, shared) = make(dev.clone(), &dir, Some(st));
        dev.0.lock().unwrap().stop_after = Some((3, shared.clone()));
        assert_eq!(e.run().unwrap(), Outcome::Stopped);
        assert_eq!(e.st.phase, 1);
        let g = dev.0.lock().unwrap();
        let n = e.st.offset as usize;
        assert!(n > 0);
        let nonzero = g.data[..n].iter().filter(|&&b| b != 0).count();
        assert!(nonzero > n * 98 / 100, "乱数パスで書き込まれていること");
    }

    #[test]
    fn stop_and_resume() {
        let dir = tmpdir("resume");
        let dev = FakeDev::new(1 << 20, 512);
        let (mut e, shared) = make(dev.clone(), &dir, None);
        let sh = shared.clone();
        let h = std::thread::spawn(move || {
            loop {
                let s = sh.snapshot();
                if s.phase == 1 && s.offset >= 128 * 1024 {
                    sh.set_cmd(CMD_STOP, REASON_USER);
                    return;
                }
                std::thread::sleep(Duration::from_micros(50));
            }
        });
        let out = e.run().unwrap();
        h.join().unwrap();
        assert_eq!(out, Outcome::Stopped);
        let state_file = dir.join("resume.json");
        assert!(state_file.exists());
        let st = JobState::load(&state_file).unwrap();
        assert_eq!(st.phase, 1);
        assert!(st.offset >= 128 * 1024);
        // 再開
        let (mut e2, shared2) = make(dev.clone(), &dir, Some(st));
        assert_eq!(e2.run().unwrap(), Outcome::Finished);
        assert!(dev.0.lock().unwrap().data.iter().all(|&b| b == 0));
        assert_eq!(shared2.snapshot().status, Status::Finished);
        assert!(!state_file.exists());
    }

    #[test]
    fn bad_sectors_are_skipped_and_reported() {
        let dir = tmpdir("bad");
        let dev = FakeDev::new(1 << 20, 512);
        {
            let mut g = dev.0.lock().unwrap();
            // 書込み・読込みとも不能: 100..110
            for l in 100..110 {
                g.bad_write.insert(l);
                g.bad_read.insert(l);
            }
            // 書込み不能だが読める(連続100セクタ = 64以上): 500..600
            for l in 500..600 {
                g.bad_write.insert(l);
            }
        }
        let (mut e, shared) = make(dev.clone(), &dir, None);
        assert_eq!(e.run().unwrap(), Outcome::Finished);
        let st = &e.st;
        let un: u64 = st.bad_runs.iter().filter(|r| r.kind == BadKind::Unreadable).map(|r| r.len).sum();
        let res: u64 = st.bad_runs.iter().filter(|r| r.kind == BadKind::Residual).map(|r| r.len).sum();
        assert_eq!(un, 10);
        assert_eq!(res, 100);
        assert!(st.write_retries > 0);
        // 他の領域はすべてゼロ
        let g = dev.0.lock().unwrap();
        for (i, chunk) in g.data.chunks(512).enumerate() {
            let l = i as u64;
            let bad = (100..110).contains(&l) || (500..600).contains(&l);
            if !bad {
                assert!(chunk.iter().all(|&b| b == 0), "sector {l}");
            }
        }
        drop(g);
        let rp = shared.snapshot().report_path.unwrap();
        let text = std::fs::read_to_string(rp).unwrap();
        assert!(text.contains("未消去"));
        assert!(text.contains("64セクタ以上"));
    }

    #[test]
    fn large_unerased_range_is_refilled_completely() {
        let dir = tmpdir("refill_big");
        let dev = FakeDev::new(1 << 20, 512);
        let (mut e, _s) = make(dev.clone(), &dir, None);
        // 2048 セクタ中の 5..2000 が未消去として記録されている状態(書き込みは可能)
        let mut st = e.st.clone();
        for l in 5..2000u64 {
            st.add_bad(l, BadKind::Unreadable, 0, None);
        }
        drop(e);
        let dir2 = tmpdir("refill_big2");
        let (mut e2, _s2) = make(dev.clone(), &dir2, Some(st));
        assert_eq!(e2.st.total_bad_sectors(), 1995);
        assert_eq!(e2.run().unwrap(), Outcome::Finished);
        assert_eq!(e2.st.total_bad_sectors(), 0, "範囲の全体が書き直される");
    }

    fn finished_state_at_verify(dev: &FakeDev) -> JobState {
        let dir = tmpdir("verify_gone_base");
        let (mut e, _s) = make(dev.clone(), &dir, None);
        assert_eq!(e.run().unwrap(), Outcome::Finished);
        let mut st = e.st.clone();
        st.phase = 3;
        st.offset = 0;
        st
    }

    #[test]
    fn verify_does_not_record_bad_sectors_when_disk_is_gone() {
        let dev = FakeDev::new(1 << 20, 512);
        let st = finished_state_at_verify(&dev);
        dev.0.lock().unwrap().gone = true;
        let dir2 = tmpdir("verify_gone2");
        let (mut e2, _s2) = make(dev, &dir2, Some(st));
        assert!(e2.run().is_err(), "切断として中断する");
        assert_eq!(e2.st.total_bad_sectors(), 0, "切断中の失敗を不良セクタにしない");
    }

    #[test]
    fn verify_stops_when_failures_continue_and_first_sector_is_unreadable() {
        let dev = FakeDev::new(1 << 20, 512);
        let st = finished_state_at_verify(&dev);
        {
            // OSエラーコードの無い読込み失敗が、先頭セクタも含めて続く(消えたディスクの状態)
            let mut g = dev.0.lock().unwrap();
            for l in 0..2000 {
                g.bad_read.insert(l);
            }
        }
        let dir2 = tmpdir("verify_gone3");
        let (mut e2, _s2) = make(dev, &dir2, Some(st));
        assert!(e2.run().is_err());
        assert!(e2.st.total_bad_sectors() <= 8, "先頭の数セクタ以外は記録しない: {}", e2.st.total_bad_sectors());
    }

    #[test]
    fn unchecked_ranges_are_read_checked_first() {
        let dir = tmpdir("verify_first");
        let dev = FakeDev::new(1 << 20, 512);
        let (mut e, _s) = make(dev.clone(), &dir, None);
        assert_eq!(e.run().unwrap(), Outcome::Finished);
        let mut st = e.st.clone();
        drop(e);
        // 最終工程の途中からやり直す状況: 確認できていない範囲が記録されている
        st.phase = 3;
        st.offset = 0;
        for l in 100..110 {
            st.add_bad(l, BadKind::Unreadable, 0, None);
        }
        assert_eq!(st.total_bad_sectors(), 10);
        let dir2 = tmpdir("verify_first2");
        let (mut e2, _s2) = make(dev, &dir2, Some(st));
        assert_eq!(e2.run().unwrap(), Outcome::Finished);
        assert_eq!(e2.st.total_bad_sectors(), 0);
        assert!(e2.st.events.iter().any(|v| v.what.contains("読み取り確認を優先して実施")));
    }

    #[test]
    fn resume_file_is_saved_later_when_space_becomes_available() {
        let dir = tmpdir("save_retry");
        let dev = FakeDev::new(1 << 20, 512);
        let (mut e, s) = make(dev, &dir, None);
        // 保存先が使えない(空き容量不足の代わりに、存在しない場所)
        let good = e.state_path.clone();
        let bad_dir = dir.join("no_such_dir");
        e.state_path = bad_dir.join("x.json");
        assert!(!e.try_save());
        assert!(e.save_pending);
        assert!(s.snapshot().message.starts_with("再開ファイルの保存に失敗"));
        // 10秒たっていなければ再試行の時期ではないが、時間が過ぎれば保存を試みる契機になる
        e.last_save_try = Instant::now() - Duration::from_secs(11);
        assert!(e.checkpoint_due());
        // 保存先が使えるようになった
        std::fs::create_dir_all(&bad_dir).unwrap();
        assert!(e.try_save());
        assert!(!e.save_pending);
        assert!(s.snapshot().message.is_empty());
        assert!(e.state_path.exists());
        assert!(JobState::load(&e.state_path).unwrap().events.iter().any(|v| v.what.contains("再開ファイルを保存できました")));
        let _ = good;
    }

    #[test]
    fn unerased_sectors_are_refilled_first_when_writable_again() {
        let dir = tmpdir("refill");
        let dev = FakeDev::new(1 << 20, 512);
        {
            let mut g = dev.0.lock().unwrap();
            for l in 100..110 {
                g.bad_write.insert(l);
            }
            for l in 700..705 {
                g.bad_write.insert(l);
            }
        }
        let (mut e, _s) = make(dev.clone(), &dir, None);
        assert_eq!(e.run().unwrap(), Outcome::Finished);
        let mut st = e.st.clone();
        assert_eq!(st.total_bad_sectors(), 15);
        drop(e);
        // 700..705 は書けるようになり、100..110 は書けないまま。やり直しの工程で書ける分だけ解消される
        {
            let mut g = dev.0.lock().unwrap();
            for l in 700..705 {
                g.bad_write.remove(&l);
            }
            for b in g.data.iter_mut() {
                *b = 0xAA;
            }
        }
        st.phase = 0;
        st.offset = 0;
        let dir2 = tmpdir("refill2");
        let (mut e2, _s2) = make(dev.clone(), &dir2, Some(st));
        assert_eq!(e2.run().unwrap(), Outcome::Finished);
        assert_eq!(e2.st.total_bad_sectors(), 10, "書けるようになった5セクタだけが解消される");
        assert!(e2.st.bad_runs.iter().all(|r| r.start == 100 && r.len == 10));
        let g = dev.0.lock().unwrap();
        for l in 700..705usize {
            assert!(g.data[l * 512..(l + 1) * 512].iter().all(|&b| b == 0));
        }
    }

    #[test]
    fn verify_detects_silent_drop() {
        let dir = tmpdir("silent");
        let dev = FakeDev::new(256 * 1024, 512);
        dev.0.lock().unwrap().silent_drop.insert(7);
        let (mut e, _shared) = make(dev.clone(), &dir, None);
        assert_eq!(e.run().unwrap(), Outcome::Finished);
        assert!(e.st.bad_runs.iter().any(|r| r.kind == BadKind::VerifyMismatch && r.start == 7));
    }

    #[test]
    fn pause_then_run() {
        let dir = tmpdir("pause");
        let dev = FakeDev::new(512 * 1024, 512);
        let (mut e, shared) = make(dev.clone(), &dir, None);
        shared.set_cmd(CMD_PAUSE, REASON_USER);
        let sh = shared.clone();
        let h = std::thread::spawn(move || {
            // 負荷が高くても、一時停止になるのを待ってから再開する(失敗しても必ず再開させる)
            let t0 = Instant::now();
            let mut paused = false;
            while t0.elapsed() < Duration::from_secs(10) {
                if sh.snapshot().status == Status::Paused {
                    paused = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            sh.set_cmd(CMD_RUN, REASON_USER);
            paused
        });
        assert_eq!(e.run().unwrap(), Outcome::Finished);
        assert!(h.join().unwrap(), "一時停止状態になること");
    }

    #[test]
    fn sequential_mode_also_works() {
        let dir = tmpdir("seq");
        let dev = FakeDev::new(1 << 20, 512);
        let cfg = EngineCfg { queue_depth: 1, ..small_cfg() };
        let (mut e, _s) = make_with(dev.clone(), &dir, None, cfg);
        assert_eq!(e.run().unwrap(), Outcome::Finished);
        assert!(dev.0.lock().unwrap().data.iter().all(|&b| b == 0));
    }

    #[test]
    fn cached_write_failure_is_found_via_flush() {
        let dir = tmpdir("deferred");
        let dev = FakeDev::new(1 << 20, 512);
        // 書込みは成功扱いだが、flush で初めてエラーになるセクタ
        dev.0.lock().unwrap().deferred_bad.insert(1000);
        let (mut e, shared) = make(dev.clone(), &dir, None);
        assert_eq!(e.run().unwrap(), Outcome::Finished);
        assert!(
            e.st.bad_runs.iter().any(|r| r.start <= 1000 && r.end() > 1000),
            "flush失敗を切り分けて不良セクタとして記録すること: {:?}",
            e.st.bad_runs
        );
        let g = dev.0.lock().unwrap();
        for (i, chunk) in g.data.chunks(512).enumerate() {
            if i != 1000 {
                assert!(chunk.iter().all(|&b| b == 0), "sector {i}");
            }
        }
        // 巻き戻しで件数が二重に数えられていない
        assert_eq!(e.st.phase_ok[0] + e.st.phase_err[0] + e.st.phase_skip[0], (1 << 20) / 512);
        assert_eq!(shared.snapshot().status, Status::Finished);
    }

    #[test]
    fn counts_add_up_with_pipeline_and_bad_sectors() {
        let dir = tmpdir("counts");
        let dev = FakeDev::new(2 << 20, 512);
        {
            let mut g = dev.0.lock().unwrap();
            for l in [10u64, 11, 5000] {
                g.bad_write.insert(l);
                g.bad_read.insert(l);
            }
        }
        let (mut e, _s) = make(dev, &dir, None);
        assert_eq!(e.run().unwrap(), Outcome::Finished);
        let total = (2u64 << 20) / 512;
        for p in 0..3 {
            assert_eq!(e.st.phase_ok[p] + e.st.phase_err[p] + e.st.phase_skip[p], total, "phase {p}");
        }
        assert_eq!(e.st.phase_ok[3] + e.st.phase_err[3] + e.st.phase_skip[3], total);
    }

    #[test]
    fn preflight_detects_unwritable_disk() {
        let dev = FakeDev::new(4 << 20, 512);
        let mut d = dev.clone();
        assert!(preflight(&mut d).is_ok());
        // 内容は変わらない
        let before = dev.0.lock().unwrap().data.clone();
        assert!(preflight(&mut d).is_ok());
        assert_eq!(before, dev.0.lock().unwrap().data);
        let sectors = dev.0.lock().unwrap().data.len() as u64 / 512;
        {
            let mut g = dev.0.lock().unwrap();
            for l in 0..sectors {
                g.bad_write.insert(l);
            }
        }
        let e = preflight(&mut d).unwrap_err();
        assert!(e.contains("書込みに失敗"), "{e}");
    }

    #[test]
    fn systemic_failure_aborts_and_keeps_state_clean() {
        let dir = tmpdir("systemic");
        let dev = FakeDev::new(256 << 20, 512);
        {
            let mut g = dev.0.lock().unwrap();
            // 全セクタ書込み不可(読込みは可)
            for l in 0..(256u64 << 20) / 512 {
                g.bad_write.insert(l);
            }
        }
        let cfg = EngineCfg { block: 4 << 20, checkpoint_bytes: 1 << 30, ..small_cfg() };
        let (mut e, _shared) = make_with(dev, &dir, None, cfg);
        let err = e.run().unwrap_err();
        assert!(err.contains("ほとんど書き込めません"), "{err}");
        assert!(err.contains("write error"), "最後のエラーが含まれる: {err}");
        // 誤った不良セクタが状態に残らず、再開しても全域をやり直せる
        assert!(e.st.bad_runs.is_empty());
        assert_eq!(e.st.offset, 0);
        assert_eq!(e.st.phase, 0);
        assert!(!e.st.write_errors.is_empty());
        assert!(dir.join("resume.json").exists());
    }

    fn mode_state(dev: &FakeDev, mode: EraseMode) -> JobState {
        JobState::new_with_mode(ident(dev.total_bytes(), 512), 1, mode)
    }

    #[test]
    fn every_mode_ends_with_all_zero() {
        for mode in EraseMode::ALL {
            let dir = tmpdir(&format!("mode{:?}", mode));
            let dev = FakeDev::new(1 << 20, 512);
            let st = mode_state(&dev, mode);
            let (mut e, shared) = make(dev.clone(), &dir, Some(st));
            assert_eq!(e.run().unwrap(), Outcome::Finished, "{mode:?}");
            assert!(dev.0.lock().unwrap().data.iter().all(|&b| b == 0), "{mode:?}");
            // 実行しない工程は処理されない
            for slot in 0..4u8 {
                let n = e.st.phase_ok[slot as usize];
                assert_eq!(n > 0, mode.slot_enabled(slot), "{mode:?} slot{slot}");
            }
            let rp = std::fs::read_to_string(shared.snapshot().report_path.unwrap()).unwrap();
            assert!(rp.contains(mode.short()), "レポートに方式が載る: {mode:?}");
        }
    }

    #[test]
    fn deferred_head_and_tail_are_wiped_last() {
        use crate::dev::DeferEnds;
        let dir = tmpdir("defer");
        let fake = FakeDev::new(1 << 20, 512);
        let orig = fake.0.lock().unwrap().data.clone();
        let (head, tail) = (64 * 1024usize, 32 * 1024usize);
        let size = fake.total_bytes();
        let mut st = JobState::new(ident(size, 512), 1);
        st.deferred = (head + tail) as u64;
        let shared = JobShared::new(size - st.deferred, 512);
        shared.set_cmd(CMD_RUN, REASON_USER);
        fake.0.lock().unwrap().stop_after = Some((40, shared.clone()));
        let dev = Box::new(DeferEnds::new(Box::new(fake.clone()), head as u64, tail as u64));
        let mut e = Engine::new(dev, shared.clone(), st, dir.join("resume.json"), dir.clone(), small_cfg());
        assert_eq!(e.run().unwrap(), Outcome::Stopped);
        {
            // 途中で止めた時点では、先頭・末尾(パーティション情報)は元のまま、間は書き換わっている
            let g = fake.0.lock().unwrap();
            assert_eq!(&g.data[..head], &orig[..head], "先頭は途中では消さない");
            assert_eq!(&g.data[size as usize - tail..], &orig[size as usize - tail..], "末尾は途中では消さない");
            assert_ne!(&g.data[head..size as usize - tail], &orig[head..size as usize - tail]);
        }
        drop(e);
        // 再開して最後まで実行すると、先頭・末尾も含めてすべてゼロになる
        fake.0.lock().unwrap().stop_after = None;
        let st2 = JobState::load(&dir.join("resume.json")).unwrap();
        assert_eq!(st2.deferred, (head + tail) as u64);
        let shared2 = JobShared::new(size - st2.deferred, 512);
        shared2.set_cmd(CMD_RUN, REASON_USER);
        let dev2 = Box::new(DeferEnds::new(Box::new(fake.clone()), head as u64, tail as u64));
        let mut e2 = Engine::new(dev2, shared2, st2, dir.join("resume.json"), dir.clone(), small_cfg());
        assert_eq!(e2.run().unwrap(), Outcome::Finished);
        assert!(fake.0.lock().unwrap().data.iter().all(|&b| b == 0));
    }

    #[test]
    fn one_pass_does_less_work_than_standard() {
        let dev1 = FakeDev::new(1 << 20, 512);
        let dev2 = FakeDev::new(1 << 20, 512);
        let d1 = tmpdir("w_std");
        let d2 = tmpdir("w_one");
        let st1 = mode_state(&dev1, EraseMode::Standard);
        let st2 = mode_state(&dev2, EraseMode::OnePass);
        let (mut e1, _) = make(dev1.clone(), &d1, Some(st1));
        let (mut e2, _) = make(dev2.clone(), &d2, Some(st2));
        e1.run().unwrap();
        e2.run().unwrap();
        let w1 = dev1.0.lock().unwrap().write_calls;
        let w2 = dev2.0.lock().unwrap().write_calls;
        assert!(w2 * 2 < w1, "簡易1周の書込み回数は標準の半分未満: {w2} vs {w1}");
    }

    #[test]
    fn sample_verify_detects_silent_drop_on_small_disk() {
        let dir = tmpdir("sample_drop");
        let dev = FakeDev::new(1 << 20, 512);
        dev.0.lock().unwrap().silent_drop.insert(9);
        let st = mode_state(&dev, EraseMode::FastVerify);
        let (mut e, _s) = make(dev, &dir, Some(st));
        assert_eq!(e.run().unwrap(), Outcome::Finished);
        assert!(e.st.bad_runs.iter().any(|r| r.kind == BadKind::VerifyMismatch && r.start == 9));
    }

    #[test]
    fn sample_verify_stop_and_resume() {
        let dir = tmpdir("sample_resume");
        let dev = FakeDev::new(4 << 20, 512);
        let st = mode_state(&dev, EraseMode::OnePass);
        let (mut e, shared) = make(dev.clone(), &dir, Some(st));
        let sh = shared.clone();
        let h = std::thread::spawn(move || {
            let t0 = Instant::now();
            while t0.elapsed() < Duration::from_secs(20) {
                let s = sh.snapshot();
                if s.phase == 3 && s.offset > 0 {
                    break;
                }
                std::thread::sleep(Duration::from_micros(20));
            }
            sh.set_cmd(CMD_STOP, REASON_USER);
        });
        let out = e.run().unwrap();
        h.join().unwrap();
        if out == Outcome::Stopped {
            let st = JobState::load(&dir.join("resume.json")).unwrap();
            assert_eq!(st.mode, EraseMode::OnePass);
            let (mut e2, _s2) = make(dev.clone(), &dir, Some(st));
            assert_eq!(e2.run().unwrap(), Outcome::Finished);
        }
        assert!(dev.0.lock().unwrap().data.iter().all(|&b| b == 0));
    }

    #[test]
    fn autotune_picks_a_config_and_still_wipes() {
        let dir = tmpdir("tune");
        let dev = FakeDev::new(256 << 20, 512);
        let cfg = EngineCfg { block: 1 << 20, autotune: true, tune_warmup_ms: 1, tune_probe_ms: 2, checkpoint_bytes: 1 << 30, ..small_cfg() };
        let (mut e, shared) = make_with(dev.clone(), &dir, None, cfg);
        assert_eq!(e.run().unwrap(), Outcome::Finished);
        assert!(dev.0.lock().unwrap().data.iter().all(|&b| b == 0));
        assert!(e.st.tuned.is_some(), "調整結果が記録される");
        assert!(e.st.events.iter().any(|ev| ev.what.contains("自動調整")));
        assert!(shared.snapshot().notes.contains("自動調整"));
    }

    #[test]
    fn pipelined_verify_reports_unreadable_sectors() {
        let dir = tmpdir("vread");
        let dev = FakeDev::new(1 << 20, 512);
        // 書込みは成功するが読込みだけ失敗するセクタ(検証で見つかる)
        dev.0.lock().unwrap().bad_read.insert(700);
        let (mut e, _s) = make(dev, &dir, None);
        assert_eq!(e.run().unwrap(), Outcome::Finished);
        assert!(e.st.bad_runs.iter().any(|r| r.kind == BadKind::Unreadable && r.start <= 700 && r.end() > 700));
    }
}
