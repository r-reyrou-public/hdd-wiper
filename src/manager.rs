//! 複数ディスクの同時実行と、帯域不足時に1台へ絞るスケジューラ。

use crate::disk::{volume_overview, DiskInfo, WinDisk};
use crate::dev::{BlockDev, DeferEnds};
use crate::engine::*;
use crate::state::*;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub const MAX_PARALLEL: usize = 3;
pub const BASELINE_SECS: u64 = 20;
pub const WARMUP_SECS: u64 = 40;
pub const SPEED_WINDOW: Duration = Duration::from_secs(15);
pub const DEFAULT_THRESHOLD: f64 = 0.70;

/// 再開ファイルのパス。同型ディスクが複数つながっている場合は番号で区別する
pub fn resume_path(log_dir: &Path, id: &DiskIdentity, dup_number: Option<u32>) -> PathBuf {
    match dup_number {
        Some(n) => log_dir.join(format!("resume_{}_d{}.json", id.key(), n)),
        None => log_dir.join(format!("resume_{}.json", id.key())),
    }
}

/// この識別情報に対応する再開ファイルの候補を列挙する
pub fn find_resume_candidates(log_dir: &Path, id: &DiskIdentity) -> Vec<(PathBuf, JobState)> {
    let key = id.key();
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(log_dir) else { return out };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        let Some(rest) = name.strip_prefix(&format!("resume_{key}")).and_then(|r| r.strip_suffix(".json")) else {
            continue;
        };
        let ok = rest.is_empty()
            || rest.strip_prefix("_d").map(|d| !d.is_empty() && d.chars().all(|c| c.is_ascii_digit())).unwrap_or(false);
        if !ok {
            continue;
        }
        if let Ok(st) = JobState::load(&e.path()) {
            if st.identity.same_disk(id) {
                out.push((e.path(), st));
            }
        }
    }
    out
}

pub struct Job {
    pub disk: DiskInfo,
    pub shared: Arc<JobShared>,
    pub state_path: PathBuf,
    pub baseline: Option<f64>,
    _thread: JoinHandle<()>,
}

impl Job {
    pub fn status(&self) -> Status {
        self.shared.snap.lock().unwrap().status.clone()
    }
    pub fn is_terminal(&self) -> bool {
        matches!(self.status(), Status::Finished | Status::Stopped | Status::Failed(_))
    }
}

/// Windowsセキュリティの「コントロールされたフォルダー アクセス」が、このプログラムの
/// ディスク書込みをブロックした記録(イベントID 1127)があれば、原因と対処を返す。
pub fn defender_hint() -> Option<String> {
    use std::os::windows::process::CommandExt;
    let exe = std::env::current_exe().ok()?;
    let out = std::process::Command::new("wevtutil")
        .args([
            "qe",
            "Microsoft-Windows-Windows Defender/Operational",
            "/q:*[System[(EventID=1127)]]",
            "/c:20",
            "/rd:true",
            "/f:text",
        ])
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    // wevtutil の出力は日本語環境では CP932 になり、パスの日本語部分は照合できない。
    // パスの先頭の ASCII 部分(ドライブ文字と最初のフォルダ名など)だけで照合する。
    let full = exe.to_string_lossy().to_string();
    let prefix: String = full.chars().take_while(|c| c.is_ascii()).collect();
    if prefix.len() < 4 {
        return None;
    }
    // 該当する最新のイベント(/rd:true なので新しい順)
    let latest = text
        .split("Event[")
        .find(|ev| ev.contains(&prefix) && (ev.contains("Harddisk") || ev.contains("PhysicalDrive")))?;
    // wevtutil の Date: はこのPCの時刻なのに末尾に Z が付く(UTCではない)。Z と秒未満を落とす。
    let when = latest
        .lines()
        .find_map(|l| l.trim().strip_prefix("Date:"))
        .map(|d| d.trim().trim_end_matches('Z').split('.').next().unwrap_or("").replacen('T', " ", 1))
        .unwrap_or_default();
    Some(format!(
        "【原因】Windowsセキュリティの「コントロールされたフォルダー アクセス」が、このプログラムによるディスクへの直接書き込みをブロックしています(Defenderのイベント ID 1127 を確認しました。最新のブロック記録: {when} ※このPCの時刻)。許可を設定した後もこの表示が出る場合は、この時刻が今回の失敗より前かを確認してください。
【対処】次のどちらかを行ってから、やり直してください。
 (1) Windowsセキュリティ → ウイルスと脅威の防止 → ランサムウェア防止の管理 → コントロールされたフォルダー アクセス → 「コントロールされたフォルダー アクセスによるアプリの許可」→ 次のファイルを追加
     {}
 (2) 管理者のPowerShellで: Add-MpPreference -ControlledFolderAccessAllowedApplications \"{}\"
 (消去が終わったら、許可を外して元の設定に戻せます)

",
        exe.display(),
        exe.display(),
        when = when
    ))
}

/// 失敗メッセージが「Defenderのコントロールされたフォルダー アクセスによるブロック」を示すか
pub fn is_defender_block(msg: &str) -> bool {
    msg.contains("【原因】Windowsセキュリティの「コントロールされたフォルダー アクセス」")
}

/// このプログラム自身を、Defenderの「コントロールされたフォルダー アクセス」の許可アプリに追加する
/// (管理者権限が必要。利用者が画面のボタンで同意したときだけ呼ぶこと)。
/// 成功時は説明文、失敗時は理由と手動の手順を返す。実施内容は log_dir に記録する。
pub fn allow_in_defender(log_dir: &Path) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    let exe = std::env::current_exe().map_err(|e| format!("このプログラムの場所を取得できません: {e}"))?;
    let exe_s = exe.to_string_lossy().trim_start_matches(r"\\?\").to_string();
    // パスは環境変数で渡す(引用符の扱いで壊れないようにするため)
    let script = "$ErrorActionPreference='Stop'; \
        try { Add-MpPreference -ControlledFolderAccessAllowedApplications $env:HDDW_EXE } catch { exit 2 }; \
        $l=@((Get-MpPreference).ControlledFolderAccessAllowedApplications); \
        if ($l -contains $env:HDDW_EXE) { exit 0 } else { exit 3 }";
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
        .env("HDDW_EXE", &exe_s)
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .output()
        .map_err(|e| format!("PowerShell を起動できません: {e}"))?;
    let code = out.status.code().unwrap_or(-1);
    let manual = format!(
        "手動で行う場合は、管理者のPowerShellで次を実行してください:\nAdd-MpPreference -ControlledFolderAccessAllowedApplications \"{exe_s}\""
    );
    let result = match code {
        0 => Ok(format!(
            "Defenderの許可アプリに追加しました: {exe_s}\n不要になったら、管理者のPowerShellで次を実行すると元に戻せます:\nRemove-MpPreference -ControlledFolderAccessAllowedApplications \"{exe_s}\""
        )),
        2 => Err(format!(
            "許可アプリへの追加を、Windowsに拒否されました。Windowsセキュリティの「改ざん防止」がオンの場合や、組織の管理下にあるPCでは、この方法は使えないことがあります。\n{manual}"
        )),
        3 => Err(format!("追加を実行しましたが、許可アプリの一覧に反映されていません。\n{manual}")),
        c => Err(format!("許可アプリへの追加に失敗しました(終了コード {c})。\n{manual}")),
    };
    let _ = std::fs::create_dir_all(log_dir);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(log_dir.join("defender_allow_log.txt")) {
        use std::io::Write;
        let _ = writeln!(
            f,
            "{} 利用者の操作で許可アプリへの追加を実行: {exe_s} -> {}",
            now_str(),
            if result.is_ok() { "成功".to_string() } else { format!("失敗(終了コード {code})") }
        );
    }
    result
}

pub fn spawn_job(
    disk: DiskInfo,
    existing: Option<JobState>,
    state_path: PathBuf,
    log_dir: &Path,
    write_through: bool,
    mode: EraseMode,
) -> Job {
    let shared = JobShared::new(disk.identity.size, disk.identity.sector_size);
    // 書けなかったセクタが残っている再開ジョブは、通常の書き込みの前に、1本ずつ優先して書き直す
    if let Some(st) = existing.as_ref() {
        let refillable = st.phase < 3 && st.bad_runs.iter().any(|r| r.kind != crate::state::BadKind::VerifyMismatch);
        shared.refill_pending.store(refillable, std::sync::atomic::Ordering::SeqCst);
    }
    let (sh, d, sp, ld) = (shared.clone(), disk.clone(), state_path.clone(), log_dir.to_path_buf());
    let thread = std::thread::spawn(move || {
        let res = (|| -> Result<Outcome, String> {
            std::fs::create_dir_all(&ld).map_err(|e| format!("ログフォルダを作成できません: {e}"))?;
            let cfg = EngineCfg { write_through, ..EngineCfg::default() };
            let mut dev = WinDisk::open_for_wipe(d.number, d.identity.sector_size, d.identity.size, write_through, cfg.queue_depth)
                .map_err(|e| e.to_string())?;
            // 書込みテスト(内容は変えない)。失敗したら属性の解除を試し、それでも駄目なら理由を示して中止する
            let mut early_layout_note = String::new();
            if let Err(first) = preflight(&mut dev) {
                // パーティション情報が残ったままでは、Windowsがディスクへの書込みを拒否する場合がある。
                // その場合に限り、従来どおり開始時にパーティション情報を削除する(ハンドルを閉じて開き直し、最初に削除)。
                drop(dev);
                dev = WinDisk::open_with(d.number, d.identity.sector_size, d.identity.size, write_through, cfg.queue_depth)
                    .map_err(|e| format!("書込みに失敗したため開き直そうとしましたが、開けませんでした: {e}\n(1回目: {first})"))?;
                let n0 = dev.delete_layout();
                early_layout_note = format!(
                    "パーティション情報が残っていると書き込めなかったため、開始時にパーティション情報を削除しました({n0})。この場合、中断後の再開ではドライブ割り当てが失われています"
                );
                dev.layout_note = early_layout_note.clone();
                // 考えられる対処を順に試す: 属性の解除 → パーティション情報の再削除
                let note1 = dev.try_enable_write();
                let note2 = dev.delete_layout();
                if let Err(second) = preflight(&mut dev) {
                    let probe = dev.probe_writes();
                    let hint = defender_hint().unwrap_or_default();
                    let report = format!(
                        "{hint}このディスクに書き込めません。{second}\n(1回目: {first})\n{}\n試した対処: {note1} / 2回目の{note2}\n開始時の準備: {}\nロック・マウント解除したボリューム: {:?}\n全ボリューム:\n{}\n書込み位置別の結果(読んだ内容を書き戻すテスト):\n{}",
                        dev.attributes_text(),
                        dev.layout_note,
                        dev.locked,
                        volume_overview().join("\n"),
                        probe
                    );
                    let _ = std::fs::write(ld.join(format!("write_failure_disk{}.txt", d.number)), format!("\u{feff}{report}"));
                    return Err(report);
                }
            }
            // ディスクの書込みキャッシュを有効にする(USB接続では無効のことがあり、大きく遅くなる)
            let cache_note = if write_through { None } else { Some(dev.enable_write_cache()) };
            let lock_notes: Vec<String> = dev.locked.clone();
            let is_new = existing.is_none();
            let mut st = existing.unwrap_or_else(|| JobState::new_with_mode(d.identity.clone(), d.number, mode));
            st.last_disk_number = d.number;
            // 新規ジョブは、先頭・末尾(パーティション情報など)を最後に消す。
            // 旧版で始めた再開ジョブは、進捗の基準が違うので従来どおり全域を工程で処理する
            let (head, tail) = if is_new || st.deferred > 0 { deferred_sizes(d.identity.size) } else { (0, 0) };
            let dev: Box<dyn BlockDev> = if head + tail > 0 {
                st.deferred = head + tail;
                Box::new(DeferEnds::new(Box::new(dev), head, tail))
            } else {
                Box::new(dev)
            };
            let mut eng = Engine::new(dev, sh.clone(), st, sp, ld, cfg);
            for n in lock_notes {
                eng.add_note(format!("ボリューム: {n}"));
            }
            if !early_layout_note.is_empty() {
                eng.add_note(early_layout_note);
            }
            if let Some(n) = cache_note {
                eng.add_note(n);
            }
            let res = eng.run();
            if eng.is_hung() {
                // 取り消しに応じないI/Oがカーネルに残っている。バッファやハンドルを解放すると危険なので、そのまま残す
                std::mem::forget(eng);
            }
            res
        })();
        match res {
            Ok(Outcome::Finished) => {}
            Ok(Outcome::Stopped) => sh.set_status(Status::Stopped),
            Err(e) => sh.set_status(Status::Failed(e)),
        }
    });
    Job { disk, shared, state_path, baseline: None, _thread: thread }
}

#[derive(Clone, Debug)]
pub enum Stage {
    Single,
    /// 未消去セクタの書き直しが残っているジョブを、1本ずつ先に動かす
    Refill,
    Baseline { idx: usize, since: Option<Instant> },
    Concurrent { since: Option<Instant>, decided: bool },
    /// 絞り込みと判定する直前に、同じ位置で1台ずつ単独速度を測り直して確かめる
    Recheck { idx: usize, since: Option<Instant> },
    Serial,
}

pub struct Scheduler {
    pub jobs: Vec<Job>,
    pub stage: Stage,
    pub user_paused: bool,
    pub threshold: f64,
    pub last_ratio: Option<f64>,
    pub throttled: bool,
    /// 中断を指示したジョブ。スケジューラは以後このジョブの実行/停止の指示を上書きしない
    stopping: Vec<bool>,
    /// 利用者が個別に一時停止したジョブ(他のジョブの実行・速度判定からは外す)
    job_paused: Vec<bool>,
    /// 中断を指示した時刻(中断が終わらないジョブの検出用)
    stop_started: Vec<Option<Instant>>,
    serial_since: Option<Instant>,
    /// 帯域の絞り込みの原因調査用ログ(logs/scheduler_log.txt)
    log_path: Option<PathBuf>,
    last_sample_log: Option<Instant>,
    /// 測り直しの材料: 判定時点の同時実行の速度 / 測り直した単独速度 (ジョブ番号, bytes/s)
    recheck_now: Vec<(usize, f64)>,
    recheck_base: Vec<(usize, f64)>,
}

/// 同時実行の合計速度が、単独時の合計に対して threshold を下回ったか
pub fn should_throttle(base: &[f64], now: &[f64], threshold: f64) -> Option<(bool, f64)> {
    let mut sb = 0.0;
    let mut sn = 0.0;
    for (b, n) in base.iter().zip(now.iter()) {
        sb += b;
        sn += n;
    }
    if sb <= 0.0 {
        return None;
    }
    let ratio = sn / sb;
    // n台を1台ずつ実行した場合の合計速度は、単独時の合計の 1/n。同時実行がそれを
    // 25%以上上回るなら、同時実行のほうが速い。設定値が厳しすぎても、速い同時実行を捨てない。
    let n = base.len().max(1) as f64;
    let limit = threshold.min(1.25 / n);
    Some((ratio < limit, ratio))
}

/// 1台ずつの実行に切り替えた後、同時実行を試し直すまでの時間
pub const SERIAL_RETRY_SECS: u64 = 600;

impl Scheduler {
    pub fn new(jobs: Vec<Job>, threshold: f64) -> Self {
        let pending = jobs.iter().any(|j| j.shared.refill_pending.load(std::sync::atomic::Ordering::SeqCst));
        let stage = if jobs.len() <= 1 {
            Stage::Single
        } else if pending {
            Stage::Refill
        } else {
            Stage::Baseline { idx: 0, since: None }
        };
        let n = jobs.len();
        Scheduler { jobs, stage, user_paused: false, threshold, last_ratio: None, throttled: false, stopping: vec![false; n], job_paused: vec![false; n], stop_started: vec![None; n], serial_since: None, log_path: None, last_sample_log: None, recheck_now: Vec::new(), recheck_base: Vec::new() }
    }

    pub fn all_terminal(&self) -> bool {
        self.jobs.iter().all(|j| j.is_terminal())
    }

    /// 調査用ログの出力先を設定する
    pub fn set_log(&mut self, path: PathBuf) {
        self.log_path = Some(path);
        let mut s = String::from("=== スケジューラ開始 ===
");
        s += &format!("設定: しきい値 {:.2} / 基準測定 {}秒 / ウォームアップ {}秒 / 速度窓 {}秒 / 直列の試し直し {}秒
",
            self.threshold, BASELINE_SECS, WARMUP_SECS, SPEED_WINDOW.as_secs(), SERIAL_RETRY_SECS);
        for j in &self.jobs {
            s += &format!("  PhysicalDrive{} {} {}
", j.disk.number, j.disk.identity.model, j.disk.identity.serial);
        }
        self.log_raw(&s);
    }

    fn log_raw(&self, text: &str) {
        let Some(p) = &self.log_path else { return };
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
            for line in text.lines() {
                let _ = writeln!(f, "[{}] {}", crate::state::now_str(), line);
            }
        }
    }

    fn stage_name(&self) -> &'static str {
        match self.stage {
            Stage::Single => "Single",
            Stage::Refill => "Refill",
            Stage::Baseline { .. } => "Baseline",
            Stage::Concurrent { decided: false, .. } => "Concurrent(確認中)",
            Stage::Concurrent { decided: true, .. } => "Concurrent(確定)",
            Stage::Recheck { .. } => "Recheck",
            Stage::Serial => "Serial",
        }
    }

    /// 各ジョブの状態を1行ずつ書く(速度は15秒窓と60秒窓)
    fn job_lines(&self) -> String {
        let mut out = String::new();
        for (i, j) in self.jobs.iter().enumerate() {
            let sn = j.shared.snapshot();
            let f = |v: Option<f64>| v.map(|x| format!("{:.1}", x / 1048576.0)).unwrap_or_else(|| "-".into());
            out += &format!(
                "  d{} {:?} cmd={} reason={} 工程{} 位置{:.3}TB 速度15s={} 60s={} MiB/s 基準={} stall={}s ok={} err={} skip={} 再試行W{}/R{} 標本{}件
",
                j.disk.number,
                sn.status,
                j.shared.cmd.load(std::sync::atomic::Ordering::SeqCst),
                j.shared.reason.load(std::sync::atomic::Ordering::SeqCst),
                sn.phase + 1,
                sn.offset as f64 / 1e12,
                f(sn.speed(SPEED_WINDOW)),
                f(sn.speed(Duration::from_secs(60))),
                f(j.baseline),
                j.shared.stall_secs.load(std::sync::atomic::Ordering::SeqCst),
                sn.ok, sn.err, sn.skip, sn.write_retries, sn.read_retries, sn.samples.len(),
            );
            let ((wn, wa, wm), (fnn, fa, fm)) = j.shared.lat.take();
            out += &format!("      前回ログ以降: 書込み完了待ち {}回 平均{:.1}ms 最大{:.1}ms / flush {}回 平均{:.1}ms 最大{:.1}ms
", wn, wa, wm, fnn, fa, fm);
            let _ = i;
        }
        out
    }

    pub fn stage_text(&self) -> String {
        if self.user_paused {
            return "一時停止中".into();
        }
        match &self.stage {
            Stage::Single => "実行中".into(),
            Stage::Refill => "未消去セクタを優先して書き直し中(1台ずつ)".into(),
            Stage::Baseline { idx, .. } => {
                format!("単独速度を測定中({}台目 / {}台)", idx + 1, self.jobs.len())
            }
            Stage::Concurrent { decided: false, .. } => "同時実行の速度を確認中".into(),
            Stage::Concurrent { decided: true, .. } => match self.last_ratio {
                Some(r) => format!("同時実行中(単独時の{:.0}%の速度)", r * 100.0),
                None => "同時実行中".into(),
            },
            Stage::Recheck { idx, .. } => format!("絞り込みの前に単独速度を測り直し中({}台目 / {}台)", idx + 1, self.jobs.len()),
            Stage::Serial => format!(
                "帯域不足のため1台ずつ実行中(同時実行時は単独時の{:.0}%)",
                self.last_ratio.unwrap_or(0.0) * 100.0
            ),
        }
    }

    /// 1台ずつ実行中(帯域不足の判定後)かどうか
    pub fn is_serial(&self) -> bool {
        matches!(self.stage, Stage::Serial)
    }

    /// 利用者の指示で、全台の同時実行に戻す。以後は速度による自動の絞り込みを行わない
    pub fn force_concurrent(&mut self) {
        self.log_raw("利用者の操作: 全台の同時実行に戻す");
        self.serial_since = None;
        self.throttled = false;
        self.stage = Stage::Concurrent { since: None, decided: true };
    }

    pub fn set_user_paused(&mut self, p: bool) {
        if self.user_paused && !p {
            // 再開: 速度測定のやり直し
            match &mut self.stage {
                Stage::Baseline { since, .. } => *since = None,
                Stage::Concurrent { since, .. } => *since = None,
                _ => {}
            }
        }
        self.user_paused = p;
    }

    /// 失敗したジョブを、新しく起動し直したジョブに入れ替える(Defenderの許可後の再試行など)
    pub fn replace_job(&mut self, idx: usize, job: Job) {
        self.jobs[idx] = job;
        self.stopping[idx] = false;
        self.stop_started[idx] = None;
        self.job_paused[idx] = false;
    }

    pub fn is_job_paused(&self, idx: usize) -> bool {
        self.job_paused[idx]
    }

    /// 利用者の指示で、1台だけ一時停止/再開する。再開後は速度の測定をやり直す
    pub fn set_job_paused(&mut self, idx: usize, p: bool) {
        if self.job_paused[idx] == p {
            return;
        }
        self.job_paused[idx] = p;
        self.log_raw(&format!("利用者の操作: d{} を{}", self.jobs[idx].disk.number, if p { "一時停止" } else { "再開" }));
        if p {
            self.jobs[idx].shared.set_cmd(CMD_PAUSE, REASON_USER);
        } else {
            match &mut self.stage {
                Stage::Baseline { since, .. } => *since = None,
                Stage::Concurrent { since, decided } if !*decided => *since = None,
                Stage::Recheck { since, .. } => *since = None,
                _ => {}
            }
        }
    }

    /// 中断を指示してから `secs` 秒たっても終わらないジョブがあるか
    pub fn stop_is_stuck(&self, secs: u64) -> bool {
        (0..self.jobs.len()).any(|i| {
            self.stopping[i]
                && !self.jobs[i].is_terminal()
                && self.stop_started[i].map(|t| t.elapsed().as_secs() >= secs).unwrap_or(false)
        })
    }

    pub fn stop_job(&mut self, idx: usize) {
        if self.stop_started[idx].is_none() {
            self.stop_started[idx] = Some(Instant::now());
        }
        self.stopping[idx] = true;
        self.jobs[idx].shared.set_cmd(CMD_STOP, REASON_USER);
    }

    pub fn tick(&mut self) {
        let before = self.stage_name();
        self.tick_inner();
        let after = self.stage_name();
        if self.log_path.is_some() {
            if before != after {
                let mut t = format!("段階の遷移: {} → {} (直近の比率 {:?} / 一時停止={})
", before, after, self.last_ratio, self.user_paused);
                t += &self.job_lines();
                self.log_raw(&t);
                self.last_sample_log = Some(Instant::now());
            } else if self.last_sample_log.map_or(true, |t| t.elapsed() >= Duration::from_secs(30)) {
                self.last_sample_log = Some(Instant::now());
                let t = format!("定期サンプル [{}]
{}", after, self.job_lines());
                self.log_raw(&t);
            }
        }
    }

    fn tick_inner(&mut self) {
        for i in 0..self.jobs.len() {
            if self.job_paused[i] && !self.stopping[i] && !self.jobs[i].is_terminal() {
                self.jobs[i].shared.set_cmd(CMD_PAUSE, REASON_USER);
            }
        }
        let active: Vec<usize> = (0..self.jobs.len())
            .filter(|&i| !self.stopping[i] && !self.job_paused[i] && !self.jobs[i].is_terminal())
            .collect();
        if active.is_empty() {
            return;
        }
        if self.user_paused {
            for &i in &active {
                self.jobs[i].shared.set_cmd(CMD_PAUSE, REASON_USER);
            }
            return;
        }
        // 書き直しが残っているジョブがあれば、何より先に、1台ずつ処理する(他は待機)
        let pend = |s: &Self, i: usize| s.jobs[i].shared.refill_pending.load(std::sync::atomic::Ordering::SeqCst);
        if active.len() >= 2 && !matches!(self.stage, Stage::Refill) && active.iter().any(|&i| pend(self, i)) {
            self.stage = Stage::Refill;
        }
        match self.stage.clone() {
            Stage::Single => {
                for &i in &active {
                    self.jobs[i].shared.set_cmd(CMD_RUN, REASON_USER);
                }
            }
            Stage::Refill => {
                let Some(&cur) = active.iter().find(|&&i| pend(self, i)) else {
                    self.stage = Stage::Baseline { idx: 0, since: None };
                    return;
                };
                for &i in &active {
                    if i == cur {
                        self.jobs[i].shared.set_cmd(CMD_RUN, REASON_USER);
                    } else {
                        self.jobs[i].shared.set_cmd(CMD_PAUSE, REASON_QUEUE);
                    }
                }
            }
            Stage::Baseline { idx, since } => {
                let Some(&cur) = active.iter().find(|&&i| i >= idx) else {
                    self.stage = Stage::Concurrent { since: None, decided: false };
                    return;
                };
                for &i in &active {
                    if i == cur {
                        self.jobs[i].shared.set_cmd(CMD_RUN, REASON_USER);
                    } else {
                        self.jobs[i].shared.set_cmd(CMD_PAUSE, REASON_QUEUE);
                    }
                }
                let snap = self.jobs[cur].shared.snapshot();
                if snap.status == Status::Running {
                    let since = since.unwrap_or_else(Instant::now);
                    if since.elapsed() >= Duration::from_secs(BASELINE_SECS) {
                        self.jobs[cur].baseline = snap.speed(SPEED_WINDOW);
                        self.log_raw(&format!("単独速度を記録: d{} 基準={:?} B/s (15秒窓) 標本{}件 工程{} 位置{:.3}TB", self.jobs[cur].disk.number, self.jobs[cur].baseline.map(|b| b as u64), snap.samples.len(), snap.phase + 1, snap.offset as f64 / 1e12));
                        self.stage = Stage::Baseline { idx: cur + 1, since: None };
                    } else {
                        self.stage = Stage::Baseline { idx: cur, since: Some(since) };
                    }
                } else {
                    self.stage = Stage::Baseline { idx: cur, since: None };
                }
            }
            Stage::Concurrent { since, decided } => {
                for &i in &active {
                    self.jobs[i].shared.set_cmd(CMD_RUN, REASON_USER);
                }
                if decided || active.len() < 2 {
                    return;
                }
                let all_running = active.iter().all(|&i| self.jobs[i].status() == Status::Running);
                if !all_running {
                    self.stage = Stage::Concurrent { since: None, decided };
                    return;
                }
                let since = since.unwrap_or_else(Instant::now);
                if since.elapsed() < Duration::from_secs(WARMUP_SECS) {
                    self.stage = Stage::Concurrent { since: Some(since), decided };
                    return;
                }
                let mut base = Vec::new();
                let mut now = Vec::new();
                for &i in &active {
                    if let (Some(b), Some(n)) =
                        (self.jobs[i].baseline, self.jobs[i].shared.snapshot().speed(Duration::from_secs(20)))
                    {
                        base.push(b);
                        now.push(n);
                    }
                }
                {
                    let nn = base.len().max(1) as f64;
                    let mut t = format!(
                        "同時実行の判定: 比較対象{}台(稼働{}台) 基準合計={:.1} 現在合計={:.1} MiB/s しきい値{:.2} 1.25/n={:.2} 実効上限={:.2}
",
                        base.len(), active.len(),
                        base.iter().sum::<f64>() / 1048576.0, now.iter().sum::<f64>() / 1048576.0,
                        self.threshold, 1.25 / nn, self.threshold.min(1.25 / nn)
                    );
                    t += &self.job_lines();
                    self.log_raw(&t);
                }
                match should_throttle(&base, &now, self.threshold) {
                    Some((true, r)) if active.len() >= 2 => {
                        self.log_raw(&format!("→ 帯域不足の疑い: 比率 {:.3}。確定する前に、1台ずつ単独速度を測り直す", r));
                        self.recheck_now = active
                            .iter()
                            .filter_map(|&i| self.jobs[i].shared.snapshot().speed(Duration::from_secs(20)).map(|n| (i, n)))
                            .collect();
                        self.recheck_base.clear();
                        self.last_ratio = Some(r);
                        self.stage = Stage::Recheck { idx: 0, since: None };
                    }
                    Some((true, r)) => {
                        self.log_raw(&format!("→ 帯域不足と判定: 比率 {:.3}。1台ずつ実行に切り替え", r));
                        self.last_ratio = Some(r);
                        self.throttled = true;
                        self.stage = Stage::Serial;
                    }
                    Some((false, r)) => {
                        self.log_raw(&format!("→ 同時実行を継続: 比率 {:.3}", r));
                        self.last_ratio = Some(r);
                        self.stage = Stage::Concurrent { since: Some(since), decided: true };
                    }
                    None => {
                        self.stage = Stage::Concurrent { since: Some(since), decided: true };
                    }
                }
            }
            Stage::Recheck { idx, since } => {
                let Some(&cur) = active.iter().find(|&&i| i >= idx) else {
                    // 測り直し完了: 同じ位置・同じ時期の単独速度で判定し直す
                    let mut base = Vec::new();
                    let mut now = Vec::new();
                    for &(i, n) in &self.recheck_now {
                        if let Some(&(_, b)) = self.recheck_base.iter().find(|(j, _)| *j == i) {
                            base.push(b);
                            now.push(n);
                            self.jobs[i].baseline = Some(b);
                        }
                    }
                    let sb: f64 = base.iter().sum();
                    let sn: f64 = now.iter().sum();
                    let res = should_throttle(&base, &now, self.threshold);
                    self.log_raw(&format!(
                        "測り直し結果: 単独合計(新)={:.1} 同時合計={:.1} MiB/s 台数{} → {}",
                        sb / 1048576.0, sn / 1048576.0, base.len(),
                        match res { Some((true, r)) => format!("やはり帯域不足(比率 {:.3})。1台ずつに切り替え", r), Some((false, r)) => format!("帯域は足りている(比率 {:.3})。基準が高すぎたので同時実行を継続", r), None => "判定不能のため同時実行を継続".into() }
                    ));
                    self.recheck_now.clear();
                    self.recheck_base.clear();
                    match res {
                        Some((true, r)) => {
                            self.last_ratio = Some(r);
                            self.throttled = true;
                            self.stage = Stage::Serial;
                        }
                        Some((false, r)) => {
                            self.last_ratio = Some(r);
                            self.stage = Stage::Concurrent { since: Some(Instant::now()), decided: true };
                        }
                        None => self.stage = Stage::Concurrent { since: Some(Instant::now()), decided: true },
                    }
                    return;
                };
                for &i in &active {
                    if i == cur {
                        self.jobs[i].shared.set_cmd(CMD_RUN, REASON_USER);
                    } else {
                        self.jobs[i].shared.set_cmd(CMD_PAUSE, REASON_QUEUE);
                    }
                }
                let snap = self.jobs[cur].shared.snapshot();
                if snap.status == Status::Running {
                    let since = since.unwrap_or_else(Instant::now);
                    if since.elapsed() >= Duration::from_secs(BASELINE_SECS) {
                        if let Some(sp) = snap.speed(SPEED_WINDOW) {
                            self.recheck_base.push((cur, sp));
                            self.log_raw(&format!("測り直し: d{} 単独 {:.1} MiB/s (位置{:.3}TB)", self.jobs[cur].disk.number, sp / 1048576.0, snap.offset as f64 / 1e12));
                        }
                        self.stage = Stage::Recheck { idx: cur + 1, since: None };
                    } else {
                        self.stage = Stage::Recheck { idx: cur, since: Some(since) };
                    }
                } else {
                    self.stage = Stage::Recheck { idx: cur, since: None };
                }
            }
            Stage::Serial => {
                // 一時的な速度低下(キャッシュ切れ・他の処理・停止からの回復中)で切り替わっても戻れるよう、定期的に試し直す
                let since = *self.serial_since.get_or_insert_with(Instant::now);
                if active.len() >= 2 && since.elapsed() >= Duration::from_secs(SERIAL_RETRY_SECS) {
                    self.serial_since = None;
                    self.throttled = false;
                    self.stage = Stage::Baseline { idx: 0, since: None };
                    return;
                }
                let cur = active[0];
                for &i in &active {
                    if i == cur {
                        self.jobs[i].shared.set_cmd(CMD_RUN, REASON_USER);
                    } else {
                        self.jobs[i].shared.set_cmd(CMD_PAUSE, REASON_BANDWIDTH);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn throttle_decision() {
        let (t, r) = should_throttle(&[150e6, 150e6, 150e6], &[40e6, 40e6, 40e6], 0.7).unwrap();
        assert!(t);
        assert!((r - 120.0 / 450.0).abs() < 1e-9);
        // 3台が単独時の60%(合計270MB/s)なら、1台ずつ(150MB/s)より速いので同時実行を続ける
        let (t, _) = should_throttle(&[150e6; 3], &[90e6; 3], 0.7).unwrap();
        assert!(!t);
        // 3台の合計が1台分(150MB/s)と同程度なら1台ずつに切り替える
        let (t, _) = should_throttle(&[150e6; 3], &[55e6; 3], 0.7).unwrap();
        assert!(t);
        let (t, _) = should_throttle(&[150e6, 150e6], &[140e6, 135e6], 0.7).unwrap();
        assert!(!t);
        assert!(should_throttle(&[], &[], 0.7).is_none());
    }

    #[test]
    fn resume_candidates_for_identical_drives() {
        let dir = std::env::temp_dir().join(format!("hddwiper_mgr_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let id = DiskIdentity { vendor: "WDC".into(), model: "X".into(), serial: "0000".into(), size: 1000, sector_size: 512, bus: "USB".into() };
        let other = DiskIdentity { model: "X_d1".into(), ..id.clone() };
        for (n, ident) in [(3u32, &id), (4u32, &id), (9u32, &other)] {
            let mut st = JobState::new(ident.clone(), n);
            st.phase = 1;
            st.save(&resume_path(&dir, ident, Some(n))).unwrap();
        }
        let c = find_resume_candidates(&dir, &id);
        assert_eq!(c.len(), 2, "別モデルのファイルを拾わないこと");
        let mut nums: Vec<u32> = c.iter().map(|(_, s)| s.last_disk_number).collect();
        nums.sort();
        assert_eq!(nums, vec![3, 4]);
        assert_ne!(resume_path(&dir, &id, Some(3)), resume_path(&dir, &id, Some(4)));
    }

    fn fake_job(n: u32) -> Job {
        use crate::disk::DiskClass;
        let identity = DiskIdentity { vendor: "T".into(), model: format!("M{n}"), serial: "S".into(), size: 1 << 20, sector_size: 512, bus: "SATA".into() };
        let disk = DiskInfo { number: n, identity, class: DiskClass::Hdd, serial_untrusted: false, ident_duplicate: false, volumes: vec![] };
        let shared = JobShared::new(1 << 20, 512);
        shared.set_status(Status::Running);
        Job { disk, shared, state_path: PathBuf::new(), baseline: None, _thread: std::thread::spawn(|| {}) }
    }

    #[test]
    fn jobs_with_unerased_sectors_are_refilled_one_at_a_time_first() {
        use std::sync::atomic::Ordering::SeqCst;
        let jobs = vec![fake_job(1), fake_job(2), fake_job(3)];
        jobs[1].shared.refill_pending.store(true, SeqCst);
        let mut sch = Scheduler::new(jobs, 0.7);
        assert!(matches!(sch.stage, Stage::Refill));
        sch.tick();
        assert_eq!(sch.jobs[1].shared.cmd.load(SeqCst), CMD_RUN);
        assert_eq!(sch.jobs[0].shared.cmd.load(SeqCst), CMD_PAUSE);
        assert_eq!(sch.jobs[2].shared.cmd.load(SeqCst), CMD_PAUSE);
        // 書き直しが終わったら、通常の手順(単独速度の測定)に進む
        sch.jobs[1].shared.refill_pending.store(false, SeqCst);
        sch.tick();
        assert!(matches!(sch.stage, Stage::Baseline { .. }));
        // 実行中に別のジョブが書き直し待ちになっても、先に1台ずつ処理する
        sch.jobs[2].shared.refill_pending.store(true, SeqCst);
        sch.tick();
        assert!(matches!(sch.stage, Stage::Refill));
        assert_eq!(sch.jobs[2].shared.cmd.load(SeqCst), CMD_RUN);
    }

    #[test]
    fn stop_request_is_not_overwritten_by_tick() {
        let mut sch = Scheduler::new(vec![fake_job(1), fake_job(2)], 0.7);
        sch.tick();
        sch.stop_job(0);
        for _ in 0..5 {
            sch.tick();
            assert_eq!(sch.jobs[0].shared.cmd.load(std::sync::atomic::Ordering::SeqCst), CMD_STOP);
        }
        // 他のジョブは引き続きスケジュールされる
        assert_ne!(sch.jobs[1].shared.cmd.load(std::sync::atomic::Ordering::SeqCst), CMD_STOP);
    }

    #[test]
    fn single_job_can_be_paused_and_resumed_by_user() {
        use std::sync::atomic::Ordering::SeqCst;
        let mut sch = Scheduler::new(vec![fake_job(1), fake_job(2)], 0.7);
        sch.tick();
        sch.set_job_paused(0, true);
        for _ in 0..5 {
            sch.tick();
            assert_eq!(sch.jobs[0].shared.cmd.load(SeqCst), CMD_PAUSE);
            assert_eq!(sch.jobs[0].shared.reason.load(SeqCst), REASON_USER);
        }
        // 残りのジョブは動き続ける
        assert_eq!(sch.jobs[1].shared.cmd.load(SeqCst), CMD_RUN);
        sch.set_job_paused(0, false);
        for _ in 0..5 {
            sch.tick();
        }
        assert!(!sch.is_job_paused(0));
        assert!(sch.jobs.iter().any(|j| j.shared.cmd.load(SeqCst) == CMD_RUN));
    }
}
