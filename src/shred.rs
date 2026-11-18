//! ファイル・フォルダの上書き消去と、空き容量の上書き消去。
//!
//! ディスク全体の消去(engine.rs)とは別の、ファイルシステム越しの消去。
//! 方式は EraseMode の書込み工程(0 → 乱数 → 0 など)に合わせる。

use crate::state::{now_str, EraseMode};
use crate::util::{fmt_bytes, fmt_duration};
use rand_chacha::ChaCha8Rng;
use rand_core::{Rng, SeedableRng};
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

const FILE_FLAG_WRITE_THROUGH: u32 = 0x8000_0000;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const ERROR_DISK_FULL: i32 = 112;
const ERROR_HANDLE_DISK_FULL: i32 = 39;
const CHUNK: usize = 1 << 20;
/// 空き容量の消去で作る1ファイルの最大サイズ
const FILL_FILE_MAX: u64 = 4 << 30;
/// 空き容量の消去で、最低限残す空き容量
pub const MIN_RESERVE: u64 = 256 << 20;
const MAX_ERRORS: usize = 300;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pat {
    Zero,
    Random,
}

/// 方式ごとの書込み工程
pub fn passes(mode: EraseMode) -> Vec<Pat> {
    match mode {
        EraseMode::Standard | EraseMode::FastVerify => vec![Pat::Zero, Pat::Random, Pat::Zero],
        EraseMode::TwoPass => vec![Pat::Random, Pat::Zero],
        EraseMode::OnePass => vec![Pat::Zero],
    }
}

fn pat_label(p: Pat) -> &'static str {
    match p {
        Pat::Zero => "ゼロ",
        Pat::Random => "乱数",
    }
}

#[derive(Clone, Debug)]
pub enum Task {
    /// ファイル・フォルダ(中身ごと)
    Targets(Vec<PathBuf>),
    /// 指定場所があるボリュームの空き容量。`reserve` バイトは空けておく
    FreeSpace { dir: PathBuf, reserve: u64 },
}

impl Task {
    pub fn title(&self) -> String {
        match self {
            Task::Targets(t) => format!("ファイル・フォルダの消去({}件指定)", t.len()),
            Task::FreeSpace { dir, .. } => format!("空き容量の消去({})", dir.display()),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ShStatus {
    Scanning,
    Running,
    Finished,
    Stopped,
    Failed(String),
}

#[derive(Clone, Debug)]
pub struct ShSnap {
    pub status: ShStatus,
    pub title: String,
    pub current: String,
    pub pass: usize,
    pub passes: usize,
    pub pass_label: &'static str,
    pub done: u64,
    pub total: u64,
    pub files_done: u64,
    pub files_total: u64,
    pub errors: Vec<String>,
    pub error_count: u64,
    pub report: Option<PathBuf>,
    pub started: Instant,
    pub finished: Option<Instant>,
}

pub struct ShShared {
    pub stop: AtomicBool,
    pub snap: Mutex<ShSnap>,
}

impl ShShared {
    fn new(title: String) -> Arc<Self> {
        Arc::new(ShShared {
            stop: AtomicBool::new(false),
            snap: Mutex::new(ShSnap {
                status: ShStatus::Scanning,
                title,
                current: String::new(),
                pass: 0,
                passes: 0,
                pass_label: "",
                done: 0,
                total: 0,
                files_done: 0,
                files_total: 0,
                errors: Vec::new(),
                error_count: 0,
                report: None,
                started: Instant::now(),
                finished: None,
            }),
        })
    }

    pub fn snapshot(&self) -> ShSnap {
        self.snap.lock().unwrap().clone()
    }

    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    fn add_err(&self, msg: String) {
        let mut s = self.snap.lock().unwrap();
        s.error_count += 1;
        if s.errors.len() < MAX_ERRORS {
            s.errors.push(msg);
        }
    }

    fn add_done(&self, n: u64) {
        self.snap.lock().unwrap().done += n;
    }
}

pub struct FileJob {
    pub shared: Arc<ShShared>,
    _thread: JoinHandle<()>,
}

impl FileJob {
    pub fn is_running(&self) -> bool {
        matches!(self.shared.snapshot().status, ShStatus::Scanning | ShStatus::Running)
    }
}

pub fn spawn(task: Task, mode: EraseMode, log_dir: PathBuf) -> FileJob {
    let shared = ShShared::new(task.title());
    let sh = shared.clone();
    let thread = std::thread::spawn(move || {
        let pats = passes(mode);
        let res = match &task {
            Task::Targets(t) => run_targets(t, &pats, &sh),
            Task::FreeSpace { dir, reserve } => wipe_free(dir, *reserve, &pats, &sh, &free_bytes),
        };
        let report = write_report(&task, mode, &sh, &res, &log_dir);
        let mut s = sh.snap.lock().unwrap();
        s.report = report.ok();
        s.finished = Some(Instant::now());
        s.status = match res {
            Ok(true) => ShStatus::Finished,
            Ok(false) => ShStatus::Stopped,
            Err(e) => ShStatus::Failed(e),
        };
    });
    FileJob { shared, _thread: thread }
}

// ---------------------------------------------------------------- 安全確認

fn norm(p: &Path) -> String {
    let s = p.to_string_lossy().to_string();
    let s = s.strip_prefix(r"\\?\UNC\").map(|r| format!(r"\\{r}")).unwrap_or_else(|| s.trim_start_matches(r"\\?\").to_string());
    s.trim_end_matches('\\').to_lowercase()
}

fn is_under(child: &str, parent: &str) -> bool {
    child == parent || child.starts_with(&format!("{parent}\\"))
}

/// 消去の対象にしてよいか確認する。問題なければ正規化したパスを返す
pub fn check_target(p: &Path, exe_dir: &Path) -> Result<PathBuf, String> {
    let meta = std::fs::symlink_metadata(p).map_err(|e| format!("{}: 見つかりません({e})", p.display()))?;
    // リンクは、リンク自体だけを消す(指す先は触らない)ので、実体の場所では判定しない
    let is_link = meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    let canon = if is_link {
        // 親フォルダは実体に解決し、名前部分はそのまま使う
        match (p.parent().and_then(|d| std::fs::canonicalize(d).ok()), p.file_name()) {
            (Some(d), Some(n)) => d.join(n),
            _ => p.to_path_buf(),
        }
    } else {
        std::fs::canonicalize(p).map_err(|e| format!("{}: パスを解決できません({e})", p.display()))?
    };
    let t = norm(&canon);
    // ドライブ直下・ルート
    let body = t.trim_start_matches(|c: char| c.is_ascii_alphabetic()).trim_start_matches(':').trim_matches('\\');
    if body.is_empty() || t.starts_with(r"\\") && t.trim_start_matches('\\').split('\\').count() <= 2 {
        return Err(format!("{}: ドライブ・共有全体は指定できません(空き容量の消去か、ディスク全体の消去を使ってください)", p.display()));
    }
    let mut protect: Vec<(String, &str)> = Vec::new();
    for (var, why) in [
        ("SystemRoot", "Windows本体"),
        ("ProgramFiles", "Program Files"),
        ("ProgramFiles(x86)", "Program Files (x86)"),
    ] {
        if let Ok(v) = std::env::var(var) {
            protect.push((norm(Path::new(&v)), why));
        }
    }
    protect.push((norm(exe_dir), "このツールの保存フォルダ(ログを含む)"));
    if let Ok(v) = std::env::var("USERPROFILE") {
        protect.push((norm(Path::new(&v)), "ユーザープロファイルのフォルダ"));
    }
    for (pr, why) in &protect {
        if is_under(&t, pr) && *why != "ユーザープロファイルのフォルダ" {
            return Err(format!("{}: {why}の中は消去できません", p.display()));
        }
        if is_under(pr, &t) {
            return Err(format!("{}: {why}を含むため消去できません", p.display()));
        }
    }
    // 表示・ログ用に、ドライブ文字のパスに付く \\?\ を外す(UNCは \\?\UNC\ のまま)
    let shown = canon.to_string_lossy().to_string();
    if let Some(rest) = shown.strip_prefix(r"\\?\") {
        if !rest.starts_with("UNC\\") {
            return Ok(PathBuf::from(rest));
        }
    }
    Ok(canon)
}

// ---------------------------------------------------------------- ファイル・フォルダ

struct Plan {
    files: Vec<(PathBuf, u64)>,
    /// シンボリックリンク・ジャンクション (パス, ディレクトリか)
    links: Vec<(PathBuf, bool)>,
    /// 親より後に消すため、親が先に入っている
    dirs: Vec<PathBuf>,
}

fn collect(path: &Path, plan: &mut Plan, sh: &ShShared) {
    if sh.stopped() {
        return;
    }
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => {
            sh.add_err(format!("{}: 調べられません({e})", path.display()));
            return;
        }
    };
    let attrs = meta.file_attributes();
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        plan.links.push((path.to_path_buf(), attrs & FILE_ATTRIBUTE_DIRECTORY != 0));
    } else if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
        plan.dirs.push(path.to_path_buf());
        match std::fs::read_dir(path) {
            Ok(rd) => {
                for e in rd.flatten() {
                    collect(&e.path(), plan, sh);
                }
            }
            Err(e) => sh.add_err(format!("{}: フォルダを読めません({e})", path.display())),
        }
    } else {
        plan.files.push((path.to_path_buf(), meta.len()));
    }
}

#[cfg(test)]
thread_local! {
    /// テスト用: 各工程の書込み・同期の直後に呼ばれ、ファイルの実際の内容を検査できる
    static AFTER_PASS: std::cell::RefCell<Option<Box<dyn FnMut(usize, &Path)>>> = std::cell::RefCell::new(None);
}

#[inline]
fn after_pass(_pass: usize, _path: &Path) {
    #[cfg(test)]
    AFTER_PASS.with(|h| {
        if let Some(f) = h.borrow_mut().as_mut() {
            f(_pass, _path);
        }
    });
}

fn new_rng() -> ChaCha8Rng {
    let mut seed = [0u8; 32];
    let _ = getrandom::fill(&mut seed);
    ChaCha8Rng::from_seed(seed)
}

fn random_name(rng: &mut ChaCha8Rng) -> String {
    format!("{:016x}", rng.next_u64())
}

fn fill_pat(buf: &mut [u8], p: Pat, rng: &mut ChaCha8Rng) {
    match p {
        Pat::Zero => buf.fill(0),
        Pat::Random => rng.fill_bytes(buf),
    }
}

/// 同じフォルダ内で無意味な名前に変えてから削除する(元の名前を残さない)。名前変更に失敗したら元の名前のまま削除
fn rename_and_remove(path: &Path, is_dir: bool, rng: &mut ChaCha8Rng) -> std::io::Result<()> {
    let target = match path.parent() {
        Some(d) => {
            let np = d.join(random_name(rng));
            if std::fs::rename(path, &np).is_ok() { np } else { path.to_path_buf() }
        }
        None => path.to_path_buf(),
    };
    if is_dir { std::fs::remove_dir(&target) } else { std::fs::remove_file(&target) }
}

/// 1ファイルを上書きして削除する。Ok(false) は中断(ファイルは残る)
fn shred_file(path: &Path, pats: &[Pat], rng: &mut ChaCha8Rng, buf: &mut [u8], sh: &ShShared) -> Result<bool, String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    let len = meta.len();
    let mut perm = meta.permissions();
    if perm.readonly() {
        perm.set_readonly(false);
        std::fs::set_permissions(path, perm).map_err(|e| format!("読み取り専用を解除できません({e})"))?;
    }
    if len > 0 {
        let mut f = OpenOptions::new()
            .write(true)
            .custom_flags(FILE_FLAG_WRITE_THROUGH)
            .open(path)
            .map_err(|e| format!("書込みで開けません({e})。他のアプリが使用中か、アクセス権がない可能性があります"))?;
        for (i, &p) in pats.iter().enumerate() {
            {
                let mut s = sh.snap.lock().unwrap();
                s.pass = i + 1;
                s.pass_label = pat_label(p);
            }
            f.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
            let mut left = len;
            while left > 0 {
                if sh.stopped() {
                    let _ = f.sync_all();
                    return Ok(false);
                }
                let n = left.min(buf.len() as u64) as usize;
                fill_pat(&mut buf[..n], p, rng);
                f.write_all(&buf[..n]).map_err(|e| format!("書込みに失敗({e})"))?;
                left -= n as u64;
                sh.add_done(n as u64);
            }
            f.sync_all().map_err(|e| format!("同期に失敗({e})"))?;
            after_pass(i, path);
        }
        // 長さを0にして、ファイルサイズの情報も残さない
        let _ = f.set_len(0);
        let _ = f.sync_all();
    }
    rename_and_remove(path, false, rng).map_err(|e| format!("削除できません({e})"))?;
    Ok(true)
}

fn run_targets(targets: &[PathBuf], pats: &[Pat], sh: &ShShared) -> Result<bool, String> {
    let mut plan = Plan { files: vec![], links: vec![], dirs: vec![] };
    for t in targets {
        collect(t, &mut plan, sh);
    }
    if sh.stopped() {
        return Ok(false);
    }
    // 親フォルダと中のファイルを両方指定された場合などの重複を除く
    plan.files.sort_by(|a, b| a.0.cmp(&b.0));
    plan.files.dedup_by(|a, b| a.0 == b.0);
    plan.dirs.sort();
    plan.dirs.dedup();
    plan.links.sort_by(|a, b| a.0.cmp(&b.0));
    plan.links.dedup_by(|a, b| a.0 == b.0);
    {
        let mut s = sh.snap.lock().unwrap();
        s.total = plan.files.iter().map(|f| f.1).sum::<u64>() * pats.len() as u64;
        s.files_total = plan.files.len() as u64;
        s.passes = pats.len();
        s.status = ShStatus::Running;
    }
    let mut rng = new_rng();
    let mut buf = vec![0u8; CHUNK];
    for (path, _) in &plan.files {
        if sh.stopped() {
            return Ok(false);
        }
        sh.snap.lock().unwrap().current = path.display().to_string();
        match shred_file(path, pats, &mut rng, &mut buf, sh) {
            Ok(true) => sh.snap.lock().unwrap().files_done += 1,
            Ok(false) => return Ok(false),
            Err(e) => sh.add_err(format!("{}: {e}", path.display())),
        }
    }
    for (path, is_dir) in &plan.links {
        let r = if *is_dir { std::fs::remove_dir(path) } else { std::fs::remove_file(path) };
        if let Err(e) = r {
            sh.add_err(format!("{}: リンクを削除できません({e})", path.display()));
        }
    }
    for d in plan.dirs.iter().rev() {
        sh.snap.lock().unwrap().current = d.display().to_string();
        if let Err(e) = rename_and_remove(d, true, &mut rng) {
            sh.add_err(format!("{}: フォルダを削除できません({e})", d.display()));
        }
    }
    sh.snap.lock().unwrap().current.clear();
    Ok(true)
}

// ---------------------------------------------------------------- 空き容量

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 指定場所があるボリュームの、このユーザーが使える空き容量(バイト)
pub fn free_bytes(dir: &Path) -> std::io::Result<u64> {
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let w = wide(&dir.to_string_lossy());
    let (mut avail, mut total, mut free) = (0u64, 0u64, 0u64);
    let ok = unsafe { GetDiskFreeSpaceExW(w.as_ptr(), &mut avail, &mut total, &mut free) };
    if ok == 0 { Err(std::io::Error::last_os_error()) } else { Ok(avail) }
}

fn is_disk_full(e: &std::io::Error) -> bool {
    matches!(e.raw_os_error(), Some(ERROR_DISK_FULL) | Some(ERROR_HANDLE_DISK_FULL))
}

/// 空き容量を、一時ファイルで埋めて上書きする。最後に一時ファイルは削除する。
/// `free` は空き容量を返す関数(テストで差し替える)。
fn wipe_free(
    dir: &Path,
    reserve: u64,
    pats: &[Pat],
    sh: &ShShared,
    free: &dyn Fn(&Path) -> std::io::Result<u64>,
) -> Result<bool, String> {
    if !dir.is_dir() {
        return Err(format!("{} はフォルダ(またはドライブ)ではありません", dir.display()));
    }
    let reserve = reserve.max(MIN_RESERVE);
    let free0 = free(dir).map_err(|e| format!("空き容量を取得できません({e})"))?;
    if free0 <= reserve + CHUNK as u64 {
        return Err(format!("空き容量({})が、残す容量({})以下です", fmt_bytes(free0), fmt_bytes(reserve)));
    }
    let target = free0 - reserve;
    {
        let mut s = sh.snap.lock().unwrap();
        s.total = target * pats.len() as u64;
        s.passes = pats.len();
        s.files_total = 0;
        s.status = ShStatus::Running;
    }
    let mut rng = new_rng();
    let tmp = dir.join(format!(".hddwiper_free_{}", random_name(&mut rng)));
    std::fs::create_dir(&tmp).map_err(|e| format!("作業フォルダを作れません({e})"))?;
    let result = fill_and_overwrite(&tmp, dir, reserve, pats, sh, free, &mut rng);
    // 成否にかかわらず、作った一時ファイルは必ず片付ける
    sh.snap.lock().unwrap().current = "一時ファイルを削除中…".into();
    if let Ok(rd) = std::fs::read_dir(&tmp) {
        for e in rd.flatten() {
            if let Err(err) = std::fs::remove_file(e.path()) {
                sh.add_err(format!("{}: 一時ファイルを削除できません({err})", e.path().display()));
            }
        }
    }
    if let Err(e) = std::fs::remove_dir(&tmp) {
        sh.add_err(format!("{}: 作業フォルダを削除できません({e})。手動で削除してください", tmp.display()));
    }
    sh.snap.lock().unwrap().current.clear();
    result
}

fn fill_and_overwrite(
    tmp: &Path,
    dir: &Path,
    reserve: u64,
    pats: &[Pat],
    sh: &ShShared,
    free: &dyn Fn(&Path) -> std::io::Result<u64>,
    rng: &mut ChaCha8Rng,
) -> Result<bool, String> {
    let mut buf = vec![0u8; CHUNK];
    let mut files: Vec<(PathBuf, u64)> = Vec::new();
    // 工程1: 空き容量を埋める(新しいクラスタに書く)
    {
        let mut s = sh.snap.lock().unwrap();
        s.pass = 1;
        s.pass_label = pat_label(pats[0]);
    }
    let mut n = 0u32;
    'outer: loop {
        let avail = free(dir).unwrap_or(0);
        if avail <= reserve + CHUNK as u64 {
            break;
        }
        let path = tmp.join(format!("fill_{n:05}.tmp"));
        n += 1;
        sh.snap.lock().unwrap().current = path.display().to_string();
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_WRITE_THROUGH)
            .open(&path)
            .map_err(|e| format!("一時ファイルを作れません({e})"))?;
        let cap = (avail - reserve).min(FILL_FILE_MAX);
        let mut written = 0u64;
        let mut full = false;
        while written < cap {
            if sh.stopped() {
                let _ = f.sync_all();
                files.push((path, written));
                return Ok(false);
            }
            let k = (cap - written).min(CHUNK as u64) as usize;
            fill_pat(&mut buf[..k], pats[0], rng);
            match f.write_all(&buf[..k]) {
                Ok(()) => {
                    written += k as u64;
                    sh.add_done(k as u64);
                }
                Err(e) if is_disk_full(&e) => {
                    full = true;
                    break;
                }
                Err(e) => {
                    files.push((path, written));
                    return Err(format!("書込みに失敗({e})"));
                }
            }
            // 残す容量を割り込まないよう、数MBごとに空き容量を確認する
            if (written / CHUNK as u64) % 8 == 0 && free(dir).map(|a| a <= reserve).unwrap_or(false) {
                break;
            }
        }
        f.sync_all().map_err(|e| format!("同期に失敗({e})"))?;
        after_pass(0, &path);
        files.push((path, written));
        if full {
            break 'outer;
        }
    }
    // 工程2以降: 同じファイルを書き直す(新しい領域は使わない)
    for (i, &p) in pats.iter().enumerate().skip(1) {
        {
            let mut s = sh.snap.lock().unwrap();
            s.pass = i + 1;
            s.pass_label = pat_label(p);
        }
        for (path, len) in &files {
            sh.snap.lock().unwrap().current = path.display().to_string();
            let mut f = OpenOptions::new()
                .write(true)
                .custom_flags(FILE_FLAG_WRITE_THROUGH)
                .open(path)
                .map_err(|e| format!("一時ファイルを開けません({e})"))?;
            let mut left = *len;
            while left > 0 {
                if sh.stopped() {
                    let _ = f.sync_all();
                    return Ok(false);
                }
                let k = left.min(CHUNK as u64) as usize;
                fill_pat(&mut buf[..k], p, rng);
                f.write_all(&buf[..k]).map_err(|e| format!("書込みに失敗({e})"))?;
                left -= k as u64;
                sh.add_done(k as u64);
            }
            f.sync_all().map_err(|e| format!("同期に失敗({e})"))?;
            after_pass(i, path);
        }
    }
    Ok(true)
}

// ---------------------------------------------------------------- 結果ログ

fn write_report(
    task: &Task,
    mode: EraseMode,
    sh: &ShShared,
    res: &Result<bool, String>,
    log_dir: &Path,
) -> std::io::Result<PathBuf> {
    use std::fmt::Write as _;
    let s = sh.snapshot();
    let mut o = String::from("\u{feff}");
    let _ = writeln!(o, "===== {} =====", s.title);
    let _ = writeln!(o, "実行日時: {}", now_str());
    let _ = writeln!(o, "消去方式: {}", mode.short().split('(').next().unwrap_or(""));
    let _ = writeln!(
        o,
        "書込み工程: {}",
        passes(mode).iter().map(|p| pat_label(*p)).collect::<Vec<_>>().join(" → ")
    );
    let _ = writeln!(
        o,
        "結果: {}",
        match res {
            Ok(true) if s.error_count == 0 => "完了".to_string(),
            Ok(true) => "完了(一部エラーあり)".to_string(),
            Ok(false) => "中断".to_string(),
            Err(e) => format!("失敗: {e}"),
        }
    );
    let secs = s.started.elapsed().as_secs_f64();
    let _ = writeln!(o, "処理時間: {}", fmt_duration(secs));
    let _ = writeln!(o, "書込み量: {} / 予定 {}", fmt_bytes(s.done), fmt_bytes(s.total));
    match task {
        Task::Targets(t) => {
            let _ = writeln!(o, "消去したファイル数: {} / {}", s.files_done, s.files_total);
            let _ = writeln!(o, "指定した対象:");
            for p in t {
                let _ = writeln!(o, "  {}", p.display());
            }
        }
        Task::FreeSpace { dir, reserve } => {
            let _ = writeln!(o, "対象の場所: {}", dir.display());
            let _ = writeln!(o, "残した空き容量: {}", fmt_bytes((*reserve).max(MIN_RESERVE)));
        }
    }
    let _ = writeln!(o, "エラー: {} 件", s.error_count);
    for e in &s.errors {
        let _ = writeln!(o, "  ★ {e}");
    }
    let _ = writeln!(o, "\n【注意】");
    let _ = writeln!(o, "- SSD・USBメモリ・クラウド同期フォルダ・ボリュームシャドウコピーや復元ポイントに残るデータ、");
    let _ = writeln!(o, "  圧縮・暗号化(EFS)・スパースファイルの一部、代替データストリームは、この方法では消去を保証できません。");
    let _ = writeln!(o, "- ファイル名や属性の一部は、NTFSのログ(ジャーナル)に残ることがあります。");
    let _ = std::fs::create_dir_all(log_dir);
    let name = format!(
        "{}_{}.txt",
        match task {
            Task::Targets(_) => "file_wipe",
            Task::FreeSpace { .. } => "freespace_wipe",
        },
        chrono::Local::now().format("%Y%m%d_%H%M%S")
    );
    let p = log_dir.join(name);
    std::fs::write(&p, o)?;
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("hddwiper_shred_{}_{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn folder_and_file_are_removed() {
        let d = tmp("tree");
        let sub = d.join("a").join("b");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(d.join("one.txt"), vec![7u8; 3_000_000]).unwrap();
        std::fs::write(sub.join("two.bin"), b"hello").unwrap();
        std::fs::write(sub.join("empty"), b"").unwrap();
        let ro = sub.join("ro.txt");
        std::fs::write(&ro, b"readonly").unwrap();
        let mut p = std::fs::metadata(&ro).unwrap().permissions();
        p.set_readonly(true);
        std::fs::set_permissions(&ro, p).unwrap();
        let single = tmp("single").join("x.dat");
        std::fs::write(&single, vec![1u8; 100_000]).unwrap();

        let sh = ShShared::new("t".into());
        let r = run_targets(&[d.clone(), single.clone()], &passes(EraseMode::Standard), &sh);
        assert_eq!(r, Ok(true));
        assert!(!d.exists(), "フォルダごと消える");
        assert!(!single.exists());
        let s = sh.snapshot();
        assert_eq!(s.error_count, 0, "{:?}", s.errors);
        assert_eq!(s.files_done, 5);
        assert_eq!(s.done, s.total, "全工程分を書き込む");
        let _ = std::fs::remove_dir_all(single.parent().unwrap());
    }

    #[test]
    fn overwrite_patterns_reach_the_file() {
        // 消去前の内容が残っていないこと: 削除の直前にゼロで終わる(最終工程がゼロ)
        let d = tmp("pat");
        let f = d.join("secret.txt");
        std::fs::write(&f, vec![0xABu8; 2_500_000]).unwrap();
        let sh = ShShared::new("t".into());
        let mut rng = new_rng();
        let mut buf = vec![0u8; CHUNK];
        // 中断させて、途中のファイル内容を確認する(1工程目のゼロ書込みの最中に止める)
        sh.request_stop();
        assert_eq!(shred_file(&f, &[Pat::Zero], &mut rng, &mut buf, &sh), Ok(false));
        assert!(f.exists(), "中断したファイルは残る");
        sh.stop.store(false, Ordering::SeqCst);
        assert_eq!(shred_file(&f, &[Pat::Zero, Pat::Random, Pat::Zero], &mut rng, &mut buf, &sh), Ok(true));
        assert!(!f.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    fn install_hook(f: impl FnMut(usize, &Path) + 'static) {
        AFTER_PASS.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }

    fn clear_hook() {
        AFTER_PASS.with(|h| *h.borrow_mut() = None);
    }

    fn entropy_ok(b: &[u8]) -> bool {
        // 乱数なら、256種類のバイト値がほぼ満遍なく出る
        let mut seen = [false; 256];
        b.iter().for_each(|&x| seen[x as usize] = true);
        seen.iter().filter(|&&s| s).count() >= 250
    }

    /// 各工程の直後にファイルを読み戻して、実際にゼロ→乱数→ゼロが書かれていることを確かめる
    #[test]
    fn file_content_really_goes_zero_random_zero() {
        let d = tmp("content");
        let f = d.join("secret.bin");
        let original: Vec<u8> = (0..3_500_000u32).map(|i| (i % 251) as u8 | 0x80).collect();
        std::fs::write(&f, &original).unwrap();
        let log = std::rc::Rc::new(std::cell::RefCell::new(Vec::<String>::new()));
        let l2 = log.clone();
        let orig2 = original.clone();
        install_hook(move |pass, path| {
            let data = std::fs::read(path).unwrap();
            let verdict = match pass {
                0 | 2 => {
                    if data.len() == orig2.len() && data.iter().all(|&b| b == 0) { "zero-ok" } else { "ZERO-NG" }
                }
                1 => {
                    let same = data.iter().zip(orig2.iter()).filter(|(a, b)| a == b).count();
                    // 乱数: 長さが同じで、元の内容とほぼ一致せず(偶然一致は約1/256)、バイト値が偏らない
                    if data.len() == orig2.len() && same < data.len() / 100 && entropy_ok(&data) { "random-ok" } else { "RANDOM-NG" }
                }
                _ => "unexpected-pass",
            };
            l2.borrow_mut().push(format!("pass{pass}:{verdict}"));
        });
        let sh = ShShared::new("t".into());
        let mut rng = new_rng();
        let mut buf = vec![0u8; CHUNK];
        let r = shred_file(&f, &passes(EraseMode::Standard), &mut rng, &mut buf, &sh);
        clear_hook();
        assert_eq!(r, Ok(true));
        assert_eq!(*log.borrow(), vec!["pass0:zero-ok", "pass1:random-ok", "pass2:zero-ok"]);
        assert!(!f.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// 空き容量の消去でも、一時ファイルの実際の内容が工程ごとにゼロ→乱数→ゼロになっている
    #[test]
    fn free_space_content_really_goes_zero_random_zero() {
        let d = tmp("freecontent");
        let log = std::rc::Rc::new(std::cell::RefCell::new(Vec::<String>::new()));
        let l2 = log.clone();
        install_hook(move |pass, path| {
            let data = std::fs::read(path).unwrap();
            let v = match pass {
                0 | 2 => if data.iter().all(|&b| b == 0) { "zero-ok" } else { "ZERO-NG" },
                1 => if entropy_ok(&data[..data.len().min(1 << 20)]) { "random-ok" } else { "RANDOM-NG" },
                _ => "unexpected",
            };
            l2.borrow_mut().push(format!("pass{pass}:{v}:{}B", data.len()));
        });
        let total: u64 = 300 << 20;
        let free = move |p: &Path| -> std::io::Result<u64> { Ok(total.saturating_sub(dir_size(p))) };
        let sh = ShShared::new("t".into());
        let r = wipe_free(&d, 0, &passes(EraseMode::Standard), &sh, &free);
        clear_hook();
        assert_eq!(r, Ok(true));
        let l = log.borrow();
        assert_eq!(l.len(), 3, "{l:?}");
        assert!(l[0].starts_with("pass0:zero-ok") && l[1].starts_with("pass1:random-ok") && l[2].starts_with("pass2:zero-ok"), "{l:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn protected_paths_are_refused() {
        let exe_dir = std::env::current_exe().unwrap().parent().unwrap().to_path_buf();
        assert!(check_target(Path::new(r"C:\"), &exe_dir).is_err(), "ドライブ全体");
        let win = std::env::var("SystemRoot").unwrap_or(r"C:\Windows".into());
        assert!(check_target(Path::new(&win), &exe_dir).is_err());
        assert!(check_target(&Path::new(&win).join("System32"), &exe_dir).is_err());
        assert!(check_target(&exe_dir, &exe_dir).is_err(), "ツール自身のフォルダ");
        assert!(check_target(exe_dir.parent().unwrap(), &exe_dir).is_err(), "ツールを含む親フォルダ");
        let ok = tmp("okdir");
        let shown = check_target(&ok, &exe_dir).unwrap();
        assert!(!shown.to_string_lossy().starts_with(r"\\?\"), "表示用に \\\\?\\ を外す: {}", shown.display());
        assert!(check_target(&ok.join("nothing"), &exe_dir).is_err(), "存在しない");
        let _ = std::fs::remove_dir_all(&ok);
    }

    fn dir_size(d: &Path) -> u64 {
        let mut n = 0;
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                match e.metadata() {
                    Ok(m) if m.is_dir() => n += dir_size(&e.path()),
                    Ok(m) => n += m.len(),
                    _ => {}
                }
            }
        }
        n
    }

    #[test]
    fn free_space_fill_overwrites_and_cleans_up() {
        let d = tmp("free");
        // 模擬ボリューム: 全体 300MiB。実際には d の中のファイルの合計を引く
        let total: u64 = 300 << 20;
        let free = move |p: &Path| -> std::io::Result<u64> { Ok(total.saturating_sub(dir_size(p))) };
        let sh = ShShared::new("t".into());
        let r = wipe_free(&d, 0, &passes(EraseMode::Standard), &sh, &free);
        assert_eq!(r, Ok(true));
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 0, "一時ファイル・作業フォルダは残らない");
        let s = sh.snapshot();
        assert_eq!(s.error_count, 0, "{:?}", s.errors);
        // 最低限残す容量(256MiB)を守る: 埋めるのは約44MiB
        let filled = s.done / 3;
        assert!(filled <= (total - MIN_RESERVE) + (16 << 20), "残す容量を割り込まない: {filled}");
        assert!(filled >= (total - MIN_RESERVE) - (16 << 20), "ほぼ全て埋める: {filled}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn real_free_bytes_api_works() {
        let d = tmp("api");
        let f = free_bytes(&d).expect("空き容量を取得できる");
        assert!(f > 0);
        assert!(free_bytes(&d.join("no_such_dir")).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn free_space_refuses_when_no_room() {
        let d = tmp("free2");
        let free = |_: &Path| -> std::io::Result<u64> { Ok(100 << 20) };
        let sh = ShShared::new("t".into());
        assert!(wipe_free(&d, 0, &[Pat::Zero], &sh, &free).is_err());
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&d);
    }
}
