use std::io::Write;
use std::path::Path;

/// ファイルをゼロで上書きして同期した後、名前を変えて削除する(ベストエフォート)
pub fn secure_erase_file(path: &Path) {
    let Ok(meta) = std::fs::metadata(path) else { return };
    let len = meta.len();
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
        let zeros = vec![0u8; 64 * 1024];
        let mut left = len;
        while left > 0 {
            let n = left.min(zeros.len() as u64) as usize;
            if f.write_all(&zeros[..n]).is_err() {
                break;
            }
            left -= n as u64;
        }
        let _ = f.sync_all();
    }
    let renamed = path.with_file_name("erased.tmp");
    let target = if std::fs::rename(path, &renamed).is_ok() { renamed } else { path.to_path_buf() };
    let _ = std::fs::remove_file(target);
}

pub fn fmt_bytes(b: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1000.0 && i < U.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    if i == 0 { format!("{b} B") } else { format!("{v:.2} {}", U[i]) }
}

pub fn fmt_duration(secs: f64) -> String {
    if !secs.is_finite() || secs < 0.0 {
        return "--".into();
    }
    let s = secs as u64;
    let (d, h, m, sec) = (s / 86400, (s % 86400) / 3600, (s % 3600) / 60, s % 60);
    if d > 0 {
        format!("{d}日{h}時間{m:02}分")
    } else if h > 0 {
        format!("{h}時間{m:02}分{sec:02}秒")
    } else {
        format!("{m}分{sec:02}秒")
    }
}
