#![windows_subsystem = "windows"]

mod app;
mod classify;
mod dev;
mod diag;
mod disk;
mod engine;
mod manager;
mod report;
mod shred;
mod state;
mod util;

/// デバッグ用: `--list` でディスク一覧を exe の隣の disks.txt に書き出す
fn list_disks() {
    use std::fmt::Write;
    let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|p| p.to_path_buf())).unwrap_or_default();
    let log_dir = exe_dir.join("logs");
    let allow_virtual = std::env::var("HDDWIPER_ALLOW_VIRTUAL").map(|v| v == "1").unwrap_or(false);
    let mut o = format!("admin={}
", disk::is_admin());
    for d in disk::enumerate_disks(&[log_dir.as_path(), exe_dir.as_path()], allow_virtual) {
        let _ = writeln!(o, "{:?}", d);
    }
    let _ = writeln!(o, "
全ボリューム:");
    for v in disk::volume_overview() {
        let _ = writeln!(o, "{v}");
    }
    let _ = std::fs::write(exe_dir.join("disks.txt"), o);
}

fn main() -> eframe::Result {
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--diag") {
        if let Some(n) = args.get(i + 1).and_then(|n| n.parse::<u32>().ok()) {
            diag::run(n);
        }
        return Ok(());
    }
    if let Some(i) = args.iter().position(|a| a == "--probe") {
        if let Some(n) = args.get(i + 1).and_then(|n| n.parse::<u32>().ok()) {
            let start = args.get(i + 2).and_then(|s| s.parse::<u64>().ok());
            let sustain = args.iter().position(|a| a == "--secs").and_then(|j| args.get(j + 1)).and_then(|s| s.parse::<u64>().ok());
            diag::probe(n, start, args.iter().any(|a| a == "--write"), sustain);
        }
        // 応答しないI/Oが残っていても終われるよう、プロセスごと終える
        unsafe {
            windows_sys::Win32::System::Threading::TerminateProcess(windows_sys::Win32::System::Threading::GetCurrentProcess(), 0);
        }
        return Ok(());
    }
    if std::env::args().any(|a| a == "--list") {
        list_disks();
        return Ok(());
    }
    let icon = eframe::egui::IconData { rgba: include_bytes!("../assets/icon_128.rgba").to_vec(), width: 128, height: 128 };
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_icon(icon)
            .with_inner_size([1100.0, 720.0])
            .with_min_inner_size([800.0, 500.0]),
        ..Default::default()
    };
    let r = eframe::run_native(
        "HDD完全消去ツール",
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    );
    // 画面を閉じたら、残ったスレッドやハンドルを待たずにプロセスを終える
    unsafe {
        windows_sys::Win32::System::Threading::TerminateProcess(windows_sys::Win32::System::Threading::GetCurrentProcess(), if r.is_ok() { 0 } else { 1 });
    }
    r
}
