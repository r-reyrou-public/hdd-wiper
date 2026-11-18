//! 診断モード: `hdd-wiper.exe --diag <ディスク番号>`
//! 書込みに失敗する原因を調べるため、読込み→同じ内容の書き戻しを、サイズや場所を変えて試し、
//! OSのエラーコードを diag_<番号>.txt に書き出す。データの内容は変えない(ただし準備として
//! ボリュームのロック・マウント解除と、パーティション情報の削除を行う)。

use crate::dev::{AlignedBuf, BlockDev};
use crate::disk::{self, WinDisk};
use crate::engine::os_label;
use std::fmt::Write;

fn tests(dev: &mut WinDisk, label: &str, o: &mut String) {
    let ss = dev.sector_size() as usize;
    let size = dev.total_bytes();
    let _ = writeln!(o, "\n== {label} ==");
    let mut buf = AlignedBuf::new(4 << 20);
    let mid = (size / 2) / (4 << 20) * (4 << 20);
    let last = (size - (4 << 20)) / ss as u64 * ss as u64;
    let cases: Vec<(u64, usize)> = vec![
        (0, ss),
        (0, 4096),
        (0, 1 << 20),
        (0, 4 << 20),
        (mid, ss),
        (mid, 4 << 20),
        (last, 4 << 20),
    ];
    for (off, len) in cases {
        let r = dev.read_at(off, &mut buf.as_mut_slice()[..len]);
        let rs = match &r {
            Ok(()) => "成功".to_string(),
            Err(e) => format!("失敗 {}", os_label(e)),
        };
        let ws = if r.is_ok() {
            match dev.write_at(off, &buf.as_slice()[..len]) {
                Ok(()) => "成功".to_string(),
                Err(e) => format!("失敗 {}", os_label(&e)),
            }
        } else {
            "(読込み失敗のため未実施)".to_string()
        };
        let _ = writeln!(o, "offset={off:>14} len={len:>8}  読込み: {rs}  /  同内容の書き戻し: {ws}");
    }
    let _ = writeln!(o, "{}", dev.attributes_text());
}

/// 切り分けモード: `hdd-wiper.exe --probe <ディスク番号> [開始位置(バイト)] [--write]`
/// 指定位置の前後256MiBと、比較用の1TB付近を、1本ずつ(同時発行なし)読み、
/// `--write` 付きなら同じ範囲に0を書いて、1回ごとの所要時間を diag_probe_<番号>.txt に追記する。
/// 書き込みは消去対象のディスクの中身を0にするだけだが、消去前のデータが必要なら使わないこと。
pub fn probe(number: u32, start: Option<u64>, write: bool, sustain: Option<u64>) {
    use std::io::Write as _;
    use std::time::Instant;
    let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|p| p.to_path_buf())).unwrap_or_default();
    let path = exe_dir.join(format!("diag_probe_{number}.txt"));
    let mut f = std::fs::File::create(&path).ok();
    let mut out = move |s: String| {
        if let Some(f) = f.as_mut() {
            let _ = writeln!(f, "{s}");
            let _ = f.flush();
        }
    };
    let (n, st, wr) = (number, start, write);
    // ディスクが応答しなくなっても終われるよう、作業は別スレッドで行い、一定時間でプロセスごと終える
    let worker = std::thread::spawn(move || {
        let disks = disk::enumerate_disks(&[], true);
        let Some(d) = disks.iter().find(|d| d.number == n) else {
            out("そのディスクが見つかりません".into());
            return;
        };
        out(format!("切り分け PhysicalDrive{n} 管理者権限={} 書込み={}", disk::is_admin(), wr));
        out(format!("{:?}", d.identity));
        let mut dev = match WinDisk::open_with(n, d.identity.sector_size, d.identity.size, false, 0) {
            Ok(v) => v,
            Err(e) => {
                out(format!("ディスクを開けません: {}", os_label(&e)));
                return;
            }
        };
        out(format!("ロック・マウント解除: {:?}", dev.locked));
        let size = dev.total_bytes();
        let mib = 1u64 << 20;
        let center = st.unwrap_or(6_372_494_147_584).min(size.saturating_sub(mib)) / mib * mib;
        let regions = [("対象位置", center), ("比較: 1TB付近", (1u64 << 40).min(size / 2) / mib * mib)];
        let mut buf = AlignedBuf::new(16 << 20);
        for (name, c) in regions {
            let from = c.saturating_sub(128 * mib);
            let to = (c + 128 * mib).min(size);
            for (op, is_write) in [("読込み", false), ("書込み", true)] {
                if is_write && !wr {
                    continue;
                }
                for bs in [mib, 16 * mib] {
                    out(format!("\n== {name} {op} {} MiB単位 / {}〜{} ==", bs / mib, from, to));
                    let (mut off, mut cnt, mut errs, mut slow, mut max_ms, mut total_ms) = (from, 0u64, 0u64, 0u64, 0u128, 0u128);
                    let t0 = Instant::now();
                    while off + bs <= to {
                        let t = Instant::now();
                        let r = if is_write {
                            dev.write_at(off, &buf.as_slice()[..bs as usize])
                        } else {
                            dev.read_at(off, &mut buf.as_mut_slice()[..bs as usize])
                        };
                        let ms = t.elapsed().as_millis();
                        cnt += 1;
                        total_ms += ms;
                        max_ms = max_ms.max(ms);
                        if let Err(e) = &r {
                            errs += 1;
                            out(format!("offset={off} {ms}ms エラー {}", os_label(e)));
                        } else if ms >= 500 {
                            slow += 1;
                            out(format!("offset={off} {ms}ms (遅い)"));
                        }
                        off += bs;
                    }
                    if is_write {
                        let t = Instant::now();
                        let fr = dev.flush();
                        out(format!("flush {}ms {}", t.elapsed().as_millis(), if fr.is_ok() { "成功".into() } else { format!("失敗 {}", os_label(&fr.unwrap_err())) }));
                    }
                    let secs = t0.elapsed().as_secs_f64().max(0.001);
                    out(format!(
                        "回数={cnt} エラー={errs} 500ms以上={slow} 最大={max_ms}ms 平均={}ms 速度={:.1} MB/s",
                        if cnt > 0 { total_ms / cnt as u128 } else { 0 },
                        (cnt * bs) as f64 / secs / 1e6
                    ));
                }
            }
        }
        // 持続書込み: 他のディスクと同時に実行して、同時書込み時に止まるかを調べる(--secs N)
        if let (Some(secs), true) = (sustain, wr) {
            out(format!("\n== 持続書込み {secs}秒 16 MiB単位 / {}〜 ==", center));
            let t0 = Instant::now();
            let (mut off, mut cnt, mut slow, mut max_ms) = (center, 0u64, 0u64, 0u128);
            let mut last_report = Instant::now();
            let mut consec_err = 0u32;
            while t0.elapsed().as_secs() < secs && off + 16 * mib <= size {
                let t = Instant::now();
                let r = dev.write_at(off, &buf.as_slice()[..(16 * mib) as usize]);
                let ms = t.elapsed().as_millis();
                cnt += 1;
                max_ms = max_ms.max(ms);
                if r.is_ok() {
                    consec_err = 0;
                }
                if let Err(e) = &r {
                    out(format!("offset={off} {ms}ms エラー {}", os_label(e)));
                    consec_err += 1;
                    if consec_err >= 3 {
                        out(format!("{}秒後 連続してエラーになったため中止します(ディスクが切断された可能性)", t0.elapsed().as_secs()));
                        break;
                    }
                } else if ms >= 1000 {
                    consec_err = 0;
                    slow += 1;
                    out(format!("{}秒後 offset={off} {ms}ms (遅い)", t0.elapsed().as_secs()));
                }
                off += 16 * mib;
                if last_report.elapsed().as_secs() >= 30 {
                    last_report = Instant::now();
                    let t = Instant::now();
                    let fr = dev.flush();
                    out(format!(
                        "{}秒後 {}回 {:.1} MB/s 最大={}ms flush {}ms {}",
                        t0.elapsed().as_secs(),
                        cnt,
                        (cnt * 16 * mib) as f64 / t0.elapsed().as_secs_f64().max(0.001) / 1e6,
                        max_ms,
                        t.elapsed().as_millis(),
                        if fr.is_ok() { "成功" } else { "失敗" }
                    ));
                }
            }
            out(format!("持続書込み 終了: {cnt}回 1秒以上={slow} 最大={max_ms}ms"));
        }
        out("\n完了".into());
    });
    // 全体で30分たっても終わらなければ、応答停止とみなして終了する
    for _ in 0..1800 {
        if worker.is_finished() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(&path) {
        let _ = writeln!(f, "\n30分たっても終わりませんでした。ディスクが応答していないとみられます");
    }
}

pub fn run(number: u32) {
    let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|p| p.to_path_buf())).unwrap_or_default();
    let mut o = String::new();
    let _ = writeln!(o, "診断 PhysicalDrive{number}  管理者権限={}", disk::is_admin());
    let disks = disk::enumerate_disks(&[], true);
    let Some(d) = disks.iter().find(|d| d.number == number) else {
        let _ = writeln!(o, "そのディスクが見つかりません");
        let _ = std::fs::write(exe_dir.join(format!("diag_{number}.txt")), o);
        return;
    };
    let _ = writeln!(o, "{:?}", d.identity);
    let _ = writeln!(o, "判定: {:?}", d.class);
    match WinDisk::open_with(number, d.identity.sector_size, d.identity.size, false, 0) {
        Err(e) => {
            let _ = writeln!(o, "ディスクを開けません: {}", os_label(&e));
        }
        Ok(mut dev) => {
            let _ = writeln!(o, "ロック・マウント解除したボリューム: {:?}", dev.locked);
            tests(&mut dev, "パーティション情報を削除する前", &mut o);
            let _ = writeln!(o, "\n{}", dev.delete_layout());
            tests(&mut dev, "パーティション情報を削除した後", &mut o);
            let _ = writeln!(o, "\n属性の解除を試行: {}", dev.try_enable_write());
            tests(&mut dev, "属性の解除を試行した後", &mut o);
        }
    }
    let _ = std::fs::write(exe_dir.join(format!("diag_{number}.txt")), o);
}
