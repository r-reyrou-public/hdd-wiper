//! 完了時の結果報告ログ(人が読めるテキスト)。データの断片は含めない。

use crate::classify::class_names;
use crate::state::*;
use crate::util::{fmt_bytes, fmt_duration};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// 注目する連続範囲のしきい値(セクタ数)
pub const ATTENTION_SECTORS: u64 = 64;

pub fn kind_label(k: BadKind) -> &'static str {
    match k {
        BadKind::Unreadable => "書込み不可・読込み不可",
        BadKind::Residual => "書込み不可・読込み可(データ残存の可能性)",
        BadKind::VerifyMismatch => "検証で0以外を検出(再書込みでも修復不可)",
    }
}

pub fn build_report(st: &JobState) -> String {
    let id = &st.identity;
    let ss = id.sector_size as u64;
    let total_sectors = id.size / ss;
    let mut o = String::new();
    let bad_total = st.total_bad_sectors();
    let bad_bytes = bad_total * ss;

    let _ = writeln!(o, "==== ディスク消去 結果報告 ====");
    let _ = writeln!(o, "作成日時      : {}", now_str());
    let lens = st.slot_lens();
    let sample = st.mode.sample_verify();
    let verdict = if bad_total == 0 && !sample {
        "正常完了(全セクタを消去し、最終ゼロ書込みを全域で検証済み)"
    } else if bad_total == 0 {
        "正常完了(全セクタに最終ゼロ書込み済み。検証は抽出のため、全域の確認は行っていません)"
    } else {
        "完了(ただし未消去領域あり)"
    };
    let _ = writeln!(o, "総合結果      : {verdict}");
    let _ = writeln!(o);
    let _ = writeln!(o, "---- 対象ディスク ----");
    let _ = writeln!(o, "メーカー      : {}", id.vendor);
    let _ = writeln!(o, "モデル        : {}", id.model);
    let _ = writeln!(o, "シリアル      : {}", id.serial);
    let _ = writeln!(o, "接続          : {}", id.bus);
    let _ = writeln!(o, "容量          : {} ({} バイト)", fmt_bytes(id.size), id.size);
    let _ = writeln!(o, "セクタサイズ  : {} バイト / 総セクタ数 {}", ss, total_sectors);
    let _ = writeln!(o, "実行時ディスク番号: PhysicalDrive{}", st.last_disk_number);
    let _ = writeln!(o);

    let _ = writeln!(o, "---- 方式 ----");
    let _ = writeln!(o, "消去方式: {}", st.mode.short());
    if sample {
        let _ = writeln!(
            o,
            "検証: 先頭・末尾と乱数で選んだ区間のみを読んでゼロを確認(検証した容量 {} / ディスク全体の {:.2}%)",
            fmt_bytes(lens[3]),
            lens[3] as f64 * 100.0 / id.size as f64
        );
    } else {
        let _ = writeln!(o, "検証: 全域を読み込んでゼロを確認");
    }
    if let Some((b, d)) = st.tuned {
        let _ = writeln!(o, "転送設定(自動調整): ブロック {} MiB × 同時発行 {}", b >> 20, d);
    }
    let _ = writeln!(o, "不良セクタ: ブロック失敗後にセクタ単位へ切り分け、各セクタ最大3回再試行。");
    let _ = writeln!(o, "           書込み・読込みとも不能なセクタはスキップ。連続256セクタ失敗した領域では再試行を省略。");
    let _ = writeln!(o);

    let _ = writeln!(o, "---- 実行時間 ----");
    let _ = writeln!(o, "開始日時      : {}", st.started);
    let total_secs: f64 = st.phase_secs.iter().sum();
    let _ = writeln!(o, "実処理時間    : {} (一時停止中を除く)", fmt_duration(total_secs));
    let _ = writeln!(o);

    let _ = writeln!(o, "---- 工程別の集計 (単位: セクタ) ----");
    let _ = writeln!(o, "{:<22} {:>14} {:>12} {:>12} {:>12} {:>12}", "工程", "消し込み/確認済", "エラー", "スキップ", "所要時間", "平均速度");
    for p in 0..PHASE_COUNT {
        if !st.mode.slot_enabled(p as u8) {
            let _ = writeln!(o, "{:<22} 省略(方式による)", phase_label(p as u8));
            continue;
        }
        let secs = st.phase_secs[p];
        let speed = if secs > 0.5 { fmt_bytes(((lens[p] as f64) / secs) as u64) + "/s" } else { "--".into() };
        let _ = writeln!(
            o,
            "{:<22} {:>14} {:>12} {:>12} {:>12} {:>12}",
            phase_label(p as u8),
            st.phase_ok[p],
            st.phase_err[p],
            st.phase_skip[p],
            fmt_duration(secs),
            speed
        );
    }
    let _ = writeln!(o);
    let _ = writeln!(o, "書込み再試行回数      : {}", st.write_retries);
    let _ = writeln!(o, "読込み再試行回数      : {}", st.read_retries);
    let _ = writeln!(o, "検証後に再書込みで修復: {} セクタ", st.verify_fixed);
    let _ = writeln!(o);

    let _ = writeln!(o, "---- エラーセクタ(未消去)の概要 ----");
    let _ = writeln!(o, "未消去・要確認セクタ総数: {} セクタ ({})", bad_total, fmt_bytes(bad_bytes));
    for kind in [BadKind::Unreadable, BadKind::Residual, BadKind::VerifyMismatch] {
        let n: u64 = st.bad_runs.iter().filter(|r| r.kind == kind).map(|r| r.len).sum();
        let runs = st.bad_runs.iter().filter(|r| r.kind == kind).count();
        let _ = writeln!(o, "  {} : {} セクタ / {} 範囲", kind_label(kind), n, runs);
    }
    let _ = writeln!(o);

    if !st.write_errors.is_empty() {
        let _ = writeln!(o, "---- 書込みエラーの内訳(OSのエラー別) ----");
        for (label, n) in &st.write_errors {
            let _ = writeln!(o, "{n:>12} 回  {label}");
        }
        let _ = writeln!(o);
    }

    let attention: Vec<&BadRun> = st.bad_runs.iter().filter(|r| r.len >= ATTENTION_SECTORS).collect();
    let small: Vec<&BadRun> = st.bad_runs.iter().filter(|r| r.len < ATTENTION_SECTORS).collect();
    let _ = writeln!(o, "---- 注目範囲 (連続{}セクタ以上) ----", ATTENTION_SECTORS);
    if attention.is_empty() {
        let _ = writeln!(o, "なし");
    }
    for r in &attention {
        let _ = writeln!(
            o,
            "LBA {} - {} ({} セクタ, {}) : {}",
            r.start,
            r.end() - 1,
            r.len,
            fmt_bytes(r.len * ss),
            kind_label(r.kind)
        );
        if r.kind != BadKind::Unreadable {
            let names = class_names(r.classes);
            if !names.is_empty() {
                let _ = writeln!(o, "    内容の分類: {}", names.join(" / "));
            }
            if !r.sigs.is_empty() {
                let _ = writeln!(o, "    検出した署名: {}", r.sigs.join(", "));
            }
            if r.classes & CLASS_ENTROPY != 0 && r.len >= 2048 {
                let _ = writeln!(o, "    ※ 長く連続した高エントロピー領域です。動画・写真・圧縮/暗号化ファイルの一部である可能性があります。");
            }
        }
    }
    let _ = writeln!(o);
    let small_n: u64 = small.iter().map(|r| r.len).sum();
    let _ = writeln!(o, "---- 小さな断片 (連続{}セクタ未満) ----", ATTENTION_SECTORS);
    let _ = writeln!(o, "{} 範囲 / 合計 {} セクタ", small.len(), small_n);
    for r in small.iter().take(200) {
        let _ = writeln!(o, "LBA {}{} : {}", r.start, if r.len > 1 { format!(" - {}", r.end() - 1) } else { String::new() }, kind_label(r.kind));
    }
    if small.len() > 200 {
        let _ = writeln!(o, "... 他 {} 範囲(省略)", small.len() - 200);
    }
    let _ = writeln!(o);

    if bad_total > 0 {
        let _ = writeln!(o, "★ 警告 ★");
        let _ = writeln!(o, "上記のセクタは書き込めなかったため、元のデータが残っている可能性があります。");
        let _ = writeln!(o, "機密性が高いディスクの場合は、物理破壊などの追加対応を検討してください。");
        let _ = writeln!(o);
    }

    let _ = writeln!(o, "---- 履歴 ----");
    for e in &st.events {
        let _ = writeln!(o, "{}  {}", e.time, e.what);
    }
    o
}

pub fn write_report(st: &JobState, log_dir: &Path) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(log_dir)?;
    let stamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let name = format!("report_{}_{}.txt", stamp, st.identity.key());
    let path = log_dir.join(name);
    let mut data = vec![0xEF, 0xBB, 0xBF]; // UTF-8 BOM (メモ帳での文字化け対策)
    data.extend_from_slice(build_report(st).as_bytes());
    std::fs::write(&path, data)?;
    Ok(path)
}
