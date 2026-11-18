//! egui による GUI。

use crate::disk::{self, DiskClass, DiskInfo};
use crate::engine::*;
use crate::manager::*;
use crate::shred::{self, FileJob, ShStatus, Task};
use crate::state::*;
use crate::util::{fmt_bytes, fmt_duration, secure_erase_file};
use eframe::egui::{self, Color32, RichText};
use std::collections::BTreeSet;
use std::os::windows::fs::MetadataExt;
use std::path::PathBuf;
use std::time::Duration;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, TerminateProcess};
use windows_sys::Win32::System::Power::{ES_CONTINUOUS, ES_SYSTEM_REQUIRED, SetThreadExecutionState};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Disk,
    Files,
    Free,
}

/// ファイル・フォルダ/空き容量の消去の最終確認
struct FConfirm {
    task: Task,
    lines: Vec<String>,
    warns: Vec<String>,
    input: String,
}

const BROWSE_LIMIT: usize = 5000;

struct BrowseEntry {
    path: PathBuf,
    name: String,
    is_dir: bool,
    link: bool,
    size: u64,
}

/// アプリ内の「ファイルとフォルダを選択」画面(ファイルとフォルダを混ぜて複数選択できる)
struct Browser {
    /// None のときはドライブ一覧
    dir: Option<PathBuf>,
    entries: Vec<BrowseEntry>,
    truncated: bool,
    selected: BTreeSet<PathBuf>,
    path_input: String,
    error: String,
}

impl Browser {
    fn new(start: Option<PathBuf>) -> Self {
        let mut b = Browser {
            dir: None,
            entries: vec![],
            truncated: false,
            selected: BTreeSet::new(),
            path_input: String::new(),
            error: String::new(),
        };
        b.go(start);
        b
    }

    fn go(&mut self, dir: Option<PathBuf>) {
        self.error.clear();
        self.truncated = false;
        let Some(d) = dir else {
            self.dir = None;
            self.path_input.clear();
            self.entries = (b'A'..=b'Z')
                .map(|c| format!("{}:\\", c as char))
                .filter(|r| std::path::Path::new(r).exists())
                .map(|r| BrowseEntry { path: PathBuf::from(&r), name: r, is_dir: true, link: false, size: 0 })
                .collect();
            return;
        };
        match std::fs::read_dir(&d) {
            Ok(rd) => {
                let mut v: Vec<BrowseEntry> = Vec::new();
                for e in rd.flatten() {
                    if v.len() >= BROWSE_LIMIT {
                        self.truncated = true;
                        break;
                    }
                    let Ok(m) = e.path().symlink_metadata() else { continue };
                    let attrs = m.file_attributes();
                    let link = attrs & 0x400 != 0;
                    let is_dir = attrs & 0x10 != 0;
                    v.push(BrowseEntry {
                        name: e.file_name().to_string_lossy().to_string(),
                        path: e.path(),
                        is_dir,
                        link,
                        size: m.len(),
                    });
                }
                v.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
                self.entries = v;
                self.path_input = d.display().to_string();
                self.dir = Some(d);
            }
            Err(e) => {
                self.error = format!("{}: 開けません({e})", d.display());
            }
        }
    }
}

struct ConfirmEntry {
    disk_idx: usize,
    input: String,
    hdd_ok: bool,
    same_ok: bool,
}

pub struct App {
    log_dir: PathBuf,
    exe_dir: PathBuf,
    admin: bool,
    allow_virtual: bool,
    disks: Vec<DiskInfo>,
    resumes: Vec<Option<(PathBuf, JobState)>>,
    fresh_paths: Vec<PathBuf>,
    selected: Vec<bool>,
    confirm: Option<Vec<ConfirmEntry>>,
    sched: Option<Scheduler>,
    threshold: f64,
    write_through: bool,
    mode: EraseMode,
    message: String,
    /// Defenderの許可アプリ追加の結果表示
    defender_msg: String,
    closing: bool,
    close_started: Option<std::time::Instant>,
    discard_confirm: Vec<bool>,
    tab: Tab,
    targets: Vec<PathBuf>,
    path_input: String,
    free_dir: String,
    reserve_mb: u64,
    file_mode: EraseMode,
    fconfirm: Option<FConfirm>,
    fmessage: String,
    fjob: Option<FileJob>,
    browser: Option<Browser>,
}

fn setup_fonts(ctx: &egui::Context) {
    let candidates = [
        r"C:\Windows\Fonts\meiryo.ttc",
        r"C:\Windows\Fonts\YuGothM.ttc",
        r"C:\Windows\Fonts\msgothic.ttc",
        r"C:\Windows\Fonts\BIZ-UDGothicR.ttc",
    ];
    for path in candidates {
        if let Ok(data) = std::fs::read(path) {
            let mut fonts = egui::FontDefinitions::default();
            fonts.font_data.insert("jp".into(), std::sync::Arc::new(egui::FontData::from_owned(data)));
            for fam in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
                fonts.families.entry(fam).or_default().insert(0, "jp".into());
            }
            ctx.set_fonts(fonts);
            return;
        }
    }
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        setup_fonts(&cc.egui_ctx);
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| PathBuf::from("."));
        let log_dir = exe_dir.join("logs");
        let _ = std::fs::create_dir_all(&log_dir);
        let mut app = App {
            log_dir,
            exe_dir,
            admin: disk::is_admin(),
            allow_virtual: std::env::var("HDDWIPER_ALLOW_VIRTUAL").map(|v| v == "1").unwrap_or(false),
            disks: vec![],
            resumes: vec![],
            fresh_paths: vec![],
            selected: vec![],
            confirm: None,
            sched: None,
            threshold: DEFAULT_THRESHOLD,
            write_through: false,
            mode: EraseMode::Standard,
            message: String::new(),
            defender_msg: String::new(),
            closing: false,
            close_started: None,
            discard_confirm: vec![],
            tab: Tab::Disk,
            targets: vec![],
            path_input: String::new(),
            free_dir: String::new(),
            reserve_mb: 1024,
            file_mode: EraseMode::Standard,
            fconfirm: None,
            fmessage: String::new(),
            fjob: None,
            browser: None,
        };
        app.rescan();
        app
    }

    fn rescan(&mut self) {
        self.disks = disk::enumerate_disks(&[self.log_dir.as_path(), self.exe_dir.as_path()], self.allow_virtual);
        self.selected = vec![false; self.disks.len()];
        self.resumes = vec![None; self.disks.len()];
        self.fresh_paths = Vec::new();
        let mut claimed: Vec<PathBuf> = Vec::new();
        // 1巡目: ディスク番号が一致する再開ファイル / 重複のない識別情報
        for i in 0..self.disks.len() {
            let d = &self.disks[i];
            let cands = find_resume_candidates(&self.log_dir, &d.identity);
            let pick = if d.ident_duplicate {
                cands.into_iter().find(|(_, st)| st.last_disk_number == d.number)
            } else {
                cands.into_iter().next()
            };
            if let Some((p, st)) = pick {
                claimed.push(p.clone());
                self.resumes[i] = Some((p, st));
            }
        }
        // 2巡目: 同型ディスクで番号が変わっていた場合、残りの候補を割り当てる(最終確認で人が判断)
        for i in 0..self.disks.len() {
            if self.resumes[i].is_some() || !self.disks[i].ident_duplicate {
                continue;
            }
            let cands = find_resume_candidates(&self.log_dir, &self.disks[i].identity);
            if let Some((p, st)) = cands.into_iter().find(|(p, _)| !claimed.contains(p)) {
                claimed.push(p.clone());
                self.resumes[i] = Some((p, st));
            }
        }
        for i in 0..self.disks.len() {
            let d = &self.disks[i];
            let p = match &self.resumes[i] {
                Some((p, _)) => p.clone(),
                None => resume_path(&self.log_dir, &d.identity, if d.ident_duplicate { Some(d.number) } else { None }),
            };
            self.fresh_paths.push(p);
        }
    }

    /// ディスク上のドライブ(ドライブ文字+ボリューム名)の表示文字列
    fn drives_text(d: &DiskInfo) -> String {
        if d.volumes.is_empty() {
            "(ドライブ文字なし)".to_string()
        } else {
            d.volumes.join(" / ")
        }
    }

    fn selectable(d: &DiskInfo) -> bool {
        !matches!(d.class, DiskClass::Excluded(_))
    }

    fn required_text(d: &DiskInfo) -> String {
        if d.serial_untrusted {
            format!("DISK{}", d.number)
        } else {
            let a: Vec<char> = d.identity.serial.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
            a[a.len() - 4..].iter().collect()
        }
    }

    fn start_confirm(&mut self) {
        let idxs: Vec<usize> = (0..self.disks.len()).filter(|&i| self.selected[i]).collect();
        if idxs.is_empty() {
            return;
        }
        let mut paths: Vec<&PathBuf> = idxs.iter().map(|&i| &self.fresh_paths[i]).collect();
        paths.sort();
        if paths.windows(2).any(|w| w[0] == w[1]) {
            self.message = "再開ファイルが衝突するディスクが選択されています。1台ずつ実行してください。".into();
            return;
        }
        self.message.clear();
        self.confirm = Some(
            idxs.into_iter()
                .map(|disk_idx| ConfirmEntry { disk_idx, input: String::new(), hdd_ok: false, same_ok: false })
                .collect(),
        );
    }

    fn launch(&mut self) {
        let Some(entries) = self.confirm.take() else { return };
        let mut jobs = Vec::new();
        for e in entries {
            let d = self.disks[e.disk_idx].clone();
            let st = self.resumes[e.disk_idx].take().map(|(_, st)| st);
            let path = self.fresh_paths[e.disk_idx].clone();
            jobs.push(spawn_job(d, st, path, &self.log_dir, self.write_through, self.mode));
        }
        self.discard_confirm = vec![false; jobs.len()];
        let mut sch = Scheduler::new(jobs, self.threshold);
        sch.set_log(self.log_dir.join("scheduler_log.txt"));
        self.sched = Some(sch);
    }

    // ------------------------------------------------------------ 画面: ディスク選択

    fn ui_select(&mut self, ui: &mut egui::Ui) {
        if !self.admin {
            ui.colored_label(Color32::from_rgb(255, 120, 80), "管理者権限で起動されていません。ディスクの消去には「管理者として実行」が必要です。");
        }
        ui.horizontal(|ui| {
            if ui.button("再スキャン").clicked() {
                self.rescan();
            }
            ui.label("消去率の目安: 同時実行で単独時の");
            let mut pct = (self.threshold * 100.0) as u32;
            if ui.add(egui::Slider::new(&mut pct, 40..=95).suffix("%")).changed() {
                self.threshold = pct as f64 / 100.0;
            }
            ui.label("を下回り、かつ1台ずつより遅い場合に切替(10分ごとに同時実行を試し直し)");
        });
        ui.horizontal(|ui| {
            ui.label("消去方式:");
            egui::ComboBox::from_id_salt("mode")
                .selected_text(self.mode.label())
                .width(420.0)
                .show_ui(ui, |ui| {
                    for m in EraseMode::ALL {
                        ui.selectable_value(&mut self.mode, m, m.label());
                    }
                });
        });
        ui.small("抽出検証: 先頭・末尾と乱数で選んだ約2.5GBだけを読んで確認します(全域検証より大幅に短縮)。再開するディスクは、前回の方式のまま続けます。簡易方式は書込み回数が少ないため、機密性の高いディスクには標準を推奨します。");
        ui.checkbox(&mut self.write_through, "書込みスルーを使う(安全だが遅い)");
        ui.small("OFF(既定): ディスクの書込みキャッシュを使い、約90秒ごとに(書き込みを止めずに)確実に書き出して確認します。速度優先ですが、書込み失敗が見つかった場合は、その区間(最大約90秒分)を1ブロックずつ確認しながら書き直します。ONは1ブロックごとに到達を待つため遅くなります。");
        ui.separator();
        let count = self.selected.iter().filter(|&&s| s).count();
        egui::Grid::new("disks").striped(true).num_columns(9).spacing([12.0, 6.0]).show(ui, |ui| {
            for h in ["選択", "番号", "ドライブ", "モデル", "シリアル", "容量", "接続", "判定", "再開情報"] {
                ui.label(RichText::new(h).strong());
            }
            ui.end_row();
            for i in 0..self.disks.len() {
                let d = &self.disks[i];
                let ok = Self::selectable(d);
                let can_check = ok && (self.selected[i] || count < MAX_PARALLEL);
                ui.add_enabled(can_check, egui::Checkbox::without_text(&mut self.selected[i]));
                ui.label(format!("PhysicalDrive{}", d.number));
                ui.label(Self::drives_text(d));
                ui.label(format!("{} {}", d.identity.vendor, d.identity.model));
                let mut ser = d.identity.serial.clone();
                if d.serial_untrusted {
                    ser += "  (要注意)";
                }
                ui.label(ser);
                ui.label(fmt_bytes(d.identity.size));
                ui.label(&d.identity.bus);
                match &d.class {
                    DiskClass::Hdd => ui.colored_label(Color32::from_rgb(90, 200, 120), "HDD"),
                    DiskClass::Unsure(w) => ui.colored_label(Color32::from_rgb(240, 200, 80), format!("要確認: {w}")),
                    DiskClass::Excluded(w) => ui.colored_label(Color32::GRAY, format!("対象外: {w}")),
                };
                match &self.resumes[i] {
                    Some((_, s)) => {
                        let pct = s.progress_bytes(d.identity.size) as f64 * 100.0 / s.total_bytes().max(1) as f64;
                        ui.label(format!("再開可能 ({} / {} / 全体{:.1}%)", s.mode.short(), phase_label(s.phase), pct));
                    }
                    None => {
                        ui.label("-");
                    }
                }
                ui.end_row();
            }
        });
        if self.disks.is_empty() {
            ui.label("ディスクが見つかりません。");
        }
        ui.add_space(8.0);
        ui.label(format!("最大{MAX_PARALLEL}台まで同時に選択できます。OSのディスク・SSD・NVMeは選択できません。"));
        if !self.message.is_empty() {
            ui.colored_label(Color32::from_rgb(255, 120, 80), &self.message);
        }
        ui.add_space(8.0);
        let any_resume = (0..self.disks.len()).any(|i| self.selected[i] && self.resumes[i].is_some());
        let label = if any_resume { format!("開始 / 再開 ({count}台)…") } else { format!("消去を開始 ({count}台)…") };
        if ui.add_enabled(count > 0 && self.admin, egui::Button::new(label)).clicked() {
            self.start_confirm();
        }
    }

    fn ui_confirm(&mut self, ctx: &egui::Context) {
        let Some(entries) = self.confirm.as_mut() else { return };
        let mut go = false;
        let mut cancel = false;
        let screen = ctx.content_rect().size();
        egui::Window::new("最終確認 - この操作は取り消せません")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .max_width((screen.x - 60.0).max(300.0))
            .show(ctx, |ui| {
                ui.colored_label(Color32::from_rgb(255, 120, 80), "選択したディスクの全データが完全に消去されます。");
                ui.separator();
                // ディスクが多い・文章が長い場合は、この一覧だけをスクロールさせる(ボタンは常に見える位置に残す)
                let max_h = (screen.y - 200.0).max(150.0);
                let mut all_ok = true;
                egui::ScrollArea::both().max_height(max_h).auto_shrink([true, true]).show(ui, |ui| {
                for e in entries.iter_mut() {
                    let d = &self.disks[e.disk_idx];
                    ui.group(|ui| {
                        ui.label(RichText::new(format!(
                            "PhysicalDrive{} [{}] / {} {} / {} / シリアル {} / {}",
                            d.number, Self::drives_text(d), d.identity.vendor, d.identity.model, fmt_bytes(d.identity.size),
                            if d.identity.serial.is_empty() { "(なし)" } else { &d.identity.serial },
                            d.identity.bus
                        )).strong());
                        if let Some((_, s)) = &self.resumes[e.disk_idx] {
                            ui.label(format!(
                                "前回の続きから再開します({}、前回の番号 PhysicalDrive{})",
                                phase_label(s.phase), s.last_disk_number
                            ));
                        }
                        if d.ident_duplicate {
                            ui.colored_label(Color32::from_rgb(240, 200, 80), "同じ型番・シリアルのディスクが複数つながっています。取り違えに注意してください(PhysicalDrive番号と接続口で見分けてください)。");
                        }
                        let need = Self::required_text(d);
                        if d.serial_untrusted {
                            ui.colored_label(Color32::from_rgb(240, 200, 80), "シリアル番号が識別に使えません(未取得・短い・重複)。ディスクを取り違えていないか、よく確認してください。");
                            ui.horizontal(|ui| {
                                ui.label(format!("確認のため「{need}」と入力:"));
                                ui.text_edit_singleline(&mut e.input);
                            });
                        } else {
                            ui.horizontal(|ui| {
                                ui.label(format!("確認のためシリアル番号の末尾4文字「{need}」を入力:"));
                                ui.text_edit_singleline(&mut e.input);
                            });
                        }
                        let mut ok = e.input.trim().eq_ignore_ascii_case(&need);
                        if matches!(d.class, DiskClass::Unsure(_)) {
                            ui.checkbox(&mut e.hdd_ok, "このディスクが回転式HDDであることを確認した");
                            ok &= e.hdd_ok;
                        }
                        if self.resumes[e.disk_idx].is_some() && d.serial_untrusted {
                            ui.checkbox(&mut e.same_ok, "前回途中まで消去したディスクと同一であることを確認した");
                            ok &= e.same_ok;
                        }
                        all_ok &= ok;
                    });
                }
                });
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.add_enabled(all_ok, egui::Button::new("消去を実行")).clicked() {
                        go = true;
                    }
                    if ui.button("キャンセル").clicked() {
                        cancel = true;
                    }
                });
            });
        if go {
            self.launch();
        } else if cancel {
            self.confirm = None;
        }
    }


    // ------------------------------------------------------------ 画面: ファイル・フォルダ / 空き容量

    fn add_target(&mut self, p: PathBuf) {
        match shred::check_target(&p, &self.exe_dir) {
            Ok(c) => {
                if !self.targets.contains(&c) {
                    self.targets.push(c);
                }
                self.fmessage.clear();
            }
            Err(e) => self.fmessage = e,
        }
    }

    fn file_mode_combo(&mut self, ui: &mut egui::Ui) {
        let label = |m: EraseMode| {
            let t = shred::passes(m)
                .iter()
                .map(|p| if *p == shred::Pat::Zero { "ゼロ" } else { "乱数" })
                .collect::<Vec<_>>()
                .join(" → ");
            match m {
                EraseMode::Standard | EraseMode::FastVerify => format!("標準: {t}"),
                EraseMode::TwoPass => format!("簡易2周: {t}"),
                EraseMode::OnePass => format!("簡易1周: {t}"),
            }
        };
        if self.file_mode == EraseMode::FastVerify {
            self.file_mode = EraseMode::Standard;
        }
        ui.horizontal(|ui| {
            ui.label("消去方式:");
            egui::ComboBox::from_id_salt("file_mode")
                .selected_text(label(self.file_mode))
                .width(320.0)
                .show_ui(ui, |ui| {
                    for m in [EraseMode::Standard, EraseMode::TwoPass, EraseMode::OnePass] {
                        ui.selectable_value(&mut self.file_mode, m, label(m));
                    }
                });
        });
    }

    fn ui_files(&mut self, ui: &mut egui::Ui) {
        if !self.admin {
            ui.colored_label(Color32::from_rgb(255, 120, 80), "管理者権限で起動されていません。他のユーザーのファイルなどは消去できないことがあります。");
        }
        ui.label("消去するファイルやフォルダを追加してください。フォルダは中身ごと、元に戻せない形で消去されます(ごみ箱は経由しません)。エクスプローラーからこの画面へドラッグ&ドロップしても追加できます。");
        ui.horizontal(|ui| {
            if ui.button("ファイルを追加…").clicked() {
                if let Some(v) = rfd::FileDialog::new().set_title("消去するファイルを選択").pick_files() {
                    for p in v {
                        self.add_target(p);
                    }
                }
            }
            if ui.button("フォルダを追加…").clicked() {
                if let Some(v) = rfd::FileDialog::new().set_title("消去するフォルダを選択(複数選択できます)").pick_folders() {
                    for p in v {
                        self.add_target(p);
                    }
                }
            }
            if ui.button("ファイルとフォルダをまとめて選択…").clicked() {
                let start = self.targets.last().and_then(|t| t.parent().map(|p| p.to_path_buf()));
                self.browser = Some(Browser::new(start));
            }
        });
        ui.horizontal(|ui| {
            ui.label("パスを直接入力:");
            let r = ui.add(egui::TextEdit::singleline(&mut self.path_input).desired_width(480.0));
            let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if (ui.button("追加").clicked() || enter) && !self.path_input.trim().is_empty() {
                let p = PathBuf::from(self.path_input.trim().trim_matches('"'));
                self.path_input.clear();
                self.add_target(p);
            }
        });
        if !self.fmessage.is_empty() {
            ui.colored_label(Color32::from_rgb(255, 120, 80), &self.fmessage);
        }
        ui.separator();
        ui.label(RichText::new(format!("消去する対象 ({}件)", self.targets.len())).strong());
        let mut remove = None;
        egui::ScrollArea::both().id_salt("targets").max_height(260.0).auto_shrink([false, true]).show(ui, |ui| {
            for (i, t) in self.targets.iter().enumerate() {
                ui.horizontal(|ui| {
                    if ui.small_button("✕").on_hover_text("一覧から外す").clicked() {
                        remove = Some(i);
                    }
                    let kind = if t.is_dir() { "📁" } else { "📄" };
                    ui.label(format!("{kind} {}", t.display()));
                });
            }
            if self.targets.is_empty() {
                ui.colored_label(Color32::GRAY, "(まだ追加されていません)");
            }
        });
        if let Some(i) = remove {
            self.targets.remove(i);
        }
        if !self.targets.is_empty() && ui.button("一覧をすべて外す").clicked() {
            self.targets.clear();
        }
        ui.separator();
        self.file_mode_combo(ui);
        ui.small("ファイルの中身を上書きしてから、長さを0にし、名前を無意味なものに変えて削除します。読み取り専用のファイルも対象です。シンボリックリンク・ジャンクションは、リンク自体だけを消し、指す先には触れません。");
        ui.small("Windows本体・Program Files・このツールの保存フォルダ・ユーザープロファイル全体・ドライブ全体は指定できません。");
        ui.small("注意: SSD・USBメモリ・クラウド同期フォルダでは、内部の仕組み上、古い内容が残る場合があります。書込み後の検証読込みは行いません。");
        ui.add_space(6.0);
        if ui.add_enabled(!self.targets.is_empty(), egui::Button::new(format!("消去を実行 ({}件)…", self.targets.len()))).clicked() {
            let lines: Vec<String> = self
                .targets
                .iter()
                .map(|t| format!("{} {}", if t.is_dir() { "📁" } else { "📄" }, t.display()))
                .collect();
            self.fconfirm = Some(FConfirm {
                task: Task::Targets(self.targets.clone()),
                lines,
                warns: vec!["上の対象は、ごみ箱を経由せず完全に消去され、元に戻せません(フォルダは中身すべてを含みます)。".into()],
                input: String::new(),
            });
        }
    }

    fn ui_free(&mut self, ui: &mut egui::Ui) {
        if !self.admin {
            ui.colored_label(Color32::from_rgb(255, 120, 80), "管理者権限で起動されていません。");
        }
        ui.label("ドライブ(またはフォルダ)を指定すると、そのドライブの「空き容量」に残っている削除済みデータを上書きして、復元できなくします。既存のファイルには触れません。");
        ui.horizontal(|ui| {
            ui.label("ドライブ:");
            for c in b'A'..=b'Z' {
                let root = format!("{}:\\", c as char);
                if std::path::Path::new(&root).exists() && ui.small_button(&root).clicked() {
                    self.free_dir = root;
                }
            }
        });
        ui.horizontal(|ui| {
            ui.label("場所:");
            ui.add(egui::TextEdit::singleline(&mut self.free_dir).desired_width(420.0));
            if ui.button("フォルダを選択…").clicked() {
                if let Some(p) = rfd::FileDialog::new().set_title("空き容量を消去するドライブ内のフォルダを選択").pick_folder() {
                    self.free_dir = p.display().to_string();
                }
            }
        });
        let dir = PathBuf::from(self.free_dir.trim().trim_matches('"'));
        let free = if self.free_dir.trim().is_empty() { None } else { shred::free_bytes(&dir).ok() };
        match free {
            Some(f) => {
                ui.label(format!("現在の空き容量: {}", fmt_bytes(f)));
            }
            None if !self.free_dir.trim().is_empty() => {
                ui.colored_label(Color32::from_rgb(255, 120, 80), "この場所の空き容量を取得できません。");
            }
            None => {}
        }
        ui.horizontal(|ui| {
            ui.label("消去後に残す空き容量:");
            ui.add(egui::DragValue::new(&mut self.reserve_mb).range(256..=10_000_000).speed(16.0).suffix(" MB"));
        });
        ui.small("空き容量を一時的に使い切るため、他のアプリが「ディスクの空きがない」と失敗することがあります。残す容量は最低256MBです。Windowsが入っているドライブでは、余裕(1GB以上)を持たせてください。終了時に一時ファイルは削除されます。");
        self.file_mode_combo(ui);
        ui.small("空き領域を一時ファイルで埋めて、工程ごとに上書きします。ファイル名が残る極小ファイル(MFT内)や、ファイル末尾の余り領域は対象外です。SSD・USBメモリでは完全な消去を保証できません。書込み後の検証読込みは行いません。");
        if !self.fmessage.is_empty() {
            ui.colored_label(Color32::from_rgb(255, 120, 80), &self.fmessage);
        }
        ui.add_space(6.0);
        let ok = free.is_some() && dir.is_dir();
        if ui.add_enabled(ok, egui::Button::new("空き容量の消去を実行…")).clicked() {
            let reserve = self.reserve_mb * 1_000_000;
            let f = free.unwrap_or(0);
            if f <= reserve.max(shred::MIN_RESERVE) {
                self.fmessage = "空き容量が、残す容量以下です。残す容量を小さくしてください。".into();
            } else {
                self.fmessage.clear();
                let mut warns = vec![format!(
                    "{} のうち約 {} の空き容量を、一時ファイルで埋めて上書きします(約 {} を残します)。",
                    dir.display(),
                    fmt_bytes(f - reserve.max(shred::MIN_RESERVE)),
                    fmt_bytes(reserve.max(shred::MIN_RESERVE))
                )];
                if let Ok(sd) = std::env::var("SystemDrive") {
                    if self.free_dir.trim().to_uppercase().starts_with(&sd.to_uppercase()) {
                        warns.push("Windowsが入っているドライブです。実行中は他のアプリが動かなくなることがあります。".into());
                    }
                }
                self.fconfirm = Some(FConfirm {
                    task: Task::FreeSpace { dir: dir.clone(), reserve },
                    lines: vec![format!("💽 {}", dir.display())],
                    warns,
                    input: String::new(),
                });
            }
        }
    }

    fn ui_fconfirm(&mut self, ctx: &egui::Context) {
        let Some(c) = self.fconfirm.as_mut() else { return };
        let mut go = false;
        let mut cancel = false;
        let screen = ctx.content_rect().size();
        egui::Window::new("最終確認 - この操作は取り消せません")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .max_width((screen.x - 60.0).max(300.0))
            .show(ctx, |ui| {
                for w in &c.warns {
                    ui.colored_label(Color32::from_rgb(255, 120, 80), w);
                }
                ui.separator();
                egui::ScrollArea::both().id_salt("fconfirm").max_height((screen.y - 280.0).max(120.0)).auto_shrink([true, true]).show(ui, |ui| {
                    for l in &c.lines {
                        ui.label(l);
                    }
                });
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("実行するには「消去」と入力:");
                    ui.text_edit_singleline(&mut c.input);
                });
                ui.horizontal(|ui| {
                    if ui.add_enabled(c.input.trim() == "消去", egui::Button::new("実行")).clicked() {
                        go = true;
                    }
                    if ui.button("キャンセル").clicked() {
                        cancel = true;
                    }
                });
            });
        if go {
            if let Some(c) = self.fconfirm.take() {
                self.fjob = Some(shred::spawn(c.task, self.file_mode, self.log_dir.clone()));
            }
        } else if cancel {
            self.fconfirm = None;
        }
    }

    fn ui_fjob(&mut self, ui: &mut egui::Ui) {
        let Some(job) = self.fjob.as_ref() else { return };
        let s = job.shared.snapshot();
        ui.label(RichText::new(&s.title).strong().size(16.0));
        let (txt, col) = match &s.status {
            ShStatus::Scanning => ("対象を調べています…".to_string(), Color32::LIGHT_GRAY),
            ShStatus::Running => (
                format!("実行中: 工程 {}/{} ({})", s.pass.max(1), s.passes.max(1), s.pass_label),
                Color32::from_rgb(90, 200, 120),
            ),
            ShStatus::Finished => (
                if s.error_count == 0 { "完了".to_string() } else { format!("完了(エラー {} 件)", s.error_count) },
                Color32::from_rgb(90, 200, 255),
            ),
            ShStatus::Stopped => ("中断しました".to_string(), Color32::from_rgb(240, 200, 80)),
            ShStatus::Failed(e) => (format!("失敗: {e}"), Color32::from_rgb(255, 100, 100)),
        };
        ui.colored_label(col, txt);
        let frac = s.done as f64 / s.total.max(1) as f64;
        ui.add(egui::ProgressBar::new(frac.min(1.0) as f32).text(format!(
            "{:.2}%  ({} / {})",
            frac.min(1.0) * 100.0,
            fmt_bytes(s.done),
            fmt_bytes(s.total)
        )).desired_height(20.0));
        let elapsed = s.finished.unwrap_or_else(std::time::Instant::now).duration_since(s.started).as_secs_f64();
        ui.horizontal_wrapped(|ui| {
            if s.files_total > 0 {
                ui.label(format!("ファイル {} / {}", s.files_done, s.files_total));
            }
            ui.label(format!("| 経過 {}", fmt_duration(elapsed)));
            if s.status == ShStatus::Running && elapsed > 3.0 && s.done > 0 {
                let sp = s.done as f64 / elapsed;
                ui.label(format!("| 平均 {}/s", fmt_bytes(sp as u64)));
                ui.label(format!("| 残り {}", fmt_duration(s.total.saturating_sub(s.done) as f64 / sp)));
            }
        });
        if !s.current.is_empty() {
            ui.label(format!("処理中: {}", s.current));
        }
        if s.error_count > 0 {
            ui.colored_label(Color32::from_rgb(255, 160, 80), format!("エラー {} 件(先頭 {} 件を表示)", s.error_count, s.errors.len()));
            egui::ScrollArea::both().id_salt("fjob_err").max_height(200.0).auto_shrink([false, true]).show(ui, |ui| {
                for e in &s.errors {
                    ui.colored_label(Color32::from_rgb(255, 160, 80), e);
                }
            });
        }
        ui.separator();
        let mut back = false;
        ui.horizontal(|ui| match &s.status {
            ShStatus::Scanning | ShStatus::Running => {
                if ui.button("中断").clicked() {
                    job.shared.request_stop();
                }
            }
            _ => {
                if let Some(p) = &s.report {
                    ui.label(format!("結果ログ: {}", p.display()));
                    if ui.button("結果ログを開く").clicked() {
                        let _ = std::process::Command::new("notepad").arg(p).spawn();
                    }
                }
                if ui.button("戻る").clicked() {
                    back = true;
                }
            }
        });
        if back {
            self.fjob = None;
            self.targets.retain(|t| t.exists());
        }
    }


    // ------------------------------------------------------------ ファイル・フォルダ選択画面(複数・混在)

    fn ui_browser(&mut self, ctx: &egui::Context) {
        let Some(mut b) = self.browser.take() else { return };
        let mut nav: Option<Option<PathBuf>> = None;
        let mut toggle: Option<PathBuf> = None;
        let mut add_all = false;
        let mut clear = false;
        let mut done = false;
        let mut cancel = false;
        let mut go_input = false;
        let mut open = true;
        egui::Window::new("ファイルとフォルダを選択(複数選択できます)")
            .collapsible(false)
            .resizable(true)
            .default_size([760.0, 560.0])
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .open(&mut open)
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label("ドライブ:");
                    for c in b'A'..=b'Z' {
                        let root = format!("{}:\\", c as char);
                        if std::path::Path::new(&root).exists() && ui.small_button(&root).clicked() {
                            nav = Some(Some(PathBuf::from(root)));
                        }
                    }
                });
                ui.horizontal(|ui| {
                    if ui.add_enabled(b.dir.is_some(), egui::Button::new("⬆ 上へ")).clicked() {
                        nav = Some(b.dir.as_ref().and_then(|d| d.parent().map(|p| p.to_path_buf())));
                    }
                    let r = ui.add(egui::TextEdit::singleline(&mut b.path_input).desired_width(ui.available_width() - 70.0));
                    if (r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))) || ui.button("移動").clicked() {
                        go_input = true;
                    }
                });
                if !b.error.is_empty() {
                    ui.colored_label(Color32::from_rgb(255, 120, 80), &b.error);
                }
                ui.horizontal(|ui| {
                    if ui.button("このフォルダ内をすべて選択").clicked() {
                        add_all = true;
                    }
                    if ui.button("選択をすべて解除").clicked() {
                        clear = true;
                    }
                    ui.label(format!("選択中: {} 件", b.selected.len()));
                });
                ui.separator();
                egui::ScrollArea::vertical().id_salt("browser_list").max_height(330.0).auto_shrink([false, false]).show(ui, |ui| {
                    for e in &b.entries {
                        ui.horizontal(|ui| {
                            let mut sel = b.selected.contains(&e.path);
                            if b.dir.is_some() && ui.checkbox(&mut sel, "").changed() {
                                toggle = Some(e.path.clone());
                            }
                            if e.is_dir {
                                let mark = if e.link { "🔗" } else { "📁" };
                                if ui.button(format!("{mark} {}", e.name)).on_hover_text("開く").clicked() {
                                    nav = Some(Some(e.path.clone()));
                                }
                            } else {
                                ui.label(format!("📄 {}", e.name));
                                ui.colored_label(Color32::GRAY, fmt_bytes(e.size));
                            }
                        });
                    }
                    if b.entries.is_empty() {
                        ui.colored_label(Color32::GRAY, "(空です)");
                    }
                    if b.truncated {
                        ui.colored_label(Color32::from_rgb(240, 200, 80), format!("多いため先頭 {} 件のみ表示しています。フォルダごと選ぶには、上のフォルダで選択してください。", BROWSE_LIMIT));
                    }
                });
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.add_enabled(!b.selected.is_empty(), egui::Button::new(format!("選択した {} 件を追加", b.selected.len()))).clicked() {
                        done = true;
                    }
                    if ui.button("キャンセル").clicked() {
                        cancel = true;
                    }
                });
            });
        if go_input {
            let p = PathBuf::from(b.path_input.trim().trim_matches('"'));
            nav = Some(Some(p));
        }
        if let Some(p) = toggle {
            if !b.selected.remove(&p) {
                b.selected.insert(p);
            }
        }
        if add_all {
            for e in &b.entries {
                b.selected.insert(e.path.clone());
            }
        }
        if clear {
            b.selected.clear();
        }
        if let Some(d) = nav {
            b.go(d);
        }
        if done {
            let mut errs = Vec::new();
            for p in std::mem::take(&mut b.selected) {
                self.add_target(p);
                if !self.fmessage.is_empty() {
                    errs.push(std::mem::take(&mut self.fmessage));
                }
            }
            self.fmessage = errs.join("\n");
            return;
        }
        if cancel || !open {
            return;
        }
        self.browser = Some(b);
    }

    // ------------------------------------------------------------ 画面: 実行

    fn ui_running(&mut self, ui: &mut egui::Ui) {
        let Some(sched) = self.sched.as_mut() else { return };
        ui.horizontal(|ui| {
            ui.label(RichText::new(sched.stage_text()).strong());
            let all_term = sched.all_terminal();
            if !all_term {
                let label = if sched.user_paused { "全て再開" } else { "全て一時停止" };
                if ui.button(label).clicked() {
                    let p = !sched.user_paused;
                    sched.set_user_paused(p);
                }
            }
            if sched.is_serial()
                && ui
                    .button("全台の同時実行に戻す")
                    .on_hover_text("一時的な帯域不足で1台ずつになった場合に、すぐ全台を同時に動かします。以後は自動で絞り込みません。")
                    .clicked()
            {
                sched.force_concurrent();
            }
            if ui.button("ログフォルダを開く").clicked() {
                let _ = std::process::Command::new("explorer").arg(&self.log_dir).spawn();
            }
        });
        if sched.stop_is_stuck(20) {
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(
                    Color32::from_rgb(255, 160, 80),
                    "中断の指示から20秒以上たっても終わらないディスクがあります(ディスクの応答待ちなど)。",
                );
                if ui.button("待たずに強制終了").on_hover_text("再開ファイルは約90秒ごとに保存済みです。直近の保存位置から再開できます。").clicked() {
                    unsafe {
                        TerminateProcess(GetCurrentProcess(), 0);
                    }
                }
            });
        }
        ui.separator();
        let mut stop_idx = None;
        let mut pause_req: Option<(usize, bool)> = None;
        let mut discard_idx = None;
        let mut allow_idx = None;
        if !self.defender_msg.is_empty() {
            ui.colored_label(Color32::from_rgb(240, 200, 80), &self.defender_msg);
            ui.separator();
        }
        let sched_paused: Vec<bool> = (0..sched.jobs.len()).map(|i| sched.is_job_paused(i)).collect();
        egui::ScrollArea::vertical().show(ui, |ui| {
            for (n, job) in sched.jobs.iter().enumerate() {
                let snap = job.shared.snapshot();
                let map = job.shared.map.lock().unwrap().clone();
                let id = &job.disk.identity;
                ui.group(|ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new(format!(
                        "PhysicalDrive{}  {} {}  (シリアル {})  {}",
                        job.disk.number, id.vendor, id.model, id.serial, fmt_bytes(id.size)
                    )).strong().size(16.0));
                    let reason = job.shared.reason.load(std::sync::atomic::Ordering::SeqCst);
                    let status_text = match &snap.status {
                        Status::Preparing => ("準備中(ボリュームのロック・マウント解除)".to_string(), Color32::LIGHT_GRAY),
                        Status::Running => (format!("実行中: {}", phase_label(snap.phase)), Color32::from_rgb(90, 200, 120)),
                        Status::Paused => (
                            match reason {
                                REASON_BANDWIDTH => "待機中(帯域不足のため1台ずつ実行)".to_string(),
                                REASON_USER => "一時停止中".to_string(),
                                _ => "待機中".to_string(),
                            },
                            Color32::from_rgb(240, 200, 80),
                        ),
                        Status::Finished => ("完了".to_string(), Color32::from_rgb(90, 200, 255)),
                        Status::Stopped => ("中断しました(再開用ログあり。次回起動時に続きから再開できます)".to_string(), Color32::from_rgb(240, 200, 80)),
                        Status::Failed(e) => (format!("失敗: {e}"), Color32::from_rgb(255, 100, 100)),
                    };
                    ui.colored_label(status_text.1, status_text.0);
                    if let Status::Failed(e) = &snap.status {
                        if is_defender_block(e) {
                            ui.horizontal_wrapped(|ui| {
                                if ui.button("Defenderの許可アプリに追加して再試行").clicked() {
                                    allow_idx = Some(n);
                                }
                                ui.small("このボタンを押すと、このツールをWindows Defenderの「コントロールされたフォルダー アクセス」の許可アプリに追加します(管理者権限で実行)。追加の記録は defender_allow_log.txt に残ります。");
                            });
                        }
                    }
                    let stall = job.shared.stall_secs.load(std::sync::atomic::Ordering::Relaxed);
                    if stall >= 15 && matches!(snap.status, Status::Running | Status::Paused) {
                        ui.colored_label(
                            Color32::from_rgb(255, 90, 90),
                            format!("⚠ ディスクが {stall} 秒間応答していません(USB接続・電源・ケースを確認してください。「中断」を押すとI/Oを取り消して、進捗を保存します)"),
                        );
                    }
                    if !snap.last_error.is_empty() {
                        ui.colored_label(Color32::from_rgb(255, 160, 80), format!("直近の書込みエラー: {}", snap.last_error));
                    }
                    if !snap.message.is_empty() {
                        ui.colored_label(Color32::from_rgb(255, 160, 80), &snap.message);
                    }

                    let total_all = snap.total_bytes_all().max(1);
                    let overall = snap.total_done as f64 / total_all as f64;
                    ui.add(egui::ProgressBar::new(overall as f32).text(format!("全体 {:.2}%", overall * 100.0)).desired_height(20.0));
                    let ph = snap.phase.min(3);
                    if snap.phase < PHASE_DONE {
                        let pf = snap.offset as f64 / snap.size.max(1) as f64;
                        ui.add(egui::ProgressBar::new(pf as f32).text(format!(
                            "{} {:.2}%  ({} / {} , LBA {})",
                            phase_label(ph), pf * 100.0, fmt_bytes(snap.offset), fmt_bytes(snap.size),
                            snap.offset / snap.sector_size.max(1) as u64
                        )));
                    }
                    let speed = snap.speed(SPEED_WINDOW);
                    ui.horizontal_wrapped(|ui| {
                        match (&snap.status, speed) {
                            (Status::Running, Some(s)) if s > 0.0 => {
                                let rem_phase = snap.size.saturating_sub(snap.offset) as f64 / s;
                                let rem_total = total_all.saturating_sub(snap.total_done) as f64 / s;
                                ui.label(format!("速度 {}/s", fmt_bytes(s as u64)));
                                ui.label(format!("| 現在の工程の残り {}", fmt_duration(rem_phase)));
                                ui.label(format!("| 全体の残り {}", fmt_duration(rem_total)));
                            }
                            (Status::Running, _) => {
                                ui.label("速度を計測中…");
                            }
                            _ => {}
                        }
                    });
                    ui.horizontal_wrapped(|ui| {
                        ui.label(format!("この工程: 処理済 {} セクタ", snap.ok));
                        ui.label(format!("| エラー {}", snap.err));
                        ui.label(format!("| スキップ {}", snap.skip));
                        ui.label(format!("| 再試行 書込{} / 読込{}", snap.write_retries, snap.read_retries));
                        let c = if snap.bad_sectors > 0 { Color32::from_rgb(255, 120, 80) } else { Color32::GRAY };
                        ui.colored_label(c, format!("| 未消去セクタ {}", snap.bad_sectors));
                    });

                    // セクタマップ
                    let w = ui.available_width();
                    let cols = 128usize;
                    let rows = CELLS / cols;
                    let cw = w / cols as f32;
                    let ch = 3.0f32.max(cw.min(6.0));
                    let (rect, _) = ui.allocate_exact_size(egui::vec2(w, ch * rows as f32), egui::Sense::hover());
                    let painter = ui.painter_at(rect);
                    painter.rect_filled(rect, 0.0, Color32::from_gray(25));
                    let done_col = match ph {
                        1 => Color32::from_rgb(170, 100, 210),
                        3 => Color32::from_rgb(60, 180, 130),
                        _ => Color32::from_rgb(70, 130, 210),
                    };
                    for (i, &c) in map.iter().enumerate() {
                        let col = match c {
                            1 => done_col,
                            2 => Color32::from_rgb(230, 60, 60),
                            _ => continue,
                        };
                        let (x, y) = (i % cols, i / cols);
                        let r = egui::Rect::from_min_size(
                            rect.min + egui::vec2(x as f32 * cw, y as f32 * ch),
                            egui::vec2(cw.max(1.0), ch),
                        );
                        painter.rect_filled(r, 0.0, col);
                    }
                    if snap.status == Status::Running && snap.phase < PHASE_DONE {
                        let ci = ((snap.offset as u128 * CELLS as u128 / snap.size.max(1) as u128) as usize).min(CELLS - 1);
                        let (x, y) = (ci % cols, ci / cols);
                        let r = egui::Rect::from_min_size(
                            rect.min + egui::vec2(x as f32 * cw, y as f32 * ch),
                            egui::vec2(cw.max(2.0), ch),
                        );
                        painter.rect_filled(r, 0.0, Color32::YELLOW);
                    }
                    ui.small("セクタマップ: 灰=未処理 / 色付き=この工程で処理済 / 赤=不良・未消去 / 黄=現在位置");

                    ui.horizontal(|ui| {
                        match &snap.status {
                            Status::Running | Status::Paused | Status::Preparing => {
                                let jp = sched_paused[n];
                                if !matches!(snap.status, Status::Preparing)
                                    && ui.button(if jp { "このディスクを再開" } else { "このディスクを一時停止" }).clicked()
                                {
                                    pause_req = Some((n, !jp));
                                }
                                if ui.button("中断して保存(再開可能)").clicked() {
                                    stop_idx = Some(n);
                                }
                            }
                            Status::Stopped | Status::Failed(_) => {
                                if job.state_path.exists() {
                                    ui.checkbox(&mut self.discard_confirm[n], "再開を諦める");
                                    if ui.add_enabled(self.discard_confirm[n], egui::Button::new("再開用ログを消し込んで削除")).clicked() {
                                        discard_idx = Some(n);
                                    }
                                }
                            }
                            Status::Finished => {
                                if let Some(p) = &snap.report_path {
                                    ui.label(format!("結果ログ: {}", p.display()));
                                    if ui.button("結果ログを開く").clicked() {
                                        let _ = std::process::Command::new("notepad").arg(p).spawn();
                                    }
                                }
                                if snap.bad_sectors > 0 {
                                    ui.colored_label(Color32::from_rgb(255, 120, 80), "未消去領域があります。結果ログを確認してください。");
                                }
                            }
                        }
                    });
                });
            }
        });
        if let Some((i, p)) = pause_req {
            sched.set_job_paused(i, p);
        }
        if let Some(i) = stop_idx {
            sched.stop_job(i);
        }
        if let Some(i) = allow_idx {
            match allow_in_defender(&self.log_dir) {
                Ok(m) => {
                    self.defender_msg = format!("{m}\n許可を追加したので、このディスクの処理をやり直します。");
                    let (disk, sp) = (sched.jobs[i].disk.clone(), sched.jobs[i].state_path.clone());
                    let existing = JobState::load(&sp).ok();
                    let job = spawn_job(disk, existing, sp, &self.log_dir, self.write_through, self.mode);
                    sched.replace_job(i, job);
                }
                Err(m) => self.defender_msg = m,
            }
        }
        if let Some(i) = discard_idx {
            secure_erase_file(&sched.jobs[i].state_path);
            secure_erase_file(&sched.jobs[i].state_path.with_extension("json.tmp"));
        }
        if sched.all_terminal() {
            ui.separator();
            if ui.button("ディスク選択に戻る").clicked() {
                self.sched = None;
                self.rescan();
            }
        }
    }
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(s) = self.sched.as_mut() {
            s.tick();
        }
        let disk_running = self.sched.as_ref().map(|s| !s.all_terminal()).unwrap_or(false);
        let file_running = self.fjob.as_ref().map(|f| f.is_running()).unwrap_or(false);
        let running = disk_running || file_running;
        unsafe {
            SetThreadExecutionState(if running { ES_CONTINUOUS | ES_SYSTEM_REQUIRED } else { ES_CONTINUOUS });
        }

        if ctx.input(|i| i.viewport().close_requested()) {
            if running {
                if !self.closing {
                    self.closing = true;
                    if let Some(f) = self.fjob.as_ref() {
                        f.shared.request_stop();
                    }
                    if let Some(s) = self.sched.as_mut() {
                        for i in 0..s.jobs.len() {
                            s.stop_job(i);
                        }
                    }
                    self.close_started = Some(std::time::Instant::now());
                }
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            }
        }
        if self.closing && !running {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        // 閉じる操作が通る状態になったら、終了処理で固まっても8秒後にプロセスを確実に終わらせる
        // (残ったプロセスがボリュームのロックを持ち続けると、次の再開が「アクセス拒否」になるため)
        let closing_now = ctx.input(|i| i.viewport().close_requested()) && !running || self.closing && !running;
        if closing_now {
            static STARTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
            if !STARTED.swap(true, std::sync::atomic::Ordering::SeqCst) {
                std::thread::spawn(|| {
                    std::thread::sleep(Duration::from_secs(8));
                    unsafe {
                        TerminateProcess(GetCurrentProcess(), 0);
                    }
                });
            }
        }
        ctx.request_repaint_after(Duration::from_millis(if running { 500 } else { 1500 }));
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        ui.heading("HDD 完全消去ツール (0 → 乱数 → 0 + 検証)");
        if self.closing {
            ui.colored_label(Color32::from_rgb(240, 200, 80), "進捗を保存して中断しています。しばらくお待ちください…");
            if self.close_started.map(|t| t.elapsed().as_secs() >= 10).unwrap_or(false) {
                ui.label("ディスクの応答待ちで時間がかかっています。待たずに終了することもできます。");
                ui.small("再開ファイルは約90秒ごとに保存済みです。強制終了しても、直近の保存位置から再開できます(最大約90秒分の進捗が失われます)。");
                if ui.button("待たずに強制終了").clicked() {
                    unsafe {
                        TerminateProcess(GetCurrentProcess(), 0);
                    }
                }
            }
        }
        ui.separator();
        if self.fjob.is_some() {
            self.ui_fjob(ui);
        } else if self.sched.is_some() {
            self.ui_running(ui);
        } else {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Disk, "ディスク全体の消去");
                ui.selectable_value(&mut self.tab, Tab::Files, "ファイル・フォルダの消去");
                ui.selectable_value(&mut self.tab, Tab::Free, "空き容量の消去");
            });
            ui.separator();
            let ctx = ui.ctx().clone();
            match self.tab {
                Tab::Disk => {
                    self.ui_select(ui);
                    self.ui_confirm(&ctx);
                }
                Tab::Files => {
                    // エクスプローラーからのドラッグ&ドロップ(ファイル・フォルダを複数同時に可)
                    let dropped: Vec<PathBuf> =
                        ctx.input(|i| i.raw.dropped_files.iter().map(|f| f.path().to_path_buf()).collect());
                    let mut errs = Vec::new();
                    for p in dropped {
                        self.add_target(p);
                        if !self.fmessage.is_empty() {
                            errs.push(std::mem::take(&mut self.fmessage));
                        }
                    }
                    if !errs.is_empty() {
                        self.fmessage = errs.join("\n");
                    }
                    if ctx.input(|i| !i.raw.hovered_files.is_empty()) {
                        let screen = ctx.content_rect();
                        let painter = ctx.layer_painter(egui::LayerId::new(egui::Order::Foreground, egui::Id::new("drop_hint")));
                        painter.rect_filled(screen, 0.0, Color32::from_black_alpha(170));
                        painter.text(
                            screen.center(),
                            egui::Align2::CENTER_CENTER,
                            "ここにドロップすると、消去対象に追加します",
                            egui::FontId::proportional(24.0),
                            Color32::WHITE,
                        );
                    }
                    self.ui_files(ui);
                    self.ui_browser(&ctx);
                }
                Tab::Free => self.ui_free(ui),
            }
            self.ui_fconfirm(&ctx);
        }
    }
}
