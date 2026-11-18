//! Windows の物理ドライブ列挙・分類・実機I/O。

use crate::dev::{AlignedBuf, BlockDev};
use crate::state::DiskIdentity;
use std::ffi::c_void;
use std::io;
use std::path::Path;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Ioctl::*;
use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult};
use crate::engine::JobShared;
use std::sync::Arc;
use std::time::{Duration, Instant};
use windows_sys::Win32::System::IO::OVERLAPPED;
use windows_sys::Win32::System::Threading::{CreateEventW, GetCurrentProcess, OpenProcessToken, ResetEvent, WaitForSingleObject};

const FSCTL_ALLOW_EXTENDED_DASD_IO_CODE: u32 = 0x0009_0083;
// IOCTL_DISK_GET/SET_DISK_ATTRIBUTES = CTL_CODE(IOCTL_DISK_BASE=7, 0x3c/0x3d, METHOD_BUFFERED, FILE_READ|WRITE_ACCESS)
const IOCTL_DISK_GET_DISK_ATTRIBUTES_CODE: u32 = 0x0007_00F0;
const IOCTL_DISK_SET_DISK_ATTRIBUTES_CODE: u32 = 0x0007_C0F4;
// IOCTL_DISK_GET/SET_CACHE_INFORMATION = CTL_CODE(IOCTL_DISK_BASE, 0x35/0x36, METHOD_BUFFERED, ...)
const IOCTL_DISK_GET_CACHE_INFORMATION_CODE: u32 = 0x0007_40D4;
const IOCTL_DISK_SET_CACHE_INFORMATION_CODE: u32 = 0x0007_C0D8;

/// 実行中でも、これだけ(秒)I/Oが完了しなければ取り消して発行し直す
pub const AUTO_CANCEL_SECS: u64 = 90;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn last_err() -> io::Error {
    io::Error::last_os_error()
}

struct OwnedHandle(HANDLE);
unsafe impl Send for OwnedHandle {}
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if self.0 != INVALID_HANDLE_VALUE && !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

fn open_path(path: &str, access: u32, flags: u32) -> io::Result<OwnedHandle> {
    let w = wide(path);
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            flags,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        Err(last_err())
    } else {
        Ok(OwnedHandle(h))
    }
}

fn ioctl<T, U>(h: HANDLE, code: u32, input: Option<&T>, out: &mut [U]) -> io::Result<u32> {
    let mut ret = 0u32;
    let (ip, il) = match input {
        Some(i) => (i as *const T as *const c_void, std::mem::size_of::<T>() as u32),
        None => (std::ptr::null(), 0),
    };
    let ok = unsafe {
        DeviceIoControl(
            h,
            code,
            ip,
            il,
            out.as_mut_ptr() as *mut c_void,
            std::mem::size_of_val(out) as u32,
            &mut ret,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 { Err(last_err()) } else { Ok(ret) }
}

fn ioctl_noout(h: HANDLE, code: u32) -> io::Result<()> {
    let mut ret = 0u32;
    let ok = unsafe {
        DeviceIoControl(h, code, std::ptr::null(), 0, std::ptr::null_mut(), 0, &mut ret, std::ptr::null_mut())
    };
    if ok == 0 { Err(last_err()) } else { Ok(()) }
}

pub fn is_admin() -> bool {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let _g = OwnedHandle(token);
        let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut ret = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elev as *mut _ as *mut c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        );
        ok != 0 && elev.TokenIsElevated != 0
    }
}

// ---------------------------------------------------------------- 列挙

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiskClass {
    /// シークペナルティあり = 回転式HDD
    Hdd,
    /// HDDかどうか機械的に判定できない(USB接続など)。人が判断する
    Unsure(String),
    /// 対象外
    Excluded(String),
}

#[derive(Clone, Debug)]
pub struct DiskInfo {
    pub number: u32,
    pub identity: DiskIdentity,
    pub class: DiskClass,
    /// シリアルが空・短い・重複などで本人確認に使えない
    pub serial_untrusted: bool,
    /// 同じ識別情報(メーカー/モデル/シリアル/容量)のディスクが他にもつながっている
    pub ident_duplicate: bool,
    /// このディスク上のドライブ(例: `G:\ 「HD-ADU3」`)。ドライブ文字のあるものだけ
    pub volumes: Vec<String>,
}

/// ドライブ文字のあるボリュームを、ディスク番号ごとにまとめて返す(ドライブ文字+ボリューム名)
fn drive_names_by_disk() -> Vec<(u32, String)> {
    let mut out = Vec::new();
    let mut name = [0u16; 261];
    let fh = unsafe { FindFirstVolumeW(name.as_mut_ptr(), 261) };
    if fh == INVALID_HANDLE_VALUE {
        return out;
    }
    loop {
        let len = name.iter().position(|&c| c == 0).unwrap_or(0);
        let vol = String::from_utf16_lossy(&name[..len]).trim_end_matches('\\').to_string();
        if !mount_points_of(&vol).is_empty() {
            let text = drive_display(&vol, &volume_label_of(&vol));
            for d in volume_disk_numbers(&vol) {
                out.push((d, text.clone()));
            }
        }
        if unsafe { FindNextVolumeW(fh, name.as_mut_ptr(), 261) } == 0 {
            break;
        }
    }
    unsafe { FindVolumeClose(fh) };
    out
}

fn bus_name(b: i32) -> String {
    match b {
        0 => "不明",
        1 => "SCSI",
        2 => "ATAPI",
        3 => "ATA",
        4 => "IEEE1394",
        5 => "SSA",
        6 => "ファイバチャネル",
        7 => "USB",
        8 => "RAID",
        9 => "iSCSI",
        10 => "SAS",
        11 => "SATA",
        12 => "SD",
        13 => "MMC",
        14 => "仮想",
        15 => "ファイルバック仮想",
        16 => "Storage Spaces",
        17 => "NVMe",
        _ => "その他",
    }
    .to_string()
}

fn read_cstr(buf: &[u8], off: u32) -> String {
    if off == 0 || off as usize >= buf.len() {
        return String::new();
    }
    let s = &buf[off as usize..];
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    String::from_utf8_lossy(&s[..end]).trim().to_string()
}

fn volume_disk_numbers(volume_path: &str) -> Vec<u32> {
    let Ok(h) = open_path(volume_path, 0, 0) else { return vec![] };
    let mut buf = vec![0u64; 64];
    // VOLUME_DISK_EXTENTS: NumberOfDiskExtents(u32) + padding + DISK_EXTENT[]
    match ioctl::<(), u64>(h.0, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, None, &mut buf) {
        Ok(_) => {
            let bytes: &[u8] =
                unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, buf.len() * 8) };
            let n = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
            let mut v = Vec::new();
            for i in 0..n.min(14) {
                let o = 8 + i * 24; // DISK_EXTENT = DiskNumber(u32)+pad+StartingOffset(i64)+ExtentLength(i64)
                v.push(u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap()));
            }
            v
        }
        Err(_) => vec![],
    }
}

/// OS(Windowsフォルダ)やこのツール(ログ保存先)が載っているディスク番号
fn protected_disks(extra_paths: &[&Path]) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    let mut buf = [0u16; 260];
    let n = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), 260) } as usize;
    if n >= 2 {
        let s = String::from_utf16_lossy(&buf[..n]);
        let drive = &s[..2];
        for d in volume_disk_numbers(&format!("\\\\.\\{drive}")) {
            out.push((d, "OS(Windows)が入っているディスク".to_string()));
        }
    }
    for p in extra_paths {
        let s = p.to_string_lossy();
        let s = s.trim_start_matches(r"\\?\");
        if s.len() >= 2 && s.as_bytes()[1] == b':' {
            for d in volume_disk_numbers(&format!("\\\\.\\{}", &s[..2])) {
                out.push((d, "このツール/ログの保存先があるディスク".to_string()));
            }
        }
    }
    out
}

pub fn enumerate_disks(extra_protected: &[&Path], allow_virtual: bool) -> Vec<DiskInfo> {
    let prot = protected_disks(extra_protected);
    let drives = drive_names_by_disk();
    let mut list: Vec<DiskInfo> = Vec::new();
    for n in 0..64u32 {
        let Ok(h) = open_path(&format!("\\\\.\\PhysicalDrive{n}"), 0, 0) else { continue };
        let q = STORAGE_PROPERTY_QUERY {
            PropertyId: StorageDeviceProperty,
            QueryType: PropertyStandardQuery,
            AdditionalParameters: [0],
        };
        let mut buf = vec![0u8; 2048];
        let (mut vendor, mut model, mut serial, mut bus, mut removable) =
            (String::new(), String::new(), String::new(), 0i32, false);
        if ioctl(h.0, IOCTL_STORAGE_QUERY_PROPERTY, Some(&q), &mut buf[..]).is_ok() {
            let d = unsafe { &*(buf.as_ptr() as *const STORAGE_DEVICE_DESCRIPTOR) };
            vendor = read_cstr(&buf, d.VendorIdOffset);
            model = read_cstr(&buf, d.ProductIdOffset);
            serial = read_cstr(&buf, d.SerialNumberOffset);
            bus = d.BusType;
            removable = d.RemovableMedia;
        }
        // 容量・セクタサイズ
        let mut geo = vec![0u8; 256];
        let (mut size, mut ss) = (0u64, 512u32);
        if ioctl::<(), u8>(h.0, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, None, &mut geo).is_ok() {
            let g = unsafe { &*(geo.as_ptr() as *const DISK_GEOMETRY_EX) };
            size = g.DiskSize as u64;
            ss = g.Geometry.BytesPerSector;
        }
        if size == 0 {
            continue;
        }
        // シークペナルティ
        let q2 = STORAGE_PROPERTY_QUERY {
            PropertyId: StorageDeviceSeekPenaltyProperty,
            QueryType: PropertyStandardQuery,
            AdditionalParameters: [0],
        };
        let mut sp = [0u8; 64];
        let seek: Option<bool> = match ioctl(h.0, IOCTL_STORAGE_QUERY_PROPERTY, Some(&q2), &mut sp[..]) {
            Ok(_) => {
                let d = unsafe { &*(sp.as_ptr() as *const DEVICE_SEEK_PENALTY_DESCRIPTOR) };
                Some(d.IncursSeekPenalty)
            }
            Err(_) => None,
        };
        let bus_s = bus_name(bus);
        let class = if let Some((_, why)) = prot.iter().find(|(d, _)| *d == n) {
            DiskClass::Excluded(why.clone())
        } else if bus == 17 {
            DiskClass::Excluded("NVMe(M.2)は対象外".into())
        } else if bus == 12 || bus == 13 {
            DiskClass::Excluded("SD/MMCは対象外".into())
        } else if bus == 15 || bus == 14 {
            if allow_virtual {
                DiskClass::Hdd
            } else {
                DiskClass::Excluded("仮想ディスクは対象外".into())
            }
        } else if bus == 7 || bus == 4 {
            // USB/1394: ブリッジ越しの判定は不確実なので、人が判断する
            match seek {
                Some(true) => DiskClass::Unsure("USB接続(回転式と報告)。HDDであることを確認してください".into()),
                Some(false) => DiskClass::Unsure("USB接続(SSD/USBメモリの可能性)。HDDであることを確認してください".into()),
                None => DiskClass::Unsure("USB接続(種別を判定できません)。HDDであることを確認してください".into()),
            }
        } else {
            match seek {
                Some(true) => DiskClass::Hdd,
                Some(false) => DiskClass::Excluded("SSD(シークペナルティなし)は対象外".into()),
                None => {
                    if removable {
                        DiskClass::Unsure("リムーバブル。種別を判定できません".into())
                    } else {
                        DiskClass::Unsure("種別を判定できません。HDDであることを確認してください".into())
                    }
                }
            }
        };
        list.push(DiskInfo {
            number: n,
            identity: DiskIdentity { vendor, model, serial, size, sector_size: ss, bus: bus_s },
            class,
            serial_untrusted: false,
            ident_duplicate: false,
            volumes: drives.iter().filter(|(d, _)| *d == n).map(|(_, t)| t.clone()).collect(),
        });
    }
    // シリアルの信頼性判定
    let serials: Vec<String> = list.iter().map(|d| d.identity.serial.clone()).collect();
    let keys: Vec<String> = list.iter().map(|d| d.identity.key()).collect();
    for (i, d) in list.iter_mut().enumerate() {
        d.ident_duplicate = keys.iter().filter(|k| **k == keys[i]).count() > 1;
        let s = d.identity.serial.trim().to_string();
        let alnum: Vec<char> = s.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
        let all_same = alnum.windows(2).all(|w| w[0] == w[1]);
        let dup = serials.iter().filter(|x| **x == d.identity.serial).count() > 1;
        d.serial_untrusted = alnum.len() < 4 || all_same || dup;
    }
    list
}

// ---------------------------------------------------------------- 実機I/O

/// 重複(オーバーラップ)I/O 1本分の状態。OVERLAPPED のアドレスは固定が必要なので Box で持つ
struct IoSlot {
    ov: OVERLAPPED,
    ev: HANDLE,
    len: usize,
}

unsafe impl Send for IoSlot {}

impl IoSlot {
    fn new() -> io::Result<Box<IoSlot>> {
        let ev = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if ev.is_null() {
            return Err(last_err());
        }
        Ok(Box::new(IoSlot { ov: unsafe { std::mem::zeroed() }, ev, len: 0 }))
    }
    fn prep(&mut self, off: u64, len: usize) {
        self.ov = unsafe { std::mem::zeroed() };
        self.ov.hEvent = self.ev;
        self.ov.Anonymous.Anonymous.Offset = off as u32;
        self.ov.Anonymous.Anonymous.OffsetHigh = (off >> 32) as u32;
        self.len = len;
        unsafe { ResetEvent(self.ev) };
    }
}

impl Drop for IoSlot {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.ev) };
    }
}

pub struct WinDisk {
    h: OwnedHandle,
    ss: u32,
    size: u64,
    sync_slot: Box<IoSlot>,
    slots: Vec<Box<IoSlot>>,
    _locks: Vec<OwnedHandle>,
    /// ロック・マウント解除したボリューム名(診断用)
    pub locked: Vec<String>,
    /// 書込みキャッシュを私たちが変更した場合、終了時に戻す元の値
    cache_restore: Option<bool>,
    /// 開始時のパーティション情報削除の結果(診断用)
    pub layout_note: String,
    /// 応答停止の監視・取り消し用(Engine が attach で設定する)
    watch: Option<Arc<JobShared>>,
}

impl WinDisk {
    /// 対象ディスクのボリュームをロック・マウント解除して物理ドライブを開く。
    /// パーティション情報(ドライブの割り当て)はここでは消さない。途中で中断しても再開できるよう、
    /// 全工程が終わってから `finish_wipe` で消す。
    /// `write_through` が false のときは書込みキャッシュを使う(チェックポイントで flush する前提)。
    pub fn open_for_wipe(number: u32, ss: u32, size: u64, write_through: bool, async_slots: usize) -> io::Result<WinDisk> {
        let mut d = WinDisk::open_with(number, ss, size, write_through, async_slots)?;
        d.layout_note = "パーティション情報は全工程の完了後に削除します".to_string();
        Ok(d)
    }

    /// ボリュームのロックとディスクのオープンまで(パーティション情報はそのまま)
    pub fn open_with(number: u32, ss: u32, size: u64, write_through: bool, async_slots: usize) -> io::Result<WinDisk> {
        let (locks, locked) = lock_volumes_of(number)?;
        let mut flags = FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED;
        if write_through {
            flags |= FILE_FLAG_WRITE_THROUGH;
        }
        let h = open_path(&format!(r"\\.\PhysicalDrive{number}"), GENERIC_READ | GENERIC_WRITE, flags)
            .map_err(|e| io::Error::new(e.kind(), format!("ディスクを開けません(管理者権限が必要です): {e}")))?;
        let _ = ioctl_noout(h.0, FSCTL_ALLOW_EXTENDED_DASD_IO_CODE);
        let mut slots = Vec::new();
        for _ in 0..async_slots {
            slots.push(IoSlot::new()?);
        }
        Ok(WinDisk { h, ss, size, sync_slot: IoSlot::new()?, slots, _locks: locks, locked, cache_restore: None, layout_note: String::new(), watch: None })
    }

    fn cache_info(&self) -> io::Result<[u8; 24]> {
        // DISK_CACHE_INFORMATION: ParametersSavable(1) ReadCacheEnabled(1) WriteCacheEnabled(1) pad(1)
        //   ReadRetentionPriority(4) WriteRetentionPriority(4) + 共用体(8) = 24バイト程度
        let mut out = [0u8; 24];
        ioctl::<(), u8>(self.h.0, IOCTL_DISK_GET_CACHE_INFORMATION_CODE, None, &mut out)?;
        Ok(out)
    }

    pub fn write_cache_enabled(&self) -> io::Result<bool> {
        Ok(self.cache_info()?[2] != 0)
    }

    fn set_write_cache(&self, on: bool) -> io::Result<()> {
        let mut info = self.cache_info()?;
        info[2] = on as u8;
        ioctl::<[u8; 24], u8>(self.h.0, IOCTL_DISK_SET_CACHE_INFORMATION_CODE, Some(&info), &mut [])?;
        Ok(())
    }

    /// ディスクの書込みキャッシュを有効にする(終了時に元の設定へ戻す)。結果の説明を返す
    pub fn enable_write_cache(&mut self) -> String {
        match self.write_cache_enabled() {
            Ok(true) => "ディスクの書込みキャッシュ: すでに有効".to_string(),
            Ok(false) => match self.set_write_cache(true) {
                Ok(()) => {
                    self.cache_restore = Some(false);
                    "ディスクの書込みキャッシュ: 無効だったため有効にしました(終了時に元へ戻します)".to_string()
                }
                Err(e) => format!("ディスクの書込みキャッシュ: 無効です。有効にできませんでした({e})"),
            },
            Err(e) => format!("ディスクの書込みキャッシュ: 状態を取得できません({e})。この接続では変更できない可能性があります"),
        }
    }

    /// 書込み位置別の診断: 読んだ内容をそのまま書き戻す(データは変わらない)
    pub fn probe_writes(&mut self) -> String {
        let ss = self.ss as usize;
        let size = self.size;
        let mut buf = AlignedBuf::new(1 << 20);
        let mut offs: Vec<u64> = vec![0, 512, 1 << 20, 1 << 30, (100u64 << 30), size / 2 / 4096 * 4096, size.saturating_sub(1 << 20) / 4096 * 4096];
        offs.retain(|&o| o + (1 << 20) <= size);
        offs.dedup();
        let mut out = Vec::new();
        for off in offs {
            for len in [ss, 1usize << 20] {
                let o = off / ss as u64 * ss as u64;
                let r = self.read_at(o, &mut buf.as_mut_slice()[..len]);
                let res = match r {
                    Err(e) => format!("読込み失敗({})", crate::engine::os_label(&e)),
                    Ok(()) => match self.write_at(o, &buf.as_slice()[..len]) {
                        Ok(()) => "書込み成功".to_string(),
                        Err(e) => format!("書込み失敗({})", crate::engine::os_label(&e)),
                    },
                };
                out.push(format!("  オフセット {o:>14} 長さ {len:>8}: {res}"));
            }
        }
        out.join("\n")
    }

    /// パーティション情報を削除し、OSに再認識させる(失敗しても続行)
    pub fn delete_layout(&mut self) -> String {
        let a = ioctl_noout(self.h.0, IOCTL_DISK_DELETE_DRIVE_LAYOUT);
        let b = ioctl_noout(self.h.0, IOCTL_DISK_UPDATE_PROPERTIES);
        format!(
            "パーティション情報の削除: {} / プロパティ更新: {}",
            a.map(|_| "成功".to_string()).unwrap_or_else(|e| format!("失敗({e})")),
            b.map(|_| "成功".to_string()).unwrap_or_else(|e| format!("失敗({e})"))
        )
    }

    /// ディスク属性(bit0=オフライン, bit1=読み取り専用)
    pub fn attributes(&self) -> io::Result<u64> {
        let mut out = [0u64; 2]; // GET_DISK_ATTRIBUTES: Version(4) Reserved(4) Attributes(8)
        ioctl::<(), u64>(self.h.0, IOCTL_DISK_GET_DISK_ATTRIBUTES_CODE, None, &mut out)?;
        Ok(out[1])
    }

    pub fn attributes_text(&self) -> String {
        match self.attributes() {
            Ok(a) => format!(
                "ディスク属性: 読み取り専用={} / オフライン={}",
                if a & 2 != 0 { "はい" } else { "いいえ" },
                if a & 1 != 0 { "はい" } else { "いいえ" }
            ),
            Err(e) => format!("ディスク属性を取得できません({e})"),
        }
    }

    /// 読み取り専用・オフラインの属性を解除する。実施した内容を返す
    pub fn try_enable_write(&mut self) -> String {
        let mut notes = Vec::new();
        if let Ok(a) = self.attributes() {
            for (bit, name) in [(2u64, "読み取り専用"), (1u64, "オフライン")] {
                if a & bit != 0 {
                    // SET_DISK_ATTRIBUTES: Version(4) Persist(1) Reserved(3) Attributes(8) Mask(8) Reserved2(16)
                    let mut inp = [0u8; 40];
                    inp[0..4].copy_from_slice(&40u32.to_le_bytes());
                    inp[16..24].copy_from_slice(&bit.to_le_bytes());
                    let r = ioctl::<[u8; 40], u8>(self.h.0, IOCTL_DISK_SET_DISK_ATTRIBUTES_CODE, Some(&inp), &mut []);
                    notes.push(format!("{name}属性の解除: {}", r.map(|_| "成功".to_string()).unwrap_or_else(|e| format!("失敗({e})"))));
                }
            }
        }
        if notes.is_empty() { "解除が必要な属性はありませんでした".into() } else { notes.join(" / ") }
    }

    /// テスト用: 通常ファイルを物理ディスクの代わりに開く(同じオーバーラップI/Oの経路を通る)
    #[cfg(test)]
    pub fn open_file_for_test(path: &str, ss: u32, size: u64, write_through: bool, async_slots: usize) -> io::Result<WinDisk> {
        let mut flags = FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED;
        if write_through {
            flags |= FILE_FLAG_WRITE_THROUGH;
        }
        let h = open_path(path, GENERIC_READ | GENERIC_WRITE, flags)?;
        let mut slots = Vec::new();
        for _ in 0..async_slots {
            slots.push(IoSlot::new()?);
        }
        Ok(WinDisk { h, ss, size, sync_slot: IoSlot::new()?, slots, _locks: vec![], locked: vec![], cache_restore: None, layout_note: String::new(), watch: None })
    }

    fn issue(h: HANDLE, write: bool, slot: &mut IoSlot, ptr: *mut u8, len: usize, off: u64) -> io::Result<()> {
        slot.prep(off, len);
        let ok = unsafe {
            if write {
                WriteFile(h, ptr as *const u8, len as u32, std::ptr::null_mut(), &mut slot.ov)
            } else {
                ReadFile(h, ptr, len as u32, std::ptr::null_mut(), &mut slot.ov)
            }
        };
        if ok == 0 {
            let e = unsafe { GetLastError() };
            if e != ERROR_IO_PENDING {
                return Err(io::Error::from_raw_os_error(e as i32));
            }
        }
        Ok(())
    }

    /// I/O の完了を待つ。0.5秒ごとに様子を見て、応答停止の秒数を共有状態へ出す。
    /// `cancellable` のとき、中断指示(または10秒以上応答なしでの一時停止指示)があれば I/O を取り消す。
    /// 取り消しにも20秒応じなければ `StallAbort { hung: true }` を返す(バッファはカーネルが参照中の可能性がある)。
    fn wait(h: HANDLE, slot: &mut IoSlot, watch: &Option<Arc<JobShared>>, cancellable: bool) -> io::Result<()> {
        use crate::dev::StallAbort;
        use crate::engine::{CMD_PAUSE, CMD_STOP};
        use std::sync::atomic::Ordering;
        let start = Instant::now();
        let mut cancelled: Option<Instant> = None;
        loop {
            if unsafe { WaitForSingleObject(slot.ev, 500) } != WAIT_TIMEOUT {
                break;
            }
            let stalled = start.elapsed().as_secs();
            if let Some(w) = watch {
                w.stall_secs.store(stalled, Ordering::Relaxed);
                if cancellable && cancelled.is_none() {
                    let cmd = w.cmd.load(Ordering::SeqCst);
                    // 中断なら即時、一時停止なら10秒、実行中でも90秒まったく進まなければ取り消す
                    // (書込みは何度やり直しても同じ結果になるので、取り消して発行し直しても安全)
                    if cmd == CMD_STOP || (cmd == CMD_PAUSE && stalled >= 10) || stalled >= AUTO_CANCEL_SECS {
                        unsafe { CancelIoEx(h, &slot.ov) };
                        cancelled = Some(Instant::now());
                    }
                }
            }
            if let Some(c) = cancelled {
                if c.elapsed() > Duration::from_secs(20) {
                    if let Some(w) = watch {
                        w.stall_secs.store(0, Ordering::Relaxed);
                    }
                    return Err(io::Error::new(io::ErrorKind::Interrupted, StallAbort { hung: true }));
                }
            }
        }
        if let Some(w) = watch {
            w.stall_secs.store(0, Ordering::Relaxed);
        }
        let mut n = 0u32;
        let ok = unsafe { GetOverlappedResult(h, &slot.ov, &mut n, 0) };
        if ok == 0 {
            if cancelled.is_some() {
                return Err(io::Error::new(io::ErrorKind::Interrupted, StallAbort { hung: false }));
            }
            Err(last_err())
        } else if n as usize != slot.len {
            Err(io::Error::new(io::ErrorKind::UnexpectedEof, "転送バイト数が不足"))
        } else {
            Ok(())
        }
    }
}

/// 全ボリュームの一覧(どのディスクにあるか、ドライブ文字は何か)。診断用
pub fn volume_overview() -> Vec<String> {
    let mut out = Vec::new();
    let mut name = [0u16; 261];
    let fh = unsafe { FindFirstVolumeW(name.as_mut_ptr(), 261) };
    if fh == INVALID_HANDLE_VALUE {
        return vec![format!("ボリュームを列挙できません({})", last_err())];
    }
    loop {
        let len = name.iter().position(|&c| c == 0).unwrap_or(0);
        let with_slash = String::from_utf16_lossy(&name[..len]);
        let no_slash = with_slash.trim_end_matches('\\').to_string();
        let disks = volume_disk_numbers(&no_slash);
        let mut paths = [0u16; 512];
        let mut ret = 0u32;
        let w = wide(&with_slash);
        let ok = unsafe { GetVolumePathNamesForVolumeNameW(w.as_ptr(), paths.as_mut_ptr(), 512, &mut ret) };
        let mounts: Vec<String> = if ok != 0 {
            String::from_utf16_lossy(&paths[..(ret as usize).min(512)])
                .split('\0')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        } else {
            vec![]
        };
        out.push(format!("  {no_slash}  ディスク番号={disks:?}  マウント先={mounts:?}"));
        if unsafe { FindNextVolumeW(fh, name.as_mut_ptr(), 261) } == 0 {
            break;
        }
    }
    unsafe { FindVolumeClose(fh) };
    out
}

/// ボリュームのロックに成功した経路
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum LockOutcome {
    /// そのままロックできた
    Locked,
    /// 使用中のファイルがあり、強制的にマウント解除してからロックできた
    LockedAfterDismount,
    /// 使用中のファイルがあり、ロックはできないが強制的にマウント解除した(ハンドルを持ち続ける限り再マウントされない)
    DismountedOnly,
}

/// ロックを試し、使用中のファイルがあって拒否されたら、再試行 → 強制マウント解除 → 再ロックの順に対処する。
/// ディスク全体を消去する前提なので、使用中のアプリのハンドルは無効にしてよい。
/// `wait` は待機(ミリ秒)。テストで差し替える。
fn lock_with_fallback(
    lock: &mut dyn FnMut() -> io::Result<()>,
    dismount: &mut dyn FnMut() -> io::Result<()>,
    wait: &dyn Fn(u64),
) -> Result<LockOutcome, String> {
    let mut last = String::new();
    // 1) インデックス作成・ウイルススキャンなどの一時的なハンドルが閉じるのを待つ
    for i in 0..6 {
        match lock() {
            Ok(()) => return Ok(LockOutcome::Locked),
            Err(e) => last = e.to_string(),
        }
        if i < 5 {
            wait(1000);
        }
    }
    // 2) 強制的にマウント解除して、使用中のハンドルをすべて無効にする
    if let Err(e) = dismount() {
        return Err(format!("ロック: {last} / 強制マウント解除も失敗: {e}"));
    }
    // 3) 解除後は使用中のファイルがなくなるので、ロックし直す
    for i in 0..3 {
        if lock().is_ok() {
            return Ok(LockOutcome::LockedAfterDismount);
        }
        if i < 2 {
            wait(500);
        }
    }
    Ok(LockOutcome::DismountedOnly)
}

/// ボリュームのドライブ文字・マウント先(例: "G:\\")
fn mount_points_of(vol_no_slash: &str) -> Vec<String> {
    let with_slash = format!("{vol_no_slash}\\");
    let w = wide(&with_slash);
    let mut paths = [0u16; 512];
    let mut ret = 0u32;
    let ok = unsafe { GetVolumePathNamesForVolumeNameW(w.as_ptr(), paths.as_mut_ptr(), 512, &mut ret) };
    if ok == 0 {
        return vec![];
    }
    String::from_utf16_lossy(&paths[..(ret as usize).min(512)])
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// ボリュームのラベル(ボリューム名)。取得できなければ空。マウント解除前に呼ぶこと。
fn volume_label_of(vol_no_slash: &str) -> String {
    let w = wide(&format!("{vol_no_slash}\\"));
    let mut label = [0u16; 261];
    let ok = unsafe {
        GetVolumeInformationW(
            w.as_ptr(),
            label.as_mut_ptr(),
            261,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
        )
    };
    if ok == 0 {
        return String::new();
    }
    let len = label.iter().position(|&c| c == 0).unwrap_or(0);
    String::from_utf16_lossy(&label[..len])
}

/// 表示用のドライブ名。例: "G:\ 「HD-ADU3」"。ドライブ文字がなければボリューム名のみ。
fn drive_display(vol_no_slash: &str, label: &str) -> String {
    let mp = mount_points_of(vol_no_slash);
    let letters = if mp.is_empty() { "(ドライブ文字なし)".to_string() } else { mp.join(", ") };
    if label.is_empty() {
        letters
    } else {
        format!("{letters} 「{label}」")
    }
}

fn lock_volumes_of(number: u32) -> io::Result<(Vec<OwnedHandle>, Vec<String>)> {
    let mut locks = Vec::new();
    let mut names = Vec::new();
    let mut name = [0u16; 261];
    let fh = unsafe { FindFirstVolumeW(name.as_mut_ptr(), 261) };
    if fh == INVALID_HANDLE_VALUE {
        return Ok((locks, names));
    }
    loop {
        let len = name.iter().position(|&c| c == 0).unwrap_or(0);
        let mut vol = String::from_utf16_lossy(&name[..len]);
        if vol.ends_with('\\') {
            vol.pop();
        }
        if volume_disk_numbers(&vol).contains(&number) {
            let h = open_path(&vol, GENERIC_READ | GENERIC_WRITE, 0).map_err(|e| {
                let drive = drive_display(&vol, &volume_label_of(&vol));
                io::Error::new(
                    e.kind(),
                    format!(
                        "ボリューム {vol} ({drive}) を開けません: {e}\n\
                         【多くの場合の原因】前回起動したこのツール(別のプロセス)が、そのボリュームをロックしたまま残っています。\n\
                         タスクマネージャーで「hdd-wiper」または「HDD完全消去ツール」が他に動いていないか確認し、残っていれば終了してから再開してください。"
                    ),
                )
            })?;
            let hh = h.0 as usize;
            // ラベルはマウント解除すると読めなくなるため、先に取得しておく
            let label = volume_label_of(&vol);
            let outcome = lock_with_fallback(
                &mut || ioctl_noout(hh as HANDLE, FSCTL_LOCK_VOLUME),
                &mut || ioctl_noout(hh as HANDLE, FSCTL_DISMOUNT_VOLUME),
                &|ms| std::thread::sleep(std::time::Duration::from_millis(ms)),
            )
            .map_err(|why| {
                let drive = drive_display(&vol, &label);
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "ボリューム {vol} ({drive}) をロックできず、強制マウント解除もできませんでした: {why}\n\
                         【考えられる原因と対処】\n\
                         ・{drive} をエクスプローラー、コマンドプロンプト、他のアプリで開いていれば閉じてください\n\
                         ・ウイルス対策ソフト・バックアップ・同期ソフトが {drive} を監視している場合は、一時的に除外または停止してください\n\
                         ・{drive} にページファイルやアプリのデータがないか確認してください\n\
                         ・管理者として実行していない場合は、「管理者として実行」で起動し直してください\n\
                         ・どうしても解決しない場合は、ディスクを一度取り外して接続し直す(再接続後は未使用の状態になります)か、WinPE からの消去を使ってください"
                    ),
                )
            })?;
            let dm_note = match outcome {
                LockOutcome::Locked => {
                    let dm = ioctl_noout(h.0, FSCTL_DISMOUNT_VOLUME);
                    format!("ロック成功 / マウント解除: {}", if dm.is_ok() { "成功" } else { "失敗" })
                }
                LockOutcome::LockedAfterDismount => {
                    "使用中のファイルがあったため、強制マウント解除してからロックしました".to_string()
                }
                LockOutcome::DismountedOnly => {
                    "使用中のファイルがあったため、ロックせず強制マウント解除しました(ハンドルを保持して再マウントを防ぎます)".to_string()
                }
            };
            names.push(format!("{vol} [{}] ({dm_note})", drive_display(&vol, &label)));
            locks.push(h);
        }
        if unsafe { FindNextVolumeW(fh, name.as_mut_ptr(), 261) } == 0 {
            break;
        }
    }
    unsafe { FindVolumeClose(fh) };
    Ok((locks, names))
}

impl BlockDev for WinDisk {
    fn attach(&mut self, shared: Arc<JobShared>) {
        self.watch = Some(shared);
    }
    fn sector_size(&self) -> u32 {
        self.ss
    }
    fn total_bytes(&self) -> u64 {
        self.size
    }
    fn write_at(&mut self, off: u64, buf: &[u8]) -> io::Result<()> {
        let h = self.h.0;
        WinDisk::issue(h, true, &mut self.sync_slot, buf.as_ptr() as *mut u8, buf.len(), off)?;
        WinDisk::wait(h, &mut self.sync_slot, &self.watch, false)
    }
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        let h = self.h.0;
        WinDisk::issue(h, false, &mut self.sync_slot, buf.as_mut_ptr(), buf.len(), off)?;
        WinDisk::wait(h, &mut self.sync_slot, &self.watch, false)
    }
    /// FlushFileBuffers は取り消せないので、別スレッドで実行して待つ。
    /// 待っている秒数を共有状態へ出し、中断指示から20秒たっても終わらなければ StallAbort(hung) を返す。
    fn flush(&mut self) -> io::Result<()> {
        use crate::dev::StallAbort;
        use crate::engine::CMD_STOP;
        use std::sync::atomic::Ordering;
        let h = self.h.0 as usize;
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let r = if unsafe { FlushFileBuffers(h as HANDLE) } == 0 { Err(last_err()) } else { Ok(()) };
            let _ = tx.send(r);
        });
        let start = Instant::now();
        let mut stop_seen: Option<Instant> = None;
        loop {
            match rx.recv_timeout(Duration::from_millis(500)) {
                Ok(r) => {
                    if let Some(w) = &self.watch {
                        w.stall_secs.store(0, Ordering::Relaxed);
                    }
                    return r;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if let Some(w) = &self.watch {
                        w.stall_secs.store(start.elapsed().as_secs(), Ordering::Relaxed);
                        if w.cmd.load(Ordering::SeqCst) == CMD_STOP {
                            let s = *stop_seen.get_or_insert_with(Instant::now);
                            if s.elapsed() > Duration::from_secs(20) {
                                w.stall_secs.store(0, Ordering::Relaxed);
                                return Err(io::Error::new(io::ErrorKind::Interrupted, StallAbort { hung: true }));
                            }
                        }
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::other("flush スレッドが異常終了しました"));
                }
            }
        }
    }
    fn async_slots(&self) -> usize {
        self.slots.len()
    }
    unsafe fn begin_write(&mut self, slot: usize, off: u64, ptr: *const u8, len: usize) -> io::Result<()> {
        let h = self.h.0;
        WinDisk::issue(h, true, &mut self.slots[slot], ptr as *mut u8, len, off)
    }
    fn finish_write(&mut self, slot: usize) -> io::Result<()> {
        let h = self.h.0;
        WinDisk::wait(h, &mut self.slots[slot], &self.watch, true)
    }
    unsafe fn begin_read(&mut self, slot: usize, off: u64, ptr: *mut u8, len: usize) -> io::Result<()> {
        let h = self.h.0;
        WinDisk::issue(h, false, &mut self.slots[slot], ptr, len, off)
    }
    fn finish_read(&mut self, slot: usize) -> io::Result<()> {
        let h = self.h.0;
        WinDisk::wait(h, &mut self.slots[slot], &self.watch, true)
    }
    fn write_raw(&mut self, off: u64, buf: &[u8]) -> io::Result<()> {
        self.write_at(off, buf)
    }
    fn read_raw(&mut self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        self.read_at(off, buf)
    }
    /// 全工程が終わってから、パーティション情報を削除して OS に再認識させる
    fn finish_wipe(&mut self) -> String {
        self.delete_layout()
    }
}

impl Drop for WinDisk {
    fn drop(&mut self) {
        if let Some(orig) = self.cache_restore.take() {
            let _ = self.set_write_cache(orig);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::*;
    use crate::state::*;

    #[test]
    fn lock_succeeds_first_try() {
        let mut calls = 0;
        let r = lock_with_fallback(&mut || { calls += 1; Ok(()) }, &mut || panic!("呼ばれない"), &|_| {});
        assert_eq!(r, Ok(LockOutcome::Locked));
        assert_eq!(calls, 1);
    }

    #[test]
    fn lock_retries_while_transient_handle_is_open() {
        let mut calls = 0;
        let waits = std::cell::Cell::new(0);
        let r = lock_with_fallback(
            &mut || { calls += 1; if calls < 4 { Err(io::Error::from_raw_os_error(5)) } else { Ok(()) } },
            &mut || panic!("再試行で成功すれば強制解除しない"),
            &|_| waits.set(waits.get() + 1),
        );
        assert_eq!(r, Ok(LockOutcome::Locked));
        assert_eq!(waits.get(), 3);
    }

    #[test]
    fn lock_falls_back_to_forced_dismount_then_lock() {
        // 使用中のファイルがある間はロックできず、マウント解除後はロックできる
        let dismounted = std::cell::Cell::new(false);
        let mut lock = || if dismounted.get() { Ok(()) } else { Err(io::Error::from_raw_os_error(5)) };
        let mut dm = || { dismounted.set(true); Ok(()) };
        let r = lock_with_fallback(&mut lock, &mut dm, &|_| {});
        assert_eq!(r, Ok(LockOutcome::LockedAfterDismount));
    }

    #[test]
    fn lock_continues_when_only_dismount_works() {
        let mut dm_calls = 0;
        let r = lock_with_fallback(&mut || Err(io::Error::from_raw_os_error(5)), &mut || { dm_calls += 1; Ok(()) }, &|_| {});
        assert_eq!(r, Ok(LockOutcome::DismountedOnly));
        assert_eq!(dm_calls, 1);
    }

    #[test]
    fn lock_fails_when_nothing_works() {
        let r = lock_with_fallback(
            &mut || Err(io::Error::from_raw_os_error(5)),
            &mut || Err(io::Error::from_raw_os_error(5)),
            &|_| {},
        );
        let e = r.unwrap_err();
        assert!(e.contains("強制マウント解除も失敗"), "{e}");
    }

    fn run_on_file(write_through: bool, depth: usize) {
        run_on_file_mode(write_through, depth, EraseMode::Standard, false);
    }

    fn run_on_file_mode(write_through: bool, depth: usize, mode: EraseMode, autotune: bool) {
        let dir = std::env::temp_dir().join(format!("hddwiper_win_{}_{}_{:?}_{}_{}", write_through, depth, mode, autotune, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let img = dir.join("disk.img");
        let size: u64 = 8 << 20;
        // 元データ(非ゼロ)で埋めたイメージ
        let init: Vec<u8> = (0..size as usize).map(|i| (i as u8).wrapping_mul(13) | 1).collect();
        std::fs::write(&img, &init).unwrap();
        let dev = WinDisk::open_file_for_test(img.to_str().unwrap(), 512, size, write_through, 4).expect("open");
        let shared = JobShared::new(size, 512);
        shared.set_cmd(CMD_RUN, REASON_USER);
        let id = DiskIdentity { vendor: "T".into(), model: "FILE".into(), serial: "WINTEST1".into(), size, sector_size: 512, bus: "FILE".into() };
        let cfg = EngineCfg { block: 256 * 1024, queue_depth: depth, write_through, checkpoint_bytes: 1 << 20, checkpoint_secs: 1, autotune, tune_min_size: 0, tune_warmup_ms: 5, tune_probe_ms: 10, ..EngineCfg::default() };
        let mut e = Engine::new(Box::new(dev), shared.clone(), JobState::new_with_mode(id, 9, mode), dir.join("resume.json"), dir.clone(), cfg);
        assert_eq!(e.run().unwrap(), Outcome::Finished);
        drop(e);
        let out = std::fs::read(&img).unwrap();
        assert_eq!(out.len() as u64, size);
        assert!(out.iter().all(|&b| b == 0), "最終的に全域ゼロ");
        assert_eq!(shared.snapshot().bad_sectors, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn overlapped_io_pipeline_on_file() {
        run_on_file(false, 3);
    }

    #[test]
    fn overlapped_io_write_through_on_file() {
        run_on_file(true, 3);
    }

    #[test]
    fn overlapped_io_sequential_on_file() {
        run_on_file(false, 1);
    }

    #[test]
    fn overlapped_io_all_modes_on_file() {
        for mode in EraseMode::ALL {
            run_on_file_mode(false, 3, mode, false);
        }
    }

    #[test]
    fn overlapped_io_autotune_on_file() {
        run_on_file_mode(false, 3, EraseMode::Standard, true);
    }
}
