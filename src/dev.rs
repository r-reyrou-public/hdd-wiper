//! ブロックデバイス抽象。実機(Windows物理ドライブ)とテスト用の模擬デバイスを共通で扱う。

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::io;

/// 応答しないI/Oを取り消したことを示すエラー(不良セクタとして扱ってはいけない)
#[derive(Debug)]
pub struct StallAbort {
    /// 取り消し要求にもディスクが応じず、I/Oが完了しなかった
    pub hung: bool,
}

impl std::fmt::Display for StallAbort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.hung {
            write!(f, "ディスクが応答せず、取り消しにも応じませんでした")
        } else {
            write!(f, "ディスクが応答しないため、I/Oを取り消しました")
        }
    }
}

impl std::error::Error for StallAbort {}

pub trait BlockDev: Send {
    /// ジョブの共有状態を結びつける(応答停止の監視と、中断指示によるI/O取り消しに使う)
    fn attach(&mut self, _shared: std::sync::Arc<crate::engine::JobShared>) {}

    fn sector_size(&self) -> u32;
    fn total_bytes(&self) -> u64;
    fn write_at(&mut self, off: u64, buf: &[u8]) -> io::Result<()>;
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> io::Result<()>;
    fn flush(&mut self) -> io::Result<()>;

    /// 非同期(重ね書き)に使えるスロット数。0なら非対応
    fn async_slots(&self) -> usize {
        0
    }
    /// 書込みを発行して即座に戻る。`ptr` は finish_write が戻るまで有効であること。
    ///
    /// # Safety
    /// `ptr` から `len` バイトが、対応する `finish_write` 完了まで有効かつ移動しないこと。
    unsafe fn begin_write(&mut self, _slot: usize, _off: u64, _ptr: *const u8, _len: usize) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "非同期書込み非対応"))
    }
    /// begin_write の完了を待つ
    fn finish_write(&mut self, _slot: usize) -> io::Result<()> {
        Ok(())
    }
    /// 読込みを発行して即座に戻る。
    ///
    /// # Safety
    /// `ptr` から `len` バイトが、対応する `finish_read` 完了まで有効かつ移動しないこと。
    unsafe fn begin_read(&mut self, _slot: usize, _off: u64, _ptr: *mut u8, _len: usize) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "非同期読込み非対応"))
    }
    /// begin_read の完了を待つ
    fn finish_read(&mut self, _slot: usize) -> io::Result<()> {
        Ok(())
    }

    /// 通常の工程から外し、全工程の最後に消す物理範囲 (物理オフセット, 長さ)。
    /// パーティション情報・ドライブの割り当てなど、途中で消すと再開できなくなる領域
    fn deferred_ranges(&self) -> Vec<(u64, u64)> {
        vec![]
    }
    /// `deferred_ranges` の範囲を物理オフセットのまま書く
    fn write_raw(&mut self, _off: u64, _buf: &[u8]) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "非対応"))
    }
    /// `deferred_ranges` の範囲を物理オフセットのまま読む
    fn read_raw(&mut self, _off: u64, _buf: &mut [u8]) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "非対応"))
    }
    /// 全工程が終わったあとに呼ぶ。パーティション情報の削除など。結果の説明を返す
    fn finish_wipe(&mut self) -> String {
        String::new()
    }
}

/// ディスクの先頭 `head` バイトと末尾 `tail` バイトを工程から外し、間の部分だけを見せるデバイス。
/// 外した範囲は、最後に Engine が `write_raw` で消す。
/// (先頭にはパーティション表とボリュームの起動情報があり、途中で消すとドライブとして認識できなくなって再開しづらいため)
pub struct DeferEnds {
    inner: Box<dyn BlockDev>,
    head: u64,
    tail: u64,
}

impl DeferEnds {
    pub fn new(inner: Box<dyn BlockDev>, head: u64, tail: u64) -> Self {
        DeferEnds { inner, head, tail }
    }
}

impl BlockDev for DeferEnds {
    fn attach(&mut self, shared: std::sync::Arc<crate::engine::JobShared>) {
        self.inner.attach(shared);
    }
    fn sector_size(&self) -> u32 {
        self.inner.sector_size()
    }
    fn total_bytes(&self) -> u64 {
        self.inner.total_bytes() - self.head - self.tail
    }
    fn write_at(&mut self, off: u64, buf: &[u8]) -> io::Result<()> {
        self.inner.write_at(off + self.head, buf)
    }
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        self.inner.read_at(off + self.head, buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
    fn async_slots(&self) -> usize {
        self.inner.async_slots()
    }
    unsafe fn begin_write(&mut self, slot: usize, off: u64, ptr: *const u8, len: usize) -> io::Result<()> {
        unsafe { self.inner.begin_write(slot, off + self.head, ptr, len) }
    }
    fn finish_write(&mut self, slot: usize) -> io::Result<()> {
        self.inner.finish_write(slot)
    }
    unsafe fn begin_read(&mut self, slot: usize, off: u64, ptr: *mut u8, len: usize) -> io::Result<()> {
        unsafe { self.inner.begin_read(slot, off + self.head, ptr, len) }
    }
    fn finish_read(&mut self, slot: usize) -> io::Result<()> {
        self.inner.finish_read(slot)
    }
    fn deferred_ranges(&self) -> Vec<(u64, u64)> {
        let mut v = Vec::new();
        if self.head > 0 {
            v.push((0, self.head));
        }
        if self.tail > 0 {
            v.push((self.inner.total_bytes() - self.tail, self.tail));
        }
        v
    }
    fn write_raw(&mut self, off: u64, buf: &[u8]) -> io::Result<()> {
        self.inner.write_at(off, buf)
    }
    fn read_raw(&mut self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        self.inner.read_at(off, buf)
    }
    fn finish_wipe(&mut self) -> String {
        self.inner.finish_wipe()
    }
}

/// 4096バイト境界に揃えたバッファ(バッファなしI/Oに必要)
pub struct AlignedBuf {
    ptr: *mut u8,
    len: usize,
}

unsafe impl Send for AlignedBuf {}

impl AlignedBuf {
    pub fn new(len: usize) -> Self {
        let layout = Layout::from_size_align(len, 4096).expect("layout");
        let ptr = unsafe { alloc_zeroed(layout) };
        assert!(!ptr.is_null(), "メモリ確保に失敗しました");
        AlignedBuf { ptr, len }
    }
    pub fn ptr(&self) -> *const u8 {
        self.ptr
    }
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        let layout = Layout::from_size_align(self.len, 4096).expect("layout");
        unsafe { dealloc(self.ptr, layout) };
    }
}

// ---------------------------------------------------------------- 模擬デバイス (テスト用)

#[cfg(test)]
pub mod fake {
    use super::*;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    pub struct FakeInner {
        pub data: Vec<u8>,
        pub ss: u32,
        pub bad_write: HashSet<u64>,
        pub bad_read: HashSet<u64>,
        /// true なら、全ての読み書きが OSエラー433(デバイスが存在しない)で失敗する
        pub gone: bool,
        /// 書込みが成功扱いだが反映されないセクタ
        pub silent_drop: HashSet<u64>,
        pub write_calls: u64,
        /// N回目の書込み後に中断指示を出す
        /// 書込みは成功するがキャッシュから落ち、flush で初めてエラーになるセクタ
        pub deferred_bad: HashSet<u64>,
        pub pending_err: bool,
        pub async_results: std::collections::HashMap<usize, bool>,
        pub stop_after: Option<(u64, std::sync::Arc<crate::engine::JobShared>)>,
    }

    #[derive(Clone)]
    pub struct FakeDev(pub Arc<Mutex<FakeInner>>);

    impl FakeDev {
        pub fn new(size: usize, ss: u32) -> Self {
            let mut data = vec![0u8; size];
            // 元データとして非ゼロを入れておく
            for (i, b) in data.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(31).wrapping_add(7) | 1;
            }
            FakeDev(Arc::new(Mutex::new(FakeInner {
                data,
                ss,
                bad_write: HashSet::new(),
                bad_read: HashSet::new(),
                gone: false,
                silent_drop: HashSet::new(),
                write_calls: 0,
                deferred_bad: HashSet::new(),
                pending_err: false,
                async_results: std::collections::HashMap::new(),
                stop_after: None,
            })))
        }
    }

    impl BlockDev for FakeDev {
        fn sector_size(&self) -> u32 {
            self.0.lock().unwrap().ss
        }
        fn total_bytes(&self) -> u64 {
            self.0.lock().unwrap().data.len() as u64
        }
        fn write_at(&mut self, off: u64, buf: &[u8]) -> io::Result<()> {
            let mut g = self.0.lock().unwrap();
            g.write_calls += 1;
            if g.gone {
                return Err(io::Error::from_raw_os_error(433));
            }
            if let Some((n, sh)) = &g.stop_after {
                if g.write_calls >= *n {
                    sh.set_cmd(crate::engine::CMD_STOP, crate::engine::REASON_USER);
                }
            }
            let ss = g.ss as u64;
            let first = off / ss;
            let n = buf.len() as u64 / ss;
            for i in 0..n {
                if g.bad_write.contains(&(first + i)) {
                    return Err(io::Error::other("write error"));
                }
            }
            for i in 0..n {
                if g.deferred_bad.contains(&(first + i)) {
                    g.pending_err = true;
                    continue;
                }
                if g.silent_drop.contains(&(first + i)) {
                    continue;
                }
                let o = ((first + i) * ss) as usize;
                let s = (i * ss) as usize;
                g.data[o..o + ss as usize].copy_from_slice(&buf[s..s + ss as usize]);
            }
            Ok(())
        }
        fn read_at(&mut self, off: u64, buf: &mut [u8]) -> io::Result<()> {
            let g = self.0.lock().unwrap();
            if g.gone {
                return Err(io::Error::from_raw_os_error(433));
            }
            let ss = g.ss as u64;
            let first = off / ss;
            let n = buf.len() as u64 / ss;
            for i in 0..n {
                if g.bad_read.contains(&(first + i)) {
                    return Err(io::Error::other("read error"));
                }
            }
            let o = off as usize;
            buf.copy_from_slice(&g.data[o..o + buf.len()]);
            Ok(())
        }
        fn flush(&mut self) -> io::Result<()> {
            let mut g = self.0.lock().unwrap();
            if g.pending_err {
                g.pending_err = false;
                return Err(io::Error::other("flush error"));
            }
            Ok(())
        }
        fn async_slots(&self) -> usize {
            8
        }
        unsafe fn begin_write(&mut self, slot: usize, off: u64, ptr: *const u8, len: usize) -> io::Result<()> {
            let buf = unsafe { std::slice::from_raw_parts(ptr, len) };
            let ok = self.write_at(off, buf).is_ok();
            self.0.lock().unwrap().async_results.insert(slot, ok);
            Ok(())
        }
        fn finish_write(&mut self, slot: usize) -> io::Result<()> {
            let ok = self.0.lock().unwrap().async_results.remove(&slot).unwrap_or(false);
            if ok { Ok(()) } else { Err(io::Error::other("async write error")) }
        }
        unsafe fn begin_read(&mut self, slot: usize, off: u64, ptr: *mut u8, len: usize) -> io::Result<()> {
            let buf = unsafe { std::slice::from_raw_parts_mut(ptr, len) };
            let ok = self.read_at(off, buf).is_ok();
            self.0.lock().unwrap().async_results.insert(slot, ok);
            Ok(())
        }
        fn finish_read(&mut self, slot: usize) -> io::Result<()> {
            let ok = self.0.lock().unwrap().async_results.remove(&slot).unwrap_or(false);
            if ok { Ok(()) } else { Err(io::Error::other("async read error")) }
        }
    }
}
