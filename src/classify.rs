//! 書込み不能だが読み取れたセクタの内容を、中身を残さずに分類する。

use crate::state::{CLASS_ENTROPY, CLASS_OTHER, CLASS_SIGNATURE, CLASS_TEXT, CLASS_ZERO};

pub struct Classification {
    pub classes: u8,
    pub sig: Option<&'static str>,
}

const SIGNATURES: &[(&[u8], usize, &str)] = &[
    (b"\xFF\xD8\xFF", 0, "JPEG"),
    (b"\x89PNG\r\n\x1a\n", 0, "PNG"),
    (b"GIF8", 0, "GIF"),
    (b"%PDF", 0, "PDF"),
    (b"PK\x03\x04", 0, "ZIP/Office"),
    (b"Rar!", 0, "RAR"),
    (b"7z\xBC\xAF\x27\x1C", 0, "7-Zip"),
    (b"ftyp", 4, "MP4/MOV"),
    (b"RIFF", 0, "RIFF(AVI/WAV)"),
    (b"\x1A\x45\xDF\xA3", 0, "MKV/WebM"),
    (b"ID3", 0, "MP3"),
    (b"OggS", 0, "Ogg"),
    (b"MZ", 0, "EXE/DLL"),
    (b"FILE", 0, "NTFS MFTレコード"),
    (b"INDX", 0, "NTFS INDXレコード"),
    (b"SQLite format 3", 0, "SQLite"),
    (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", 0, "旧Office(OLE)"),
];

fn entropy(data: &[u8]) -> f64 {
    let mut hist = [0u32; 256];
    for &b in data {
        hist[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut e = 0.0;
    for &c in hist.iter() {
        if c > 0 {
            let p = c as f64 / n;
            e -= p * p.log2();
        }
    }
    e
}

/// n バイトのランダムデータの期待エントロピーより少し低い値を閾値とする
fn entropy_threshold(n: usize) -> f64 {
    let expected = 8.0 - 255.0 / (2.0 * n as f64 * std::f64::consts::LN_2);
    expected - 0.35
}

pub fn classify(sector: &[u8]) -> Classification {
    if sector.iter().all(|&b| b == 0) {
        return Classification { classes: CLASS_ZERO, sig: None };
    }
    let mut classes = 0u8;
    let mut sig = None;
    for (magic, off, name) in SIGNATURES {
        if sector.len() >= off + magic.len() && &sector[*off..*off + magic.len()] == *magic {
            classes |= CLASS_SIGNATURE;
            sig = Some(*name);
            break;
        }
    }
    // 文字列らしさ: 印字可能ASCII+空白類が大半、またはUTF-8として正しく日本語等を含む
    let printable = sector
        .iter()
        .filter(|&&b| (0x20..0x7F).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t')
        .count();
    let mut is_text = printable * 100 >= sector.len() * 85;
    if !is_text {
        let valid_len = match std::str::from_utf8(sector) {
            Ok(_) => sector.len(),
            Err(e) => {
                if e.error_len().is_none() {
                    e.valid_up_to()
                } else {
                    0
                }
            }
        };
        if valid_len + 4 >= sector.len() {
            let s = &sector[..valid_len];
            let ctrl = s.iter().filter(|&&b| b < 0x20 && b != b'\n' && b != b'\r' && b != b'\t').count();
            let multibyte = s.iter().filter(|&&b| b >= 0x80).count();
            if multibyte > 0 && ctrl * 100 < s.len() * 5 {
                is_text = true;
            }
        }
    }
    if is_text {
        classes |= CLASS_TEXT;
    }
    if sector.len() >= 512 && entropy(sector) >= entropy_threshold(sector.len()) {
        classes |= CLASS_ENTROPY;
    }
    if classes == 0 {
        classes = CLASS_OTHER;
    }
    Classification { classes, sig }
}

pub fn class_names(classes: u8) -> Vec<&'static str> {
    let mut v = Vec::new();
    if classes & CLASS_ZERO != 0 {
        v.push("全て0");
    }
    if classes & CLASS_TEXT != 0 {
        v.push("文字列らしい");
    }
    if classes & CLASS_SIGNATURE != 0 {
        v.push("既知のファイル署名あり");
    }
    if classes & CLASS_ENTROPY != 0 {
        v.push("高エントロピー(動画・圧縮・暗号化データの可能性)");
    }
    if classes & CLASS_OTHER != 0 {
        v.push("その他(0以外のデータ)");
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_sector() {
        let c = classify(&[0u8; 512]);
        assert_eq!(c.classes, CLASS_ZERO);
    }

    #[test]
    fn jpeg_signature() {
        let mut s = vec![0u8; 512];
        s[..3].copy_from_slice(b"\xFF\xD8\xFF");
        s[3] = 0xE0;
        let c = classify(&s);
        assert!(c.classes & CLASS_SIGNATURE != 0);
        assert_eq!(c.sig, Some("JPEG"));
    }

    #[test]
    fn text_sector() {
        let s: Vec<u8> = b"hello world, this is plain text. ".iter().cycle().take(512).copied().collect();
        assert!(classify(&s).classes & CLASS_TEXT != 0);
    }

    #[test]
    fn random_sector_is_high_entropy() {
        let mut x: u64 = 0x1234_5678_9abc_def1;
        let s: Vec<u8> = (0..512)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect();
        assert!(classify(&s).classes & CLASS_ENTROPY != 0);
    }
}
