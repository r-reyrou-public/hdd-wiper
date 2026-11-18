"""アイコン生成: HDDのプラッタ + 消去済み(赤)のセクタ。
出力: assets/icon.ico, assets/icon.res (exe埋め込み用), assets/icon_128.rgba (ウィンドウ用)
使い方: python tools/make_icon.py
"""
import io
import math
import os
import struct

from PIL import Image, ImageDraw, ImageFilter

S = 1024
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "assets")
os.makedirs(OUT, exist_ok=True)


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def vgrad(size, top, bottom):
    img = Image.new("RGB", (size, size))
    px = img.load()
    for y in range(size):
        c = lerp(top, bottom, y / (size - 1))
        for x in range(size):
            px[x, y] = c
    return img


def render():
    # 背景: 角丸の濃紺
    bg = vgrad(S, (38, 60, 92), (12, 20, 34)).convert("RGBA")
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle((16, 16, S - 16, S - 16), radius=210, fill=255)
    base = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    base.paste(bg, (0, 0), mask)

    d = ImageDraw.Draw(base)
    cx = cy = S // 2
    R = 372
    # プラッタ(銀)
    plat = vgrad(S, (236, 242, 248), (150, 162, 176)).convert("RGBA")
    pm = Image.new("L", (S, S), 0)
    ImageDraw.Draw(pm).ellipse((cx - R, cy - R, cx + R, cy + R), fill=255)
    base.paste(plat, (0, 0), pm)
    # 同心円のトラック
    for r in range(130, R, 46):
        d.ellipse((cx - r, cy - r, cx + r, cy + r), outline=(120, 132, 148, 150), width=5)
    # 赤い扇形 = 消去済みセクタ
    box = (cx - R, cy - R, cx + R, cy + R)
    d.pieslice(box, -78, 8, fill=(229, 57, 53, 255), outline=(255, 255, 255, 255), width=10)
    # 外周の縁
    d.ellipse(box, outline=(255, 255, 255, 255), width=12)
    # 中央のハブ
    d.ellipse((cx - 92, cy - 92, cx + 92, cy + 92), fill=(40, 52, 70, 255), outline=(255, 255, 255, 255), width=8)
    d.ellipse((cx - 28, cy - 28, cx + 28, cy + 28), fill=(210, 220, 232, 255))
    # アクチュエータアーム(HDDらしさ)
    px, py = 880, 880
    tx, ty = 560, 640
    d.line((px, py, tx, ty), fill=(70, 82, 100, 255), width=46)
    d.line((px, py, tx, ty), fill=(176, 188, 204, 255), width=26)
    d.ellipse((px - 52, py - 52, px + 52, py + 52), fill=(70, 82, 100, 255))
    d.ellipse((px - 22, py - 22, px + 22, py + 22), fill=(210, 220, 232, 255))
    d.polygon([(tx, ty), (tx + 52, ty - 4), (tx + 16, ty - 40)], fill=(70, 82, 100, 255))
    return base


def to_png(img, size):
    im = img.resize((size, size), Image.LANCZOS)
    b = io.BytesIO()
    im.save(b, format="PNG")
    return b.getvalue(), im


def main():
    img = render()
    sizes = [256, 128, 64, 48, 32, 24, 16]
    pngs = {s: to_png(img, s)[0] for s in sizes}

    # --- .ico
    n = len(sizes)
    ico = struct.pack("<HHH", 0, 1, n)
    offset = 6 + 16 * n
    body = b""
    for s in sizes:
        data = pngs[s]
        w = 0 if s >= 256 else s
        ico += struct.pack("<BBBBHHII", w, w, 0, 0, 1, 32, len(data), offset + len(body))
        body += data
    open(os.path.join(OUT, "icon.ico"), "wb").write(ico + body)

    # --- .res (RT_ICON x n + RT_GROUP_ICON)
    def pad4(b):
        return b + b"\0" * ((4 - len(b) % 4) % 4)

    def res_entry(rtype, rid, data):
        hdr_tail = struct.pack("<IHHII", 0, 0x1030, 0, 0, 0)  # DataVersion, MemFlags, Lang, Version, Characteristics
        ident = struct.pack("<HHHH", 0xFFFF, rtype, 0xFFFF, rid)
        header_size = 8 + len(ident) + len(hdr_tail)
        head = struct.pack("<II", len(data), header_size) + ident + hdr_tail
        return pad4(head) + pad4(data)

    res = struct.pack("<IIHHHHIHHII", 0, 32, 0xFFFF, 0, 0xFFFF, 0, 0, 0, 0, 0, 0)
    group = struct.pack("<HHH", 0, 1, n)
    for i, s in enumerate(sizes, start=1):
        w = 0 if s >= 256 else s
        group += struct.pack("<BBBBHHIH", w, w, 0, 0, 1, 32, len(pngs[s]), i)
        res += res_entry(3, i, pngs[s])
    res += res_entry(14, 1, group)
    open(os.path.join(OUT, "icon.res"), "wb").write(res)

    # --- ウィンドウ用 RGBA 128x128
    _, im128 = to_png(img, 128)
    open(os.path.join(OUT, "icon_128.rgba"), "wb").write(im128.convert("RGBA").tobytes())
    # 確認用プレビュー
    img.resize((256, 256), Image.LANCZOS).save(os.path.join(OUT, "icon_preview.png"))
    print("ok", {s: len(pngs[s]) for s in sizes})


main()
