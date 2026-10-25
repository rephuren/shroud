"""Генерирует assets/demo.png: оригинал, изображение со скрытыми данными и плоскость LSB."""
import sys
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from shroud import scan  # noqa: E402
from tests.helpers import embed_lsb, to_png_bytes  # noqa: E402

W, H = 420, 280
MESSAGE = ("Не прячусь, просто не в кадре. " * 0 +
           "flag{lsb_hides_in_plain_sight_but_not_from_shroud} " + "the quick brown fox jumps over the lazy dog. " * 80).encode()


def make_cover():
    y, x = np.mgrid[0:H, 0:W].astype(np.float32)
    r = 40 + 150 * (x / W) + 30 * np.sin(y / 23)
    g = 30 + 90 * (y / H) + 25 * np.sin(x / 31)
    b = 70 + 110 * (1 - x / W) * (y / H)
    img = np.stack([r, g, b], axis=-1)
    cx, cy = W * 0.62, H * 0.45
    mask = (x - cx) ** 2 + (y - cy) ** 2 < 70 ** 2
    img[mask] = img[mask] * 0.35 + 20
    return np.clip(img, 0, 255).astype(np.uint8)


BG, PANEL, LINE, TEXT, DIM, RED = (5, 5, 5), (11, 11, 11), (26, 26, 26), (232, 232, 232), (138, 138, 138), (179, 0, 15)
FONT_PATHS = ["/System/Library/Fonts/Menlo.ttc", "/System/Library/Fonts/Monaco.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
              "C:/Windows/Fonts/consola.ttf"]


def font(size):
    for path in FONT_PATHS:
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            continue
    return ImageFont.load_default()


def spaced(draw, xy, text, fnt, fill, gap):
    x, y = xy
    for ch in text:
        draw.text((x, y), ch, fill=fill, font=fnt)
        x += draw.textlength(ch, font=fnt) + gap
    return x


def panel(arr, title, accent=False):
    img = Image.fromarray(arr)
    canvas = Image.new("RGB", (W + 2, H + 38), PANEL)
    d = ImageDraw.Draw(canvas)
    d.rectangle([0, 0, W + 1, H + 37], outline=LINE)
    d.rectangle([12, 13, 18, 19], fill=RED if accent else DIM)
    spaced(d, (28, 9), title.upper(), font(11), DIM, 2)
    canvas.paste(img, (1, 37))
    return canvas


def main():
    cover = make_cover()
    bits = np.unpackbits(np.frombuffer(MESSAGE, dtype=np.uint8))
    stego = embed_lsb(cover, bits)
    plane = ((stego & 1) * 255).astype(np.uint8)
    report = scan.scan_bytes(to_png_bytes(stego), "stego")
    pad, head, foot = 28, 74, 52
    sheet = Image.new("RGB", (3 * (W + 2) + 2 * 18 + 2 * pad, head + H + 38 + foot + pad), BG)
    d = ImageDraw.Draw(sheet)
    spaced(d, (pad, 22), "SHROUD", font(30), (138, 138, 138), 12)
    panels = [(cover, "cover", False), (stego, "stego: data hidden in LSB", False), (plane, "LSB plane of stego", True)]
    for i, (arr, title, accent) in enumerate(panels):
        sheet.paste(panel(arr, title, accent), (pad + i * (W + 2 + 18), head))
    rs = report.metrics.get("rs_median", 0)
    y = head + H + 38 + 18
    d.rectangle([pad, y + 3, pad + 6, y + 9], fill=RED)
    verdict = {"likely": "LIKELY STEGO", "suspicious": "SUSPICIOUS", "odd": "ODD", "clean": "CLEAN"}[report.verdict]
    spaced(d, (pad + 16, y - 1), f"VERDICT  {verdict}   ·   RS ESTIMATE {rs * 100:.0f}%   ·   LSB TEXT RECOVERED", font(12), TEXT, 1)
    out = ROOT / "assets"
    out.mkdir(exist_ok=True)
    sheet.save(out / "demo.png")
    Image.fromarray(stego).save(out / "demo-stego.png")
    Image.fromarray(cover).save(out / "demo-cover.png")
    for name in ("demo-cover.png", "demo-stego.png"):
        print(scan.scan_bytes((out / name).read_bytes(), name).verdict, name)


main()
