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


def panel(arr, title):
    img = Image.fromarray(arr)
    canvas = Image.new("RGB", (W, H + 26), (5, 5, 5))
    canvas.paste(img, (0, 26))
    ImageDraw.Draw(canvas).text((8, 7), title, fill=(232, 232, 232), font=ImageFont.load_default())
    return canvas


def main():
    cover = make_cover()
    bits = np.unpackbits(np.frombuffer(MESSAGE, dtype=np.uint8))
    stego = embed_lsb(cover, bits)
    plane = ((stego & 1) * 255).astype(np.uint8)
    sheet = Image.new("RGB", (W * 3 + 40, H + 26), (5, 5, 5))
    for i, (arr, title) in enumerate([(cover, "cover"), (stego, "stego (data hidden in LSB)"), (plane, "LSB plane of stego")]):
        sheet.paste(panel(arr, title), (i * (W + 20), 0))
    out = ROOT / "assets"
    out.mkdir(exist_ok=True)
    sheet.save(out / "demo.png")
    Image.fromarray(stego).save(out / "demo-stego.png")
    Image.fromarray(cover).save(out / "demo-cover.png")
    for name in ("demo-cover.png", "demo-stego.png"):
        print(scan.scan_bytes((out / name).read_bytes(), name).verdict, name)


main()
