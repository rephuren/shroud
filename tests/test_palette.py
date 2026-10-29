import io

import numpy as np
import pytest
from PIL import Image

from shroud import palette, scan
from shroud.scan import ALERT, CLEAN

from .helpers import cover, embed_lsb, random_bits


def indexed(seed, colors=64, ordered=False):
    img = Image.fromarray(cover(256, 256, seed)).quantize(colors, dither=Image.Dither.NONE)
    if ordered:
        _, ranks = palette.luminance_ranks(img)
        pal = np.array(img.getpalette()[: colors * 3]).reshape(-1, 3)
        order = np.argsort(pal @ np.array([0.299, 0.587, 0.114]), kind="stable")
        img = Image.fromarray(ranks.astype(np.uint8), "P")
        img.putpalette(pal[order].reshape(-1).tolist())
    return img


def encode(img, fmt):
    buf = io.BytesIO()
    img.save(buf, fmt)
    return buf.getvalue()


def stego(img, fraction=1.0):
    arr = np.asarray(img).copy()
    out = Image.fromarray(embed_lsb(arr, random_bits(int(arr.size * fraction))), "P")
    out.putpalette(img.getpalette())
    return out


def codes(report, level=None):
    return {f.code for f in report.findings if level is None or f.level == level}


@pytest.mark.parametrize("fmt", ["GIF", "PNG"])
@pytest.mark.parametrize("ordered", [False, True])
@pytest.mark.parametrize("seed", [1, 2, 3, 4])
def test_clean_palette_images_are_not_flagged(fmt, ordered, seed):
    r = scan.scan_bytes(encode(indexed(seed, ordered=ordered), fmt), "clean")
    assert r.verdict == CLEAN, [f.message for f in r.findings]
    assert "palette" in r.metrics


@pytest.mark.parametrize("fmt", ["GIF", "PNG"])
@pytest.mark.parametrize("colors", [32, 128])
def test_full_embedding_is_flagged(fmt, colors):
    r = scan.scan_bytes(encode(stego(indexed(1, colors)), fmt), "stego")
    assert {"palette-rs", "palette-chi-flat"} & codes(r, ALERT)
    assert r.verdict in (scan.SUSPICIOUS, scan.LIKELY)


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_partial_embedding_is_flagged_by_prefix_contrast(seed):
    r = scan.scan_bytes(encode(stego(indexed(seed, 64), 0.3), "PNG"), "partial")
    assert "palette-chi" in codes(r, ALERT) or "palette-rs" in codes(r, ALERT)


def test_few_colors_is_skipped_not_flagged():
    flat = Image.fromarray((np.arange(64 * 64).reshape(64, 64) % 7 * 30).astype(np.uint8)).convert("P")
    r = scan.scan_bytes(encode(flat, "GIF"), "flat")
    assert "palette-few-colors" in codes(r) and r.verdict == CLEAN


def test_text_payload_in_indices_is_extracted():
    img = indexed(5, 64)
    arr = np.asarray(img).copy()
    msg = b"flag{palette_indices_hide_this_message_well}"
    bits = np.unpackbits(np.frombuffer(msg, dtype=np.uint8))
    out = Image.fromarray(embed_lsb(arr, bits), "P")
    out.putpalette(img.getpalette())
    r = scan.scan_bytes(encode(out, "PNG"), "msg")
    assert "palette-extract" in codes(r, ALERT)


def test_luminance_ranks_follow_brightness():
    img = Image.new("P", (4, 1))
    img.putpalette([200, 200, 200, 0, 0, 0, 100, 100, 100] + [0] * 759)
    img.putdata([0, 1, 2, 0])
    idx, ranks = palette.luminance_ranks(img)
    assert list(idx.reshape(-1)) == [0, 1, 2, 0] and list(ranks.reshape(-1))[:3] == [ranks[0, 0], ranks[0, 1], ranks[0, 2]]
    assert ranks[0, 1] < ranks[0, 2] < ranks[0, 0]


def test_palette_image_without_palette_data_does_not_crash():
    img = Image.new("P", (300, 300), 0)
    r = scan.scan_bytes(encode(img, "PNG"), "blank")
    assert r.verdict == CLEAN


def test_lsb_plane_works_for_palette_images():
    data = encode(indexed(1, 64), "PNG")
    assert scan.lsb_plane_image(data).size == (256, 256)


def test_pa_mode_is_handled():
    # Pillow не пишет PA в PNG, поэтому вызываем анализ напрямую
    report = scan.Report(path="pa", size=0, fmt="png")
    scan._palette_analysis(indexed(2, 64).convert("PA"), report)
    assert "palette" in report.metrics and not codes(report, ALERT)
