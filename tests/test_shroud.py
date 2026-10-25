import io
import json
import struct
import subprocess
import sys
import zlib
import zipfile
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

from shroud import extract, lsb, scan
from tests.helpers import cover, embed_lsb, random_bits, to_jpeg_bytes, to_png_bytes

ROOT = Path(__file__).resolve().parent.parent


def codes(report, level=None):
    return {f.code for f in report.findings if level is None or f.level == level}


def zip_bytes(payload=b"secret"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("flag.txt", payload)
    return buf.getvalue()


def png_chunk(ctype, body):
    return struct.pack(">I", len(body)) + ctype + body + struct.pack(">I", zlib.crc32(ctype + body) & 0xFFFFFFFF)


def png_with_extra_raw(extra, w=8, h=8):
    raw = b"".join(b"\x00" + bytes([i % 256] * (w * 3)) for i in range(h)) + extra
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", ihdr) + png_chunk(b"IDAT", zlib.compress(raw))
            + png_chunk(b"IEND", b""))


@pytest.fixture(scope="module")
def clean_png():
    return to_png_bytes(cover(seed=11))


def test_clean_images_stay_clean():
    for seed in range(1, 8):
        r = scan.scan_bytes(to_png_bytes(cover(seed=seed)), f"cover{seed}")
        assert r.verdict == scan.CLEAN, (seed, [f.message for f in r.findings])


def test_png_trailing_zip_is_found(clean_png):
    r = scan.scan_bytes(clean_png + zip_bytes(), "x.png")
    assert {"trailing-data", "embedded-file"} <= codes(r, "alert")
    assert r.verdict == scan.LIKELY


def test_png_idat_unused_and_extra_data():
    r = scan.scan_bytes(png_with_extra_raw(b"HIDDEN-PAYLOAD-" * 4), "extra.png")
    assert "idat-extra" in codes(r, "alert")
    plain = scan.scan_bytes(png_with_extra_raw(b""), "plain.png")
    assert not codes(plain, "alert")


def test_png_unknown_private_chunk_and_big_text(clean_png):
    iend = clean_png.rindex(b"\x00\x00\x00\x00IEND")
    custom = png_chunk(b"stEg", b"x" * 40) + png_chunk(b"tEXt", b"Comment\x00" + b"A" * 700)
    r = scan.scan_bytes(clean_png[:iend] + custom + clean_png[iend:], "chunks.png")
    assert {"unknown-chunk", "large-metadata"} <= codes(r, "warn")
    assert r.verdict == scan.ODD


def test_png_crc_mismatch_is_reported(clean_png):
    broken = bytearray(clean_png)
    broken[20] ^= 0xFF  # внутри IHDR
    assert "crc-mismatch" in codes(scan.scan_bytes(bytes(broken), "bad.png"))


def test_jpeg_trailing_data_and_comment():
    jpg = to_jpeg_bytes(cover(seed=3))
    r = scan.scan_bytes(jpg + zip_bytes(), "x.jpg")
    assert {"trailing-data", "embedded-file"} <= codes(r, "alert")
    note = b"B" * 200
    with_com = jpg[:2] + b"\xff\xfe" + struct.pack(">H", len(note) + 2) + note + jpg[2:]
    assert "jpeg-comment" in codes(scan.scan_bytes(with_com, "c.jpg"), "warn")
    assert scan.scan_bytes(jpg, "ok.jpg").verdict == scan.CLEAN


def test_gif_and_bmp_trailing_data():
    buf = io.BytesIO()
    Image.fromarray((np.arange(64 * 64).reshape(64, 64) % 7 * 30).astype(np.uint8)).convert("P").save(buf, "GIF")
    gif = buf.getvalue()
    assert scan.scan_bytes(gif, "a.gif").verdict == scan.CLEAN
    assert "trailing-data" in codes(scan.scan_bytes(gif + b"just some hidden text here", "b.gif"), "alert")
    buf = io.BytesIO()
    Image.fromarray(cover(64, 64, seed=2)).save(buf, "BMP")
    bmp = buf.getvalue()
    assert "trailing-data" in codes(scan.scan_bytes(bmp + zip_bytes(), "a.bmp"), "alert")


def test_lsb_text_message_is_extracted():
    msg = b"flag{lsb_is_not_encryption}"
    stego = embed_lsb(cover(seed=5), np.unpackbits(np.frombuffer(msg, dtype=np.uint8)))
    r = scan.scan_bytes(to_png_bytes(stego), "msg.png")
    texts = [f.message for f in r.findings if f.code == "lsb-extract"]
    assert texts and "flag{lsb_is_not_encryption}" in texts[0]
    assert r.verdict == scan.SUSPICIOUS


def test_lsb_embedded_file_signature_is_extracted():
    bits = np.unpackbits(np.frombuffer(zip_bytes(b"x" * 200), dtype=np.uint8))
    r = scan.scan_bytes(to_png_bytes(embed_lsb(cover(seed=6), bits)), "zip.png")
    assert any("ZIP" in f.message for f in r.findings if f.code == "lsb-extract")


def test_rs_estimates_rate_on_partial_embedding():
    c = cover(seed=1)
    prev = -1
    for frac, lo, hi in ((0.0, 0.0, 0.04), (0.25, 0.12, 0.35), (0.5, 0.3, 0.65)):
        s = c if frac == 0 else embed_lsb(c, random_bits(int(c.size * frac), 1))
        mid = float(np.median([lsb.rs_estimate(s[:, :, i])[0] for i in range(3)]))
        assert lo <= mid <= hi, (frac, mid)
        assert mid > prev
        prev = mid


def test_rs_alert_on_25_percent_embedding():
    c = cover(seed=2)
    r = scan.scan_bytes(to_png_bytes(embed_lsb(c, random_bits(int(c.size * 0.25), 2))), "rs.png")
    assert "rs-lsb" in codes(r, "alert")


def test_chi_square_prefix_on_spiky_cover():
    base = cover(seed=4).astype(np.int32) // 2 * 2  # только чётные значения: «спиковая» гистограмма
    base = base.astype(np.uint8)
    stego = embed_lsb(base, random_bits(base.size // 3, 4))
    prof = lsb.chi_square_profile([stego[:, :, i] for i in range(3)])
    assert prof[0] < 1.5 and np.median(prof[4:]) > 4
    assert "chi-prefix" in codes(scan.scan_bytes(to_png_bytes(stego), "spiky.png"), "alert")
    assert "chi-prefix" not in codes(scan.scan_bytes(to_png_bytes(base), "spiky-clean.png"))


def test_gammq_known_values():
    assert lsb._gammq(1.0, 1.0) == pytest.approx(0.36787944, rel=1e-6)  # e^-1
    assert lsb._gammq(5.0, 5.0) == pytest.approx(0.44049, rel=1e-3)


def test_unknown_format_and_garbage():
    r = scan.scan_bytes(b"this is not an image", "x.bin")
    assert r.fmt is None and "unknown-format" in codes(r)


def test_extract_does_not_fire_on_noise():
    rng = np.random.default_rng(0)
    noise = rng.integers(0, 256, (128, 128, 3), dtype=np.uint8)
    assert extract.candidates([noise[:, :, i] for i in range(3)]) == []


def test_cli_json_and_exit_code(tmp_path, clean_png):
    clean = tmp_path / "clean.png"
    dirty = tmp_path / "dirty.png"
    clean.write_bytes(clean_png)
    dirty.write_bytes(clean_png + zip_bytes())

    def run(*args):
        return subprocess.run([sys.executable, "-m", "shroud", *args], cwd=ROOT, capture_output=True, text=True)

    ok = run("scan", str(clean), "--json")
    assert ok.returncode == 0 and json.loads(ok.stdout)[0]["verdict"] == "clean"
    bad = run("scan", str(dirty), "--json")
    assert bad.returncode == 1 and json.loads(bad.stdout)[0]["verdict"] == "likely"
    plane = tmp_path / "plane.png"
    assert run("lsb-plane", str(clean), str(plane)).returncode == 0 and plane.exists()
