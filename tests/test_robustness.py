import json
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from shroud import htmlreport, scan
from tests.helpers import cover, to_jpeg_bytes, to_png_bytes

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def png():
    return to_png_bytes(cover(seed=3))


@pytest.fixture(scope="module")
def jpg():
    return to_jpeg_bytes(cover(seed=3))


def broken_samples(png, jpg):
    return {
        "empty": b"",
        "zeros": b"\x00" * 100,
        "png-signature-only": png[:8],
        "png-truncated-ihdr": png[:20],
        "png-truncated-middle": png[: len(png) // 2],
        "png-bad-crc": png[:40] + bytes([png[40] ^ 0xFF]) + png[41:],
        "jpeg-truncated": jpg[: len(jpg) // 2],
        "jpeg-soi-only": b"\xff\xd8",
        "gif-signature-only": b"GIF89a",
        "bmp-signature-only": b"BM",
        "bmp-truncated-header": b"BM" + b"\x00" * 30,
    }


def test_corrupted_files_never_crash(png, jpg):
    for name, data in broken_samples(png, jpg).items():
        report = scan.scan_bytes(data, name)
        assert report.verdict in (scan.CLEAN, scan.ODD, scan.SUSPICIOUS, scan.LIKELY), name


def test_truncated_png_is_reported_not_clean(png):
    report = scan.scan_bytes(png[: len(png) // 2], "cut.png")
    assert report.verdict != scan.CLEAN
    assert "truncated" in {f.code for f in report.findings}


def test_random_bytes_after_png_signature_do_not_crash(png):
    import random

    rng = random.Random(1)
    for _ in range(40):
        junk = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 300)))
        scan.scan_bytes(png[:8] + junk, "fuzz.png")


def test_huge_declared_dimensions_are_skipped_not_loaded():
    ihdr = struct.pack(">IIBBBBB", 60000, 60000, 8, 2, 0, 0, 0)

    def chunk(t, b):
        import zlib

        return struct.pack(">I", len(b)) + t + b + struct.pack(">I", zlib.crc32(t + b) & 0xFFFFFFFF)

    data = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", b"") + chunk(b"IEND", b"")
    report = scan.scan_bytes(data, "bomb.png")
    assert "too-large" in {f.code for f in report.findings}


def test_oversized_file_is_skipped(tmp_path, monkeypatch):
    f = tmp_path / "big.png"
    f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
    monkeypatch.setattr(scan, "MAX_FILE_BYTES", 16)
    report = scan.scan_path(f)
    assert [x.code for x in report.findings] == ["too-large"]


def test_html_report_escapes_hostile_names_and_messages(png):
    report = scan.scan_bytes(png, '<script>alert(1)</script>.png')
    out = htmlreport.render([report])
    assert "<script>alert(1)" not in out
    assert "&lt;script&gt;" in out
    assert "Content-Security-Policy" in out


def test_cli_writes_html_and_json(tmp_path, png):
    img = tmp_path / "a.png"
    img.write_bytes(png)
    html = tmp_path / "r.html"
    proc = subprocess.run([sys.executable, "-m", "shroud", "scan", str(img), "--json", "--html", str(html)],
                          capture_output=True, text=True, cwd=ROOT)
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert data[0]["verdict"] == "clean"
    assert html.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_cli_survives_unreadable_and_garbage_inputs(tmp_path):
    bad = tmp_path / "bad.png"
    bad.write_bytes(b"not an image at all")
    proc = subprocess.run([sys.executable, "-m", "shroud", "scan", str(bad), str(tmp_path / "missing.png")],
                          capture_output=True, text=True, cwd=ROOT)
    assert proc.returncode in (0, 1)
    assert "Traceback" not in proc.stderr
