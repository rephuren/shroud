import io

import numpy as np
import pytest
from PIL import Image

from shroud import jpegdct
from shroud.scan import scan_bytes
from tests import jpeg_helpers as jh
from tests.helpers import cover


def _stego(seed, quality=85, fraction=1.0):
    data = jh.gray_jpeg(cover(256, 256, seed), quality)
    coef = jpegdct.decode(data).coefficients(0)
    capacity = int(np.count_nonzero((coef[:, 1:] != 0) & (coef[:, 1:] != 1)))
    bits = np.random.default_rng(seed).integers(0, 2, int(capacity * fraction))
    modified, _ = jh.jsteg_embed(coef, bits)
    return jh.reencode(data, modified)


def _codes(report):
    return {f.code for f in report.findings}


def test_decoder_matches_pillow():
    data = jh.gray_jpeg(cover(128, 96, 3), 80)
    dec = jpegdct.decode(data)
    mine = jh.pixels_from_coefficients(dec)
    ref = np.asarray(Image.open(io.BytesIO(data)).convert("L"), dtype=int)
    assert mine.shape == ref.shape
    assert np.abs(mine - ref).max() <= 1


def test_encoder_roundtrip_is_exact():
    data = jh.gray_jpeg(cover(128, 128, 4), 75)
    coef = jpegdct.decode(data).coefficients(0)
    again = jpegdct.decode(jh.reencode(data, coef)).coefficients(0)
    assert np.array_equal(coef, again)


@pytest.mark.parametrize("seed", [16, 17, 18, 19, 20, 21])
@pytest.mark.parametrize("quality", [65, 85, 95])
def test_clean_jpeg_is_not_flagged(seed, quality):
    data = jh.gray_jpeg(cover(256, 256, seed), quality)
    assert "jpeg-dct-chi" not in _codes(scan_bytes(data))


@pytest.mark.parametrize("seed", [1, 2, 3, 16, 17])
def test_full_jsteg_is_flagged(seed):
    report = scan_bytes(_stego(seed))
    assert "jpeg-dct-chi" in _codes(report)
    assert report.verdict != "чисто"


def test_partial_jsteg_prefix_is_flagged_on_high_quality():
    flagged = sum("jpeg-dct-chi" in _codes(scan_bytes(_stego(s, 95, 0.5))) for s in range(1, 6))
    assert flagged >= 3


def test_small_payload_is_not_detected():
    # честная граница: 10% ёмкости статистикой не видно
    flagged = sum("jpeg-dct-chi" in _codes(scan_bytes(_stego(s, 95, 0.1))) for s in range(1, 6))
    assert flagged == 0


def test_progressive_jpeg_is_skipped_not_crashed():
    buf = io.BytesIO()
    Image.fromarray(cover(128, 128, 2)).save(buf, "JPEG", quality=85, progressive=True)
    report = scan_bytes(buf.getvalue())
    assert "jpeg-dct" in _codes(report)
    assert "jpeg-dct-chi" not in _codes(report)


def test_truncated_and_corrupt_jpeg_do_not_raise():
    data = jh.gray_jpeg(cover(128, 128, 5), 85)
    for cut in (30, 200, len(data) // 2, len(data) - 5):
        scan_bytes(data[:cut])
    rng = np.random.default_rng(0)
    for _ in range(20):
        broken = bytearray(data)
        for pos in rng.integers(100, len(data), 5):
            broken[pos] ^= 0xFF
        scan_bytes(bytes(broken))


def test_tiny_jpeg_has_too_few_coefficients():
    buf = io.BytesIO()
    Image.new("L", (8, 8), 128).save(buf, "JPEG")
    assert "jpeg-dct-chi" not in _codes(scan_bytes(buf.getvalue()))
