"""Синтетические изображения и учебный LSB-встраиватель только для проверки детектора."""
import io

import numpy as np
from PIL import Image


def cover(width=256, height=256, seed=1, stretch=True):
    """Гладкий «фотоподобный» RGB-оригинал. stretch=True растягивает контраст:
    в гистограмме появляются провалы, как у реальных обработанных фото."""
    rng = np.random.default_rng(seed)
    small = rng.uniform(0, 255, (9, 9, 3)).astype(np.float32)
    big = np.asarray(Image.fromarray(small.astype(np.uint8)).resize((width, height), Image.BICUBIC), dtype=np.float32)
    big += rng.normal(0, 1.2, big.shape)
    big = np.clip(big, 0, 255)
    if stretch:
        lo, hi = np.percentile(big, 1), np.percentile(big, 99)
        big = np.clip((big - lo) / (hi - lo) * 255, 0, 255)
    return np.round(big).astype(np.uint8)


def embed_lsb(arr, bits, start=0):
    flat = arr.reshape(-1).copy()
    n = len(bits)
    flat[start:start + n] = (flat[start:start + n] & 0xFE) | np.asarray(bits, dtype=np.uint8)
    return flat.reshape(arr.shape)


def random_bits(n, seed=7):
    return np.random.default_rng(seed).integers(0, 2, n, dtype=np.uint8)


def to_png_bytes(arr):
    buf = io.BytesIO()
    Image.fromarray(arr).save(buf, "PNG")
    return buf.getvalue()


def to_jpeg_bytes(arr, quality=85):
    buf = io.BytesIO()
    Image.fromarray(arr).save(buf, "JPEG", quality=quality)
    return buf.getvalue()
