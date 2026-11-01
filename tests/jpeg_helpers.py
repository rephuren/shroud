"""Тестовый кодировщик JPEG (только оттенки серого, стандартные таблицы Хаффмана из файла Pillow) и учебный jsteg.
Нужен, чтобы проверить декодер на настоящих файлах и получить настоящие stego-JPEG; в пакет не входит."""
import io
import struct

import numpy as np
from PIL import Image

from shroud.jpegdct import ZIGZAG


def gray_jpeg(arr, quality=85):
    buf = io.BytesIO()
    Image.fromarray(arr).convert("L").save(buf, "JPEG", quality=quality)
    return buf.getvalue()


def _segments(data):
    pos = 2
    while pos + 4 <= len(data):
        marker = data[pos + 1]
        (length,) = struct.unpack(">H", data[pos + 2:pos + 4])
        yield marker, data[pos + 4:pos + 2 + length], pos + 2 + length
        if marker == 0xDA:
            return
        pos += 2 + length


def _codes(counts, symbols):
    out, code, k = {}, 0, 0
    for length in range(1, 17):
        for _ in range(counts[length - 1]):
            out[symbols[k]] = (code, length)
            code += 1
            k += 1
        code <<= 1
    return out


def _huffman_tables(data):
    tables = {}
    for marker, seg, _ in _segments(data):
        if marker == 0xC4:
            i = 0
            while i + 17 <= len(seg):
                counts = list(seg[i + 1:i + 17])
                total = sum(counts)
                tables[(seg[i] >> 4, seg[i] & 15)] = _codes(counts, list(seg[i + 17:i + 17 + total]))
                i += 17 + total
    return tables


class _Writer:
    def __init__(self):
        self.out = bytearray()
        self.acc = 0
        self.n = 0

    def put(self, code, length):
        self.acc = (self.acc << length) | code
        self.n += length
        while self.n >= 8:
            self.n -= 8
            byte = (self.acc >> self.n) & 0xFF
            self.out.append(byte)
            if byte == 0xFF:
                self.out.append(0)
        self.acc &= (1 << self.n) - 1

    def finish(self):
        if self.n:
            self.put((1 << (8 - self.n)) - 1, 8 - self.n)
        return bytes(self.out)


def _size(v):
    return abs(int(v)).bit_length()


def _bits(v, size):
    return int(v) if v > 0 else int(v) + (1 << size) - 1


def reencode(data, coef):
    """Заменяет данные скана серого JPEG на заданные коэффициенты (n, 64 в порядке зигзага). Заголовки остаются прежними."""
    tables = _huffman_tables(data)
    dc, ac = tables[(0, 0)], tables[(1, 0)]
    header_end = next(end for marker, _, end in _segments(data) if marker == 0xDA)
    w = _Writer()
    pred = 0
    for blk in coef:
        diff = int(blk[0]) - pred
        pred = int(blk[0])
        s = _size(diff)
        w.put(*dc[s])
        if s:
            w.put(_bits(diff, s), s)
        run = 0
        last = max((i for i in range(1, 64) if blk[i] != 0), default=0)
        for k in range(1, last + 1):
            v = int(blk[k])
            if v == 0:
                run += 1
                continue
            while run > 15:
                w.put(*ac[0xF0])
                run -= 16
            s = _size(v)
            w.put(*ac[(run << 4) | s])
            w.put(_bits(v, s), s)
            run = 0
        if last < 63:
            w.put(*ac[0x00])
    return data[:header_end] + w.finish() + b"\xff\xd9"


def jsteg_embed(coef, bits):
    """LSB-замена в AC-коэффициентах, кроме 0 и 1, подряд с начала потока (так делает jsteg)."""
    out = coef.copy()
    flat = out[:, 1:].reshape(-1)  # копия-представление: reshape даёт вид, поэтому пишем обратно ниже
    pos = np.flatnonzero((flat != 0) & (flat != 1))[: len(bits)]
    flat[pos] = (flat[pos] & ~1) | np.asarray(bits[: len(pos)], dtype=np.int32)
    out[:, 1:] = flat.reshape(-1, 63)
    return out, len(pos)


def pixels_from_coefficients(dec):
    """Обратное DCT серого изображения: нужно только для сверки декодера с Pillow."""
    q = np.zeros(64)
    table = dec.qtables[dec.components[0].tq]
    for i, z in enumerate(ZIGZAG):
        q[z] = table[i]
    n = np.arange(8)
    c = np.cos((2 * n[None, :] + 1) * n[:, None] * np.pi / 16) * np.where(n == 0, np.sqrt(1 / 8), np.sqrt(2 / 8))[:, None]
    coef = dec.coefficients(0)
    bw = -(-dec.width // 8)
    bh = -(-dec.height // 8)
    img = np.zeros((bh * 8, bw * 8))
    for idx, blk in enumerate(coef):
        nat = np.zeros(64)
        for i, z in enumerate(ZIGZAG):
            nat[z] = blk[i]
        block = (nat * q).reshape(8, 8)
        img[(idx // bw) * 8:(idx // bw) * 8 + 8, (idx % bw) * 8:(idx % bw) * 8 + 8] = c.T @ block @ c + 128
    return np.clip(np.round(img[: dec.height, : dec.width]), 0, 255)
