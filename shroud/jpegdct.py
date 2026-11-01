"""Квантованные коэффициенты DCT из JPEG без внешних библиотек и хи-квадрат по парам значений (jsteg и похожие методы).

Поддерживается только последовательный JPEG с кодами Хаффмана (SOF0 и SOF1, 8 бит). Прогрессивные, арифметические и
12-битные файлы возвращают JpegUnsupported: для них анализ не выполняется, и это сообщается явно."""
import re
import struct
from dataclasses import dataclass, field

import numpy as np

MAX_BLOCKS = 60_000       # сколько блоков декодировать (с начала файла): чистый Python, больше будет слишком долго
MIN_EXPECTED = 5.0        # как в пиксельном хи-квадрате: пары с меньшим ожиданием не считаем
MIN_PAIRS = 6
OFFSET = 64               # значения коэффициентов сдвигаются на OFFSET, чётность пары (2k, 2k+1) при этом сохраняется
RST_SPLIT = re.compile(rb"\xff[\xd0-\xd7]")
SCAN_END = re.compile(rb"\xff[\x01-\xcf\xd8-\xfe]")
ZIGZAG = [0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6, 7, 14, 21, 28,
          35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63]


class JpegError(Exception):
    """Файл повреждён или оборван так, что разбор невозможен."""


class JpegUnsupported(Exception):
    """Корректный JPEG, но такой вид кодирования разбор не поддерживает."""


@dataclass
class Component:
    cid: int
    h: int
    v: int
    tq: int
    blocks: list = field(default_factory=list)
    declared: int = 0


@dataclass
class Decoded:
    width: int
    height: int
    components: list
    qtables: dict
    declared_blocks: int
    used_blocks: int
    partial: bool       # декодирование остановлено по лимиту блоков
    truncated: bool     # данные скана кончились раньше положенного

    def coefficients(self, index):
        """Квантованные коэффициенты компонента (n, 64) в порядке зигзага: [0] это DC, остальное AC."""
        blocks = self.components[index].blocks
        return np.array(blocks, dtype=np.int32).reshape(-1, 64) if blocks else np.zeros((0, 64), dtype=np.int32)


class _Huffman:
    """Таблица быстрого разбора: по 16 подсмотренным битам сразу (длина кода, символ)."""

    def __init__(self, counts, symbols):
        self.lookup: list = [None] * 65536
        code = k = 0
        for length in range(1, 17):
            for _ in range(counts[length - 1]):
                if k >= len(symbols):
                    raise JpegError("таблица Хаффмана длиннее списка символов")
                lo = code << (16 - length)
                hi = (code + 1) << (16 - length)
                if hi > 65536:
                    raise JpegError("некорректная таблица Хаффмана")
                self.lookup[lo:hi] = [(length, symbols[k])] * (hi - lo)
                code += 1
                k += 1
            code <<= 1


class _Bits:
    __slots__ = ("data", "pos", "acc", "n")

    def __init__(self, data):
        self.data, self.pos, self.acc, self.n = data, 0, 0, 0

    def _fill(self):
        d, p = self.data, self.pos
        while self.n < 24:
            self.acc = ((self.acc & ((1 << self.n) - 1)) << 8) | (d[p] if p < len(d) else 0)
            p += 1
            self.n += 8
        self.pos = p

    def peek16(self):
        if self.n < 16:
            self._fill()
        return (self.acc >> (self.n - 16)) & 0xFFFF

    def skip(self, k):
        self.n -= k

    def bits(self, k):
        if self.n < k:
            self._fill()
        self.n -= k
        return (self.acc >> self.n) & ((1 << k) - 1)

    def overrun(self):
        return self.pos - self.n // 8 > len(self.data) + 1


def _extend(v, size):
    return v if v >= (1 << (size - 1)) else v - (1 << size) + 1


def _block(r, dc, ac, pred):
    entry = dc.lookup[r.peek16()]
    if entry is None:
        raise JpegError("недопустимый код DC")
    r.skip(entry[0])
    size = entry[1]
    if size > 11:
        raise JpegError("недопустимая категория DC")
    pred += _extend(r.bits(size), size) if size else 0
    blk = [0] * 64
    blk[0] = pred
    k = 1
    while k < 64:
        entry = ac.lookup[r.peek16()]
        if entry is None:
            raise JpegError("недопустимый код AC")
        r.skip(entry[0])
        run, size = entry[1] >> 4, entry[1] & 15
        if size == 0:
            if run == 15:
                k += 16
                continue
            break
        k += run
        if k > 63:
            raise JpegError("коэффициент за границей блока")
        blk[k] = _extend(r.bits(size), size)
        k += 1
    return blk, pred


def _ceil(a, b):
    return -(-a // b)


def decode(data: bytes, max_blocks: int = MAX_BLOCKS) -> Decoded:
    if data[:2] != b"\xff\xd8":
        raise JpegError("нет маркера начала JPEG")
    pos, n = 2, len(data)
    qt: dict = {}
    huff: dict = {}
    comps: list = []
    width = height = 0
    restart = 0
    used = 0
    partial = truncated = False
    scans = 0
    while pos + 4 <= n:
        if data[pos] != 0xFF:
            raise JpegError("мусор между сегментами")
        while pos + 1 < n and data[pos + 1] == 0xFF:
            pos += 1
        marker = data[pos + 1]
        if marker == 0xD9:
            break
        if marker in (0x01, 0xD8) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        (length,) = struct.unpack(">H", data[pos + 2:pos + 4])
        seg = data[pos + 4:pos + 2 + length]
        if len(seg) < length - 2:
            raise JpegError("сегмент обрезан")
        pos += 2 + length
        if marker == 0xDB:
            i = 0
            while i < len(seg):
                pq, tq = seg[i] >> 4, seg[i] & 15
                step = 128 if pq else 64
                raw = seg[i + 1:i + 1 + step]
                if len(raw) < step:
                    raise JpegError("таблица квантования обрезана")
                qt[tq] = list(struct.unpack(">64H", raw)) if pq else list(raw)
                i += 1 + step
        elif marker in (0xC0, 0xC1):
            if len(seg) < 6 or seg[0] != 8:
                raise JpegUnsupported("не 8-битный JPEG")
            height, width, nf = struct.unpack(">HHB", seg[1:6])
            if width == 0 or height == 0 or nf not in (1, 3, 4) or len(seg) < 6 + 3 * nf:
                raise JpegError("некорректный заголовок кадра")
            comps = [Component(seg[6 + 3 * i], seg[7 + 3 * i] >> 4, seg[7 + 3 * i] & 15, seg[8 + 3 * i]) for i in range(nf)]
            if any(c.h < 1 or c.v < 1 or c.h > 4 or c.v > 4 for c in comps):
                raise JpegError("некорректные коэффициенты прореживания")
            hmax, vmax = max(c.h for c in comps), max(c.v for c in comps)
            for c in comps:
                c.declared = _ceil(_ceil(width * c.h, hmax), 8) * _ceil(_ceil(height * c.v, vmax), 8)
        elif marker in (0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            raise JpegUnsupported("прогрессивный, арифметический или без потерь: разбор не поддерживается")
        elif marker == 0xC4:
            i = 0
            while i + 17 <= len(seg):
                tc, th = seg[i] >> 4, seg[i] & 15
                counts = list(seg[i + 1:i + 17])
                total = sum(counts)
                huff[(tc, th)] = _Huffman(counts, list(seg[i + 17:i + 17 + total]))
                i += 17 + total
        elif marker == 0xDD:
            restart = struct.unpack(">H", seg[:2])[0]
        elif marker == 0xDA:
            if not comps:
                raise JpegError("скан раньше заголовка кадра")
            ns = seg[0]
            scan_comps = []
            for i in range(ns):
                cid, tdta = seg[1 + 2 * i], seg[2 + 2 * i]
                comp = next((c for c in comps if c.cid == cid), None)
                if comp is None:
                    raise JpegError("в скане неизвестный компонент")
                scan_comps.append((comp, tdta >> 4, tdta & 15))
            ss, se = seg[1 + 2 * ns], seg[2 + 2 * ns]
            if ss != 0 or se != 63:
                raise JpegUnsupported("спектральная выборка: прогрессивный режим")
            m = SCAN_END.search(data, pos)
            end = m.start() if m else n
            entropy, pos = data[pos:end], end
            scans += 1
            u, part, trunc = _scan(entropy, scan_comps, comps, width, height, restart, huff, max_blocks - used)
            used += u
            partial |= part
            truncated |= trunc
            if partial:
                break
    if not comps or scans == 0:
        raise JpegError("в файле нет данных изображения")
    return Decoded(width, height, comps, qt, sum(c.declared for c in comps), used, partial, truncated)


def _scan(entropy, scan_comps, comps, width, height, restart, huff, budget):
    hmax, vmax = max(c.h for c in comps), max(c.v for c in comps)
    interleaved = len(scan_comps) > 1
    if interleaved:
        mcus = _ceil(width, 8 * hmax) * _ceil(height, 8 * vmax)
        layout = [(c, dc, ac, c.h * c.v) for c, dc, ac in scan_comps]
    else:
        c, dc, ac = scan_comps[0]
        mcus = c.declared
        layout = [(c, dc, ac, 1)]
    tables = []
    for c, dc, ac, per in layout:
        if (0, dc) not in huff or (1, ac) not in huff:
            raise JpegError("не хватает таблицы Хаффмана")
        tables.append((c, huff[(0, dc)], huff[(1, ac)], per))
    segments = [s.replace(b"\xff\x00", b"\xff") for s in (RST_SPLIT.split(entropy) if restart else [entropy])]
    per_mcu_blocks = sum(per for _, _, _, per in tables)
    done = used = 0
    truncated = partial = False
    for seg in segments:
        r = _Bits(seg)
        preds = [0] * len(tables)
        count = restart if restart else mcus
        for _ in range(min(count, mcus - done)):
            if used + per_mcu_blocks > budget:
                return used, True, truncated
            try:
                for i, (c, dct, act, per) in enumerate(tables):
                    for _b in range(per):
                        blk, preds[i] = _block(r, dct, act, preds[i])
                        c.blocks.append(blk)
                        used += 1
            except JpegError:
                return used, partial, True
            done += 1
            if r.overrun():
                return used, partial, True
        if done >= mcus:
            break
    if done < mcus:
        truncated = True
    return used, partial, truncated


def pair_chi_square(values: np.ndarray):
    """Хи-квадрат по парам значений (2k, 2k+1), кроме пары (0, 1): jsteg их не трогает. Возвращает (chi2, df, число коэффициентов в учтённых парах) или None."""
    v = values[(values > -OFFSET) & (values < OFFSET)] + OFFSET
    hist = np.bincount(v, minlength=2 * OFFSET).astype(np.float64)
    even, odd = hist[0::2], hist[1::2]
    expected = (even + odd) / 2.0
    mask = expected >= MIN_EXPECTED
    mask[OFFSET // 2] = False  # пара значений (0, 1)
    pairs = int(mask.sum())
    if pairs < MIN_PAIRS:
        return None
    chi2 = float((2.0 * ((even - expected) ** 2) / np.where(mask, expected, 1.0))[mask].sum())
    return chi2, pairs, int((even + odd)[mask].sum())


def chi_profile(decoded: Decoded, parts=10):
    """[(chi2/df, число коэффициентов)] по каждой десятой части потока AC-коэффициентов; значения усреднены по компонентам,
    а счёт суммируется. None там, где данных мало."""
    streams = []
    for i in range(len(decoded.components)):
        coef = decoded.coefficients(i)
        if len(coef):
            streams.append(coef[:, 1:].reshape(-1))
    out = []
    for p in range(parts):
        vals, count = [], 0
        for s in streams:
            lo, hi = len(s) * p // parts, len(s) * (p + 1) // parts
            r = pair_chi_square(s[lo:hi])
            if r is not None:
                vals.append(r[0] / r[1])
                count += r[2]
        out.append((float(np.mean(vals)), count) if vals else None)
    return out


EQUAL_MAX = 2.5      # chi2/df не выше: пары значений выровнены, как после замены младших битов
STRUCT_MIN = 4.0     # chi2/df не ниже: гистограмма «живая», как у нетронутого изображения
MIN_COUNT = 200      # меньше коэффициентов в доле: вывод по ней не делаем (в чистых файлах «выровненные» доли были только с ~180)
MIN_USABLE = 4


def classify(profile):
    """('flat', доли) если выровнено почти всё, ('prefix', доли в начале) если выровнено только начало, иначе (None, 0).
    Пороги подобраны на одном наборе синтетических картинок и проверены на другом (см. README)."""
    usable = [(i, p[0]) for i, p in enumerate(profile) if p is not None and p[1] >= MIN_COUNT]
    if len(usable) < MIN_USABLE:
        return None, 0
    equal = [i for i, v in usable if v <= EQUAL_MAX]
    if len(equal) >= MIN_USABLE and len(equal) >= 0.8 * len(usable):
        return "flat", len(equal)
    lead = 0
    for p in profile:
        if p is not None and p[1] >= MIN_COUNT and p[0] <= EQUAL_MAX:
            lead += 1
        else:
            break
    rest = [v for i, v in usable if i >= lead]
    if lead >= 2 and len(rest) >= 2 and float(np.median(rest)) >= STRUCT_MIN:
        return "prefix", lead
    return None, 0
