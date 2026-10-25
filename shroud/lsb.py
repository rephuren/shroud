"""Статистический поиск LSB-стего в пикселях: хи-квадрат по долям изображения и RS-анализ."""
import math

import numpy as np

CHI_PARTS = 10
MIN_EXPECTED = 5.0


def _gammq(a, x):
    """Верхняя регуляризованная неполная гамма-функция Q(a, x) (Numerical Recipes)."""
    if x <= 0:
        return 1.0
    gln = math.lgamma(a)
    if x < a + 1.0:
        ap, total, delta = a, 1.0 / a, 1.0 / a
        for _ in range(1000):
            ap += 1.0
            delta *= x / ap
            total += delta
            if abs(delta) < abs(total) * 1e-12:
                break
        return max(0.0, 1.0 - total * math.exp(-x + a * math.log(x) - gln))
    b = x + 1.0 - a
    c, d = 1e300, 1.0 / b
    h = d
    for i in range(1, 1000):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        d = 1e-300 if abs(d) < 1e-300 else d
        c = b + an / c
        c = 1e-300 if abs(c) < 1e-300 else c
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-12:
            break
    return min(1.0, math.exp(-x + a * math.log(x) - gln) * h)


def pov_chi_square(samples: np.ndarray):
    """Хи-квадрат по парам значений (2k, 2k+1). Возвращает (chi2, df) или None, если данных мало."""
    hist = np.bincount(samples, minlength=256).astype(np.float64)
    even, odd = hist[0::2], hist[1::2]
    expected = (even + odd) / 2.0
    mask = expected >= MIN_EXPECTED
    pairs = int(mask.sum())
    if pairs < 8:
        return None
    chi2 = float((2.0 * ((even - expected) ** 2) / np.where(mask, expected, 1.0))[mask].sum())
    return chi2, pairs


def chi_square_profile(channels, parts=CHI_PARTS):
    """chi2/df для каждой десятой части изображения по порядку строк, усреднённо по каналам.
    У «спикового» оригинала значения велики. Случайные LSB дают значения около 1."""
    flats = [c.reshape(-1) for c in channels]
    out = []
    for i in range(parts):
        vals = []
        for f in flats:
            lo, hi = len(f) * i // parts, len(f) * (i + 1) // parts
            r = pov_chi_square(f[lo:hi])
            if r is not None:
                vals.append(r[0] / r[1])
        out.append(float(np.mean(vals)) if vals else None)
    return out


def chi_square_verdict(profile):
    """Начало потока похоже на случайные LSB, а остальное структурировано: признак частичного встраивания.
    Возвращает (подозрительно, число_частей_с_случайными_LSB_подряд_с_начала)."""
    vals = [v for v in profile]
    if len([v for v in vals if v is not None]) < parts_needed():
        return False, 0
    lead = 0
    for v in vals:
        if v is not None and v < 2.0:
            lead += 1
        else:
            break
    rest = [v for v in vals[lead:] if v is not None]
    structured = len(rest) >= 3 and float(np.median(rest)) > 5.0
    return (lead >= 1 and structured), lead


def parts_needed():
    return CHI_PARTS - 2


def _f(groups):
    return np.abs(np.diff(groups.astype(np.int32), axis=1)).sum(axis=1)


def _apply(groups, mask):
    out = groups.astype(np.int32).copy()
    for i, m in enumerate(mask):
        if m == 1:
            out[:, i] = out[:, i] ^ 1
        elif m == -1:
            out[:, i] = np.clip(((out[:, i] + 1) ^ 1) - 1, 0, 255)
    return out


def _rs_counts(groups, mask):
    base = _f(groups)
    flipped = _f(_apply(groups, mask))
    return int((flipped > base).sum()), int((flipped < base).sum())


def rs_estimate(channel: np.ndarray, group=4):
    """Оценка доли заполненных LSB по RS-анализу (Fridrich, Goljan, Du) для одного канала.
    Группы из 4 соседних пикселей по строке. Возвращает (p, число_групп) или None."""
    h, w = channel.shape
    w4 = (w // group) * group
    if w4 == 0 or h * w4 < group * 500:
        return None
    groups = channel[:, :w4].reshape(-1, group).astype(np.int32)
    mask = np.array([0, 1, 1, 0])
    inv = -mask
    inverted = groups ^ 1
    rm0, sm0 = _rs_counts(groups, mask)
    rn0, sn0 = _rs_counts(groups, inv)
    rm1, sm1 = _rs_counts(inverted, mask)
    rn1, sn1 = _rs_counts(inverted, inv)
    d0, d1 = rm0 - sm0, rm1 - sm1
    dn0, dn1 = rn0 - sn0, rn1 - sn1
    a = 2 * (d1 + d0)
    b = dn0 - dn1 - d1 - 3 * d0
    c = d0 - dn0
    if a == 0:
        roots = [-c / b] if b != 0 else []
    else:
        disc = b * b - 4 * a * c
        if disc < 0:
            return 0.0, len(groups)
        sq = math.sqrt(disc)
        roots = [(-b + sq) / (2 * a), (-b - sq) / (2 * a)]
    if not roots:
        return 0.0, len(groups)
    x = min(roots, key=abs)
    p = x / (x - 0.5) if x != 0.5 else 0.0
    return float(min(max(p, 0.0), 1.0)), len(groups)


def lsb_plane(arr: np.ndarray) -> np.ndarray:
    """Младшие биты как чёрно-белая картинка."""
    return ((arr & 1) * 255).astype(np.uint8)
