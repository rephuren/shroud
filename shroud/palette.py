"""Изображения с палитрой (GIF, PNG-P): LSB прячут в индексах цвета. Индексы в файле лежат в произвольном порядке,
поэтому проверяем и сами индексы, и их ранги после упорядочивания палитры по яркости (как это делает EzStego)."""
import numpy as np
from PIL import Image

MIN_USED = 8  # меньше используемых цветов: пары (2k, 2k+1) бессмысленны


def luminance_ranks(img: Image.Image):
    """(индексы, ранги по яркости). Ранг цвета палитры = его место при сортировке палитры по яркости."""
    idx = np.asarray(img)
    pal = img.getpalette()
    if pal is None:
        return idx, idx
    rgb = np.array(pal[:768], dtype=np.float64)
    rgb = rgb[: len(rgb) // 3 * 3].reshape(-1, 3)
    lum = 0.299 * rgb[:, 0] + 0.587 * rgb[:, 1] + 0.114 * rgb[:, 2]
    order = np.argsort(lum, kind="stable")
    rank = np.zeros(256, dtype=np.uint8)
    rank[order[:256]] = np.arange(min(len(order), 256), dtype=np.uint8)
    return idx, rank[idx]


def used_colors(idx: np.ndarray) -> int:
    return int(np.unique(idx).size)


def views(img: Image.Image):
    """Список (имя, 2D-массив) для статистического анализа, либо [] если цветов слишком мало."""
    idx, ranks = luminance_ranks(img)
    if used_colors(idx) < MIN_USED:
        return []
    out = [("I", idx)]
    if not np.array_equal(idx, ranks):
        out.append(("O", ranks))
    return out
