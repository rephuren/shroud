"""Попытка прочитать скрытое сообщение из младших битов в типичных порядках (как zsteg).
Это разбор самого изображения, которое пользователь проверяет; ничего не записывается."""
import itertools
import re

import numpy as np

MAX_BYTES = 4096
MAGICS = [
    (b"PK\x03\x04", "ZIP"), (b"%PDF-", "PDF"), (b"\x89PNG\r\n\x1a\n", "PNG"), (b"\x1f\x8b\x08", "gzip"),
    (b"\x7fELF", "ELF"), (b"7z\xbc\xaf\x27\x1c", "7z"), (b"Rar!\x1a\x07", "RAR"), (b"\xff\xd8\xff", "JPEG"),
]
TEXT_RUN = re.compile(rb"[\x20-\x7e\t\r\n]{20,}")
WORDY = re.compile(rb"[A-Za-z0-9 _{}\-.:,/!?@=\n]")
MIN_RUN, MIN_WORDY, MIN_DISTINCT = 20, 0.9, 8


def looks_like_text(run: bytes) -> bool:
    """Длинный отрезок почти из букв/цифр/знаков и с разнообразием. Отсекает случайный шум и повторы."""
    wordy = len(WORDY.findall(run)) / len(run)
    return len(run) >= MIN_RUN and wordy >= MIN_WORDY and len(set(run)) >= MIN_DISTINCT


def _selections(nchan):
    base = [(i,) for i in range(nchan)]
    if nchan >= 3:
        base += [(0, 1, 2), (2, 1, 0)]
    if nchan == 4:
        base += [(0, 1, 2, 3)]
    return base


def candidates(chans, planes=(0, 1, 2)):
    """chans: список 2D-каналов одинакового размера. Возвращает [(описание, тип, превью)]."""
    arr = np.stack(chans, axis=-1)
    out = []
    for sel, plane, bitorder, scan in itertools.product(
            _selections(arr.shape[2]), planes, ("msb", "lsb"), ("xy", "yx")):
        view = arr if scan == "xy" else arr.transpose(1, 0, 2)
        bits = ((view[..., list(sel)] >> plane) & 1).reshape(-1)[: MAX_BYTES * 8].astype(np.uint8)
        data = np.packbits(bits, bitorder="big" if bitorder == "msb" else "little").tobytes()
        label = f"b{plane + 1},{''.join('RGBA'[i] if arr.shape[2] > 1 else 'L' for i in sel).lower()},{bitorder},{scan}"
        for magic, name in MAGICS:
            if data.startswith(magic):
                out.append((label, f"файл {name}", data[:24].hex()))
        runs = [r for r in TEXT_RUN.findall(data) if looks_like_text(r)]
        if runs:
            m = max(runs, key=len)
            out.append((label, "текст", m[:80].decode("ascii", "replace")))
    out.sort(key=lambda c: not c[1].startswith("файл"))  # сначала файловые сигнатуры
    return out
