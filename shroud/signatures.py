"""Поиск вложенных файлов и оценка энтропии в «хвостовых» данных."""
import math
import re
from collections import Counter

from .findings import ALERT, INFO, WARN, Finding

SIGNATURES = [
    (b"PK\x03\x04", "ZIP-архив"),
    (b"Rar!\x1a\x07", "RAR-архив"),
    (b"7z\xbc\xaf\x27\x1c", "7z-архив"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"%PDF-", "PDF"),
    (b"\x7fELF", "ELF-бинарь"),
    (b"SQLite format 3\x00", "SQLite-база"),
    (b"-----BEGIN ", "PEM / PGP-блок"),
    (b"\x89PNG\r\n\x1a\n", "вложенный PNG"),
    (b"\xff\xd8\xff", "вложенный JPEG"),
    (b"GIF8", "вложенный GIF"),
    (b"OggS", "Ogg-контейнер"),
    (b"ID3", "MP3 (ID3)"),
]
B64_RE = re.compile(rb"[A-Za-z0-9+/]{80,}={0,2}")


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def printable_preview(data: bytes, limit=64) -> str:
    chunk = data[:limit]
    return "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)


def find_signatures(data: bytes, base_offset=0):
    found = []
    for sig, name in SIGNATURES:
        pos = data.find(sig)
        if pos != -1:
            found.append((base_offset + pos, name))
    return sorted(found)


def analyze_trailing(data: bytes, offset: int, where: str):
    """Данные, дописанные после логического конца файла."""
    findings = []
    if not data:
        return findings
    h = entropy(data)
    kind = "высокая энтропия, похоже на шифртекст или архив" if h > 7.5 else (
        "низкая энтропия, похоже на открытый текст или структуру" if h < 5 else "смешанные данные")
    findings.append(Finding(ALERT, "trailing-data",
                            f"{len(data)} байт после {where}: энтропия {h:.2f} бит/байт ({kind}); начало: «{printable_preview(data)}»",
                            offset, len(data)))
    for off, name in find_signatures(data, offset):
        findings.append(Finding(ALERT, "embedded-file", f"в хвосте найден {name} на смещении {off}", off))
    return findings


def analyze_text_value(value: bytes, label: str, offset=None):
    findings = []
    if len(value) >= 512:
        findings.append(Finding(WARN, "large-metadata",
                                f"{label}: {len(value)} байт, необычно много для метаданных; начало: «{printable_preview(value)}»",
                                offset, len(value)))
    if B64_RE.search(value):
        findings.append(Finding(WARN, "base64-in-metadata", f"{label}: длинная base64-подобная строка", offset))
    for off, name in find_signatures(value, offset or 0):
        findings.append(Finding(ALERT, "embedded-file", f"{label}: внутри найден {name}", off))
    return findings
