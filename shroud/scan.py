"""Оркестрация: структура файла + статистика пикселей, итоговый вердикт."""
import io
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
from PIL import Image

from . import extract, lsb
from .containers import analyze_container
from .findings import ALERT, INFO, WARN, Finding

LOSSLESS = {"png", "bmp"}
RS_ALERT, RS_WARN, RS_SATURATED = 0.05, 0.04, 0.9
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_PIXELS = 100_000_000
CHI_REST_MEDIAN = 4.0
CHI_LEAD_MAX = 1.5
CLEAN, ODD, SUSPICIOUS, LIKELY = "clean", "odd", "suspicious", "likely"
VERDICT_TEXT = {
    CLEAN: "чисто по проверенным признакам",
    ODD: "есть странности, стего не подтверждено",
    SUSPICIOUS: "подозрительно",
    LIKELY: "вероятно, внутри спрятаны данные",
}


@dataclass
class Report:
    path: str
    size: int
    fmt: str | None
    verdict: str = CLEAN
    findings: list = field(default_factory=list)
    metrics: dict = field(default_factory=dict)

    def as_dict(self):
        return {"path": self.path, "size": self.size, "format": self.fmt, "verdict": self.verdict,
                "findings": [f.as_dict() for f in self.findings], "metrics": self.metrics}


def _channels(img: Image.Image):
    """Список 2D-массивов каналов для анализа. None, если пиксельный анализ неприменим."""
    if img.mode in ("L", "1"):
        return [np.asarray(img.convert("L"))], "L"
    if img.mode in ("RGB", "RGBA"):
        arr = np.asarray(img)
        names = "RGBA"[:arr.shape[2]]
        chans = [(arr[:, :, i], names[i]) for i in range(arr.shape[2])]
        if img.mode == "RGBA" and np.ptp(arr[:, :, 3]) == 0:
            chans = chans[:3]  # постоянная альфа не несёт информации
        return [c for c, _ in chans], "".join(n for _, n in chans)
    return None, img.mode


def _pixel_analysis(data: bytes, fmt: str, report: Report):
    try:
        img = Image.open(io.BytesIO(data))
        if img.width * img.height > MAX_PIXELS:
            report.findings.append(Finding(INFO, "too-large",
                                           f"изображение {img.width}x{img.height}: пиксельный анализ пропущен (лимит {MAX_PIXELS // 1_000_000} Мпикс)"))
            return
        img.load()
    except Image.DecompressionBombError:
        report.findings.append(Finding(INFO, "too-large", "изображение объявляет слишком большие размеры: пиксельный анализ пропущен"))
        return
    except Exception as e:
        report.findings.append(Finding(WARN, "decode-failed", f"изображение не декодируется: {e.__class__.__name__}"))
        return
    chans, names = _channels(img)
    if chans is None:
        report.findings.append(Finding(INFO, "pixels-skipped",
                                       f"режим {names}: пиксельный LSB-анализ не применяется (палитра/другие режимы)"))
        return
    rs_values = {}
    for name, ch in zip(names, chans, strict=True):
        r = lsb.rs_estimate(ch)
        if r is not None:
            rs_values[name] = round(r[0], 3)
    profile = lsb.chi_square_profile(chans)
    report.metrics["rs"] = rs_values
    report.metrics["chi_profile"] = [None if v is None else round(v, 2) for v in profile]
    report.metrics["pixels"] = int(chans[0].size)

    if rs_values:
        vals = list(rs_values.values())
        mid = float(np.median(vals))  # настоящее встраивание задевает все каналы, шум одного канала не считается
        report.metrics["rs_median"] = round(mid, 3)
        detail = ", ".join(f"{n}={v:.2f}" for n, v in rs_values.items())
        if mid >= RS_ALERT:
            report.findings.append(Finding(ALERT, "rs-lsb", f"RS-анализ: LSB заполнены примерно на {mid * 100:.0f}% ({detail})"))
        elif max(vals) >= RS_SATURATED:
            report.findings.append(Finding(WARN, "rs-saturated",
                                           f"RS-анализ неустойчив ({detail}): возможно почти полное заполнение LSB, проверьте плоскость командой lsb-plane"))
        elif mid >= RS_WARN:
            report.findings.append(Finding(WARN, "rs-weak", f"RS-анализ: слабый сигнал ({mid * 100:.1f}%), на грани шума"))

    for label, kind, preview in extract.candidates(chans)[:4]:
        report.findings.append(Finding(ALERT, "lsb-extract", f"из младших битов ({label}) читается {kind}: «{preview}»"))

    suspicious, lead = _chi_contrast(profile)
    if suspicious:
        payload = int(report.metrics["pixels"] * len(chans) * lead / lsb.CHI_PARTS / 8)
        report.findings.append(Finding(ALERT, "chi-prefix",
                                       f"хи-квадрат: первые {lead} из {lsb.CHI_PARTS} долей изображения похожи на случайные LSB, дальше структура "
                                       f"(оценка размера скрытых данных до ~{payload} байт)"))


def _chi_contrast(profile):
    lead = 0
    for v in profile:
        if v is not None and v <= CHI_LEAD_MAX:
            lead += 1
        else:
            break
    rest = [v for v in profile[lead:] if v is not None]
    if lead >= 1 and len(rest) >= 3 and float(np.median(rest)) >= CHI_REST_MEDIAN:
        return True, lead
    return False, lead


def _verdict(findings):
    alerts = [f for f in findings if f.level == ALERT]
    warns = [f for f in findings if f.level == WARN]
    if any(f.code == "embedded-file" for f in alerts) or len(alerts) >= 2:
        return LIKELY
    if alerts:
        return SUSPICIOUS
    return ODD if warns else CLEAN


def scan_bytes(data: bytes, name="<memory>") -> Report:
    fmt, findings = analyze_container(data)
    report = Report(path=name, size=len(data), fmt=fmt, findings=list(findings))
    if fmt in LOSSLESS:
        _pixel_analysis(data, fmt, report)
    elif fmt == "jpeg":
        report.findings.append(Finding(INFO, "jpeg-dct",
                                       "JPEG: пиксельный LSB-анализ не применяется; DCT-стего (jsteg, outguess, F5) в v1 не проверяется"))
    elif fmt == "gif":
        report.findings.append(Finding(INFO, "gif-palette", "GIF: анализ индексов палитры в v1 не выполняется"))
    report.verdict = _verdict(report.findings)
    return report


def scan_path(path) -> Report:
    p = Path(path)
    size = p.stat().st_size
    if size > MAX_FILE_BYTES:
        report = Report(path=str(p), size=size, fmt=None)
        report.findings.append(Finding(INFO, "too-large", f"файл {size} байт: больше лимита {MAX_FILE_BYTES // 1024 // 1024} МБ, пропущен"))
        return report
    return scan_bytes(p.read_bytes(), str(p))


def lsb_plane_image(data: bytes) -> Image.Image:
    img = Image.open(io.BytesIO(data))
    img.load()
    chans, _ = _channels(img)
    if chans is None:
        raise ValueError("для этого режима изображения плоскость LSB не строится")
    plane = np.stack([lsb.lsb_plane(c) for c in chans[:3]], axis=-1) if len(chans) >= 3 else lsb.lsb_plane(chans[0])
    return Image.fromarray(plane)
