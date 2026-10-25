"""Разбор структуры PNG / JPEG / GIF / BMP: что лежит вне пикселей."""
import struct
import zlib

from .findings import ALERT, INFO, WARN, Finding
from .signatures import analyze_text_value, analyze_trailing

PNG_SIG = b"\x89PNG\r\n\x1a\n"
PNG_STANDARD = {
    b"IHDR", b"PLTE", b"IDAT", b"IEND", b"cHRM", b"gAMA", b"iCCP", b"sBIT", b"sRGB", b"bKGD", b"hIST",
    b"tRNS", b"pHYs", b"sPLT", b"tIME", b"iTXt", b"tEXt", b"zTXt", b"eXIf", b"acTL", b"fcTL", b"fdAT",
    b"cICP", b"mDCV", b"cLLI",
}
PNG_CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}


def sniff(data: bytes):
    if data.startswith(PNG_SIG):
        return "png"
    if data.startswith(b"\xff\xd8"):
        return "jpeg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if data.startswith(b"BM"):
        return "bmp"
    return None


def parse_png(data: bytes):
    findings, ihdr, idat = [], None, bytearray()
    pos, end = 8, None
    while pos + 12 <= len(data):
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        ctype = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + length]
        crc_pos = pos + 8 + length
        if crc_pos + 4 > len(data):
            findings.append(Finding(WARN, "truncated", f"чанк {ctype.decode('latin-1')} обрезан", pos))
            break
        stored = struct.unpack(">I", data[crc_pos:crc_pos + 4])[0]
        if zlib.crc32(data[pos + 4:crc_pos]) & 0xFFFFFFFF != stored:
            findings.append(Finding(WARN, "crc-mismatch", f"CRC чанка {ctype.decode('latin-1')} не совпадает", pos))
        name = ctype.decode("latin-1")
        if ctype == b"IHDR" and len(body) >= 13:
            ihdr = struct.unpack(">IIBBBBB", body[:13])
        elif ctype == b"IDAT":
            idat += body
        elif ctype in (b"tEXt", b"iTXt"):
            findings += analyze_text_value(body, f"чанк {name}", pos)
        elif ctype == b"zTXt":
            try:
                value = zlib.decompress(body.split(b"\x00", 1)[1][1:])
                findings += analyze_text_value(value, "чанк zTXt (распакован)", pos)
            except Exception:
                findings.append(Finding(WARN, "bad-ztxt", "zTXt не распаковывается", pos))
        if ctype not in PNG_STANDARD:
            private = ctype[1:2].islower()
            findings.append(Finding(WARN, "unknown-chunk",
                                    f"нестандартный чанк {name} ({len(body)} байт{', приватный' if private else ''})",
                                    pos, len(body)))
            findings += analyze_text_value(body, f"чанк {name}", pos)
        pos = crc_pos + 4
        if ctype == b"IEND":
            end = pos
            break
    if end is None:
        findings.append(Finding(WARN, "no-iend", "нет чанка IEND"))
        return findings
    findings += analyze_trailing(data[end:], end, "IEND")
    findings += _check_idat_stream(bytes(idat), ihdr)
    return findings


def _check_idat_stream(idat: bytes, ihdr):
    """Лишние байты после конца zlib-потока или в распакованных данных."""
    if not idat or ihdr is None:
        return []
    width, height, depth, ctype, _, _, interlace = ihdr
    out = []
    try:
        d = zlib.decompressobj()
        raw = d.decompress(idat)
    except zlib.error:
        return [Finding(WARN, "bad-idat", "поток IDAT не распаковывается")]
    if d.unused_data:
        out.append(Finding(ALERT, "idat-unused", f"{len(d.unused_data)} байт в IDAT после конца zlib-потока",
                           size=len(d.unused_data)))
    if interlace == 0 and ctype in PNG_CHANNELS:
        rowbytes = (width * PNG_CHANNELS[ctype] * depth + 7) // 8 + 1
        extra = len(raw) - rowbytes * height
        if extra > 0:
            out.append(Finding(ALERT, "idat-extra", f"{extra} лишних байт в распакованных данных изображения",
                               size=extra))
    return out


JPEG_BENIGN_APP = (b"JFIF", b"Exif", b"ICC_PROFILE", b"http://ns.adobe.com/", b"Photoshop", b"MPF", b"Adobe", b"FPXR")


def parse_jpeg(data: bytes):
    findings = []
    pos, end = 2, None
    while pos + 2 <= len(data):
        if data[pos] != 0xFF:
            findings.append(Finding(WARN, "jpeg-garbage", "мусор между сегментами JPEG", pos))
            break
        while pos + 1 < len(data) and data[pos + 1] == 0xFF:
            pos += 1
        marker = data[pos + 1] if pos + 1 < len(data) else 0
        if marker == 0xD9:
            end = pos + 2
            break
        if marker in (0x01, 0xD8) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        if pos + 4 > len(data):
            break
        length = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        seg = data[pos + 4:pos + 2 + length]
        if marker == 0xFE and len(seg) >= 64:
            findings += analyze_text_value(seg, f"комментарий JPEG ({len(seg)} байт)", pos)
            findings.append(Finding(WARN, "jpeg-comment", f"длинный COM-сегмент ({len(seg)} байт)", pos, len(seg)))
        elif 0xE0 <= marker <= 0xEF and len(seg) > 4096 and not seg.startswith(JPEG_BENIGN_APP):
            findings.append(Finding(WARN, "jpeg-app", f"большой нестандартный APP{marker - 0xE0}-сегмент ({len(seg)} байт)", pos, len(seg)))
            findings += analyze_text_value(seg, f"APP{marker - 0xE0}", pos)
        if marker == 0xDA:  # данные скана идут до следующего маркера
            p = pos + 2 + length
            while p + 1 < len(data):
                if data[p] == 0xFF and data[p + 1] != 0x00 and not (0xD0 <= data[p + 1] <= 0xD7) and data[p + 1] != 0xFF:
                    break
                p += 1
            pos = p
            continue
        pos += 2 + length
    if end is None:
        findings.append(Finding(WARN, "no-eoi", "нет маркера конца JPEG (EOI)"))
        return findings
    findings += analyze_trailing(data[end:], end, "EOI")
    return findings


def _skip_subblocks(data, pos):
    while pos < len(data):
        n = data[pos]
        pos += 1
        if n == 0:
            return pos
        pos += n
    return pos


def parse_gif(data: bytes):
    findings: list[Finding] = []
    if len(data) < 13:
        return findings
    flags = data[10]
    pos = 13
    if flags & 0x80:
        pos += 3 * (2 << (flags & 7))
    end = None
    while pos < len(data):
        block = data[pos]
        if block == 0x3B:
            end = pos + 1
            break
        if block == 0x21:  # расширение
            label = data[pos + 1] if pos + 1 < len(data) else 0
            start = pos
            pos = _skip_subblocks(data, pos + 2)
            if label == 0xFE and pos - start > 80:
                findings += analyze_text_value(data[start:pos], "комментарий GIF", start)
            elif label == 0xFF and pos - start > 1024:
                findings.append(Finding(WARN, "gif-app-ext", f"большое расширение приложения ({pos - start} байт)", start))
        elif block == 0x2C:  # кадр
            if pos + 10 > len(data):
                break
            lflags = data[pos + 9]
            pos += 10
            if lflags & 0x80:
                pos += 3 * (2 << (lflags & 7))
            pos = _skip_subblocks(data, pos + 1)
        else:
            findings.append(Finding(WARN, "gif-garbage", f"неожиданный байт блока 0x{block:02x}", pos))
            break
    if end is None:
        findings.append(Finding(WARN, "no-gif-trailer", "нет трейлера GIF (0x3B)"))
        return findings
    findings += analyze_trailing(data[end:], end, "трейлера GIF")
    return findings


def parse_bmp(data: bytes):
    if len(data) < 6:
        return []
    declared = struct.unpack("<I", data[2:6])[0]
    if declared and len(data) > declared:
        return analyze_trailing(data[declared:], declared, "заявленного конца BMP")
    return []


def analyze_container(data: bytes):
    kind = sniff(data)
    if kind is None:
        return None, [Finding(INFO, "unknown-format", "формат не распознан (поддерживаются PNG, JPEG, GIF, BMP)")]
    parser = {"png": parse_png, "jpeg": parse_jpeg, "gif": parse_gif, "bmp": parse_bmp}[kind]
    return kind, parser(data)
