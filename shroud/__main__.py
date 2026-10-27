import argparse
import json
import sys
from pathlib import Path

from . import htmlreport, scan

IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".bmp"}
RED, DIM, BOLD, RESET = "\033[38;2;179;0;15m", "\033[2m", "\033[1m", "\033[0m"
LEVEL_MARK = {"alert": ("▓", RED), "warn": ("▒", ""), "info": ("░", DIM)}
VERDICT_COLOR = {scan.CLEAN: "", scan.ODD: "", scan.SUSPICIOUS: RED, scan.LIKELY: RED + BOLD}
SPARK = "▁▂▃▄▅▆▇█"


def collect(paths):
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            yield from (f for f in sorted(p.rglob("*")) if f.suffix.lower() in IMAGE_EXT)
        else:
            yield p


def spark(profile):
    vals = [v for v in profile if v is not None]
    if not vals:
        return ""
    top = max(max(vals), 2.0)
    return "".join("·" if v is None else SPARK[min(7, int(v / top * 7))] for v in profile)


def render(report, color):

    def c(code, s):
        return f"{code}{s}{RESET}" if color and code else s

    out = [c(BOLD, report.path) + c(DIM, f"  ({report.fmt or '?'}, {report.size} байт)")]
    for f in report.findings:
        mark, code = LEVEL_MARK[f.level]
        out.append(f"  {c(code, mark)} {f.message}")
    if "chi_profile" in report.metrics:
        out.append(c(DIM, f"  хи-квадрат по долям изображения: {spark(report.metrics['chi_profile'])}"))
    out.append(f"  вердикт: {c(VERDICT_COLOR[report.verdict], scan.VERDICT_TEXT[report.verdict])}")
    return "\n".join(out)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="shroud", description="Детектор стеганографии в изображениях")
    sub = parser.add_subparsers(dest="mode", required=True)
    sc = sub.add_parser("scan", help="проверить файлы или папки")
    sc.add_argument("paths", nargs="+")
    sc.add_argument("--json", action="store_true", help="вывод в JSON")
    sc.add_argument("--html", metavar="ФАЙЛ", help="сохранить отчёт в HTML")
    sc.add_argument("--html-sort", choices=htmlreport.SORTS, default="verdict", help="порядок карточек в HTML: verdict (по умолчанию), name, size")
    sc.add_argument("--no-color", action="store_true")
    pl = sub.add_parser("lsb-plane", help="сохранить плоскость младших битов как картинку")
    pl.add_argument("path")
    pl.add_argument("out")
    args = parser.parse_args(argv)

    if args.mode == "lsb-plane":
        scan.lsb_plane_image(Path(args.path).read_bytes()).save(args.out)
        print(f"плоскость LSB сохранена: {args.out}")
        return 0

    reports = []
    for path in collect(args.paths):
        try:
            reports.append(scan.scan_path(path))
        except OSError as e:
            print(f"{path}: {e}", file=sys.stderr)
    if args.html:
        Path(args.html).write_text(htmlreport.render(reports, args.html_sort), encoding="utf-8")
        print(f"HTML-отчёт сохранён: {args.html}", file=sys.stderr)
    if args.json:
        json.dump([r.as_dict() for r in reports], sys.stdout, ensure_ascii=False, indent=2)
        print()
    else:
        color = sys.stdout.isatty() and not args.no_color
        print("\n\n".join(render(r, color) for r in reports))
    flagged = any(r.verdict in (scan.SUSPICIOUS, scan.LIKELY) for r in reports)
    return 1 if flagged else 0


if __name__ == "__main__":
    sys.exit(main())
