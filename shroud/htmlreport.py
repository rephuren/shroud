"""Самодостаточный HTML-отчёт: без внешних файлов и скриптов, все данные из файлов экранируются."""
from html import escape

from . import scan

CSS = """
:root{--bg:#050505;--panel:#0b0b0b;--line:#1a1a1a;--text:#e8e8e8;--dim:#8a8a8a;--red:#b3000f}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 'SF Mono',Menlo,Consolas,monospace}
main{max-width:980px;margin:0 auto;padding:36px 20px 60px}
h1{font-size:34px;letter-spacing:.35em;margin:0 0 4px;color:var(--dim)}
.lead{color:var(--dim);margin:0 0 28px}
.card{background:var(--panel);border:1px solid var(--line);padding:16px 18px;margin:0 0 16px}
.card h2{font-size:14px;margin:0 0 2px;word-break:break-all}.meta{color:var(--dim);font-size:12px;margin-bottom:10px}
.f{padding:3px 0;border-bottom:1px solid #101010;word-break:break-word}.f:last-child{border:0}
.alert{color:var(--red)}.warn{color:var(--text)}.info{color:var(--dim)}
.v{margin-top:10px;font-weight:700}.v.suspicious,.v.likely{color:var(--red)}
.s{display:flex;gap:10px;flex-wrap:wrap;margin:0 0 22px}.s div{border:1px solid var(--line);padding:8px 14px;background:var(--panel)}
.s b{display:block;font-size:22px}.s b.red{color:var(--red)}
.view>input{position:absolute;opacity:0;pointer-events:none}
.view>label{display:inline-block;margin:0 8px 18px 0;border:1px solid var(--line);background:var(--panel);padding:6px 14px;cursor:pointer;color:var(--dim)}
.view>input:checked + label{color:var(--text);border-color:var(--red)}
.view>input:focus-visible + label{outline:1px solid var(--text)}
#f-flag:checked ~ .cards .card:not(.v-suspicious):not(.v-likely),
#f-odd:checked ~ .cards .card:not(.v-odd),
#f-clean:checked ~ .cards .card:not(.v-clean){display:none}
"""
SORTS = ("verdict", "name", "size")
VERDICT_RANK = {scan.LIKELY: 0, scan.SUSPICIOUS: 1, scan.ODD: 2, scan.CLEAN: 3}
MARK = {"alert": "▓", "warn": "▒", "info": "░"}


def _card(r):
    rows = "".join(
        f'<div class="f {escape(f.level)}">{MARK.get(f.level, "░")} {escape(f.message)}</div>' for f in r.findings
    ) or '<div class="f info">находок нет</div>'
    return (
        f'<section class="card v-{escape(r.verdict)}"><h2>{escape(r.path)}</h2>'
        f'<div class="meta">{escape(r.fmt or "?")} · {int(r.size)} байт</div>{rows}'
        f'<div class="v {escape(r.verdict)}">вердикт: {escape(scan.VERDICT_TEXT[r.verdict])}</div></section>'
    )


def ordered(reports, sort="verdict"):
    """Порядок карточек: сначала самые опасные (по умолчанию), либо по имени, либо по размеру файла."""
    if sort not in SORTS:
        raise ValueError(f"сортировка {sort!r}: ожидается одно из {', '.join(SORTS)}")
    if sort == "name":
        return sorted(reports, key=lambda r: r.path.lower())
    if sort == "size":
        return sorted(reports, key=lambda r: (-r.size, r.path.lower()))
    return sorted(reports, key=lambda r: (VERDICT_RANK.get(r.verdict, 9), r.path.lower()))


def render(reports, sort="verdict"):
    reports = ordered(reports, sort)
    flagged = sum(r.verdict in (scan.SUSPICIOUS, scan.LIKELY) for r in reports)
    odd = sum(r.verdict == scan.ODD for r in reports)
    clean = sum(r.verdict == scan.CLEAN for r in reports)
    tabs = (
        f'<input type="radio" name="f" id="f-all" checked><label for="f-all">все {len(reports)}</label>'
        f'<input type="radio" name="f" id="f-flag"><label for="f-flag">подозрительные {flagged}</label>'
        f'<input type="radio" name="f" id="f-odd"><label for="f-odd">странности {odd}</label>'
        f'<input type="radio" name="f" id="f-clean"><label for="f-clean">чистые {clean}</label>'
    )
    return (
        '<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>shroud: отчёт</title>'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">'
        f"<style>{CSS}</style></head><body><main><h1>SHROUD</h1>"
        '<p class="lead">отчёт о проверке изображений на скрытые данные</p>'
        f'<div class="s"><div>файлов<b>{len(reports)}</b></div><div>подозрительных<b class="red">{flagged}</b></div>'
        f"<div>со странностями<b>{odd}</b></div><div>чистых<b>{clean}</b></div></div>"
        f'<div class="view">{tabs}'
        '<div class="cards">' + "".join(_card(r) for r in reports) + "</div></div>"
        "</main></body></html>\n"
    )
