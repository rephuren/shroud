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
"""
MARK = {"alert": "▓", "warn": "▒", "info": "░"}


def _card(r):
    rows = "".join(
        f'<div class="f {escape(f.level)}">{MARK.get(f.level, "░")} {escape(f.message)}</div>' for f in r.findings
    ) or '<div class="f info">находок нет</div>'
    return (
        f'<section class="card"><h2>{escape(r.path)}</h2>'
        f'<div class="meta">{escape(r.fmt or "?")} · {int(r.size)} байт</div>{rows}'
        f'<div class="v {escape(r.verdict)}">вердикт: {escape(scan.VERDICT_TEXT[r.verdict])}</div></section>'
    )


def render(reports):
    flagged = sum(r.verdict in (scan.SUSPICIOUS, scan.LIKELY) for r in reports)
    odd = sum(r.verdict == scan.ODD for r in reports)
    clean = sum(r.verdict == scan.CLEAN for r in reports)
    return (
        '<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>shroud: отчёт</title>'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">'
        f"<style>{CSS}</style></head><body><main><h1>SHROUD</h1>"
        '<p class="lead">отчёт о проверке изображений на скрытые данные</p>'
        f'<div class="s"><div>файлов<b>{len(reports)}</b></div><div>подозрительных<b class="red">{flagged}</b></div>'
        f"<div>со странностями<b>{odd}</b></div><div>чистых<b>{clean}</b></div></div>"
        + "".join(_card(r) for r in reports)
        + "</main></body></html>\n"
    )
