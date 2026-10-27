import re
import subprocess
import sys
from pathlib import Path

import pytest

from shroud import htmlreport, scan
from shroud.scan import Report

ROOT = Path(__file__).resolve().parent.parent


def rep(path, verdict, size=100):
    return Report(path=path, size=size, fmt="png", verdict=verdict)


MIXED = [
    rep("b-clean.png", scan.CLEAN, 50),
    rep("a-odd.png", scan.ODD, 300),
    rep("c-likely.png", scan.LIKELY, 10),
    rep("d-susp.png", scan.SUSPICIOUS, 200),
    rep("e-clean.png", scan.CLEAN, 400),
]


def order(html):
    return re.findall(r"<h2>([^<]+)</h2>", html)


def test_default_order_is_worst_first_then_by_name():
    assert order(htmlreport.render(MIXED)) == ["c-likely.png", "d-susp.png", "a-odd.png", "b-clean.png", "e-clean.png"]


def test_sort_by_name_and_size():
    assert order(htmlreport.render(MIXED, "name")) == ["a-odd.png", "b-clean.png", "c-likely.png", "d-susp.png", "e-clean.png"]
    assert order(htmlreport.render(MIXED, "size")) == ["e-clean.png", "a-odd.png", "d-susp.png", "b-clean.png", "c-likely.png"]


def test_unknown_sort_is_rejected():
    with pytest.raises(ValueError):
        htmlreport.render(MIXED, "random")


def test_filter_tabs_and_card_classes_present():
    html = htmlreport.render(MIXED)
    for ident in ("f-all", "f-flag", "f-odd", "f-clean"):
        assert f'id="{ident}"' in html and f'for="{ident}"' in html
    assert 'id="f-all" checked' in html
    assert html.count('class="card v-clean"') == 2 and html.count('class="card v-likely"') == 1
    assert "подозрительные 2" in html and "странности 1" in html and "чистые 2" in html and "все 5" in html


def test_filter_css_hides_other_verdicts_without_scripts():
    html = htmlreport.render(MIXED)
    assert "#f-flag:checked ~ .cards .card:not(.v-suspicious):not(.v-likely)" in html and "{display:none}" in html
    assert "<script" not in html.lower()
    assert "default-src 'none'" in html and "script-src" not in html


def test_inputs_and_cards_are_siblings_so_the_css_selector_works():
    html = htmlreport.render(MIXED)
    view = html[html.index('<div class="view">'):]
    assert view.index('id="f-clean"') < view.index('<div class="cards">')
    assert "</div></div>" in view  # cards и view закрыты, вложенного контейнера между радио и карточками нет


def test_empty_report_renders():
    html = htmlreport.render([])
    assert "все 0" in html and order(html) == []


def test_hostile_path_is_still_escaped_with_filters():
    html = htmlreport.render([rep("<img src=x onerror=alert(1)>.png", scan.LIKELY)])
    assert "<img src=x" not in html and "&lt;img src=x" in html


def test_cli_html_sort_option(tmp_path):
    from tests.helpers import cover, to_png_bytes

    for name in ("b.png", "a.png"):
        (tmp_path / name).write_bytes(to_png_bytes(cover(seed=3)))
    out = tmp_path / "r.html"
    run = [sys.executable, "-m", "shroud", "scan", str(tmp_path), "--html", str(out), "--html-sort", "name"]
    assert subprocess.run(run, capture_output=True, text=True, cwd=ROOT).returncode == 0
    assert [Path(p).name for p in order(out.read_text(encoding="utf-8"))] == ["a.png", "b.png"]
    bad = subprocess.run([*run[:-1], "bogus"], capture_output=True, text=True, cwd=ROOT)
    assert bad.returncode == 2
