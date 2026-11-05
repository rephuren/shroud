import json

from shroud.__main__ import main
from tests.helpers import cover, embed_lsb, random_bits, to_png_bytes


def _folder(tmp_path):
    (tmp_path / "clean.png").write_bytes(to_png_bytes(cover(128, 128, 2)))
    (tmp_path / "stego.png").write_bytes(to_png_bytes(embed_lsb(cover(256, 256, 1), random_bits(256 * 256 * 3 // 2))))
    return str(tmp_path)


def test_only_flagged_hides_clean_files(tmp_path, capsys):
    folder = _folder(tmp_path)
    assert main(["scan", folder, "--json", "--only-flagged"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert [r["path"].endswith("stego.png") for r in out] == [True]


def test_without_flag_everything_is_listed(tmp_path, capsys):
    main(["scan", _folder(tmp_path), "--json"])
    assert len(json.loads(capsys.readouterr().out)) == 2


def test_exit_code_and_empty_output_for_clean_folder(tmp_path, capsys):
    (tmp_path / "clean.png").write_bytes(to_png_bytes(cover(128, 128, 2)))
    assert main(["scan", str(tmp_path), "--json", "--only-flagged"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == []
    assert "проверено файлов: 1, показано: 0" in captured.err


def test_only_flagged_applies_to_sarif_and_html(tmp_path):
    folder = _folder(tmp_path)
    sarif, html = tmp_path / "r.sarif", tmp_path / "r.html"
    main(["scan", folder, "--only-flagged", "--sarif", str(sarif), "--html", str(html), "--no-color"])
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in json.loads(sarif.read_text())["runs"][0]["results"]}
    assert uris and all(u.endswith("stego.png") for u in uris)
    assert "clean.png" not in html.read_text(encoding="utf-8")
