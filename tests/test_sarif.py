import json

from shroud import sarif
from shroud.__main__ import main
from shroud.findings import ALERT, INFO, WARN, Finding
from shroud.scan import Report
from tests.helpers import cover, embed_lsb, random_bits, to_png_bytes


def _report(path="a.png", *findings):
    return Report(path=path, size=10, fmt="png", verdict="likely", findings=list(findings))


def test_structure_and_levels():
    doc = sarif.build([_report("a.png", Finding(ALERT, "rs-lsb", "заполнено"), Finding(WARN, "trailing", "хвост", 100, 20), Finding(INFO, "x", "шум"))])
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "shroud"
    levels = {r["ruleId"]: r["level"] for r in run["results"]}
    assert levels == {"rs-lsb": "error", "trailing": "warning"}  # info отброшен
    region = run["results"][1]["locations"][0]["physicalLocation"]["region"]
    assert region == {"byteOffset": 100, "byteLength": 20}
    assert "region" not in run["results"][0]["locations"][0]["physicalLocation"]


def test_rule_index_points_to_rule():
    doc = sarif.build([_report("a.png", Finding(WARN, "b", "m"), Finding(ALERT, "a", "m")), _report("b.png", Finding(WARN, "b", "m"))])
    run = doc["runs"][0]
    for res in run["results"]:
        assert run["tool"]["driver"]["rules"][res["ruleIndex"]]["id"] == res["ruleId"]
    assert len(run["tool"]["driver"]["rules"]) == 2


def test_rule_takes_highest_level_seen():
    doc = sarif.build([_report("a.png", Finding(WARN, "same", "m")), _report("b.png", Finding(ALERT, "same", "m"))])
    rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["defaultConfiguration"]["level"] == "error"
    assert rule["properties"]["security-severity"] == "8.0"


def test_windows_paths_become_uris():
    doc = sarif.build([_report("dir\\a.png", Finding(ALERT, "c", "m"))])
    assert doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "dir/a.png"


def test_clean_run_has_no_results():
    doc = sarif.build([_report("a.png", Finding(INFO, "x", "m"))])
    assert doc["runs"][0]["results"] == []


def test_cli_writes_valid_sarif(tmp_path):
    img = tmp_path / "s.png"
    img.write_bytes(to_png_bytes(embed_lsb(cover(256, 256, 1), random_bits(256 * 256 * 3 // 2))))
    out = tmp_path / "r.sarif"
    code = main(["scan", str(img), "--sarif", str(out), "--no-color"])
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert code == 1
    assert doc["runs"][0]["results"], "в стего-файле должны быть находки"
    assert all(r["level"] in ("error", "warning") for r in doc["runs"][0]["results"])
