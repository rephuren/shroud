"""SARIF 2.1.0 для GitHub code scanning. В отчёт попадают только предупреждения и тревоги: информационные находки
(«ничего не показал», «пропущено») на вкладке Security были бы шумом."""
import json
from importlib import metadata

from .findings import ALERT, WARN

LEVEL = {ALERT: "error", WARN: "warning"}
SECURITY_SEVERITY = {ALERT: "8.0", WARN: "4.0"}


def _version() -> str:
    try:
        return metadata.version("shroud")
    except metadata.PackageNotFoundError:
        return "unknown"


SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _uri(path: str) -> str:
    return path.replace("\\", "/")


def build(reports) -> dict:
    results = []
    rules: dict[str, dict] = {}
    for r in reports:
        for f in r.findings:
            if f.level not in LEVEL:
                continue
            rule = rules.setdefault(f.code, {
                "id": f.code,
                "name": f.code,
                "shortDescription": {"text": f"shroud: {f.code}"},
                "defaultConfiguration": {"level": LEVEL[f.level]},
                "properties": {"tags": ["security", "steganography"], "security-severity": SECURITY_SEVERITY[f.level]},
            })
            if LEVEL[f.level] == "error":
                rule["defaultConfiguration"]["level"] = "error"
                rule["properties"]["security-severity"] = SECURITY_SEVERITY[ALERT]
            location: dict = {"physicalLocation": {"artifactLocation": {"uri": _uri(r.path)}}}
            if f.offset is not None:
                region = {"byteOffset": f.offset}
                if f.size is not None:
                    region["byteLength"] = f.size
                location["physicalLocation"]["region"] = region
            results.append({
                "ruleId": f.code,
                "level": LEVEL[f.level],
                "message": {"text": f.message},
                "locations": [location],
                "properties": {"verdict": r.verdict, "format": r.fmt},
            })
    order = list(rules)
    for res in results:
        res["ruleIndex"] = order.index(res["ruleId"])
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "shroud", "version": _version(), "rules": [rules[k] for k in order]}}, "results": results}],
    }


def render(reports) -> str:
    return json.dumps(build(reports), ensure_ascii=False, indent=2) + "\n"
