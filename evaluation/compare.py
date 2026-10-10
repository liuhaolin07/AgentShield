"""Compare recorded outcomes while refusing changed inputs/policies/oracles."""

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


STATUSES = frozenset({"HELD", "FAILED", "UNRUN"})


def _index(report: dict[str, Any]) -> dict[tuple[int, str], dict[str, Any]]:
    indexed = {}
    for result in report["results"]:
        key = (result["run"], result["case_id"])
        if key in indexed or result["status"] not in STATUSES:
            raise ValueError("Duplicate case/run or invalid status")
        indexed[key] = result
    counts = Counter(result["status"] for result in indexed.values())
    if {status: counts[status] for status in sorted(STATUSES)} != report["summary"]:
        raise ValueError("Summary does not match recorded results")
    return indexed


def _origins(indexed: dict[tuple[int, str], dict[str, Any]]) -> dict[int, str]:
    """Normalize only the ephemeral origin actually used by each canary."""
    origins = {}
    for (run, case_id), result in indexed.items():
        if case_id != "undefended_canary":
            continue
        parsed = urlsplit(result["inputs"].get("url", ""))
        if parsed.scheme == "http" and parsed.hostname == "127.0.0.1" and parsed.port:
            origins[run] = f"http://{parsed.netloc}"
    return origins


def _inputs(result: dict[str, Any], origins: dict[int, str]) -> dict[str, Any]:
    inputs = dict(result["inputs"])
    origin = origins.get(result["run"])
    url = inputs.get("url")
    if origin and isinstance(url, str) and url.startswith(origin + "/"):
        inputs["url"] = "$LOOPBACK_ORIGIN" + url[len(origin):]
    return inputs


def compare_reports(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    for field in ("schema_version", "oracle_version", "seed", "repeat", "conditions"):
        if before.get(field) != after.get(field):
            raise ValueError(f"Incomparable reports: {field} changed")
    left, right = _index(before), _index(after)
    if left.keys() != right.keys():
        raise ValueError("Case/run set changed; record an expanded baseline before comparison")
    before_origins, after_origins = _origins(left), _origins(right)
    rows = []
    for key in sorted(left):
        old, new = left[key], right[key]
        for field in ("principle", "category", "expected", "policy", "limitations"):
            if old[field] != new[field]:
                raise ValueError(f"Changed contract: {key}, {field}")
        if _inputs(old, before_origins) != _inputs(new, after_origins):
            raise ValueError(f"Changed inputs: {key}")
        rows.append({"run": key[0], "case_id": key[1], "category": new["category"],
                     "before": old["status"], "after": new["status"],
                     "before_block_source": old["block_source"], "after_block_source": new["block_source"],
                     "before_reason": old["actual"].get("reason", old["actual"].get("completion_reason", "")),
                     "after_reason": new["actual"].get("reason", new["actual"].get("completion_reason", "")),
                     "before_duration_ms": old["duration_ms"], "after_duration_ms": new["duration_ms"]})
    transitions = Counter(f"{row['before']}->{row['after']}" for row in rows)
    return {"schema_version": 1, "before_dataset": before["dataset_version"],
            "after_dataset": after["dataset_version"], "seed": before["seed"], "repeat": before["repeat"],
            "before_summary": before["summary"], "after_summary": after["summary"],
            "transitions": dict(sorted(transitions.items())), "contracts_unchanged": True,
            "normalization": "Only each run's canary loopback origin; payloads and other destinations remain exact",
            "before_sources": before["source_sha256"], "after_sources": after["source_sha256"],
            "results": rows}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("logs/comparison"))
    args = parser.parse_args()
    try:
        result = compare_reports(json.loads(args.before.read_text(encoding="utf-8")),
                                 json.loads(args.after.read_text(encoding="utf-8")))
    except (ValueError, KeyError, TypeError) as error:
        parser.error(str(error))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "comparison.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    with (args.output_dir / "comparison.csv").open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=list(result["results"][0]))
        writer.writeheader()
        writer.writerows(result["results"])
    print(json.dumps(result["transitions"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
