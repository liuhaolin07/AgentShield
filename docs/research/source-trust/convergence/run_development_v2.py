"""Prepare, run, or rescore sixteen author-only loopback engineering rows.

No model transport, credential lookup, formal pilot or holdout execution.
"""

import argparse
from contextlib import redirect_stdout
from datetime import datetime
import io
import json
from pathlib import Path
import sys
from zoneinfo import ZoneInfo

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[3]))

from candidate_materials import BUNDLE
from corruption_graph import SP, canonical, digest
from development_execution_v2 import (aggregate, code_hashes, decode, execute_row, plan_row,
                                      read_raw, replay_sample, rescore, save_raw, sha)
from development_graph_v2 import make_graph, name_controls
from development_intake import Reader
from evaluation.receiver import LoopbackReceiver
from platform_contract import PlatformUnsupported, require_secure_io, unsupported_report
from validate_intake import require

FAMILY_IDS = ("candidate-support-file", "candidate-support-tool")


def expected_plan(manifest, graphs):
    require([f["family_id"] for f in manifest["families"]] == list(FAMILY_IDS), "known_author_smoke_only")
    rows = [plan_row(manifest, graph, f["family_id"], task["task_id"], mode)
            for graph in graphs for mode in ("no_defense", "precision")
            for f in manifest["families"] for task in f["contract"]["tasks"]]
    require(len(rows) == 16, "fixed_sixteen_row_budget")
    return {"schema": "development-smoke-plan-v2", "scope": "KNOWN_AUTHOR_FIXTURES_NOT_PILOT",
            "rows": rows, "runner_sha256": sha(Path(__file__).read_bytes()),
            "execution_code_sha256": code_hashes(), "manifest_sha256": digest(manifest),
            "name_controls_sha256": digest(name_controls(manifest)),
            "graph_sha256": [g["graph_sha256"] for g in graphs],
            "replay_sample_n": 10, "replay_sample_seed": 1729,
            "off_contract_threshold": None, "threshold_status": "PENDING_D5",
            "max_tool_calls": 16, "max_http_arrivals": 16, "model_calls": 0,
            "formal_pilot_rows": 0, "formal_materials_admitted": 0}


def prepare(root):
    require_secure_io()
    manifest = decode((BUNDLE / "manifest.json").read_bytes())
    manifest["families"] = [f for f in manifest["families"] if f["family_id"] in FAMILY_IDS]
    graphs = [make_graph(manifest), make_graph(manifest, "E1", SP, "1", 17)]
    plan = expected_plan(manifest, graphs)
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    (root / "inputs").mkdir(mode=0o700)
    (root / "rows").mkdir(mode=0o700)
    save_raw(root / "inputs/manifest.json", canonical(manifest))
    save_raw(root / "inputs/graphs.json", canonical(graphs))
    for fid in FAMILY_IDS:
        save_raw(root / f"inputs/{fid}.json", (BUNDLE / f"payloads/{fid}.json").read_bytes())
    save_raw(root / "name-controls.json", canonical(name_controls(manifest)))
    save_raw(root / "plan.json", canonical(plan))
    return plan


def load(root):
    reader = Reader(root)
    manifest = decode(reader.read("inputs/manifest.json", 1024 * 1024))
    graphs = decode(reader.read("inputs/graphs.json", 1024 * 1024))
    plan = decode(reader.read("plan.json", 1024 * 1024))
    require(plan == expected_plan(manifest, graphs), "smoke_plan_or_code_changed")
    require(decode(reader.read("name-controls.json", 1024 * 1024)) == name_controls(manifest), "name_controls_changed")
    sources = {fid: reader.read(f"inputs/{fid}.json", 65536) for fid in FAMILY_IDS}
    for family in manifest["families"]:
        require(sha(sources[family["family_id"]]) == family["contract"]["source_sha256"], "smoke_source_changed")
    return plan, manifest, graphs, sources


def execute(root):
    plan, manifest, graphs, sources = load(root)
    save_raw(root / "run-started.json", canonical({"plan_sha256": digest(plan),
             "started_at": datetime.now(ZoneInfo('Asia/Shanghai')).isoformat(), "scope": plan["scope"]}))
    scores, arrivals, failure, receiver = {}, [], None, None
    try:
        with LoopbackReceiver() as receiver:
            for row in plan["rows"]:
                graph = next(g for g in graphs if g["graph_sha256"] == row["graph_sha256"])
                with redirect_stdout(io.StringIO()):
                    actual, record = execute_row(root / "rows", manifest, graph, sources[row["family_id"]],
                                                 row["family_id"], row["task_id"], row["defense_mode"], receiver)
                require(actual == row, "executed_plan_changed")
                scores[row["row_id"]] = record["score"]
                arrivals = receiver.arrivals
    except (ValueError, TypeError, KeyError, OSError):
        failure = "ENGINEERING_EXECUTION_OR_ARCHIVE_FAILURE_NO_RETRY"
    if receiver is not None:
        arrivals = receiver.arrivals  # Preserve actual deliveries even after archive failure.
    report = {"plan_sha256": digest(plan), "summary": aggregate(plan["rows"], scores),
              "raw_archive_rows": sum(s["archive_complete"] for s in scores.values()),
              "actual_http_arrivals": len(arrivals), "execution_failure": failure,
              "model_calls": 0, "new_cost_cny": 0,
              "finished_at": datetime.now(ZoneInfo('Asia/Shanghai')).isoformat()}
    save_raw(root / "receiver.json", canonical(arrivals))
    save_raw(root / "report.json", canonical(report))
    checked = verify(root)
    save_raw(root / "archive-check.json", canonical(checked))
    return checked


def verify(root):
    plan, _, _, _ = load(root)
    reader = Reader(root)
    report = decode(reader.read("report.json", 1024 * 1024))
    scores = {p["row_id"]: rescore(root / "rows", p) for p in plan["rows"]}
    summary = aggregate(plan["rows"], scores)
    sample = replay_sample(root / "rows", plan["rows"], n=plan["replay_sample_n"], seed=plan["replay_sample_seed"])
    full_receiver = decode(reader.read("receiver.json", 1024 * 1024))
    row_arrivals = []
    for row in plan["rows"]:
        if scores[row["row_id"]]["archive_complete"]:
            response = decode(read_raw(root / "rows", row["row_id"], "response.bin"))
            row_arrivals.extend(response.get("receiver_arrivals", []))
    require(report["plan_sha256"] == digest(plan), "report_plan_binding")
    integrity = (summary == report["summary"] and sample["passed"]
                 and row_arrivals == full_receiver and len(full_receiver) == report["actual_http_arrivals"]
                 and all(s["archive_complete"] for s in scores.values())
                 and report["execution_failure"] is None)
    return {"scope": "OFFLINE_ORIGINAL_TOOL_RPC_RESCORING_AUTHOR_ONLY", "integrity_passed": integrity,
            "raw_archive_rows": sum(s["archive_complete"] for s in scores.values()),
            "planned_rows": len(plan["rows"]), "actual_http_arrivals": len(full_receiver),
            "replay_sample": sample, "current_summary": summary,
            "new_model_calls": 0, "new_tool_executions_by_verifier": 0,
            "formal_pilot_rows": 0, "formal_materials_admitted": 0,
            "model_raw_capture_integrated": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "run", "verify"))
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = prepare(args.root) if args.command == "prepare" else execute(args.root) if args.command == "run" else verify(args.root)
        if args.command == "prepare":
            print(json.dumps({"planned_rows": len(result["rows"]), "scope": result["scope"], "model_calls": 0}))
            return 0
        print(json.dumps({k: result[k] for k in ("integrity_passed", "raw_archive_rows", "planned_rows", "actual_http_arrivals", "formal_pilot_rows", "new_model_calls")}))
        return 0 if result["integrity_passed"] else 2
    except PlatformUnsupported:
        print(json.dumps(unsupported_report()))
        return 2
    except (ValueError, TypeError, KeyError, OSError, UnicodeError):
        print(json.dumps({"state": "INVALID_ENGINEERING_ARTIFACT_OR_ENVIRONMENT", "formal_pilot_rows": 0}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
