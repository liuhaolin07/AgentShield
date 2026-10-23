"""Run/check a bounded synthetic candidate rehearsal, never a formal pilot.

Controls run first, then all 936 primary rows; no adaptation, retries or models.
Inputs must match the saved author draft and exact budget before any socket.
"""

import argparse
from collections import Counter
import contextlib
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from candidate_materials import BUNDLE, validate_candidates
from corruption_graph import canonical, defense_labels, digest
from material_adapter import decode_pointer, value_digest
from runtime_probe import assess_observation, probe_identity
from validate_intake import HERE, load_unique_json, require

EXECUTION_MODULES = ("candidate_materials.py", "candidate_rehearsal.py", "runtime_probe.py", "material_adapter.py",
                     "mechanism_applicability.py", "protocol_amendment.py", "protocol-amendment.json",
                     "corruption_graph.py", "verify_graph.py", "validate_intake.py")


def execution_rows(plan):
    return [r for r in plan["rows"] if r["section"] == "control"] + [r for r in plan["rows"] if r["section"] == "primary"]


def summarize_records(directory, records):
    manifest, plan, tasks = validate_candidates(directory)
    rows = execution_rows(plan)
    require(len(records) == len(rows) == 984, "incomplete_or_excess_rehearsal")
    task_by_id = {t["task_id"]: t for t in tasks}
    family_by_id = {f["family_id"]: f for f in manifest["families"]}
    projections = {g["graph_sha256"]: {f["family_id"]: f for f in defense_labels(g)["families"]} for g in plan["graphs"]}
    previous, states, by_policy, arrivals, attempts = None, Counter(), {}, 0, 0
    for row, record in zip(rows, records):
        require(record["plan_row"] == row, "executed_row_binding")
        require(record["previous_sha256"] == previous, "ledger_sequence")
        require(record["record_sha256"] == digest({k: v for k, v in record.items() if k != "record_sha256"}), "ledger_record_digest")
        previous = record["record_sha256"]
        fid, tid, policy = row["family_id"], row["task_id"], row["policy"]
        task = task_by_id[tid]
        body = json.loads((directory / f"payloads/{fid}.json").read_bytes())
        expected = body[decode_pointer(task["output_path"])]
        require(hashlib.sha256(expected.encode()).hexdigest() == task["expected_body_sha256"], "task_receipt_contract")
        observation = record["observation"]
        if observation is None:
            require(isinstance(record["error_type"], str), "missing_failure_reason")
            state = "INCOMPLETE"
            require(record["assessment"] is None, "failed_probe_cannot_claim_success")
        else:
            control = policy if row["section"] == "control" else None
            require(observation["control"] == control and observation["strategy"] == ("precision" if control else policy), "observed_strategy_binding")
            scope = observation["mechanism_applicability"]
            projection = projections[row["graph_sha256"]][fid]
            require(scope["declaration_sha256"] == value_digest(projection)
                    and scope["source_sha256"] == family_by_id[fid]["contract"]["source_sha256"]
                    and scope["source_kind"] == family_by_id[fid]["source_kind"]
                    and scope["output_path_sha256"] == value_digest(task["output_path"]), "observed_source_and_projection_binding")
            require(scope["state"] == "STRUCTURAL_NO_CONTRAST" and scope["superiority_claim_allowed"] is False, "h5_scope_preserved")
            if record["error_type"] is None:
                assessed = assess_observation(observation, expected)
                require(record["assessment"] == assessed, "assessment_recomputed")
                state = assessed["state"]
            else:
                require(isinstance(record["error_type"], str) and record["assessment"] is None, "failed_assessment")
                state = "INCOMPLETE"  # Preserve already captured arrivals on evaluator failure.
            arrivals += len(observation["arrivals"])
            require(type(observation["outbound_entries"]) is int and 0 <= observation["outbound_entries"] <= 1, "single_attempt_per_row")
            attempts += observation["outbound_entries"]
        states[state] += 1
        by_policy.setdefault(policy, Counter())[state] += 1
    require(attempts <= plan["max_http_requests"], "http_budget_exceeded")
    controls_ok = by_policy.get("no_defense") == Counter({"OBSERVED_DELIVERY": 24}) and by_policy.get("reject_all") == Counter({"OBSERVED_BLOCK": 24})
    return {"scope": "SYNTHETIC_AUTHOR_DRAFT_ENGINEERING_REHEARSAL", "rows_recorded": len(records),
            "primary_rows": 936, "control_rows": 48, "states": dict(states),
            "by_policy": {k: dict(v) for k, v in by_policy.items()}, "outbound_attempts": attempts,
            "actual_http_arrivals": arrivals, "max_http_requests": 984, "retries": 0,
            "rows_without_probe_observation": sum(r["observation"] is None for r in records),
            "control_calibration_passed": controls_ok, "engineering_checks_passed": states["INCOMPLETE"] == 0 and controls_ok,
            "ledger_tail_sha256": previous, "plan_sha256": digest(plan), "candidate_manifest_sha256": digest(manifest),
            "candidate_families": 12, "independent_template_clusters": None, "declared_shared_template_clusters": 1,
            "independent_semantic_review": "PENDING", "independent_authorship": False,
            "admitted_research_families": 0, "formal_pilot_rows": 0, "confirmatory_rows": 0,
            "model_requests": 0, "external_http_requests": 0, "H5_superiority_claim_allowed": False,
            "power_ICC_CI_coverage_validated": False}


def verify_saved_run(directory, output):
    records = [json.loads(line) for line in (output / "rows.jsonl").read_text().splitlines()]
    result = summarize_records(directory, records)
    recorded = load_unique_json(output / "summary.json")
    require(recorded["results"] == result, "summary_mismatch")
    require(recorded["rows_file_sha256"] == hashlib.sha256((output / "rows.jsonl").read_bytes()).hexdigest(), "rows_file_digest")
    require(set(recorded["execution_code_sha256"]) == set(EXECUTION_MODULES), "complete_execution_code_binding")
    for name, saved in recorded["execution_code_sha256"].items():
        require((HERE / name).is_file() and hashlib.sha256((HERE / name).read_bytes()).hexdigest() == saved, "execution_code_changed")
    require(type(recorded["receiver_total_arrivals"]) is int and result["actual_http_arrivals"] <= recorded["receiver_total_arrivals"] <= 984, "receiver_request_budget")
    if result["rows_without_probe_observation"] == 0:
        require(recorded["receiver_total_arrivals"] == result["actual_http_arrivals"], "receiver_ledger_agreement")
    return result


def run_rehearsal(directory, output):
    from evaluation.receiver import LoopbackReceiver
    manifest, plan, tasks = validate_candidates(directory)
    task_by_id = {t["task_id"]: t for t in tasks}
    family_by_id = {f["family_id"]: f for f in manifest["families"]}
    projections = {g["graph_sha256"]: {f["family_id"]: f for f in defense_labels(g)["families"]} for g in plan["graphs"]}
    output.mkdir(parents=True, exist_ok=False)  # New run directory; never overwrite history.
    started = datetime.now(timezone.utc).isoformat()
    records, previous = [], None
    with LoopbackReceiver() as receiver, (output / "rows.jsonl").open("x", encoding="utf-8") as ledger:
        for index, row in enumerate(execution_rows(plan), 1):
            observation, assessment, error_type = None, None, None
            begin = time.perf_counter_ns()
            try:
                fid, policy = row["family_id"], row["policy"]
                raw = (directory / f"payloads/{fid}.json").read_bytes()
                task = task_by_id[row["task_id"]]
                control = policy if row["section"] == "control" else None
                with contextlib.redirect_stdout(io.StringIO()):
                    observation = probe_identity(projections[row["graph_sha256"]][fid], family_by_id[fid]["source_kind"], raw,
                        task["output_path"], "precision" if control else policy, receiver, control=control)
                assessment = assess_observation(observation, json.loads(raw)[decode_pointer(task["output_path"])])
            except Exception as error:
                assessment, error_type = None, type(error).__name__
            record = {"plan_row": row, "observation": observation, "assessment": assessment, "error_type": error_type,
                      "elapsed_ns": time.perf_counter_ns() - begin, "previous_sha256": previous}
            record["record_sha256"] = digest(record)
            previous = record["record_sha256"]
            ledger.write(canonical(record).decode() + "\n")
            ledger.flush()
            records.append(record)
            if index % 100 == 0:
                print(json.dumps({"engineering_rows_recorded": index, "planned": 984}), flush=True)
        receiver_total_arrivals = len(receiver.arrivals)
    result = summarize_records(directory, records)
    report = {"started_at": started, "finished_at": datetime.now(timezone.utc).isoformat(), "results": result,
              "receiver_total_arrivals": receiver_total_arrivals,
              "rows_file_sha256": hashlib.sha256((output / "rows.jsonl").read_bytes()).hexdigest(),
              "execution_code_sha256": {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in EXECUTION_MODULES}}
    (output / "summary.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("run", "check"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run_rehearsal(BUNDLE, args.output) if args.command == "run" else verify_saved_run(BUNDLE, args.output)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raise SystemExit(0 if result["engineering_checks_passed"] else 1)
