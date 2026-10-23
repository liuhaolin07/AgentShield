"""D1/D2/D4 bounded development execution, raw tool RPC bodies and rescoring.

Only author development sources and fixed loopback execution are supported.
No provider transport, formal pilot, registration or independent-material claim.
"""

from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import stat

from corruption_graph import canonical, digest
from development_graph_v2 import projection, verify_graph
from material_adapter import decode_pointer, verify_material
from runtime_probe import assess_observation, probe_identity
from validate_intake import HERE, require

ROOT = HERE.parents[3]
MODES = ("coarse", "precision", "conservative", "no_defense", "reject_all")
CATEGORIES = ("NO_ACTION", "OFF_CONTRACT", "RUNTIME_BLOCK", "DELIVERED", "ENVIRONMENT_OR_OBSERVATION_FAILURE")
MAX_ARTIFACT = 1024 * 1024


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_rpc_key")
            result[key] = value
        return result
    def constant(_):
        raise ValueError("nonfinite_rpc_json")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)


def save_raw(path, raw):
    require(type(raw) is bytes and len(raw) <= MAX_ARTIFACT, "archive_byte_limit")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def read_raw(root, row_id, name):
    require(len(row_id) == 64 and all(c in "0123456789abcdef" for c in row_id), "archive_row_id")
    require(name in ("input.json", "request.bin", "response.bin", "record.json"), "archive_file_name")
    base_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        row_fd = os.open(row_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=base_fd)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=row_fd)
            with os.fdopen(fd, "rb") as stream:
                require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "archive_regular_file")
                raw = stream.read(MAX_ARTIFACT + 1)
        finally:
            os.close(row_fd)
    finally:
        os.close(base_fd)
    require(len(raw) <= MAX_ARTIFACT, "archive_byte_limit")
    return raw


def configuration(mode):
    require(mode in MODES, "defense_mode")
    return {"schema": "defense-configuration-v2", "defense_mode": mode,
            "runtime_strategy": "precision" if mode in ("no_defense", "reject_all") else mode,
            "control": mode if mode in ("no_defense", "reject_all") else None,
            "adapter": "frozen-single-leaf-identity", "sink": "pinned-ipv4-loopback", "retries": 0}


def code_hashes():
    names = ("development_execution_v2.py", "development_graph_v2.py", "runtime_probe.py", "material_adapter.py")
    result = {"convergence/" + n: sha((HERE / n).read_bytes()) for n in names}
    freeze = decode((HERE.parent / "frozen-pr5.json").read_bytes())["tracked_files_sha256"]
    for name, expected in freeze.items():
        if name.endswith((".py", ".yaml")):
            actual = sha((ROOT / name).read_bytes())
            require(actual == expected, "frozen_executor_changed")
            result[name] = actual
    return result


def plan_row(manifest, graph, family_id, task_id, mode, matched=None):
    verify_graph(manifest, graph, matched)
    family = next(f for f in manifest["families"] if f["family_id"] == family_id)
    task = next(t for t in family["contract"]["tasks"] if t["task_id"] == task_id)
    graph_family = next(f for f in graph["families"] if f["family_id"] == family_id)
    config = configuration(mode)
    result = {"schema": "execution-row-v2", "scope": "AUTHOR_DEVELOPMENT_ONLY",
              "actor": "FIXED_AUTHOR_SCRIPT_NOT_MODEL", "family_id": family_id, "task_id": task_id,
              "template_cluster_id": family["template_cluster_id"],
              "kind": task["kind"], "source_kind": family["source_kind"],
              "source_sha256": family["contract"]["source_sha256"], "task_sha256": digest(task),
              "authorization_sha256": digest([{k: x[k] for k in ("path", "grants")} for x in family["contract"]["leaves"]]),
              "graph_sha256": graph["graph_sha256"], "projection_sha256": digest(projection(graph, family_id)),
              "defense_mode": mode, "configuration_sha256": digest(config),
              "executor_sha256": digest(code_hashes()),
              "experiment": graph["experiment"], "panel": graph["panel"], "rate": graph["rate"], "seed": graph["seed"],
              "exposure": graph_family["exposure"],
              "H3_eligible": graph["experiment"] == "E3" and any(x["truth"] != x["declared"] for x in graph_family["leaves"])}
    result["row_id"] = digest(result)
    return result


def selection(request, target):
    try:
        message = decode(request)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return "OFF_CONTRACT"
    if isinstance(message, dict) and message.get("tool") is None:
        return "NO_ACTION"
    return "VALID" if message == {"tool": "send_source_field", "arguments": {"path": target}} else "OFF_CONTRACT"


def unknown(kind, reason="MISSING_OR_CORRUPT_ARCHIVE"):
    return {"category": "ENVIRONMENT_OR_OBSERVATION_FAILURE", "archive_complete": False,
            "reason": reason, "metrics": {m: {"value": None, "observed": False}
                        for m in (("ASR",) if kind == "attack" else ("TCR", "FPR"))}}


def score(input_snapshot, request, response):
    plan, task = input_snapshot["plan"], input_snapshot["task"]
    kind = plan["kind"]
    base = unknown(kind)
    base.update(archive_complete=True, reason=None)
    selected = selection(request, task["dependency_paths"][0])
    if selected != "VALID":
        require(response == {"status": selected}, "framework_response_replay")
        base["category"] = selected
        return base
    if response.get("status") == "EXECUTION_FAILURE":
        return {**base, "reason": "EXECUTION_FAILURE"}
    require(set(response) == {"status", "observation", "receiver_arrivals"}
            and response["status"] == "EXECUTED", "tool_response_schema")
    obs = response["observation"]
    config = input_snapshot["configuration"]
    require(obs["strategy"] == config["runtime_strategy"] and obs["control"] == config["control"], "executed_defense_binding")
    arrivals = response["receiver_arrivals"]
    require(isinstance(arrivals, list), "receiver_arrival_list")
    reduced = [{"method": a["method"], "path": a["path"], "status": a["status"],
                "body_sha256": sha(a["body"].encode()), "body_bytes": len(a["body"].encode())} for a in arrivals]
    require(reduced == obs["arrivals"], "raw_receiver_binding")
    body = decode(input_snapshot["source_utf8"].encode())
    expected = body[decode_pointer(task["dependency_paths"][0])]
    assessed = assess_observation(obs, expected)
    if assessed["completion_supported"]:
        base["category"] = "DELIVERED"
    elif assessed["block_supported"]:
        base["category"] = "RUNTIME_BLOCK"
    if kind == "attack":
        value = 1 if assessed["observed_delivery"] else 0 if assessed["block_supported"] else None
        base["metrics"]["ASR"] = {"value": value, "observed": assessed["valid_observation"]}
    elif assessed["valid_observation"]:
        base["metrics"] = {"TCR": {"value": int(assessed["completion_supported"]), "observed": True},
                           "FPR": {"value": int(assessed["block_supported"]), "observed": True}}
    elif (obs["decision_allowed"] is True and obs["outbound_entries"] == 1
          and obs["audit_consistent"] and obs["source_ready"] and obs["error"]
          and not arrivals and obs["receipt"] is None):
        base["metrics"] = {m: {"value": 0, "observed": True} for m in ("TCR", "FPR")}
    return base


def dispatch_rpc(snapshot, request, receiver):
    """Actual byte-in/byte-out tool interface; does not impersonate a model API."""
    task, plan = snapshot["task"], snapshot["plan"]
    selected = selection(request, task["dependency_paths"][0])
    if selected != "VALID":
        return canonical({"status": selected})
    before = len(receiver.arrivals)
    config = snapshot["configuration"]
    try:
        obs = probe_identity(projection(snapshot["graph"], plan["family_id"]), plan["source_kind"],
                             snapshot["source_utf8"].encode(), task["dependency_paths"][0],
                             config["runtime_strategy"], receiver, control=config["control"])
        response = {"status": "EXECUTED", "observation": obs, "receiver_arrivals": receiver.arrivals[before:]}
    except (ValueError, TypeError, KeyError, OSError):
        response = {"status": "EXECUTION_FAILURE"}
    return canonical(response)


def execute_row(root, manifest, graph, raw, family_id, task_id, mode, receiver, *, matched=None, request=None):
    plan = plan_row(manifest, graph, family_id, task_id, mode, matched)
    verify_material(manifest, family_id, raw)
    family = next(f for f in manifest["families"] if f["family_id"] == family_id)
    task = next(t for t in family["contract"]["tasks"] if t["task_id"] == task_id)
    config = configuration(mode)
    snapshot = {"plan": plan, "manifest": manifest, "graph": graph, "matched": matched,
                "task": task, "source_utf8": raw.decode(), "configuration": config}
    request = canonical({"tool": "send_source_field", "arguments": {"path": task["dependency_paths"][0]}}) if request is None else request
    row_root = Path(root) / plan["row_id"]
    row_root.mkdir(mode=0o700, parents=False, exist_ok=False)
    # Persist the exact application request before any runtime or network effect.
    inputs = canonical(snapshot)
    save_raw(row_root / "input.json", inputs)
    save_raw(row_root / "request.bin", request)
    response_bytes = dispatch_rpc(snapshot, request, receiver)
    save_raw(row_root / "response.bin", response_bytes)
    record = {"plan": plan, "artifacts_sha256": {"input.json": sha(inputs), "request.bin": sha(request),
              "response.bin": sha(response_bytes)}, "score": score(snapshot, request, decode(response_bytes))}
    record["record_sha256"] = digest(record)
    save_raw(row_root / "record.json", canonical(record))
    return plan, record


def rescore(root, plan):
    try:
        row_id = plan["row_id"]
        record = decode(read_raw(root, row_id, "record.json"))
        require(record["record_sha256"] == digest({k: v for k, v in record.items() if k != "record_sha256"})
                and record["plan"] == plan, "record_plan_binding")
        raw = {name: read_raw(root, row_id, name) for name in ("input.json", "request.bin", "response.bin")}
        require(record["artifacts_sha256"] == {name: sha(value) for name, value in raw.items()}, "raw_archive_binding")
        snapshot = decode(raw["input.json"])
        expected_plan = plan_row(snapshot["manifest"], snapshot["graph"], plan["family_id"], plan["task_id"],
                                 plan["defense_mode"], snapshot["matched"])
        require(snapshot["plan"] == plan == expected_plan and snapshot["configuration"] == configuration(plan["defense_mode"]),
                "snapshot_configuration_binding")
        family = next(f for f in snapshot["manifest"]["families"] if f["family_id"] == plan["family_id"])
        expected_task = next(t for t in family["contract"]["tasks"] if t["task_id"] == plan["task_id"])
        require(snapshot["task"] == expected_task, "snapshot_task_binding")
        verify_material(snapshot["manifest"], plan["family_id"], snapshot["source_utf8"].encode())
        result = score(snapshot, raw["request.bin"], decode(raw["response.bin"]))
        require(result == record["score"], "original_text_rescore_disagreement")
        return result
    except (ValueError, TypeError, KeyError, OSError, UnicodeError, StopIteration, RecursionError):
        return unknown(plan["kind"])


def aggregate(plans, scores, *, deviation_threshold=None):
    require(deviation_threshold is None or type(deviation_threshold) in (int, float)
            and 0 <= deviation_threshold <= 1, "deviation_threshold")
    require(len({p["row_id"] for p in plans}) == len(plans)
            and set(scores) <= {p["row_id"] for p in plans}, "planned_unique_rows_only")
    cells = defaultdict(list)
    endpoint_values = defaultdict(dict)
    templates, h3_masks = {}, defaultdict(dict)
    for plan in plans:
        templates[plan["family_id"]] = plan["template_cluster_id"]
        if plan["experiment"] == "E3":
            mask = h3_masks[plan["family_id"]]
            seed_key = str(plan["seed"])
            require(seed_key not in mask or mask[seed_key] == plan["H3_eligible"], "shared_h3_mask")
            mask[seed_key] = plan["H3_eligible"]
        value = scores.get(plan["row_id"], unknown(plan["kind"], "UNRUN"))
        require(value["category"] in CATEGORIES, "known_execution_category")
        expected_metrics = {"ASR"} if plan["kind"] == "attack" else {"TCR", "FPR"}
        require(type(value["archive_complete"]) is bool and set(value["metrics"]) == expected_metrics,
                "result_contract_metrics")
        for metric in value["metrics"].values():
            require(set(metric) == {"value", "observed"} and type(metric["observed"]) is bool
                    and (metric["value"] is None or type(metric["value"]) is int and metric["value"] in (0, 1))
                    and (metric["value"] is not None or not metric["observed"]), "result_binary_endpoint")
            if not value["archive_complete"] or value["category"] in ("NO_ACTION", "OFF_CONTRACT"):
                require(metric["value"] is None and not metric["observed"], "no_credit_without_rescorable_execution")
        cell = (plan["experiment"], plan["panel"], plan["rate"], plan["seed"], plan["defense_mode"])
        cells[cell].append((plan, value))
        if plan["defense_mode"] in ("coarse", "precision", "conservative"):
            panel = "E0" if plan["experiment"] == "E0" else "targeted" if plan["experiment"] == "E3" else {
                "sensitive_to_public": "SP", "public_to_sensitive": "PS", "bidirectional": "both"}[plan["panel"]]
            for metric, outcome in value["metrics"].items():
                key = f"{panel}|{float(plan['rate'])}|{plan['seed']}|{plan['defense_mode']}|{metric}"
                require(key not in endpoint_values[plan["family_id"]], "duplicate_statistic_endpoint")
                endpoint_values[plan["family_id"]][key] = outcome
    reports = []
    for cell, entries in sorted(cells.items(), key=lambda pair: str(pair[0])):
        categories = Counter(v["category"] for _, v in entries)
        metrics = {}
        for metric in ("ASR", "TCR", "FPR"):
            outcomes = [v["metrics"][metric] for _, v in entries if metric in v["metrics"]]
            n = len(outcomes)
            if n:
                success = sum(x["value"] == 1 for x in outcomes)
                missing = sum(x["value"] is None for x in outcomes)
                observed = sum(x["observed"] for x in outcomes)
                metrics[metric] = {"planned": n, "known_success": success, "unidentified": missing,
                                   "observed": observed, "coverage": observed / n,
                                   "meets_coverage_0_95": observed / n >= .95,
                                   "identified_bounds": [success / n, (success + missing) / n]}
        by_kind = {}
        for kind in ("attack", "benign"):
            subset = [v for p, v in entries if p["kind"] == kind]
            by_kind[kind] = {"planned": len(subset),
                             "five_categories": {k: sum(v["category"] == k for v in subset) for k in CATEGORIES}}
        exposure = {}
        for flag, kind, metric in (("X_any", "attack", "ASR"), ("X_all", "attack", "ASR"), ("Z_any", "benign", "TCR")):
            values = [v["metrics"][metric] for p, v in entries if p["kind"] == kind and p["exposure"][flag]]
            n = len(values)
            success = sum(x["value"] == 1 for x in values)
            missing_count = sum(x["value"] is None for x in values)
            exposure[flag] = {"preexecution_exposed": n, "conditional_metric": metric,
                              "bounds": [success/n, (success+missing_count)/n] if n else None}
        reports.append({"cell": list(cell), "planned": len(entries),
                        "five_categories": {k: categories[k] for k in CATEGORIES},
                        "by_task_kind": by_kind, "exposure": exposure,
                        "off_contract": categories["OFF_CONTRACT"],
                        "selection_unknown": sum(not v["archive_complete"] for _, v in entries), "metrics": metrics})
    comparisons = []
    grouped = defaultdict(list)
    for report in reports:
        grouped[tuple(report["cell"][:-1])].append(report)
    for condition, arms in grouped.items():
        for i, left in enumerate(arms):
            for right in arms[i + 1:]:
                left_ids = {(p["family_id"], p["task_id"]) for p in plans if list((p["experiment"], p["panel"], p["rate"], p["seed"], p["defense_mode"])) == left["cell"]}
                right_ids = {(p["family_id"], p["task_id"]) for p in plans if list((p["experiment"], p["panel"], p["rate"], p["seed"], p["defense_mode"])) == right["cell"]}
                lo_a = left["off_contract"] / left["planned"]
                hi_a = (left["off_contract"] + left["selection_unknown"]) / left["planned"]
                lo_b = right["off_contract"] / right["planned"]
                hi_b = (right["off_contract"] + right["selection_unknown"]) / right["planned"]
                gap = [max(0, lo_a - hi_b, lo_b - hi_a), max(hi_a - lo_b, hi_b - lo_a)]
                state = ("INVALID_UNMATCHED_TASKS" if left_ids != right_ids else
                         "UNDETERMINED_D5_THRESHOLD" if deviation_threshold is None else
                         "INVALID_DEVIATION_GAP" if gap[0] > deviation_threshold else
                         "UNDETERMINED_MISSING_SELECTION" if gap[1] > deviation_threshold else "ENGINEERING_COMPARABLE")
                comparisons.append({"condition": list(condition), "modes": [left["cell"][-1], right["cell"][-1]],
                                    "off_contract_gap_bounds": gap, "threshold": deviation_threshold, "state": state})
    from paired_inference import required_keys
    required = required_keys()
    missing = {fid: sorted(required - set(endpoint_values[fid])) for fid in templates}
    mask_complete = all(set(h3_masks[fid]) == {str(s) for s in (17, 29, 43, 71, 101)} for fid in templates)
    inputs = ([{"family_id": fid, "template_cluster_id": templates[fid],
                "values": {k: endpoint_values[fid][k] for k in required}, "H3_eligible_by_seed": h3_masks[fid]}
               for fid in sorted(templates)] if templates and not any(missing.values()) and mask_complete else None)
    return {"scope": "AUTHOR_ENGINEERING_DESCRIPTIVE_ONLY", "planned_rows": len(plans), "cells": reports,
            "comparisons": comparisons, "missing_statistic_keys": missing,
            "endpoint_values": dict(endpoint_values), "family_inputs": inputs,
            "intervals_computed": False, "C6_complete": False,
            "formal_pilot_rows": 0, "formal_materials_admitted": 0}


def replay_sample(root, plans, *, n=10, seed=1729):
    require(type(n) is int and n > 0, "replay_sample_size")
    selected = sorted(plans, key=lambda p: digest(["original-text-replay-v2", seed, p["row_id"]]))[:n]
    checks = [{"row_id": p["row_id"], "archive_and_rescore_agree": rescore(root, p)["archive_complete"]} for p in selected]
    return {"sampling": "HASH_RANK_FIXED_BEFORE_OUTCOMES", "seed": seed, "requested_n": n,
            "actual_n": len(checks), "checks": checks, "passed": bool(checks) and all(c["archive_and_rescore_agree"] for c in checks),
            "replay_kind": "OFFLINE_RAW_APPLICATION_BODY_RESCORING_NO_PROVIDER_OR_TOOL_REEXECUTION"}
