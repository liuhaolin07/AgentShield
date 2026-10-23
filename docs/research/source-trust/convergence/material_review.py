"""Prepare author-fixture review forms and compare returned annotations offline.

No runtime import, network call, intake mutation or independent-review claim.
The packet includes the author's normative specification; it is NOT blinded.
"""

import argparse
from copy import deepcopy
from datetime import datetime
import hashlib
import json
from pathlib import Path

from material_adapter import decode_pointer, verify_material
from validate_intake import digest, fields, identifier, load_unique_json, require, scope

HERE = Path(__file__).resolve().parent
BUNDLE = HERE / "candidate-materials-v1"
SCHEMA = "author-material-review-v1"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def json_sha(value):
    return sha(json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode())


def save_new(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")


def load_sources(bundle=BUNDLE):
    """Read only explicitly named development inputs, never results or holdout."""
    manifest = load_unique_json(bundle / "manifest.json")
    spec = load_unique_json(bundle / "authoring-spec.json")
    tasks = load_unique_json(bundle / "task-contracts.json")
    require(spec["independent_authorship"] is False, "author_fixture_scope")
    require(all(f["split"] == "development" and identifier(f["family_id"])
                for f in manifest["families"]), "development_only")
    payloads = {}
    paths = [bundle / name for name in ("manifest.json", "authoring-spec.json", "task-contracts.json")]
    for family in manifest["families"]:
        path = bundle / "payloads" / (family["family_id"] + ".json")
        payloads[family["family_id"]] = path.read_bytes()
        verify_material(manifest, family["family_id"], payloads[family["family_id"]])
        paths.append(path)
    require(len(tasks) == sum(len(f["contract"]["tasks"]) for f in manifest["families"])
            and len({t["task_id"] for t in tasks}) == len(tasks), "unique_complete_task_instructions")
    bindings = {str(path.relative_to(bundle)): sha(path.read_bytes()) for path in paths}
    return manifest, spec, tasks, payloads, bindings


def prepare(bundle=BUNDLE):
    manifest, spec, tasks, payloads, bindings = load_sources(bundle)
    instructions = {t["task_id"]: t for t in tasks}
    packet = {
        "schema_version": SCHEMA, "purpose": "AUTHOR_FIXTURE_SEMANTIC_REVIEW_HANDOFF",
        "timing": "AFTER_AUTHOR_ENGINEERING_AND_MODEL_OUTCOMES",
        "independent_authorship": False, "blinded_review": False,
        "authority": spec, "source_sha256": bindings,
        "reference": manifest["reference"], "families": [],
        "limits": ["Author-owned specification is normative only for these synthetic fixtures.",
                   "Agreement does not prove external truth, independence, receipt calibration or real-world validity.",
                   "No outcomes, policy outputs or proposed per-leaf annotations are included.",
                   "Task names and the normative specification expose author intent; this is not blind review."],
    }
    for family in manifest["families"]:
        raw = payloads[family["family_id"]]
        source = json.loads(raw)
        item = {key: deepcopy(family[key]) for key in
                ("family_id", "template_cluster_id", "source_kind")}
        item["source_utf8"] = raw.decode("utf-8")
        item["tasks"] = []
        for task in family["contract"]["tasks"]:
            instruction = instructions[task["task_id"]]
            require(instruction["family_id"] == family["family_id"]
                    and instruction["output_path"] in task["dependency_paths"], "task_source_binding")
            require(sha(source[decode_pointer(instruction["output_path"])].encode())
                    == instruction["expected_body_sha256"], "expected_body_binding")
            item["tasks"].append({"task_id": task["task_id"], "instruction": instruction["instruction"],
                                  "read_scope": task["read_scope"], "sink_scope": task["sink_scope"]})
        packet["families"].append(item)
    packet["packet_sha256"] = json_sha(packet)
    form = {"schema_version": SCHEMA, "packet_sha256": packet["packet_sha256"],
            "reviewer": {key: None for key in
                         ("identity_ref", "independent_of_author", "prior_outcome_access",
                          "declaration_evidence_ref", "completed_at")}, "families": []}
    for family in manifest["families"]:
        form["families"].append({"family_id": family["family_id"],
            "template_assessment": None, "template_rationale": None,
            "leaves": [{"path": leaf["path"], "classification": None, "grants": None,
                        "rationale": None} for leaf in family["contract"]["leaves"]],
            "tasks": [{"task_id": task["task_id"], "dependency_paths": None,
                       "expected_body_sha256": None, "rationale": None}
                      for task in family["contract"]["tasks"]]})
    return packet, form


def indexed(items, key, expected, code):
    require(isinstance(items, list) and all(isinstance(i, dict) and key in i for i in items), code)
    require(all(isinstance(i[key], str) for i in items), code)
    result = {item[key]: item for item in items}
    require(len(result) == len(items) and set(result) == set(expected), code)
    return result


def note(value):
    return isinstance(value, str) and 0 < len(value.strip()) <= 4096


def compare(packet, response, bundle=BUNDLE):
    expected_packet, _ = prepare(bundle)
    require(packet == expected_packet, "packet_or_source_changed")
    fields(response, "schema_version packet_sha256 reviewer families", "response_fields")
    require(response["schema_version"] == SCHEMA
            and response["packet_sha256"] == packet["packet_sha256"], "response_packet_binding")
    reviewer = response["reviewer"]
    fields(reviewer, "identity_ref independent_of_author prior_outcome_access declaration_evidence_ref completed_at",
           "reviewer_fields")
    pending, differences = [], []
    for key in ("identity_ref", "declaration_evidence_ref"):
        if reviewer[key] is None:
            pending.append("reviewer:" + key)
        else:
            require(identifier(reviewer[key]), "reviewer_reference")
    for key in ("independent_of_author", "prior_outcome_access"):
        if reviewer[key] is None:
            pending.append("reviewer:" + key)
        else:
            require(type(reviewer[key]) is bool, "reviewer_boolean")
    if reviewer["completed_at"] is None:
        pending.append("reviewer:completed_at")
    else:
        require(isinstance(reviewer["completed_at"], str), "review_time")
        try:
            stamp = datetime.fromisoformat(reviewer["completed_at"])
        except ValueError:
            raise ValueError("review_time") from None
        require(stamp.tzinfo is not None and stamp.utcoffset() is not None, "review_time_timezone")
    manifest, _, task_contracts, _, _ = load_sources(bundle)
    expected_tasks = {t["task_id"]: t for t in task_contracts}
    families = indexed(response["families"], "family_id",
                       [f["family_id"] for f in manifest["families"]], "response_family_coverage")
    reviewed_leaves = reviewed_tasks = 0
    for family in manifest["families"]:
        fid = family["family_id"]
        entry = families[fid]
        fields(entry, "family_id template_assessment template_rationale leaves tasks", "family_review_fields")
        if entry["template_assessment"] is None or entry["template_rationale"] is None:
            pending.append(fid + ":template")
        else:
            require(entry["template_assessment"] in ("AGREE", "DISAGREE")
                    and note(entry["template_rationale"]), "template_review")
            if entry["template_assessment"] == "DISAGREE":
                differences.append({"family_id": fid, "field": "template_cluster"})
        leaves = indexed(entry["leaves"], "path", [v["path"] for v in family["contract"]["leaves"]],
                         "response_leaf_coverage")
        for proposed in family["contract"]["leaves"]:
            leaf = leaves[proposed["path"]]
            fields(leaf, "path classification grants rationale", "leaf_review_fields")
            if any(leaf[k] is None for k in ("classification", "grants", "rationale")):
                pending.append(fid + ":leaf:" + leaf["path"])
                continue
            require(leaf["classification"] in ("PUBLIC", "SENSITIVE") and note(leaf["rationale"]),
                    "leaf_review_annotation")
            require(isinstance(leaf["grants"], list), "review_grants")
            grants = [scope(g) for g in leaf["grants"]]
            require(len(set(grants)) == len(grants), "duplicate_review_grant")
            reviewed_leaves += 1
            for key, same in (("classification", leaf["classification"] == proposed["classification"]),
                              ("grants", set(grants) == {scope(g) for g in proposed["grants"]})):
                if not same:
                    differences.append({"family_id": fid, "path": leaf["path"], "field": key})
        tasks = indexed(entry["tasks"], "task_id", [t["task_id"] for t in family["contract"]["tasks"]],
                        "response_task_coverage")
        for proposed in family["contract"]["tasks"]:
            task = tasks[proposed["task_id"]]
            fields(task, "task_id dependency_paths expected_body_sha256 rationale", "task_review_fields")
            if any(task[k] is None for k in ("dependency_paths", "expected_body_sha256", "rationale")):
                pending.append(fid + ":task:" + task["task_id"])
                continue
            deps = task["dependency_paths"]
            require(isinstance(deps, list) and bool(deps) and all(isinstance(p, str) for p in deps)
                    and len(set(deps)) == len(deps) and set(deps) <= set(leaves), "review_dependencies")
            require(digest(task["expected_body_sha256"]) and note(task["rationale"]), "task_review_annotation")
            reviewed_tasks += 1
            for key, same in (("dependency_paths", set(deps) == set(proposed["dependency_paths"])),
                              ("expected_body_sha256", task["expected_body_sha256"] ==
                               expected_tasks[task["task_id"]]["expected_body_sha256"])):
                if not same:
                    differences.append({"family_id": fid, "task_id": task["task_id"], "field": key})
    return {"schema_version": SCHEMA, "packet_sha256": packet["packet_sha256"],
            "response_sha256": json_sha(response), "comparison_complete": not pending,
            "state": "PENDING" if pending else ("DISAGREEMENTS" if differences else "ANNOTATIONS_AGREE"),
            "reviewed_leaves": reviewed_leaves, "reviewed_tasks": reviewed_tasks,
            "pending": pending, "differences": differences, "reviewer_declarations": reviewer,
            "independent_review_verified": False, "identity_and_evidence_human_check_required": True,
            "independent_authorship": False, "pre_outcome_review": False,
            "formal_families_admitted": 0, "experiment_authorized": False,
            "holdout_read": False, "new_model_requests": 0, "new_tool_executions": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("prepare")
    build.add_argument("--output", type=Path, required=True)
    check = commands.add_parser("compare")
    check.add_argument("--packet", type=Path, required=True)
    check.add_argument("--response", type=Path, required=True)
    check.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            packet, form = prepare()
            args.output.mkdir(parents=True, exist_ok=False)
            save_new(args.output / "packet.json", packet)
            save_new(args.output / "response-template.json", form)
            report = compare(packet, form)
            save_new(args.output / "pending-check.json", report)
        else:
            report = compare(load_unique_json(args.packet), load_unique_json(args.response))
            save_new(args.output, report)
        print(json.dumps({k: report[k] for k in ("state", "reviewed_leaves", "reviewed_tasks",
                                                "independent_review_verified", "formal_families_admitted")}))
        # Incomplete or conflicting review is a distinct, non-passing workflow result.
        return 0 if report["state"] == "ANNOTATIONS_AGREE" else 2
    except (ValueError, KeyError, TypeError, OSError):
        print(json.dumps({"state": "INVALID", "experiment_authorized": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
