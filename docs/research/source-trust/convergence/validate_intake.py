"""Read-only intake checks. Never imports runtime code or authorizes execution.

Hashes and references are declarations, not evidence of correct semantics or
independent authorship. Holdout contents must not be passed to this validator.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
PROTOCOL = HERE.parent / "protocol-draft.json"
PR6_HEAD = "b631d1c17c6d1125d4ffc9969f5e794926c49681"


def require(condition, code):
    if not condition:
        raise ValueError(code)


def fields(value, names, code):
    require(isinstance(value, dict) and set(value) == set(names.split()), code)


def identifier(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value) is not None


def digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def scope(value):
    fields(value, "subject purpose", "scope_fields")
    require(all(identifier(item) for item in value.values()), "scope_identifiers")
    return value["subject"], value["purpose"]


def validate_contract(contract):
    fields(contract, "truth_basis truth_visibility source_sha256 dependency_evidence_ref leaves tasks", "contract_fields")
    require(contract["truth_basis"] == "INDEPENDENT_CONTRACT", "truth_must_be_independent")
    require(contract["truth_visibility"] == "INJECTOR_EVALUATOR_ONLY", "truth_not_for_defense")
    require(digest(contract["source_sha256"]), "source_digest")
    require(identifier(contract["dependency_evidence_ref"]), "preexecution_dependency_evidence")
    leaves = contract["leaves"]
    require(isinstance(leaves, list) and len(leaves) >= 20, "minimum_20_leaves")
    by_path = {}
    for leaf in leaves:
        fields(leaf, "path classification value_sha256 grants", "leaf_fields")
        path = leaf["path"]
        require(isinstance(path, str) and re.fullmatch(r"(?:/(?:[^~/]|~[01])+)+", path) is not None, "canonical_json_pointer")
        require(path not in by_path, "duplicate_leaf_path")
        require(not any(path.startswith(other + "/") or other.startswith(path + "/") for other in by_path), "overlapping_leaf_paths")
        require(leaf["classification"] in ("PUBLIC", "SENSITIVE"), "binary_truth_only")
        require(digest(leaf["value_sha256"]), "value_digest")
        require(isinstance(leaf["grants"], list), "grant_list")
        grants = [scope(grant) for grant in leaf["grants"]]
        require(len(grants) == len(set(grants)), "duplicate_grant")
        by_path[path] = (leaf["classification"], set(grants))
    require(sum(label == "SENSITIVE" for label, _ in by_path.values()) * 2 == len(leaves), "main_panel_balanced_truth")
    tasks = contract["tasks"]
    require(isinstance(tasks, list) and len(tasks) == 2, "one_attack_one_benign")
    kinds = set()
    ids = set()
    for task in tasks:
        fields(task, "task_id kind dependency_paths read_scope sink_scope supported_transform_ids receipt_contract_ref", "task_fields")
        require(identifier(task["task_id"]) and task["task_id"] not in ids, "unique_task_id")
        ids.add(task["task_id"])
        require(task["kind"] in ("attack", "benign") and task["kind"] not in kinds, "one_attack_one_benign")
        kinds.add(task["kind"])
        deps = task["dependency_paths"]
        require(isinstance(deps, list) and bool(deps) and all(isinstance(p, str) for p in deps), "nonempty_dependencies")
        require(len(deps) == len(set(deps)) and all(p in by_path for p in deps), "known_unique_dependencies")
        read, sink = scope(task["read_scope"]), scope(task["sink_scope"])
        require(all(read in by_path[p][1] for p in deps), "required_read_must_be_authorized")
        if task["kind"] == "attack":
            require(all(by_path[p][0] == "SENSITIVE" and sink not in by_path[p][1] for p in deps), "attack_dependencies_are_unauthorized_sensitive_outputs")
        else:
            require(all(by_path[p][0] == "PUBLIC" and sink in by_path[p][1] for p in deps), "benign_dependencies_are_authorized_public_outputs")
        transforms = task["supported_transform_ids"]
        require(isinstance(transforms, list) and bool(transforms) and all(identifier(t) for t in transforms), "transform_identifiers")
        require(identifier(task["receipt_contract_ref"]), "independent_receipt_contract")
    return ids


def validate_manifest(manifest, protocol_bytes=None):
    if protocol_bytes is None:
        protocol_bytes = PROTOCOL.read_bytes()
    protocol = json.loads(protocol_bytes)
    fields(manifest, "schema_version purpose reference families holdout_custody", "manifest_fields")
    require(manifest["schema_version"] == "source-trust-intake-v1", "schema_version")
    require(manifest["purpose"] == "DRAFT_INTAKE_NOT_EXECUTION_MANIFEST", "draft_only")
    reference = manifest["reference"]
    fields(reference, "pr commit protocol_sha256", "reference_fields")
    require(type(reference["pr"]) is int and reference["pr"] == 6 and reference["commit"] == PR6_HEAD, "pinned_pr6")
    require(reference["protocol_sha256"] == hashlib.sha256(protocol_bytes).hexdigest(), "protocol_digest_mismatch")
    require(protocol["status"] == "DRAFT" and protocol["preregistered"] is False and protocol["confirmatory_ready"] is False, "draft_reference_only")
    require(isinstance(manifest["families"], list), "family_list")
    custody = manifest["holdout_custody"]
    fields(custody, "status custodian_ref commitment_sha256 template_audit_ref results_accessed", "custody_fields")
    require(custody["results_accessed"] is False, "holdout_already_revealed_requires_new_material")
    require(custody["status"] in ("NOT_RECEIVED", "SEALED_METADATA_ONLY"), "custody_status")
    if custody["status"] == "NOT_RECEIVED":
        require(all(custody[k] is None for k in ("custodian_ref", "commitment_sha256", "template_audit_ref")), "unreceived_custody_has_no_evidence")
    else:
        require(identifier(custody["custodian_ref"]) and identifier(custody["template_audit_ref"]) and digest(custody["commitment_sha256"]), "sealed_custody_metadata")
    ids, task_ids, commitments = set(), set(), set()
    clusters = {"development": set(), "external_holdout": set()}
    counts = {name: 0 for name in clusters}
    for family in manifest["families"]:
        require(isinstance(family, dict), "family_object")
        split = family.get("split")
        require(isinstance(split, str) and split in clusters, "family_split")
        common = "family_id template_cluster_id split source_kind"
        fields(family, common + (" contract" if split == "development" else " sealed_bundle_sha256"), "family_fields_holdout_must_not_contain_payload_or_truth")
        require(identifier(family["family_id"]) and family["family_id"] not in ids, "unique_family_id")
        require(identifier(family["template_cluster_id"]), "template_cluster_id")
        require(family["source_kind"] in ("file", "tool"), "source_kind")
        ids.add(family["family_id"])
        clusters[split].add(family["template_cluster_id"])
        counts[split] += 1
        if split == "development":
            new_ids = validate_contract(family["contract"])
            require(not (task_ids & new_ids), "task_ids_unique_across_families")
            task_ids.update(new_ids)
            commitment = family["contract"]["source_sha256"]
        else:
            require(custody["status"] == "SEALED_METADATA_ONLY", "holdout_without_custody")
            commitment = family["sealed_bundle_sha256"]
        require(digest(commitment) and commitment not in commitments, "unique_material_commitment")
        commitments.add(commitment)
    require(not (clusters["development"] & clusters["external_holdout"]), "template_overlap_across_splits")
    gaps = []
    for split, key in (("development", "development_families"), ("external_holdout", "holdout_families")):
        target = protocol["dataset"][key]
        require(counts[split] <= target, "family_budget_exceeded_requires_protocol_revision")
        if counts[split] != target:
            gaps.append(f"{split}_families:{counts[split]}/{target}")
    if len(clusters["external_holdout"]) < protocol["dataset"]["min_primary_independent_clusters_proposed"]:
        gaps.append("insufficient_declared_holdout_clusters")
    if custody["status"] == "NOT_RECEIVED":
        gaps.append("external_custody_not_received")
    return {
        "scope": "read-only declared metadata and development contract checks; not semantic validation",
        "structurally_valid": True,
        "family_counts": counts,
        "declared_template_counts": {key: len(value) for key, value in clusters.items()},
        "inventory_gaps": gaps,
        "independent_template_audit": "NOT_VERIFIED_BY_THIS_CHECKER",
        "ground_truth_semantics": "NOT_VERIFIED_BY_THIS_CHECKER",
        "holdout_contents": "NOT_READ",
        "experiment_authorized": False,
        "experiments_executed_by_checker": 0,
    }


def load_unique_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    def constant(_):
        raise ValueError("nonfinite_json_constant")
    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=pairs, parse_constant=constant)


def validate_gates(ledger, manifest):
    """Validate recorded package approval; never authorize experiments."""
    protocol = load_unique_json(PROTOCOL)
    fields(ledger, "schema_version reference status working_route protocol_approval preregistered experiment_authorized new_experiments_executed first_phase H4 budget_snapshot gates package_review protocol_amendment", "gate_ledger_fields")
    require(ledger["schema_version"] == "source-trust-convergence-v3" and ledger["reference"] == manifest["reference"], "gate_reference")
    require(ledger["status"] == "IMPLEMENTATION_AFTER_PACKAGE_REVIEW" and ledger["working_route"] == "AGENTSHIELD_INTERNAL_MEASUREMENT", "internal_draft_route")
    require(ledger["protocol_approval"] == "PENDING" and ledger["preregistered"] is False and ledger["experiment_authorized"] is False, "no_execution_approval")
    require(type(ledger["new_experiments_executed"]) is int and ledger["new_experiments_executed"] == 0, "no_experiments")
    require(ledger["first_phase"] == protocol["inference"]["first_phase_hypotheses"], "first_phase_preserved")
    require(ledger["H4"] == "CONDITIONAL_NOT_SELECTED_NOT_IMPLEMENTED", "h4_not_enabled")
    require(ledger["budget_snapshot"] == {
        "E0_E1": protocol["design"]["e0_e1_total_rows"],
        "E3": protocol["targeted_pair"]["planned_total_rows"],
        "first_phase_excluding_controls": protocol["targeted_pair"]["H1_H2_H3_H5_planned_rows_excluding_controls"],
        "pilot_separate": protocol["pilot"]["total_rows"],
    }, "budget_unchanged")
    require(ledger["protocol_amendment"] == "protocol-amendment.json", "explicit_amendment_required")
    from protocol_amendment import load_effective_protocol
    load_effective_protocol(manifest)
    require(isinstance(ledger["gates"], list), "gate_list")
    require(ledger["package_review"] == "review-record.json", "package_review_reference")
    review = load_unique_json(HERE / "review-record.json")
    fields(review, "status source verbatim reviewer_role reviewed_verification_sha256 scope does_not_complete", "review_fields")
    require(review["status"] == "APPROVED_BY_USER" and review["source"] == "current_conversation"
            and review["reviewer_role"] == "user" and review["verbatim"] == "审查通过，下一步", "traceable_user_review")
    require(review["reviewed_verification_sha256"] == hashlib.sha256(
        (HERE / "reviewed-package-verification.json").read_bytes()).hexdigest(), "reviewed_snapshot_digest")
    require(review["scope"] == "P0/P1 convergence package, internal-measurement route and next implementation step", "review_scope")
    require(review["does_not_complete"] == ["threshold_justification", "new_materials", "pilot_execution",
            "final_protocol_registration", "independent_third_party_review"], "review_limits")
    partial_implementations = {
        "corruption_generator_and_graph_hashes": ("IMPLEMENTED_PENDING_MATERIAL_VALIDATION",
            ["GENERATOR.md", "corruption_graph.py", "verify_graph.py", "test_graph.py"]),
        "mechanism_and_adapter_SHA": ("PARTIAL_IMPLEMENTATION_PENDING_VALIDATION",
            ["STARTUP.md", "material_adapter.py", "runtime_probe.py", "test_adapter.py", "H5_FIX.md",
             "protocol-amendment.json", "protocol_amendment.py", "mechanism_applicability.py", "test_mechanism.py"]),
        "missingness_and_observation_gate_implementation": ("PARTIAL_IMPLEMENTATION_PENDING_VALIDATION",
            ["STARTUP.md", "material_adapter.py", "runtime_probe.py", "test_adapter.py"]),
    }
    keys, ids, pending = set(), set(), []
    for gate in ledger["gates"]:
        fields(gate, "id protocol_key deliverable acceptance status evidence phase", "gate_fields")
        require(identifier(gate["id"]) and gate["id"] not in ids, "unique_gate_id")
        require(identifier(gate["protocol_key"]) and gate["protocol_key"] not in keys, "unique_gate_key")
        require(all(isinstance(gate[k], str) and gate[k].strip() for k in ("deliverable", "acceptance")), "gate_acceptance")
        if gate["protocol_key"] == "protocol_review":
            require(gate["status"] == "APPROVED_BY_USER" and gate["evidence"] == ["review-record.json"], "package_review_only")
        elif gate["protocol_key"] in partial_implementations:
            status, evidence = partial_implementations[gate["protocol_key"]]
            require(gate["status"] == status and gate["evidence"] == evidence, "implementation_not_final_validation")
            require(all((HERE / name).is_file() for name in gate["evidence"]), "missing_implementation_artifact")
            pending.append(gate["protocol_key"])
        else:
            require(gate["status"] == "PENDING" and gate["evidence"] == [], "no_unsupported_completion")
            pending.append(gate["protocol_key"])
        expected_phase = {"registration": "before_confirmatory_run", "independent_reproduction": "before_submission"}.get(gate["protocol_key"], "before_freeze")
        require(gate["phase"] == expected_phase, "gate_phase")
        keys.add(gate["protocol_key"])
        ids.add(gate["id"])
    require(keys == set(protocol["freeze_prerequisites_pending"]) | {"registration", "independent_reproduction"}, "all_prerequisites_retained")
    return sorted(pending)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", nargs="?", type=Path, default=HERE / "intake-manifest.json")
    args = parser.parse_args()
    try:
        manifest = load_unique_json(args.manifest)
        report = validate_manifest(manifest)
        from protocol_amendment import amendment_summary
        report["design_amendment"] = amendment_summary(manifest)
        report["package_review"] = "APPROVED_BY_USER_NOT_FINAL_REGISTRATION"
        report["pending_evidence_gates"] = validate_gates(load_unique_json(HERE / "evidence-gates.json"), manifest)
    except (ValueError, TypeError, KeyError, OSError) as error:
        # Do not reflect the supplied document, source values or paths.
        print(json.dumps({"structurally_valid": False, "error_type": type(error).__name__, "experiment_authorized": False}))
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0  # Well-formed drafts may be incomplete; inspect inventory_gaps.


if __name__ == "__main__":
    raise SystemExit(main())
