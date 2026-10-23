"""Load an explicit, narrow design amendment without rewriting PR6 history."""

from copy import deepcopy
import hashlib
import json

from validate_intake import HERE, PROTOCOL, fields, load_unique_json, require, validate_manifest

ROOT = HERE.parents[3]
RUNTIME_FILES = (
    "security/source_trust_policy.py", "security/source_classification.py",
    "security/precision_runtime.py", "security/precision_integrity.py",
    "security/precision.py", "security/taint.py",
)


def validate_amendment(amendment, manifest, protocol_bytes=None):
    raw = PROTOCOL.read_bytes() if protocol_bytes is None else protocol_bytes
    base = json.loads(raw)
    validate_manifest(manifest, raw)
    fields(amendment, "schema_version amendment_id status base_protocol_sha256 reason implementation_authority applicability changes preserved runtime_sha256 holdout_results_accessed preregistered experiment_authorized", "amendment_fields")
    require(amendment["schema_version"] == "source-trust-amendment-v1"
            and amendment["amendment_id"] == "h5-mechanism-scope-r1", "amendment_version")
    require(amendment["status"] == "IMPLEMENTED_DRAFT_NOT_REGISTERED"
            and base["status"] == "DRAFT", "amendment_is_not_registration")
    require(amendment["base_protocol_sha256"] == hashlib.sha256(raw).hexdigest()
            == manifest["reference"]["protocol_sha256"], "amendment_base_binding")
    require(amendment["preregistered"] is False and amendment["experiment_authorized"] is False,
            "amendment_no_execution_approval")
    require(amendment["holdout_results_accessed"] is False and manifest["holdout_custody"]["results_accessed"] is False,
            "cannot_revise_using_revealed_holdout")
    require(amendment["implementation_authority"] == {
        "source": "current_conversation", "user_request": "修复问题",
        "scope": "Correct design/implementation mismatch; not final protocol approval or empirical evidence",
    }, "amendment_authority_scope")
    require(isinstance(amendment["reason"], str) and bool(amendment["reason"].strip()), "amendment_reason")
    require(amendment["applicability"] == "flat-string-complete-leaf-identity-v1", "bounded_amendment_scope")
    changes = {"H5_role": "prespecified_mechanism_scope_control", "first_phase_joint_superiority_claim": False}
    require(json.dumps(amendment["changes"], sort_keys=True) == json.dumps(changes, sort_keys=True), "only_h5_role_changes")
    from material_adapter import decode_pointer
    for family in manifest["families"]:
        if family["split"] != "development":
            continue  # Sealed contents unavailable: never infer holdout scope validity.
        contract = family["contract"]
        require(20 <= len(contract["leaves"]) <= 31, "amendment_scope_requires_new_adapter_analysis")
        for leaf in contract["leaves"]:
            decode_pointer(leaf["path"])
        require(all(len(t["dependency_paths"]) == 1 and t["supported_transform_ids"] == ["identity"]
                    for t in contract["tasks"]), "amendment_scope_requires_new_adapter_analysis")
    expected = {"hypotheses_H1_H4": "ALL_FIELDS", "H5": "ALL_FIELDS_EXCEPT_ROLE",
                "first_phase_statistic_count": base["inference"]["first_phase_statistic_count"],
                "E0_E1_rows": base["design"]["e0_e1_total_rows"],
                "E3_rows": base["targeted_pair"]["planned_total_rows"],
                "pilot_rows": base["pilot"]["total_rows"], "holdout_adaptation": False}
    require(json.dumps(amendment["preserved"], sort_keys=True) == json.dumps(expected, sort_keys=True), "preserved_design")
    require(isinstance(amendment["runtime_sha256"], dict) and set(amendment["runtime_sha256"]) == set(RUNTIME_FILES),
            "runtime_files_binding")
    freeze = load_unique_json(HERE.parent / "frozen-pr5.json")["tracked_files_sha256"]
    for name in RUNTIME_FILES:
        require(amendment["runtime_sha256"][name] == freeze[name]
                == hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), "runtime_changed_requires_reanalysis")
    effective = deepcopy(base)
    h5 = next(h for h in effective["hypotheses"] if h["id"] == "H5")
    h5["role"] = amendment["changes"]["H5_role"]
    # No promotion of H1-H3, replacement primary or lower multiplicity penalty.
    effective["design_amendment"] = {
        "id": amendment["amendment_id"], "scope": amendment["applicability"],
        "first_phase_joint_superiority_claim": False,
        "positive_mechanism_difference_required_for_new_superiority_design": True,
    }
    return effective


def load_effective_protocol(manifest=None):
    manifest = load_unique_json(HERE / "intake-manifest.json") if manifest is None else manifest
    return validate_amendment(load_unique_json(HERE / "protocol-amendment.json"), manifest)


def amendment_summary(manifest=None):
    effective = load_effective_protocol(manifest)
    return {"amendment_id": effective["design_amendment"]["id"],
            "hypothesis_roles": {h["id"]: h["role"] for h in effective["hypotheses"]},
            "first_phase_joint_superiority_claim": False,
            "statistic_count": effective["inference"]["first_phase_statistic_count"],
            "preregistered": False, "experiment_authorized": False}


if __name__ == "__main__":
    print(json.dumps(amendment_summary(), ensure_ascii=False, indent=2))
