"""Post-rehearsal sampling declaration; identifiers cannot prove independence."""

import hashlib
import json

from candidate_materials import BUNDLE, validate_candidates
from validate_intake import require


def expected_contract(directory=BUNDLE):
    manifest, _, _ = validate_candidates(directory)
    spec = json.loads((directory / "authoring-spec.json").read_text())
    paths = ("authoring-spec.json", "manifest.json", "plan.json", "rehearsal-001/rows.jsonl", "rehearsal-001/summary.json")
    return {
        "schema": "source-trust-sampling-draft-v1",
        "status": "DRAFT_DECLARED_AFTER_ENGINEERING_OUTCOMES",
        "input_files_sha256": {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in paths},
        "current_estimand": "descriptive_mean_over_fixed_author_fixture_set_and_fixed_conditions",
        "current_selection": "author_convenience_synthetic_fixtures",
        "probability_sample": False, "outcomes_seen_before_declaration": True,
        "declared_lineage": {"id": spec["template_cluster_id"], "author": spec["author"],
                             "basis": "shared authoring spec, value recipe and identity instruction template"},
        "members": [{"family_id": f["family_id"], "split": f["split"], "source_kind": f["source_kind"],
                     "template_cluster_id": f["template_cluster_id"], "lineage_id": spec["template_cluster_id"],
                     "source_sha256": f["contract"]["source_sha256"]}
                    for f in sorted(manifest["families"], key=lambda f: f["family_id"])],
        "proposed_research": {
            "status": "UNSPECIFIED_NOT_FROZEN",
            "scope": "external families satisfying the frozen first-panel contract and disjoint from development templates",
            "estimand": None, "sampling_frame_ref": None, "selection_mechanism": None,
            "sampling_randomness_ref": None, "cluster_independence_evidence_ref": None,
            "pre_outcome_design_commitment_sha256": None,
        },
        "independent_review_records": [], "independence_verified": False,
        "formal_material_admission": False, "interval_method_selected": False,
        "preregistered": False, "experiment_authorized": False,
    }


def validate_sampling_contract(contract, directory=BUNDLE):
    require(contract == expected_contract(directory), "sampling_declaration_drift_or_unsubstantiated_claim")
    lineage_clusters = {}
    for member in contract["members"]:
        lineage_clusters.setdefault(member["lineage_id"], set()).add(member["template_cluster_id"])
    require(all(len(clusters) == 1 for clusters in lineage_clusters.values()), "shared_lineage_cannot_be_split_by_renaming")
    gaps = [name for name, value in contract["proposed_research"].items() if value is None]
    return {"scope": "POST_OUTCOME_DRAFT_DECLARATION_CHECK",
            "families": len(contract["members"]),
            "declared_template_clusters": len({m["template_cluster_id"] for m in contract["members"]}),
            "independence_verified": False, "probability_sample": False,
            "research_design_gaps": gaps, "independent_review": "PENDING",
            "interval_selection_ready": False, "experiment_authorized": False}
