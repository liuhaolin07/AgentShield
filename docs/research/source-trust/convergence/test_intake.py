"""Synthetic metadata checks; no experimental samples or runtime imports."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from validate_intake import HERE, load_unique_json, validate_contract, validate_gates, validate_manifest


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def development(index=0):
    read = {"subject": "primary-model", "purpose": "task-read"}
    sink = {"subject": "http-recipient", "purpose": "export"}
    return {
        "family_id": f"dev-{index}", "template_cluster_id": f"dev-template-{index}",
        "split": "development", "source_kind": "file",
        "contract": {
            "truth_basis": "INDEPENDENT_CONTRACT", "truth_visibility": "INJECTOR_EVALUATOR_ONLY",
            "source_sha256": sha(f"synthetic-dev-{index}"),
            "dependency_evidence_ref": "synthetic-dependency-review",
            "leaves": [{
                "path": f"/field{i}", "classification": "SENSITIVE" if i < 10 else "PUBLIC",
                "value_sha256": sha(f"synthetic-{index}-{i}"),
                "grants": [read] if i < 10 else [read, sink],
            } for i in range(20)],
            "tasks": [{
                "task_id": f"dev-{index}-{kind}", "kind": kind,
                "dependency_paths": ["/field0" if kind == "attack" else "/field10"],
                "read_scope": read, "sink_scope": sink,
                "supported_transform_ids": ["identity"], "receipt_contract_ref": "synthetic-receipt",
            } for kind in ("attack", "benign")],
        },
    }


def sealed(index=0):
    return {
        "family_id": f"hold-{index}", "template_cluster_id": f"hold-template-{index}",
        "split": "external_holdout", "source_kind": "tool",
        "sealed_bundle_sha256": sha(f"synthetic-sealed-{index}"),
    }


class IntakeTests(unittest.TestCase):
    def setUp(self):
        self.manifest = load_unique_json(HERE / "intake-manifest.json")

    def with_holdout(self):
        self.manifest["holdout_custody"] = {
            "status": "SEALED_METADATA_ONLY", "custodian_ref": "synthetic-custodian",
            "commitment_sha256": sha("synthetic-bundle"),
            "template_audit_ref": "synthetic-audit", "results_accessed": False,
        }
        self.manifest["families"] = [development(), sealed()]

    def test_empty_draft_remains_incomplete_and_unauthorized(self):
        r = validate_manifest(self.manifest)
        self.assertTrue(r["structurally_valid"])
        self.assertEqual(len(r["inventory_gaps"]), 4)
        self.assertFalse(r["experiment_authorized"])

    def test_authorized_model_read_is_not_confused_with_external_release(self):
        self.manifest["families"] = [development()]
        self.assertTrue(validate_manifest(self.manifest)["structurally_valid"])

    def test_full_synthetic_inventory_does_not_confer_approval(self):
        self.with_holdout()
        self.manifest["families"] = [development(i) for i in range(60)] + [sealed(i) for i in range(60)]
        r = validate_manifest(self.manifest)
        self.assertEqual(r["inventory_gaps"], [])
        self.assertFalse(r["experiment_authorized"])
        self.assertEqual(r["ground_truth_semantics"], "NOT_VERIFIED_BY_THIS_CHECKER")

    def test_cross_split_template_overlap_rejected(self):
        self.with_holdout()
        self.manifest["families"][1]["template_cluster_id"] = "dev-template-0"
        with self.assertRaisesRegex(ValueError, "template_overlap"):
            validate_manifest(self.manifest)

    def test_holdout_payload_and_truth_are_rejected(self):
        self.with_holdout()
        for name in ("payload", "leaves", "contract"):
            corrupted = deepcopy(self.manifest)
            corrupted["families"][1][name] = {}
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "holdout_must_not"):
                validate_manifest(corrupted)

    def test_revealed_holdout_is_rejected(self):
        self.with_holdout()
        self.manifest["holdout_custody"]["results_accessed"] = True
        with self.assertRaisesRegex(ValueError, "already_revealed"):
            validate_manifest(self.manifest)

    def test_detector_derived_truth_and_defense_visible_truth_rejected(self):
        for key, value in (("truth_basis", "DETECTOR_OUTPUT"), ("truth_visibility", "DEFENSE")):
            contract = development()["contract"]
            contract[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_contract(contract)

    def test_empty_unknown_and_duplicate_dependencies_rejected(self):
        for dependencies in ([], ["/not-there"], ["/field0", "/field0"]):
            contract = development()["contract"]
            contract["tasks"][0]["dependency_paths"] = dependencies
            with self.subTest(dependencies=dependencies), self.assertRaises(ValueError):
                validate_contract(contract)

    def test_benign_unauthorized_sink_and_authorized_attack_rejected(self):
        contract = development()["contract"]
        contract["tasks"][1]["sink_scope"] = {"subject": "other-reader", "purpose": "export"}
        with self.assertRaisesRegex(ValueError, "authorized_public"):
            validate_contract(contract)
        contract = development()["contract"]
        contract["tasks"][0]["sink_scope"] = contract["tasks"][0]["read_scope"]
        with self.assertRaisesRegex(ValueError, "unauthorized_sensitive"):
            validate_contract(contract)

    def test_missing_or_duplicate_leaf_and_bad_pointer_rejected(self):
        for mode in ("missing", "duplicate", "bad_pointer", "overlap"):
            contract = development()["contract"]
            if mode == "missing":
                contract["leaves"].pop()
            else:
                contract["leaves"][1]["path"] = {"duplicate": "/field0", "bad_pointer": "/bad~2", "overlap": "/field0/child"}[mode]
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                validate_contract(contract)

    def test_stale_protocol_reference_rejected(self):
        self.manifest["reference"]["protocol_sha256"] = sha("stale")
        with self.assertRaisesRegex(ValueError, "digest_mismatch"):
            validate_manifest(self.manifest)

    def test_duplicate_json_keys_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "metadata.json"
            path.write_text('{"split":"development","split":"external_holdout"}')
            with self.assertRaisesRegex(ValueError, "duplicate_json_key"):
                load_unique_json(path)

    def test_gates_cannot_silently_enable_experiments_or_change_budget(self):
        ledger = load_unique_json(HERE / "evidence-gates.json")
        self.assertEqual(len(validate_gates(ledger, self.manifest)), 13)
        for mode in ("approve", "remove", "budget", "generator_complete", "threshold_complete", "final_protocol", "adapter_complete", "observation_complete"):
            changed = deepcopy(ledger)
            if mode == "approve":
                changed["experiment_authorized"] = True
            elif mode == "remove":
                changed["gates"].pop()
            elif mode == "generator_complete":
                changed["gates"][4]["status"] = "COMPLETE"
            elif mode in ("adapter_complete", "observation_complete"):
                changed["gates"][6 if mode == "adapter_complete" else 7]["status"] = "COMPLETE"
            elif mode == "threshold_complete":
                changed["gates"][1]["status"] = "APPROVED_BY_USER"
            elif mode == "final_protocol":
                changed["protocol_approval"] = "APPROVED"
            else:
                changed["budget_snapshot"]["E0_E1"] = 57600
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                validate_gates(changed, self.manifest)


if __name__ == "__main__":
    unittest.main()
