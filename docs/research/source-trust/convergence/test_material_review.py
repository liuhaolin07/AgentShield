"""Offline mutation tests; all filled annotations below are author test fixtures."""

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from material_review import BUNDLE, compare, load_sources, prepare, save_new
from validate_intake import load_unique_json


class MaterialReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.packet, cls.blank = prepare()
        cls.manifest, _, cls.task_contracts, _, _ = load_sources()

    def filled_fixture(self):
        """Synthetic author agreement is NOT an actual reviewer submission."""
        result = deepcopy(self.blank)
        result["reviewer"] = {"identity_ref": "test-reviewer", "independent_of_author": True,
                              "prior_outcome_access": False, "declaration_evidence_ref": "test-only",
                              "completed_at": "2026-10-23T01:00:00+08:00"}
        tasks = {t["task_id"]: t for t in self.task_contracts}
        for response, family in zip(result["families"], self.manifest["families"]):
            response["template_assessment"] = "AGREE"
            response["template_rationale"] = "TEST ONLY: shared author generator."
            for leaf, proposed in zip(response["leaves"], family["contract"]["leaves"]):
                leaf.update(classification=proposed["classification"], grants=deepcopy(proposed["grants"]),
                            rationale="TEST ONLY: author specification lookup.")
            for task, proposed in zip(response["tasks"], family["contract"]["tasks"]):
                task.update(dependency_paths=deepcopy(proposed["dependency_paths"]),
                            expected_body_sha256=tasks[task["task_id"]]["expected_body_sha256"],
                            rationale="TEST ONLY: identity selection.")
        return result

    def test_blank_packet_cannot_count_as_review_or_admission(self):
        report = compare(self.packet, self.blank)
        self.assertEqual((report["state"], report["reviewed_leaves"], report["reviewed_tasks"]),
                         ("PENDING", 0, 0))
        self.assertEqual(len(self.blank["families"]), 12)
        self.assertEqual(len(report["pending"]), 5 + 12 + 240 + 24)
        self.assertFalse(report["experiment_authorized"])
        self.assertFalse(report["independent_review_verified"])
        self.assertFalse(self.packet["blinded_review"])
        self.assertNotIn("rehearsal-001", json.dumps(self.packet))
        self.assertNotIn("expected_body_sha256", json.dumps(self.packet))

    def test_agreement_is_not_identity_proof_or_formal_evidence(self):
        report = compare(self.packet, self.filled_fixture())
        self.assertEqual((report["state"], report["reviewed_leaves"], report["reviewed_tasks"]),
                         ("ANNOTATIONS_AGREE", 240, 24))
        self.assertFalse(report["independent_review_verified"])
        self.assertFalse(report["independent_authorship"])
        self.assertFalse(report["pre_outcome_review"])
        self.assertEqual(report["formal_families_admitted"], 0)

    def test_truth_grants_dependencies_body_and_template_disagreements_survive(self):
        changed = self.filled_fixture()
        family = changed["families"][0]
        family["leaves"][0]["classification"] = "PUBLIC"
        family["leaves"][0]["grants"] = []
        family["tasks"][0]["dependency_paths"] = [family["leaves"][1]["path"]]
        family["tasks"][0]["expected_body_sha256"] = "0" * 64
        family["template_assessment"] = "DISAGREE"
        report = compare(self.packet, changed)
        self.assertEqual(report["state"], "DISAGREEMENTS")
        self.assertEqual({d["field"] for d in report["differences"]},
                         {"classification", "grants", "dependency_paths", "expected_body_sha256", "template_cluster"})

    def test_stale_packet_source_and_response_bindings_fail(self):
        packet = deepcopy(self.packet)
        packet["families"][0]["source_utf8"] += " "
        with self.assertRaisesRegex(ValueError, "packet_or_source_changed"):
            compare(packet, self.blank)
        response = deepcopy(self.blank)
        response["packet_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "response_packet_binding"):
            compare(self.packet, response)
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory)
            for name in self.packet["source_sha256"]:
                target = bundle / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((BUNDLE / name).read_bytes())
            path = bundle / "payloads" / (self.packet["families"][0]["family_id"] + ".json")
            path.write_bytes(path.read_bytes() + b" ")
            with self.assertRaisesRegex(ValueError, "source_bytes_digest_mismatch"):
                compare(self.packet, self.blank, bundle)

    def test_unknown_duplicate_missing_and_malformed_annotations_rejected(self):
        mutations = [
            lambda r: r["families"].append(deepcopy(r["families"][0])),
            lambda r: r["families"].pop(),
            lambda r: r["families"][0]["leaves"].append(deepcopy(r["families"][0]["leaves"][0])),
            lambda r: r["families"][0]["tasks"][0].update(dependency_paths=["/unknown"]),
            lambda r: r["families"][0]["leaves"][0].update(grants=[{"subject": "x", "purpose": "y"}] * 2),
            lambda r: r["reviewer"].update(independent_of_author="true"),
            lambda r: r["reviewer"].update(completed_at="2026-10-23T01:00:00"),
            lambda r: r.update(experiment_authorized=True),
        ]
        for mutation in mutations:
            response = self.filled_fixture()
            mutation(response)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                compare(self.packet, response)

    def test_json_duplicate_keys_and_overwriting_responses_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "response.json"
            path.write_text('{"packet_sha256":"a","packet_sha256":"b"}')
            with self.assertRaisesRegex(ValueError, "duplicate_json_key"):
                load_unique_json(path)
            with self.assertRaises(FileExistsError):
                save_new(path, self.blank)


if __name__ == "__main__":
    unittest.main()
