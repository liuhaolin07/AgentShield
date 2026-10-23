"""Candidate provenance, exact rehearsal budget and control regressions."""

from copy import deepcopy
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from candidate_materials import BUNDLE, build_candidates, build_plan, validate_candidates, write_candidates
from candidate_rehearsal import execution_rows, summarize_records
from corruption_graph import canonical, defense_labels, digest
from material_adapter import decode_pointer
from runtime_probe import assess_observation, probe_identity
from validate_intake import load_unique_json


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.spec = load_unique_json(BUNDLE / "authoring-spec.json")

    def test_materials_balanced_and_single_shared_template_without_author_independence(self):
        manifest, payloads, tasks = build_candidates(self.spec)
        self.assertEqual(len(manifest["families"]), 12)
        self.assertEqual(len(payloads), 12)
        self.assertEqual(len(tasks), 24)
        self.assertEqual(sum(f["source_kind"] == "file" for f in manifest["families"]), 6)
        self.assertEqual(len({f["template_cluster_id"] for f in manifest["families"]}), 1)
        self.assertFalse(self.spec["independent_authorship"])
        for family in manifest["families"]:
            self.assertEqual(sum(l["classification"] == "SENSITIVE" for l in family["contract"]["leaves"]), 10)
            self.assertEqual(len(family["contract"]["leaves"]), 20)
        self.assertEqual(manifest["holdout_custody"]["status"], "NOT_RECEIVED")

    def test_exact_984_plan_controls_correct_graph_and_no_extra_repeats(self):
        manifest, _, _ = build_candidates(self.spec)
        plan = build_plan(manifest)
        self.assertEqual(len(plan["graphs"]), 13)
        self.assertEqual(len({r["row_id"] for r in plan["rows"]}), 984)
        self.assertEqual(sum(r["section"] == "primary" for r in plan["rows"]), 936)
        e0 = next(g for g in plan["graphs"] if g["experiment"] == "E0")
        controls = [r for r in plan["rows"] if r["section"] == "control"]
        self.assertEqual(len(controls), 48)
        self.assertEqual({r["graph_sha256"] for r in controls}, {e0["graph_sha256"]})
        self.assertEqual(sum(r["policy"] == "no_defense" for r in controls), 24)
        self.assertTrue(all(r["status"] == "UNRUN" for r in plan["rows"]))
        self.assertTrue(all(r["section"] == "control" for r in execution_rows(plan)[:48]))
        self.assertEqual({g["rate"] for g in plan["graphs"]}, {"0", "0.1", "0.25"})
        self.assertEqual({g["seed"] for g in plan["graphs"]}, {None, 17, 29})

    def test_plan_rejects_wrong_source_balance(self):
        manifest, _, _ = build_candidates(self.spec)
        manifest["families"][0]["source_kind"] = "tool"
        with self.assertRaisesRegex(ValueError, "source_balance"):
            build_plan(manifest)

    def test_no_fake_independence_review_or_template_clusters(self):
        for key, value in (("independent_authorship", True), ("semantic_review", "APPROVED"),
                           ("template_cluster_id", "pretend-independent")):
            changed = deepcopy(self.spec)
            changed[key] = value
            with self.assertRaises(ValueError):
                build_candidates(changed)

    def test_reproducible_build_and_payload_tampering_detected_without_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "authoring-spec.json").write_bytes(canonical(self.spec))
            first = write_candidates(directory)
            self.assertEqual(first, write_candidates(directory))
            manifest, _, _ = validate_candidates(directory)
            path = directory / f"payloads/{manifest['families'][0]['family_id']}.json"
            path.write_bytes(path.read_bytes() + b" ")
            with self.assertRaisesRegex(ValueError, "payload_differs"):
                validate_candidates(directory)
            with self.assertRaisesRegex(ValueError, "refuse_overwrite"):
                write_candidates(directory)

    def test_plan_and_contract_changes_cannot_be_blessed_by_rehashing(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "authoring-spec.json").write_bytes(canonical(self.spec))
            write_candidates(directory)
            original = (directory / "plan.json").read_bytes()
            plan = json.loads(original)
            plan["rows"][0]["policy"] = "reject_all"
            plan["rows"][0]["row_id"] = digest({k: v for k, v in plan["rows"][0].items() if k != "row_id"})
            (directory / "plan.json").write_bytes(canonical(plan))
            with self.assertRaisesRegex(ValueError, "plan_binding"):
                validate_candidates(directory)
            (directory / "plan.json").write_bytes(original)
            manifest = load_unique_json(directory / "manifest.json")
            manifest["families"][0]["contract"]["tasks"][0]["dependency_paths"] = ["/other"]
            (directory / "manifest.json").write_bytes(canonical(manifest))
            with self.assertRaisesRegex(ValueError, "contract_differs"):
                validate_candidates(directory)

    def test_incomplete_rows_are_retained_and_never_pass_the_engineering_gate(self):
        _, plan, _ = validate_candidates()
        records, previous = [], None
        for row in execution_rows(plan):
            record = {"plan_row": row, "observation": None, "assessment": None, "error_type": "InjectedFailure",
                      "elapsed_ns": 0, "previous_sha256": previous}
            record["record_sha256"] = digest(record)
            previous = record["record_sha256"]
            records.append(record)
        report = summarize_records(BUNDLE, records)
        self.assertEqual(report["states"], {"INCOMPLETE": 984})
        self.assertFalse(report["engineering_checks_passed"])
        self.assertEqual(report["formal_pilot_rows"], 0)
        with self.assertRaisesRegex(ValueError, "incomplete_or_excess"):
            summarize_records(BUNDLE, records[:-1])
        records[-1]["plan_row"] = records[0]["plan_row"]
        with self.assertRaisesRegex(ValueError, "row_binding"):
            summarize_records(BUNDLE, records)


class CandidateControlTests(unittest.TestCase):
    def test_real_controls_share_inputs_and_have_independent_receiver_evidence(self):
        from evaluation.receiver import LoopbackReceiver
        manifest, plan, tasks = validate_candidates()
        family = manifest["families"][0]
        fid = family["family_id"]
        raw = (BUNDLE / f"payloads/{fid}.json").read_bytes()
        projection = next(f for f in defense_labels(plan["graphs"][0])["families"] if f["family_id"] == fid)
        with LoopbackReceiver() as receiver:
            for task in [t for t in tasks if t["family_id"] == fid]:
                for control in ("no_defense", "reject_all"):
                    with contextlib.redirect_stdout(io.StringIO()):
                        observation = probe_identity(projection, family["source_kind"], raw, task["output_path"], "precision", receiver, control=control)
                    report = assess_observation(observation, json.loads(raw)[decode_pointer(task["output_path"])])
                    self.assertTrue(report["valid_observation"], observation)
                    self.assertEqual(report["state"], "OBSERVED_DELIVERY" if control == "no_defense" else "OBSERVED_BLOCK")
                    self.assertEqual(observation["control"], control)
                    self.assertEqual(observation["outbound_entries"], int(control == "no_defense"))
            self.assertEqual(len(receiver.arrivals), 2)
