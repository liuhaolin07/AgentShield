"""All delivered files in these tests are temporary author fixtures, not evidence."""

from copy import deepcopy
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from development_intake import HERE, REF_KINDS, Reader, encode, parse, preflight, sha, template


class DevelopmentIntakeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "delivery"
        self.root.mkdir()
        raw, self.delivery = template()
        self.manifest = parse(raw)

    def persist(self):
        raw = encode(self.manifest)
        (self.root / "manifest.json").write_bytes(raw)
        self.delivery["manifest_sha256"] = sha(raw)
        (self.root / "delivery.json").write_bytes(encode(self.delivery))

    def fixture(self, omit_review=False):
        bundle = HERE / "candidate-materials-v1"
        family = deepcopy(parse((bundle / "manifest.json").read_bytes())["families"][0])
        fid = family["family_id"]
        self.manifest["families"] = [family]
        (self.root / "payloads").mkdir()
        (self.root / "payloads" / (fid + ".json")).write_bytes((bundle / "payloads" / (fid + ".json")).read_bytes())
        (self.root / "evidence").mkdir()

        def artifact(ref, kind):
            raw = ("TEST FIXTURE ONLY: not an independent " + kind + " record.\n").encode()
            path = "evidence/" + ref + ".md"
            (self.root / path).write_bytes(raw)
            self.delivery["evidence_inventory"].append({"ref": ref, "kind": kind, "path": path, "sha256": sha(raw)})
            return ref
        entry = {"family_id": fid, "source_file": "payloads/" + fid + ".json", "receipt_refs": {}}
        for key, kind in REF_KINDS.items():
            if omit_review and key == "review_ref":
                entry[key] = None
            else:
                ref = family["contract"]["dependency_evidence_ref"] if key == "dependency_ref" else "test-" + kind
                entry[key] = artifact(ref, kind)
        for task in family["contract"]["tasks"]:
            entry["receipt_refs"][task["task_id"]] = artifact(task["receipt_contract_ref"], "receipt")
        self.delivery["family_evidence"] = [entry]
        self.persist()

    def test_empty_delivery_remains_incomplete_and_unadmitted(self):
        self.persist()
        report = preflight(self.root)
        self.assertEqual(report["state"], "PENDING_FILES_OR_FAMILIES")
        self.assertEqual(report["development_families_delivered"], 0)
        self.assertEqual(report["formal_families_admitted"], 0)
        self.assertFalse(report["experiment_authorized"])
        self.assertEqual(set(report["input_files_sha256"]), {"manifest.json", "delivery.json"})

    def test_complete_file_bindings_still_require_manual_review(self):
        self.fixture()
        report = preflight(self.root)
        self.assertEqual(report["state"], "MANUAL_REVIEW_REQUIRED")
        self.assertEqual(report["evidence_files_bound"], 9)
        for key in ("semantics_verified", "independence_verified", "pre_execution_timing_verified",
                    "external_holdout_contents_read", "experiment_authorized"):
            self.assertFalse(report[key])
        self.assertEqual(report["formal_families_admitted"], 0)

    def test_missing_review_is_recorded_and_unlisted_files_not_opened(self):
        self.fixture(omit_review=True)
        (self.root / "unlisted-holdout.bin").write_bytes(b"MUST NOT READ")
        report = preflight(self.root)
        self.assertEqual(report["state"], "PENDING_FILES_OR_FAMILIES")
        self.assertEqual(len(report["missing_evidence"]), 1)
        self.assertTrue(report["missing_evidence"][0].endswith(":review_ref"))
        self.assertNotIn("unlisted-holdout.bin", report["input_files_sha256"])

    def test_manifest_source_and_evidence_tampering_rejected(self):
        self.fixture()
        for relative, error in [("manifest.json", "delivery_manifest_binding"),
                                (self.delivery["family_evidence"][0]["source_file"], "source_bytes_digest_mismatch"),
                                (self.delivery["evidence_inventory"][0]["path"], "evidence_bytes_digest_mismatch")]:
            path = self.root / relative
            original = path.read_bytes()
            path.write_bytes(original + b" ")
            with self.subTest(relative=relative), self.assertRaisesRegex(ValueError, error):
                preflight(self.root)
            path.write_bytes(original)

    def test_reference_kind_duplicates_and_contract_drift_rejected(self):
        self.fixture()
        initial = deepcopy(self.delivery)
        mutations = [
            lambda d: d["evidence_inventory"].append(deepcopy(d["evidence_inventory"][0])),
            lambda d: d["evidence_inventory"][0].update(kind="receipt"),
            lambda d: d["family_evidence"][0].update(truth_ref="absent"),
            lambda d: d["family_evidence"][0].update(dependency_ref=d["family_evidence"][0]["truth_ref"]),
            lambda d: d["family_evidence"][0]["receipt_refs"].clear(),
            lambda d: d.update(experiment_authorized=True),
        ]
        for mutation in mutations:
            self.delivery = deepcopy(initial)
            mutation(self.delivery)
            self.persist()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                preflight(self.root)

    def test_symlinks_traversal_and_special_files_rejected(self):
        self.fixture()
        entry = self.delivery["family_evidence"][0]
        entry["source_file"] = "../outside.json"
        self.persist()
        with self.assertRaisesRegex(ValueError, "development_payload_location"):
            preflight(self.root)
        entry["source_file"] = "payloads/" + entry["family_id"] + ".json"
        self.persist()
        source = self.root / entry["source_file"]
        outside = Path(self.temp.name) / "outside.json"
        outside.write_bytes(source.read_bytes())
        source.unlink()
        source.symlink_to(outside)
        with self.assertRaises(OSError):
            preflight(self.root)
        source.unlink()
        (self.root / "payloads").rmdir()
        (self.root / "payloads").symlink_to(Path(self.temp.name))
        with self.assertRaises(OSError):
            preflight(self.root)
        os.mkfifo(self.root / "pipe")
        with self.assertRaisesRegex(ValueError, "regular_delivery_file"):
            Reader(self.root).read("pipe", 20)

    def test_holdout_and_unreferenced_evidence_rejected_before_opening(self):
        self.fixture()
        self.manifest["families"][0]["split"] = "external_holdout"
        self.persist()
        real_read = Reader.read
        opened = []
        def watch(reader, name, limit):
            opened.append(name)
            return real_read(reader, name, limit)
        with patch.object(Reader, "read", watch), self.assertRaisesRegex(ValueError, "development_delivery_only"):
            preflight(self.root)
        self.assertEqual(opened, ["manifest.json"])
        self.manifest["families"][0]["split"] = "development"
        self.delivery["evidence_inventory"].append({"ref": "unused", "kind": "truth", "path": "evidence/unused.md", "sha256": "0" * 64})
        self.persist()
        opened.clear()
        with patch.object(Reader, "read", watch), self.assertRaisesRegex(ValueError, "unreferenced_evidence_not_read"):
            preflight(self.root)
        self.assertEqual(opened, ["manifest.json", "delivery.json"])

    def test_budget_and_duplicate_json_keys_cannot_be_bypassed(self):
        self.fixture()
        base = self.manifest["families"][0]
        self.manifest["families"] = []
        for i in range(61):
            family = deepcopy(base)
            family["family_id"] = "test-family-" + str(i)
            family["contract"]["source_sha256"] = hashlib.sha256(str(i).encode()).hexdigest()
            for task in family["contract"]["tasks"]:
                task["task_id"] = family["family_id"] + "-" + task["kind"]
            self.manifest["families"].append(family)
        self.persist()
        with self.assertRaisesRegex(ValueError, "family_budget_exceeded"):
            preflight(self.root)
        with self.assertRaisesRegex(ValueError, "duplicate_delivery_json_key"):
            parse(b'{"purpose":"a","purpose":"b"}')

    def test_cli_empty_template_and_check_do_not_overwrite(self):
        script = str(HERE / "development_intake.py")
        root = Path(self.temp.name) / "new"
        command = ["python", script, "init", "--output", str(root)]
        self.assertEqual(subprocess.run(command, capture_output=True).returncode, 2)
        self.assertEqual(subprocess.run(command, capture_output=True).returncode, 1)
        output = Path(self.temp.name) / "check.json"
        command = ["python", script, "check", "--root", str(root), "--output", str(output)]
        self.assertEqual(subprocess.run(command, capture_output=True).returncode, 2)
        original = output.read_bytes()
        self.assertEqual(subprocess.run(command, capture_output=True).returncode, 1)
        self.assertEqual(original, output.read_bytes())


if __name__ == "__main__":
    unittest.main()
