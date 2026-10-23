"""Freeze mechanics tests use disposable git repos, not research results."""
import importlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(HERE), str(HERE.parent)]


class FreezeTests(unittest.TestCase):
    def module(self):
        try:
            module = importlib.import_module("run_d5")
        except ModuleNotFoundError:
            self.fail("Missing pre-outcome freeze implementation")
        self.assertTrue(callable(getattr(module, "freeze_inputs", None)))
        return module

    def repo(self, parent):
        repo = parent / "repo"
        repo.mkdir()
        (repo / "config.json").write_bytes((HERE / "config.json").read_bytes())
        (repo / "input.txt").write_bytes(b"frozen engineering input\n")
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        for args in (("config", "user.name", "engineering-test"),
                     ("config", "user.email", "test@example.invalid"),
                     ("config", "core.autocrlf", "false"),
                     ("add", "."), ("commit", "-qm", "engineering fixture")):
            subprocess.run(["git", "-C", str(repo), *args], check=True)
        return repo

    def test_freeze_binds_clean_commit_and_refuses_mutation_or_overwrite(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            repo = self.repo(parent)
            out = parent / "run"
            frozen = m.freeze_inputs(out, repo, repo / "config.json")
            self.assertEqual(frozen["scope"], "LOCAL_PRE_OUTCOME_FREEZE_NOT_PROJECT_PREREGISTRATION")
            self.assertIn("input.txt", frozen["input_sha256"])
            m.verify_freeze(out, repo)
            with self.assertRaises((ValueError, FileExistsError)):
                m.freeze_inputs(out, repo, repo / "config.json")
            (repo / "input.txt").write_bytes(b"changed\n")
            with self.assertRaises(ValueError):
                m.verify_freeze(out, repo)
            other = parent / "dirty-run"
            with self.assertRaises(ValueError):
                m.freeze_inputs(other, repo, repo / "config.json")
            self.assertFalse(other.exists())

    def test_modified_manifest_is_not_a_valid_new_freeze(self):
        m = self.module()
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            repo = self.repo(parent)
            out = parent / "run"
            m.freeze_inputs(out, repo, repo / "config.json")
            manifest = json.loads((out / "freeze.json").read_text(encoding="utf-8"))
            manifest["contract_sha256"] = "0" * 64
            (out / "freeze.json").write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(ValueError):
                m.verify_freeze(out, repo)

    def test_archives_are_exclusive_and_payload_tampering_is_rejected(self):
        import gzip
        m = self.module()
        self.assertTrue(callable(getattr(m, "write_archive", None)), "Missing append-only outcome archive")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "rows.jsonl.gz"
            rows = [{"dataset_index": 0, "fixture": "中文工程测试"},
                    {"dataset_index": 1, "fixture": "not research evidence"}]
            m.write_archive(path, rows)
            self.assertEqual(list(m.read_archive(path)), rows)
            with self.assertRaises(FileExistsError):
                m.write_archive(path, rows)
            wrappers = [json.loads(line) for line in gzip.decompress(path.read_bytes()).splitlines()]
            wrappers[-1]["payload"]["fixture"] = "changed"
            changed = b"".join(m.canonical(w) + b"\n" for w in wrappers)
            path.write_bytes(gzip.compress(changed, mtime=0))
            with self.assertRaises(ValueError):
                list(m.read_archive(path))

    def test_simulation_requires_freeze_before_creating_any_outcomes(self):
        m = self.module()
        self.assertTrue(callable(getattr(m, "simulate", None)), "Missing frozen-only simulator")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = self.repo(root)
            out = root / "unfrozen"
            out.mkdir()
            with self.assertRaises((ValueError, OSError)):
                m.simulate(out, repo, workers=1)
            self.assertEqual(list(out.iterdir()), [])

    def test_workflow_runs_d5_engineering_tests_separately_from_212(self):
        workflow = (HERE.parents[4] / ".github/workflows/convergence.yml").read_text(encoding="utf-8")
        self.assertIn("d5-calibration-v2/requirements.txt", workflow)
        self.assertIn("python -I -X utf8 -m unittest discover -s docs/research/source-trust/convergence/d5-calibration-v2/tests", workflow)
        self.assertIn("tee logs/convergence/d5-v2-tests.log", workflow)

    def test_dataset_seed_is_order_independent_and_index_bound(self):
        m = self.module()
        self.assertTrue(callable(getattr(m, "dataset_rng", None)), "Missing index-bound RNG")
        first = m.dataset_rng(4, "engineering-alpha", 0).integers(0, 2**31, size=10).tolist()
        m.dataset_rng(4, "engineering-beta", 0).integers(0, 2**31, size=10)
        self.assertEqual(first, m.dataset_rng(4, "engineering-alpha", 0).integers(0, 2**31, size=10).tolist())
        self.assertNotEqual(first, m.dataset_rng(4, "engineering-alpha", 1).integers(0, 2**31, size=10).tolist())
        with self.assertRaises(ValueError):
            m.dataset_rng(4, "engineering-alpha", -1)


if __name__ == "__main__":
    unittest.main()
