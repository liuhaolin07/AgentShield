"""Reproduce the wrong commit/path-root regression with an isolated Git repo."""

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from evidence_snapshots import check_snapshot, repository_path, tree_hashes


class EvidenceSnapshotTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "core.autocrlf", "false")
        (self.repo / "convergence").mkdir()
        self.body = b"fixture\n"
        (self.repo / "convergence/README.md").write_bytes(self.body)
        self.git("add", ".")
        self.git("commit", "-q", "-m", "fixture")
        self.commit = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.repo, text=True, stderr=subprocess.PIPE)

    def record(self):
        manifest = {"files_sha256": {"README.md": hashlib.sha256(self.body).hexdigest()}}
        path = self.repo / "snapshot.json"
        path.write_text(json.dumps(manifest))
        return {"path": "snapshot.json", "snapshot_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "status": "REPRODUCIBLE_HISTORICAL", "path_base": "convergence", "verified_tree_commit": self.commit}

    def test_exact_commit_and_convergence_relative_paths_are_verified(self):
        record = self.record()
        self.assertEqual(check_snapshot(self.repo, record)["files_verified"], 1)
        # Changing a worktree file does not substitute it for the verified tree.
        (self.repo / "convergence/README.md").write_bytes(b"changed")
        self.assertEqual(check_snapshot(self.repo, record)["files_verified"], 1)

    def test_wrong_root_missing_file_and_wrong_digest_fail(self):
        record = self.record()
        record["path_base"] = ""
        with self.assertRaisesRegex(ValueError, "TREE_MISMATCH"):
            check_snapshot(self.repo, record)
        self.assertIsNone(tree_hashes(self.repo, self.commit, ["absent"])["absent"])
        record = self.record()
        (self.repo / "convergence/README.md").write_bytes(b"changed")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "new tree")
        record["verified_tree_commit"] = self.git("rev-parse", "HEAD").strip()
        with self.assertRaisesRegex(ValueError, "TREE_MISMATCH"):
            check_snapshot(self.repo, record)

    def test_retired_snapshot_is_not_passing_evidence(self):
        record = self.record()
        record.update(status="SUPERSEDED_UNREPRODUCIBLE", verified_tree_commit=None,
                      reason="Original artifact never had a matching committed tree")
        result = check_snapshot(self.repo, record)
        self.assertFalse(result["passing_evidence"])
        self.assertEqual(result["files_verified"], 0)

    def test_moving_refs_and_path_escape_cannot_be_used(self):
        with self.assertRaisesRegex(ValueError, "EXACT_COMMIT"):
            tree_hashes(self.repo, "HEAD", ["convergence/README.md"])
        for path in ("../outside", "/absolute", "a\nother", "a:b", "a\\b"):
            with self.assertRaises(ValueError):
                repository_path(path)


if __name__ == "__main__":
    unittest.main()
