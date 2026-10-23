"""Verify evidence against explicit Git trees; never run studies or APIs.

Retired, unreproducible snapshots retain their original bytes and review
bindings. The index names them explicitly; they do not become passing evidence.
"""

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def repository_path(path):
    normalized = PurePosixPath(path)
    if (not isinstance(path, str) or not path or normalized.is_absolute()
            or any(p in (".", "..") for p in normalized.parts)
            or str(normalized) != path or any(c in path for c in ("\n", "\r", ":", "\\"))):
        raise ValueError("SNAPSHOT_REPOSITORY_PATH")
    return path


def tree_hashes(repo, commit, paths):
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("SNAPSHOT_EXACT_COMMIT_REQUIRED")
    paths = [repository_path(path) for path in paths]
    requests = "".join(f"{commit}:{path}\n" for path in paths).encode()
    completed = subprocess.run(["git", "cat-file", "--batch"], cwd=repo, input=requests,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    stream, result = io.BytesIO(completed.stdout), {}
    for path in paths:
        header = stream.readline().rstrip(b"\n").split()
        if len(header) == 2 and header[-1] == b"missing":
            result[path] = None
            continue
        if len(header) != 3 or header[1] != b"blob":
            raise ValueError("SNAPSHOT_EXPECTED_BLOB")
        length = int(header[2])
        raw = stream.read(length)
        if len(raw) != length or stream.read(1) != b"\n":
            raise ValueError("SNAPSHOT_TRUNCATED_GIT_OUTPUT")
        result[path] = sha(raw)
    return result


def check_snapshot(repo, record):
    manifest_path = repository_path(record["path"])
    raw = (Path(repo) / manifest_path).read_bytes()
    if sha(raw) != record["snapshot_sha256"]:
        raise ValueError("SNAPSHOT_MANIFEST_CHANGED: " + manifest_path)
    if record["status"] == "SUPERSEDED_UNREPRODUCIBLE":
        if not record.get("reason") or record.get("verified_tree_commit") is not None:
            raise ValueError("SNAPSHOT_RETIREMENT_MUST_BE_EXPLICIT")
        return {"path": manifest_path, "status": record["status"], "files_verified": 0,
                "passing_evidence": False}
    if record["status"] not in ("REPRODUCIBLE_HISTORICAL", "CURRENT_REPRODUCIBLE"):
        raise ValueError("SNAPSHOT_UNKNOWN_STATUS")
    manifest = json.loads(raw)
    base = record["path_base"]
    if base:
        repository_path(base)
    expected = {repository_path(f"{base}/{p}" if base else p): h for p, h in manifest["files_sha256"].items()}
    commit = record["verified_tree_commit"]
    actual = tree_hashes(repo, commit, expected)
    mismatches = [p for p, h in expected.items() if actual[p] != h]
    if mismatches:
        raise ValueError("SNAPSHOT_TREE_MISMATCH: " + manifest_path + ": " + ", ".join(mismatches))
    if record["status"] == "CURRENT_REPRODUCIBLE":
        if manifest["reference_commit"] != commit or manifest["verified_tree_commit"] != commit:
            raise ValueError("SNAPSHOT_COMMIT_BINDING")
    return {"path": manifest_path, "status": record["status"], "verified_tree_commit": commit,
            "files_verified": len(expected), "passing_evidence": True}


def verify_index(repo, path):
    index = json.loads(Path(path).read_bytes())
    records = index["snapshots"]
    if len({r["path"] for r in records}) != len(records):
        raise ValueError("SNAPSHOT_DUPLICATE_RECORD")
    results = [check_snapshot(repo, record) for record in records]
    return {"state": "SNAPSHOT_INDEX_VERIFIED", "snapshots": results,
            "reproducible": sum(r["passing_evidence"] for r in results),
            "superseded_unreproducible": sum(not r["passing_evidence"] for r in results),
            "new_model_requests": 0, "new_tool_executions": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=Path, default=HERE / "review-fixes-v1/snapshot-index.json")
    args = parser.parse_args()
    try:
        result = verify_index(REPO, args.index)
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError):
        print(json.dumps({"state": "INVALID_SNAPSHOT_INDEX"}))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
