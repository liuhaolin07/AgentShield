"""Read-only preflight for delivered development sources and evidence files.

Evidence presence and byte binding do not verify truth, authorship or timing.
No runtime import, execution, main-intake mutation or holdout contents access.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat

from material_adapter import verify_material
from validate_intake import HERE, digest, fields, identifier, require, validate_manifest

SCHEMA = "development-delivery-v1"
MAX_TOTAL_BYTES = 16 * 1024 * 1024
REF_KINDS = {
    "truth_ref": "truth", "authorization_ref": "authorization",
    "dependency_ref": "dependency", "lineage_ref": "lineage",
    "authorship_ref": "authorship", "review_ref": "independent_review",
    "pre_execution_commitment_ref": "pre_execution_commitment",
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                       allow_nan=False) + "\n").encode()


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_delivery_json_key")
            result[key] = value
        return result
    def constant(_):
        raise ValueError("nonfinite_delivery_json")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)


class Reader:
    """Open only explicit relative regular files under one directory descriptor."""

    def __init__(self, root):
        self.root = Path(root)
        self.total = 0
        self.hashes = {}

    def read(self, relative, limit):
        parts = PurePosixPath(relative).parts
        require(isinstance(relative, str) and parts and not relative.startswith("/")
                and all(p not in (".", "..") for p in parts)
                and str(PurePosixPath(relative)) == relative, "relative_delivery_path")
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            with os.fdopen(file_fd, "rb") as stream:
                require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "regular_delivery_file")
                raw = stream.read(limit + 1)
        finally:
            os.close(fd)
        require(0 < len(raw) <= limit, "delivery_file_size_limit")
        self.total += len(raw)
        require(self.total <= MAX_TOTAL_BYTES, "delivery_total_size_limit")
        self.hashes[relative] = sha(raw)
        return raw


def template():
    raw = (HERE / "intake-manifest.json").read_bytes()
    manifest = parse(raw)
    require(not manifest["families"] and manifest["holdout_custody"]["status"] == "NOT_RECEIVED",
            "empty_initial_intake_required")
    return raw, {"schema_version": SCHEMA, "purpose": "DEVELOPMENT_ONLY_PREFLIGHT",
                 "manifest_sha256": sha(raw), "evidence_inventory": [], "family_evidence": []}


def preflight(root):
    reader = Reader(root)
    raw = reader.read("manifest.json", 2 * 1024 * 1024)
    manifest = parse(raw)
    # Reject external material before reading any named source or evidence file.
    require(isinstance(manifest, dict) and isinstance(manifest.get("families"), list)
            and all(isinstance(f, dict) and f.get("split") == "development" for f in manifest["families"])
            and isinstance(manifest.get("holdout_custody"), dict)
            and manifest["holdout_custody"].get("status") == "NOT_RECEIVED", "development_delivery_only")
    inventory = validate_manifest(manifest)
    delivery = parse(reader.read("delivery.json", 1024 * 1024))
    fields(delivery, "schema_version purpose manifest_sha256 evidence_inventory family_evidence", "delivery_fields")
    require(delivery["schema_version"] == SCHEMA and delivery["purpose"] == "DEVELOPMENT_ONLY_PREFLIGHT",
            "delivery_schema_scope")
    require(delivery["manifest_sha256"] == sha(raw), "delivery_manifest_binding")
    evidence = {}
    require(isinstance(delivery["evidence_inventory"], list), "evidence_inventory_list")
    for item in delivery["evidence_inventory"]:
        fields(item, "ref kind path sha256", "evidence_record_fields")
        ref = item["ref"]
        require(identifier(ref) and ref not in evidence, "unique_evidence_reference")
        require(item["kind"] in {*REF_KINDS.values(), "receipt"} and digest(item["sha256"]),
                "evidence_kind_and_digest")
        require(item["path"] in [f"evidence/{ref}.{ext}" for ext in ("md", "txt", "json")],
                "evidence_file_location")
        evidence[ref] = item
    entries = delivery["family_evidence"]
    require(isinstance(entries, list), "family_evidence_list")
    by_family = {}
    for item in entries:
        fields(item, "family_id source_file receipt_refs " + " ".join(REF_KINDS), "family_evidence_fields")
        fid = item["family_id"]
        require(identifier(fid) and fid not in by_family, "unique_family_evidence")
        require(item["source_file"] == f"payloads/{fid}.json", "development_payload_location")
        by_family[fid] = item
    require(set(by_family) == {f["family_id"] for f in manifest["families"]}, "family_evidence_coverage")
    missing, used = [], set()

    def bind(ref, kind, label):
        if ref is None:
            missing.append(label)
            return
        require(identifier(ref) and ref in evidence, "unresolved_evidence_reference")
        require(evidence[ref]["kind"] == kind, "evidence_reference_kind")
        used.add(ref)

    for family in manifest["families"]:
        fid = family["family_id"]
        item = by_family[fid]
        for key, kind in REF_KINDS.items():
            bind(item[key], kind, fid + ":" + key)
        require(item["dependency_ref"] is None
                or item["dependency_ref"] == family["contract"]["dependency_evidence_ref"],
                "dependency_contract_reference_binding")
        receipts = item["receipt_refs"]
        require(isinstance(receipts, dict) and set(receipts) == {t["task_id"] for t in family["contract"]["tasks"]},
                "receipt_task_coverage")
        for task in family["contract"]["tasks"]:
            ref = receipts[task["task_id"]]
            bind(ref, "receipt", fid + ":receipt:" + task["task_id"])
            require(ref is None or ref == task["receipt_contract_ref"], "receipt_contract_reference_binding")
    require(used == set(evidence), "unreferenced_evidence_not_read")
    # Only now read files named by this development-only and fully bound inventory.
    for family in manifest["families"]:
        raw_source = reader.read(by_family[family["family_id"]]["source_file"], 65536)
        verify_material(manifest, family["family_id"], raw_source)
    for ref, item in evidence.items():
        require(sha(reader.read(item["path"], 1024 * 1024)) == item["sha256"], "evidence_bytes_digest_mismatch")
    return {
        "schema_version": SCHEMA,
        "state": "PENDING_FILES_OR_FAMILIES" if missing or not manifest["families"] else "MANUAL_REVIEW_REQUIRED",
        "development_families_delivered": len(manifest["families"]),
        "source_kinds": {kind: sum(f["source_kind"] == kind for f in manifest["families"])
                         for kind in ("file", "tool")},
        "declared_template_clusters": len({f["template_cluster_id"] for f in manifest["families"]}),
        "evidence_files_bound": len(evidence), "missing_evidence": missing,
        "inventory_gaps": inventory["inventory_gaps"], "input_files_sha256": reader.hashes,
        "source_adapter_scope": "flat_string_20_to_31_leaves_single_leaf_identity",
        "semantics_verified": False, "independence_verified": False,
        "pre_execution_timing_verified": False, "external_holdout_contents_read": False,
        "formal_families_admitted": 0, "experiment_authorized": False,
        "new_model_requests": 0, "new_tool_executions": 0,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    init.add_argument("--output", type=Path, required=True)
    check = commands.add_parser("check")
    check.add_argument("--root", type=Path, required=True)
    check.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "init":
            raw, delivery = template()
            args.output.mkdir(parents=True, exist_ok=False)
            (args.output / "manifest.json").write_bytes(raw)
            (args.output / "delivery.json").write_bytes(encode(delivery))
            print(json.dumps({"state": "EMPTY_DELIVERY_TEMPLATE", "formal_families_admitted": 0}))
            return 2
        report = preflight(args.root)
        with args.output.open("xb") as stream:
            stream.write(encode(report))
        print(json.dumps({k: report[k] for k in ("state", "development_families_delivered",
                                                "evidence_files_bound", "formal_families_admitted")}))
        return 0 if report["state"] == "MANUAL_REVIEW_REQUIRED" else 2
    except (ValueError, KeyError, TypeError, OSError, UnicodeError, RecursionError):
        print(json.dumps({"state": "INVALID", "experiment_authorized": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
