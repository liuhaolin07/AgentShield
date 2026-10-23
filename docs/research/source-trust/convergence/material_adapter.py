"""Read-only development payload intake and declaration-only runtime adapter.

The first adapter supports flat JSON objects of 20..31 string leaves and
single-leaf identity output tasks. Unsupported contracts fail, never truncate.
No execution entry point; semantic truth and authorship remain unverified.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re

from validate_intake import fields, identifier, load_unique_json, require, validate_manifest


def value_digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def pointer(key):
    return "/" + key.replace("~", "~0").replace("/", "~1")


def decode_pointer(path):
    require(isinstance(path, str) and re.fullmatch(r"/(?:[^~/]|~[01])+", path) is not None,
            "adapter_requires_one_segment_pointer")
    return path[1:].replace("~1", "/").replace("~0", "~")


def parse_source(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 65536, "source_byte_budget")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_source_key")
            result[key] = value
        return result
    def constant(_):
        raise ValueError("nonfinite_source_value")
    try:
        source = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError):
        raise ValueError("invalid_source_json") from None
    require(isinstance(source, dict) and 20 <= len(source) <= 31, "adapter_leaf_budget_20_to_31")
    require(all(isinstance(key, str) and 0 < len(key) <= 128 and isinstance(value, str)
                for key, value in source.items()), "adapter_flat_string_leaves_only")
    return source


def verify_material(manifest, family_id, raw):
    validate_manifest(manifest)
    matches = [f for f in manifest["families"] if f["family_id"] == family_id and f["split"] == "development"]
    require(len(matches) == 1, "development_family_required")
    family = matches[0]
    contract = family["contract"]
    require(hashlib.sha256(raw).hexdigest() == contract["source_sha256"], "source_bytes_digest_mismatch")
    source = parse_source(raw)
    leaves = {pointer(key): value for key, value in source.items()}
    require(set(leaves) == {leaf["path"] for leaf in contract["leaves"]}, "source_leaf_universe_mismatch")
    for leaf in contract["leaves"]:
        require(value_digest(leaves[leaf["path"]]) == leaf["value_sha256"], "source_value_digest_mismatch")
    for task in contract["tasks"]:
        require(len(task["dependency_paths"]) == 1 and task["supported_transform_ids"] == ["identity"],
                "adapter_requires_single_leaf_identity_task")
    return {"family_id": family_id, "source_kind": family["source_kind"],
            "source_sha256": contract["source_sha256"], "verified_leaves": len(leaves),
            "scope": "payload bytes and declared contract consistency only",
            "semantic_truth_verified": False, "authorship_verified": False,
            "experiment_authorized": False}


def compile_declarations(family_labels, source_kind, raw):
    """Accept ONLY defense projection, source bytes and ingress kind, no oracle."""
    from security.precision import FieldRule, SourceLayout, source_value
    from security.source_classification import SourcePlan, SourceRegistry

    fields(family_labels, "family_id source_version labels", "defense_family_fields")
    require(identifier(family_labels["family_id"]), "family_identifier")
    require(source_kind in ("file", "tool"), "adapter_source_kind")
    require(hashlib.sha256(raw).hexdigest() == family_labels["source_version"], "defense_source_binding")
    source = parse_source(raw)
    require(isinstance(family_labels["labels"], list), "declaration_list")
    rules, seen = [], set()
    for leaf in family_labels["labels"]:
        fields(leaf, "path classification", "declaration_fields_no_truth")
        key = decode_pointer(leaf["path"])
        require(key in source and key not in seen, "declaration_coverage")
        require(leaf["classification"] in ("PUBLIC", "SENSITIVE"), "declaration_classification")
        seen.add(key)
        rules.append(FieldRule((key,), leaf["classification"] == "SENSITIVE"))
    require(seen == set(source), "declaration_coverage")
    reference = "data/source.json" if source_kind == "file" else "development_reader"
    layout = SourceLayout(fields=tuple(rules), structured_json=True)
    # Check existing runtime budgets before creating an executable adapter.
    source_value(source, source_kind, reference, layout)
    registry = SourceRegistry(((source_kind, reference, SourcePlan("MIXED", layout)),))
    return registry, reference


def main():
    parser = argparse.ArgumentParser(description="Verify one development payload, without executing it")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("family_id")
    parser.add_argument("payload", type=Path)
    args = parser.parse_args()
    try:
        with args.payload.open("rb") as source:
            raw = source.read(65537)
        report = verify_material(load_unique_json(args.manifest), args.family_id, raw)
    except (ValueError, TypeError, KeyError, OSError):
        print(json.dumps({"material_valid": False, "error": "material_contract_check_failed",
                          "experiment_authorized": False}))
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
