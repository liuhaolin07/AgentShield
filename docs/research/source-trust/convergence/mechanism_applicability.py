"""Pre-outcome scope check for the pinned complete-declaration identity adapter.

This compares label propagation in the frozen code, not ASR/TCR observations.
It neither imports experimental truth nor asserts empirical equivalence.
"""

import json

from material_adapter import compile_declarations, decode_pointer, value_digest
from protocol_amendment import load_effective_protocol
from validate_intake import require


def inspect_identity_pair(family_labels, source_kind, raw, output_path, *, transform_id="identity"):
    from security.precision import source_value, transform
    from security.source_trust_policy import effective_registry

    protocol = load_effective_protocol()
    require(transform_id == "identity", "unsupported_transform_requires_new_scope_analysis")
    registry, reference = compile_declarations(family_labels, source_kind, raw)
    key, source = decode_pointer(output_path), json.loads(raw)
    require(key in source, "output_path_missing")
    signatures = []
    for strategy in ("precision", "conservative"):
        plan = effective_registry(registry, strategy).classify(source_kind, reference)
        require(plan.status == "MIXED" and not plan.layout.ranges
                and not plan.layout.structure_sensitive, "unanalysed_layout")
        require({rule.path for rule in plan.layout.fields} == {(k,) for k in source}, "unanalysed_omission")
        # Both runtime strategies use the same get_item operation with precision
        # enabled; root structure labels and all selected leaf labels participate.
        root = source_value(source, source_kind, reference, plan.layout)
        selected = transform("get_item", (root,), {"key": key})
        signatures.append(sorted((label.source.source_id, label.sensitive) for label in selected.labels))
    require(signatures[0] == signatures[1], "unexpected_mechanism_difference_requires_investigation")
    return {"scope": protocol["design_amendment"]["scope"],
            "state": "STRUCTURAL_NO_CONTRAST", "hypothesis": "H5",
            "interpretation": "MECHANISM_SCOPE_CONTROL_NOT_SUPERIORITY_EVIDENCE",
            "amendment_id": protocol["design_amendment"]["id"],
            "declaration_sha256": value_digest(family_labels),
            "output_path_sha256": value_digest(output_path),
            "source_sha256": family_labels["source_version"], "source_kind": source_kind,
            "empirical_hypothesis_supported": None, "superiority_claim_allowed": False,
            "runtime_equivalence_outside_scope": False}


def require_h5_superiority_design(family_labels, source_kind, raw, output_path, *, transform_id="identity"):
    # Recompute from actual inputs. Never trust a supplied "contrast=true" flag.
    inspect_identity_pair(family_labels, source_kind, raw, output_path, transform_id=transform_id)
    raise ValueError("h5_superiority_inapplicable_to_structural_no_contrast")
