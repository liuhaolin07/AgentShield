"""Runtime-owned attestations for explicit values, not a Python process sandbox.

Untrusted callers receive handles, never an issuer or raw confidential data.
Only trusted adapters mint sources; supported transforms are replay-verified.
The per-session HMAC key and registry must stay on the trusted side of the port.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import asdict, dataclass, field
from typing import Any

from security.taint import (
    MAX_CHARS, TaintError, TaintedValue, base64_decode, base64_encode, concat,
    get_item, json_deserialize, json_serialize, make_dict, make_list,
    slice_value, url_decode, url_encode,
)


MAX_HANDLES = 512
MAX_REGISTRY_BYTES = 8 * 1024 * 1024
MAX_CHAIN = 128
MAX_PARENTS = 32
_COMPONENTS = {"file_tool": "file", "approved_tool": "tool", "model_tool": "model"}
_HEX = re.compile(r"[0-9a-f]{64}\Z")
TRANSFORMS = frozenset({"base64_encode", "base64_decode", "url_encode", "url_decode",
                        "slice", "concat", "list", "dict", "get_item", "json_encode",
                        "json_decode", "nested_json", "json_roundtrip", "slice_rejoin",
                        "segmented_encode", "mix", "checkpoint", "json_escape"})


class IntegrityError(TaintError):
    """A sanitized integrity rejection. Its reason never contains input data."""


@dataclass(frozen=True)
class ValueHandle:
    runtime_id: str
    value_id: str
    provenance_id: str
    source_hash: str
    seal: str = field(repr=False)

    @classmethod
    def from_wire(cls, value: Any) -> ValueHandle:
        if (not isinstance(value, dict) or set(value) != set(cls.__dataclass_fields__) or
                not all(isinstance(v, str) and _HEX.fullmatch(v) for v in value.values())):
            raise IntegrityError("integrity_invalid_handle")
        return cls(**value)

    def to_wire(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class IntegrityDecision:
    allowed: bool
    reason: str
    runtime_id: str
    provenance_ids: tuple[str, ...] = ()
    source_ids: tuple[str, ...] = ()

    def explain(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class _Entry:
    handle: ValueHandle
    value: TaintedValue = field(repr=False)
    operation: str
    parents: tuple[ValueHandle, ...]
    parameters_json: str
    charged_bytes: int


def _canonical(value: Any) -> bytes:
    try:
        data = json.dumps(value, sort_keys=True, ensure_ascii=False,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise IntegrityError("integrity_invalid_structure") from error
    if len(data) > 1024 * 1024:
        raise IntegrityError("integrity_structure_budget")
    return data


def _snapshot(value: TaintedValue) -> dict[str, Any]:
    labels = [{"source": asdict(label.source), "sensitive": label.sensitive,
               "allowed": sorted((t.kind, t.destination) for t in label.allowed_targets),
               "forbidden": sorted((t.kind, t.destination) for t in label.forbidden_targets)}
              for label in value.labels]
    return {"data": value.reveal(), "labels": labels, "tracking": value.tracking,
            "provenance": [asdict(record) for record in value.provenance]}


def _transform(operation: str, values: tuple[TaintedValue, ...], params: dict[str, Any]) -> TaintedValue:
    if operation not in TRANSFORMS or not 1 <= len(values) <= MAX_PARENTS:
        raise IntegrityError("integrity_unauthorized_transform")
    expected_keys = {"slice": {"start", "stop", "step"}, "dict": {"keys"},
                     "get_item": {"key"}, "mix": {"prefix", "suffix"},
                     "slice_rejoin": {"cuts"}, "segmented_encode": {"cuts"}}.get(operation, set())
    if set(params) - expected_keys:
        raise IntegrityError("integrity_invalid_parameters")
    if operation not in {"concat", "list", "dict"} and len(values) != 1:
        raise IntegrityError("integrity_invalid_arity")
    first = values[0]
    unary = {"base64_encode": base64_encode, "base64_decode": base64_decode,
             "url_encode": url_encode, "url_decode": url_decode,
             "json_encode": json_serialize, "json_decode": json_deserialize,
             "json_escape": json_serialize}
    if operation in unary:
        return unary[operation](first)
    if operation == "concat":
        return concat(*values)
    if operation == "slice":
        return slice_value(first, **params)
    if operation == "list":
        return make_list(list(values))
    if operation == "dict":
        keys = params.get("keys")
        if (not isinstance(keys, list) or len(keys) != len(values) or
                not all(isinstance(k, str) and len(k) <= 1024 for k in keys) or len(set(keys)) != len(keys)):
            raise IntegrityError("integrity_invalid_parameters")
        return make_dict(dict(zip(keys, values)))
    if operation == "get_item":
        return get_item(first, params.get("key"))
    if operation == "nested_json":
        return json_serialize(make_dict({"envelope": make_list([make_dict({"value": first})])}))
    if operation == "json_roundtrip":
        return get_item(json_deserialize(json_serialize(make_dict({"value": first}))), "value")
    if operation == "checkpoint":
        # Runtime-owned intermediate storage keeps the original labels.
        return get_item(make_list([first]), 0)
    if operation == "mix":
        prefix, suffix = params.get("prefix", ""), params.get("suffix", "")
        if not isinstance(prefix, str) or not isinstance(suffix, str) or len(prefix) + len(suffix) > MAX_CHARS:
            raise IntegrityError("integrity_invalid_parameters")
        return concat(TaintedValue.literal(prefix), first, TaintedValue.literal(suffix))
    text, cuts = first.reveal(), params.get("cuts")
    if (not isinstance(text, str) or not isinstance(cuts, list) or len(cuts) > 16 or
            any(type(c) is not int or not 0 < c < len(text) for c in cuts) or cuts != sorted(set(cuts))):
        raise IntegrityError("integrity_invalid_parameters")
    bounds = [0, *cuts, len(text)]
    pieces = [slice_value(first, bounds[i], bounds[i + 1]) for i in range(len(bounds) - 1)]
    if operation == "segmented_encode":
        joined = []
        for index, piece in enumerate(pieces):
            if index:
                joined.append(TaintedValue.literal("."))
            joined.append(base64_encode(piece))
        pieces = joined
    return concat(*pieces)


class _SourceAuthority:
    """Trusted runtime implementation detail; never handed to agent logic."""

    def __init__(self, *, source_only: bool = False, verify_integrity: bool = True) -> None:
        self.runtime_id = secrets.token_hex(32)
        self._key = secrets.token_bytes(32)
        self._entries: dict[str, _Entry] = {}
        self._charged_bytes = 0
        self.source_only = source_only  # Explicit research ablation, never a default.
        self.verify_integrity = verify_integrity

    def _mac(self, domain: str, value: Any) -> str:
        return hmac.new(self._key, domain.encode() + b"\0" + _canonical(value), hashlib.sha256).hexdigest()

    def _body(self, entry: _Entry) -> dict[str, Any]:
        return {"runtime": self.runtime_id, "id": entry.handle.value_id,
                "provenance": entry.handle.provenance_id, "source_hash": entry.handle.source_hash,
                "operation": entry.operation, "parents": [h.to_wire() for h in entry.parents],
                "parameters": entry.parameters_json, "source_only": self.source_only,
                "snapshot": _snapshot(entry.value)}

    def _issue(self, value: TaintedValue, operation: str, parents: tuple[ValueHandle, ...],
               parameters: dict[str, Any]) -> ValueHandle:
        parameters_json = _canonical(parameters).decode()
        source_hash = self._mac("source", {"sources": list(value.source_ids),
                                          "parents": [p.source_hash for p in parents],
                                          "root": _snapshot(value) if operation in _COMPONENTS else None})
        value_id = secrets.token_hex(32)
        provenance_id = self._mac("provenance", [operation, [p.provenance_id for p in parents],
                                                parameters_json, source_hash, _snapshot(value)])
        provisional = ValueHandle(self.runtime_id, value_id, provenance_id, source_hash, "")
        entry = _Entry(provisional, value, operation, parents, parameters_json, 0)
        charge = len(_canonical(self._body(entry)))
        if len(self._entries) >= MAX_HANDLES or self._charged_bytes + charge > MAX_REGISTRY_BYTES:
            raise IntegrityError("integrity_registry_budget")
        handle = ValueHandle(self.runtime_id, value_id, provenance_id, source_hash, self._mac("seal", self._body(entry)))
        self._entries[value_id] = _Entry(handle, value, operation, parents, parameters_json, charge)
        self._charged_bytes += charge
        return handle

    def _source(self, component: str, value: TaintedValue, parents: tuple[ValueHandle, ...] = ()) -> ValueHandle:
        if (component not in _COMPONENTS or value.tracking != "tracked" or not value.labels or
                not any(label.source.category == _COMPONENTS[component] for label in value.labels)):
            raise IntegrityError("integrity_untrusted_source")
        if len(parents) > MAX_PARENTS:
            raise IntegrityError("integrity_invalid_arity")
        parent_values = [self.resolve(handle) for handle in parents]
        if any(label not in value.labels for parent in parent_values for label in parent.labels):
            raise IntegrityError("integrity_unauthorized_downgrade")
        return self._issue(value, component, parents, {})

    def transform(self, operation: str, handles: tuple[ValueHandle, ...], parameters: dict[str, Any]) -> ValueHandle:
        if (not isinstance(handles, tuple) or not 1 <= len(handles) <= MAX_PARENTS or
                not isinstance(parameters, dict)):
            raise IntegrityError("integrity_invalid_parameters")
        # Check parameter structure/size before traversing or executing.
        TaintedValue.literal(parameters)
        values = tuple(self.resolve(h) for h in handles)
        value = _transform(operation, values, parameters)
        if self.source_only:
            value = TaintedValue.literal(value.reveal())
        return self._issue(value, operation, handles, parameters)

    def verify(self, handle: Any) -> IntegrityDecision:
        if not self.verify_integrity:
            if type(handle) is not ValueHandle or handle.runtime_id != self.runtime_id or handle.value_id not in self._entries:
                return IntegrityDecision(False, "integrity_invalid_reference", self.runtime_id)
            entry = self._entries[handle.value_id]
            return IntegrityDecision(True, "integrity_not_enabled", self.runtime_id,
                                     (entry.handle.provenance_id,), entry.value.source_ids)
        visited: dict[str, _Entry] = {}
        active: set[str] = set()

        def walk(candidate: Any, depth: int = 0) -> _Entry:
            if (type(candidate) is not ValueHandle or not all(isinstance(v, str) and _HEX.fullmatch(v)
                    for v in (candidate.runtime_id, candidate.value_id, candidate.provenance_id, candidate.source_hash, candidate.seal))):
                raise IntegrityError("integrity_unattested")
            if candidate.runtime_id != self.runtime_id:
                raise IntegrityError("integrity_wrong_runtime")
            entry = self._entries.get(candidate.value_id)
            if entry is None:
                raise IntegrityError("integrity_unissued")
            if candidate != entry.handle or not hmac.compare_digest(candidate.seal, self._mac("seal", self._body(entry))):
                raise IntegrityError("integrity_source_or_seal_mismatch")
            if candidate.value_id in active:
                raise IntegrityError("integrity_cycle")
            if candidate.value_id in visited:
                return entry
            if len(visited) >= MAX_CHAIN or depth >= MAX_CHAIN:
                raise IntegrityError("integrity_chain_budget")
            visited[candidate.value_id] = entry
            active.add(candidate.value_id)
            parent_entries = tuple(walk(parent, depth + 1) for parent in entry.parents)
            if entry.operation not in _COMPONENTS:
                expected = _transform(entry.operation, tuple(p.value for p in parent_entries), json.loads(entry.parameters_json))
                if self.source_only:
                    expected = TaintedValue.literal(expected.reveal())
                if expected != entry.value:
                    raise IntegrityError("integrity_chain_mismatch")
            elif any(label not in entry.value.labels for p in parent_entries for label in p.value.labels):
                raise IntegrityError("integrity_unauthorized_downgrade")
            active.remove(candidate.value_id)
            return entry

        try:
            entry = walk(handle)
        except (IntegrityError, TaintError, ValueError, TypeError, RecursionError, KeyError) as error:
            reason = str(error) if isinstance(error, IntegrityError) else "integrity_invalid_chain"
            return IntegrityDecision(False, reason, self.runtime_id)
        return IntegrityDecision(True, "integrity_verified", self.runtime_id,
                                 tuple(e.handle.provenance_id for e in visited.values()), entry.value.source_ids)

    def resolve(self, handle: Any) -> TaintedValue:
        decision = self.verify(handle)
        if not decision.allowed:
            raise IntegrityError(decision.reason)
        return self._entries[handle.value_id].value

    def explain(self, handle: Any) -> dict[str, Any]:
        decision = self.verify(handle)
        explanation = decision.explain()
        if decision.allowed:
            explanation["sensitive"] = self._entries[handle.value_id].value.sensitive
            explanation["tracking"] = self._entries[handle.value_id].value.tracking
            seen: set[str] = set()
            records = []

            def collect(candidate: ValueHandle) -> None:
                if candidate.value_id in seen:
                    return
                seen.add(candidate.value_id)
                entry = self._entries[candidate.value_id]
                for parent in entry.parents:
                    collect(parent)
                records.append({"provenance_id": candidate.provenance_id, "source_hash": candidate.source_hash,
                                "operation": entry.operation,
                                "parents": [p.provenance_id for p in entry.parents]})

            collect(handle)
            explanation["chain"] = records
        return explanation
