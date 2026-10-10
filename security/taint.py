"""Explicit, immutable, bounded provenance. No implicit Python flow tracking.

Identifiers describe lineage/operations, not secret content commitments.
Only this module's operations preserve labels. Revealed raw strings escape the
tracking domain; strict sinks reject unwrapped values, not recover their origin.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import quote, unquote, urlsplit


MAX_CHARS = 65536
MAX_NODES = 2048
MAX_DEPTH = 16
MAX_SOURCES = 32
MAX_PROVENANCE = 128
Tracking = Literal["tracked", "lost", "unsupported"]
OPERATIONS = frozenset({"literal", "source", "compose", "concat", "slice", "list", "dict",
                        "dict_item", "list_item", "json_encode", "json_decode", "base64_encode",
                        "base64_decode", "url_encode", "url_decode", "metadata_lost", "unsupported_boundary"})


def _valid_id(value: Any, kind: str) -> bool:
    return isinstance(value, str) and re.fullmatch(kind + r"_[0-9a-f]{64}", value) is not None


class TaintError(ValueError):
    """Invalid operation/metadata or an exhausted explicit-flow budget."""


def _id(kind: str, *parts: Any) -> str:
    encoded = json.dumps([kind, *parts], sort_keys=True, separators=(",", ":")).encode()
    return kind + "_" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class SinkTarget:
    kind: Literal["http", "model"]
    destination: str = "*"

    def __post_init__(self) -> None:
        if self.kind not in {"http", "model"}:
            raise TaintError("Unsupported sink kind")
        if not isinstance(self.destination, str) or len(self.destination) > 2048:
            raise TaintError("Invalid destination")
        if self.destination != "*":
            parsed = urlsplit(self.destination)
            if (parsed.scheme not in {"http", "https"} or not parsed.hostname or
                    parsed.username is not None or parsed.password is not None or
                    parsed.path or parsed.query or parsed.fragment):
                raise TaintError("Targets must be HTTP(S) origins")
            try:
                parsed.port
            except ValueError as error:
                raise TaintError("Invalid target port") from error

    @classmethod
    def from_url(cls, kind: Literal["http", "model"], url: str) -> SinkTarget:
        parsed = urlsplit(url)
        return cls(kind, f"{parsed.scheme}://{parsed.netloc}")

    def matches(self, target: SinkTarget) -> bool:
        return self.kind == target.kind and self.destination in {"*", target.destination}


@dataclass(frozen=True)
class SourceRecord:
    source_id: str
    category: str
    reference_id: str

    def __post_init__(self) -> None:
        if (self.category not in {"file", "tool", "user", "fixture", "model"} or
                not _valid_id(self.source_id, "source") or not _valid_id(self.reference_id, "reference") or
                self.source_id != _id("source", self.category, self.reference_id)):
            raise TaintError("Invalid source metadata")

    @classmethod
    def create(cls, category: str, logical_reference: str) -> SourceRecord:
        if category not in {"file", "tool", "user", "fixture", "model"}:
            raise TaintError("Unsupported source category")
        if not isinstance(logical_reference, str) or not 1 <= len(logical_reference) <= 4096:
            raise TaintError("Invalid source reference")
        reference = _id("reference", logical_reference)
        return cls(_id("source", category, reference), category, reference)


@dataclass(frozen=True)
class TaintLabel:
    source: SourceRecord
    sensitive: bool
    allowed_targets: frozenset[SinkTarget] = frozenset()
    forbidden_targets: frozenset[SinkTarget] = frozenset({SinkTarget("http"), SinkTarget("model")})

    def __post_init__(self) -> None:
        if type(self.sensitive) is not bool or not isinstance(self.source, SourceRecord):
            raise TaintError("Invalid label")
        for targets in (self.allowed_targets, self.forbidden_targets):
            if not isinstance(targets, frozenset) or len(targets) > 32 or not all(isinstance(t, SinkTarget) for t in targets):
                raise TaintError("Target sets must be immutable and bounded")


@dataclass(frozen=True)
class ProvenanceRecord:
    record_id: str
    operation: str
    parents: tuple[str, ...]
    parameters: tuple[tuple[str, int], ...] = ()

    def __post_init__(self) -> None:
        if (self.operation not in OPERATIONS or not isinstance(self.parents, tuple) or len(self.parents) > MAX_NODES or
                not all(_valid_id(parent, "source") or _valid_id(parent, "provenance") for parent in self.parents) or
                not isinstance(self.parameters, tuple) or len(self.parameters) > 3 or
                any(key not in {"start", "stop", "step"} or type(value) is not int or abs(value) > 2**63
                    for key, value in self.parameters) or
                self.record_id != _id("provenance", self.operation, self.parents, self.parameters)):
            raise TaintError("Invalid provenance metadata")

    @classmethod
    def create(cls, operation: str, parents: tuple[str, ...],
               parameters: tuple[tuple[str, int], ...] = ()) -> ProvenanceRecord:
        return cls(_id("provenance", operation, parents, parameters), operation, parents, parameters)


@dataclass(frozen=True)
class FrozenList:
    items: tuple[Any, ...]


@dataclass(frozen=True)
class FrozenDict:
    items: tuple[tuple[str, Any], ...]


class _Freezer:
    def __init__(self) -> None:
        self.nodes = self.chars = 0
        self.parents: list[TaintedValue] = []

    def freeze(self, value: Any, depth: int = 0) -> Any:
        self.nodes += 1
        if self.nodes > MAX_NODES or depth > MAX_DEPTH:
            raise TaintError("Value structure budget exceeded")
        if isinstance(value, TaintedValue):
            self.parents.append(value)
            return self.freeze(value.value, depth)
        if isinstance(value, str):
            self.chars += len(value)
            if self.chars > MAX_CHARS:
                raise TaintError("Value character budget exceeded")
            return value
        if value is None or type(value) in {bool, int}:
            if type(value) is int and value.bit_length() > 4096:
                raise TaintError("Integer budget exceeded")
            return value
        if type(value) is float and math.isfinite(value):
            return value
        if isinstance(value, (list, tuple, FrozenList)):
            items = value.items if isinstance(value, FrozenList) else value
            return FrozenList(tuple(self.freeze(item, depth + 1) for item in items))
        if isinstance(value, (dict, FrozenDict)):
            items = value.items if isinstance(value, FrozenDict) else value.items()
            pairs = []
            for key, item in items:
                if not isinstance(key, str):
                    raise TaintError("Dictionary keys must be plain strings")
                self.freeze(key, depth + 1)
                pairs.append((key, self.freeze(item, depth + 1)))
            return FrozenDict(tuple(pairs))
        raise TaintError("Unsupported value type")


def _reveal(value: Any) -> Any:
    if isinstance(value, FrozenList):
        return [_reveal(item) for item in value.items]
    if isinstance(value, FrozenDict):
        return {key: _reveal(item) for key, item in value.items}
    return value


@dataclass(frozen=True)
class TaintedValue:
    value: Any = field(repr=False)
    labels: tuple[TaintLabel, ...] = ()
    provenance: tuple[ProvenanceRecord, ...] = ()
    tracking: Tracking = "tracked"

    def __post_init__(self) -> None:
        if (not isinstance(self.labels, tuple) or not isinstance(self.provenance, tuple) or
                len(self.labels) > MAX_SOURCES or len(self.provenance) > MAX_PROVENANCE or
                not all(isinstance(label, TaintLabel) for label in self.labels) or
                not all(isinstance(record, ProvenanceRecord) for record in self.provenance) or
                self.tracking not in {"tracked", "lost", "unsupported"}):
            raise TaintError("Invalid or oversized metadata")
        freezer = _Freezer()
        frozen = freezer.freeze(self.value)
        if freezer.parents:
            raise TaintError("Use explicit list/dict composition for nested labeled values")
        object.__setattr__(self, "value", frozen)

    @property
    def sensitive(self) -> bool:
        return any(label.sensitive for label in self.labels)

    @property
    def source_ids(self) -> tuple[str, ...]:
        return tuple(sorted({label.source.source_id for label in self.labels}))

    def reveal(self) -> Any:
        """Explicit escape hatch. Returned raw data has no tracking metadata."""
        return _reveal(self.value)

    @classmethod
    def literal(cls, value: Any) -> TaintedValue:
        """Trusted non-sensitive ingress, not an inference about an arbitrary string."""
        freezer = _Freezer()
        frozen = freezer.freeze(value)
        if freezer.parents:
            return _derive(frozen, tuple(freezer.parents), "compose")
        return cls(frozen, provenance=(ProvenanceRecord.create("literal", ()),))

    @classmethod
    def from_source(cls, value: Any, source: SourceRecord, *, sensitive: bool,
                    allowed_targets: frozenset[SinkTarget] = frozenset(),
                    forbidden_targets: frozenset[SinkTarget] | None = None) -> TaintedValue:
        label = TaintLabel(source, sensitive, allowed_targets,
                           TaintLabel.__dataclass_fields__["forbidden_targets"].default
                           if forbidden_targets is None else forbidden_targets)
        return cls(value, (label,), (ProvenanceRecord.create("source", (source.source_id,)),))


def _derive(value: Any, parents: tuple[TaintedValue, ...], operation: str,
            parameters: tuple[tuple[str, int], ...] = (), tracking: Tracking | None = None) -> TaintedValue:
    labels = tuple(dict.fromkeys(label for parent in parents for label in parent.labels))
    records = tuple(dict.fromkeys(record for parent in parents for record in parent.provenance))
    if any(not parent.provenance for parent in parents):
        state: Tracking = "lost"
    elif any(parent.tracking == "lost" for parent in parents):
        state = "lost"
    elif any(parent.tracking == "unsupported" for parent in parents):
        state = "unsupported"
    else:
        state = tracking or "tracked"
    record = ProvenanceRecord.create(operation, tuple(parent.provenance[-1].record_id
                                                     for parent in parents if parent.provenance), parameters)
    return TaintedValue(value, labels, (*records, record), state)


def _text(value: TaintedValue) -> str:
    if not isinstance(value, TaintedValue) or not isinstance(value.value, str):
        raise TaintError("Operation requires labeled text")
    return value.value


def concat(*values: TaintedValue) -> TaintedValue:
    if not values or len(values) > MAX_NODES:
        raise TaintError("Invalid concatenation arity")
    texts = [_text(value) for value in values]
    if sum(map(len, texts)) > MAX_CHARS:
        raise TaintError("Concatenation character budget exceeded")
    return _derive("".join(texts), values, "concat")


def slice_value(value: TaintedValue, start: int | None = None,
                stop: int | None = None, step: int | None = None) -> TaintedValue:
    for index in (start, stop, step):
        if index is not None and (type(index) is not int or abs(index) > 2**63):
            raise TaintError("Invalid slice index")
    if step == 0:
        raise TaintError("Slice step cannot be zero")
    parameters = tuple((key, number) for key, number in (("start", start), ("stop", stop), ("step", step))
                       if number is not None)
    return _derive(_text(value)[start:stop:step], (value,), "slice", parameters)


def make_list(values: list[Any] | tuple[Any, ...]) -> TaintedValue:
    if not isinstance(values, (list, tuple)):
        raise TaintError("List composition requires a list/tuple")
    freezer = _Freezer()
    frozen = freezer.freeze(values)
    return _derive(frozen, tuple(freezer.parents), "list")


def make_dict(values: dict[str, Any]) -> TaintedValue:
    if not isinstance(values, dict):
        raise TaintError("Dictionary composition requires a dictionary")
    freezer = _Freezer()
    frozen = freezer.freeze(values)
    return _derive(frozen, tuple(freezer.parents), "dict")


def get_item(value: TaintedValue, key: str | int) -> TaintedValue:
    if isinstance(value.value, FrozenDict) and isinstance(key, str):
        for name, item in value.value.items:
            if name == key:
                return _derive(item, (value,), "dict_item")
        raise TaintError("Dictionary item missing")
    if isinstance(value.value, FrozenList) and type(key) is int:
        try:
            return _derive(value.value.items[key], (value,), "list_item")
        except IndexError as error:
            raise TaintError("List index out of range") from error
    raise TaintError("Unsupported item access")


def json_serialize(value: TaintedValue) -> TaintedValue:
    return _derive(json.dumps(value.reveal(), ensure_ascii=False, separators=(",", ":")),
                   (value,), "json_encode")


def json_deserialize(value: TaintedValue) -> TaintedValue:
    text = _text(value)
    # Bound nesting before invoking the standard decoder; do not parse integers
    # that could consume unbounded conversion work.
    quoted = escaped = False
    depth = separators = 0
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise TaintError("JSON depth budget exceeded")
        elif char in "}]":
            depth -= 1
        elif char in ",:":
            separators += 1
            if separators > MAX_NODES:
                raise TaintError("JSON node budget exceeded")
    def parse_integer(number: str) -> int:
        if len(number) > 1234:
            raise TaintError("JSON integer budget exceeded")
        return int(number)

    def parse_float(number: str) -> float:
        if len(number) > 128:
            raise TaintError("JSON float budget exceeded")
        return float(number)

    def reject_constant(_: str) -> Any:
        raise TaintError("Nonfinite JSON")

    try:
        decoded = json.loads(text, parse_int=parse_integer, parse_float=parse_float, parse_constant=reject_constant)
    except (ValueError, RecursionError) as error:
        raise TaintError("Invalid or oversized JSON") from error
    return _derive(decoded, (value,), "json_decode")


def base64_encode(value: TaintedValue) -> TaintedValue:
    text = _text(value)
    data = text.encode("utf-8")
    if 4 * ((len(data) + 2) // 3) > MAX_CHARS:
        raise TaintError("Base64 output budget exceeded")
    return _derive(base64.b64encode(data).decode(), (value,), "base64_encode")


def base64_decode(value: TaintedValue) -> TaintedValue:
    try:
        decoded = base64.b64decode(_text(value), validate=True).decode("utf-8")
    except (ValueError, binascii.Error, UnicodeError) as error:
        raise TaintError("Invalid UTF-8 Base64") from error
    return _derive(decoded, (value,), "base64_decode")


def url_encode(value: TaintedValue) -> TaintedValue:
    return _derive(quote(_text(value), safe=""), (value,), "url_encode")


def url_decode(value: TaintedValue) -> TaintedValue:
    try:
        decoded = unquote(_text(value), encoding="utf-8", errors="strict")
    except UnicodeError as error:
        raise TaintError("Invalid UTF-8 URL encoding") from error
    return _derive(decoded, (value,), "url_decode")


def mark_lost(value: TaintedValue) -> TaintedValue:
    return _derive(value.value, (value,), "metadata_lost", tracking="lost")


def mark_unsupported(value: TaintedValue) -> TaintedValue:
    """Record an unsupported boundary without pretending to execute a transform."""
    return _derive(value.value, (value,), "unsupported_boundary", tracking="unsupported")


@dataclass(frozen=True)
class TaintPolicy:
    require_tracked: bool = True

    def __post_init__(self) -> None:
        if type(self.require_tracked) is not bool:
            raise TaintError("require_tracked must be boolean")


@dataclass(frozen=True)
class TaintDecision:
    allowed: bool
    reason: str
    sensitive: bool
    tracking: str
    source_ids: tuple[str, ...] = ()
    blocked_source_ids: tuple[str, ...] = ()
    provenance: tuple[ProvenanceRecord, ...] = ()
    sources: tuple[SourceRecord, ...] = ()

    def explain(self) -> dict[str, Any]:
        return {"allowed": self.allowed, "reason": self.reason, "sensitive": self.sensitive,
                "tracking": self.tracking, "source_ids": list(self.source_ids),
                "blocked_source_ids": list(self.blocked_source_ids),
                "sources": [{"source_id": source.source_id, "category": source.category,
                             "reference_id": source.reference_id} for source in self.sources],
                "provenance": [{"id": record.record_id, "operation": record.operation,
                                "parents": list(record.parents), "parameters": dict(record.parameters)}
                               for record in self.provenance]}


def decide_taint(value: Any, target: SinkTarget, policy: TaintPolicy = TaintPolicy()) -> TaintDecision:
    if not isinstance(value, TaintedValue):
        return TaintDecision(not policy.require_tracked, "taint_untracked", False, "untracked")
    if not value.provenance or value.tracking != "tracked":
        reason = "taint_unsupported" if value.tracking == "unsupported" else "taint_metadata_lost"
        return TaintDecision(False, reason, value.sensitive, value.tracking,
                             value.source_ids, provenance=value.provenance,
                             sources=tuple(dict.fromkeys(label.source for label in value.labels)))
    blocked = []
    for label in value.labels:
        if not label.sensitive:
            continue
        denied = any(rule.matches(target) for rule in label.forbidden_targets)
        allowed = any(rule.matches(target) for rule in label.allowed_targets)
        if denied or not allowed:
            blocked.append(label.source.source_id)
    return TaintDecision(not blocked, "taint_sensitive_source" if blocked else "taint_allowed",
                         value.sensitive, value.tracking, value.source_ids,
                         tuple(sorted(set(blocked))), value.provenance,
                         tuple(dict.fromkeys(label.source for label in value.labels)))
