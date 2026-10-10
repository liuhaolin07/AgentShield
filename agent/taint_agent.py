"""Deterministic explicit-flow agent using the same guarded runtime in all arms."""

from dataclasses import dataclass
from typing import Any

from security.runtime import GuardedRuntime, RuntimeResult
from security.taint import (TaintError, TaintedValue, base64_decode, base64_encode, concat,
                            get_item, json_deserialize, json_serialize, make_dict, make_list,
                            mark_lost, slice_value, url_decode, url_encode)


SUPPORTED_OPERATIONS = frozenset({"base64_encode", "base64_decode", "url_encode", "url_decode",
                                  "slice_rejoin", "nested_json", "json_roundtrip", "segmented_encode",
                                  "mix", "metadata_loss", "unwrap"})


def apply_operations(value: TaintedValue, operations: list[dict[str, Any]],
                     observe=None) -> TaintedValue | str:
    if len(operations) > 16:
        raise TaintError("Operation budget exceeded")
    notify = observe or (lambda *args, **kwargs: None)
    for operation in operations:
        if not isinstance(value, TaintedValue):
            raise TaintError("Raw escaped data cannot undergo tracked operations")
        name = operation["op"]
        if name not in SUPPORTED_OPERATIONS:
            raise TaintError("Unsupported operation")
        if name in {"base64_encode", "base64_decode", "url_encode", "url_decode"}:
            transform = {"base64_encode": base64_encode, "base64_decode": base64_decode,
                         "url_encode": url_encode, "url_decode": url_decode}[name]
            value = transform(value)
        elif name in {"slice_rejoin", "segmented_encode"}:
            text = value.reveal()
            cuts = operation["cuts"]
            if (not isinstance(text, str) or not isinstance(cuts, list) or len(cuts) > 16 or
                    not all(type(cut) is int and 0 < cut < len(text) for cut in cuts) or cuts != sorted(set(cuts))):
                raise TaintError("Invalid segment specification")
            endpoints = [0, *cuts, len(text)]
            segments = [slice_value(value, endpoints[i], endpoints[i + 1]) for i in range(len(endpoints) - 1)]
            if name == "segmented_encode":
                pieces = []
                for index, segment in enumerate(segments):
                    if index:
                        pieces.append(TaintedValue.literal("."))
                    pieces.append(base64_encode(segment))
                value = concat(*pieces)
            else:
                value = concat(*segments)
        elif name == "nested_json":
            value = json_serialize(make_dict({"envelope": make_list([make_dict({"value": value})])}))
        elif name == "json_roundtrip":
            value = get_item(json_deserialize(json_serialize(make_dict({"value": value}))), "value")
        elif name == "mix":
            value = concat(TaintedValue.literal(operation["prefix"]), value, TaintedValue.literal(operation["suffix"]))
        elif name == "metadata_loss":
            value = mark_lost(value)
        elif name == "unwrap":
            value = value.reveal()
        notify("explicit_operation", operation=name,
               source_ids=list(value.source_ids) if isinstance(value, TaintedValue) else [],
               tracking=value.tracking if isinstance(value, TaintedValue) else "untracked",
               provenance_ids=[record.record_id for record in value.provenance] if isinstance(value, TaintedValue) else [])
    return value


@dataclass(frozen=True)
class ExplicitAgentResult:
    source_executed: bool
    completed: bool
    outbound: RuntimeResult | None


class TaintAgent:
    def __init__(self, runtime: GuardedRuntime) -> None:
        self.runtime = runtime

    def run(self, *, path: str, operations: list[dict[str, Any]], url: str,
            sink: str = "http", tool_source: str | None = None) -> ExplicitAgentResult:
        # Tool fixtures are still actual file reads approved by the same gate.
        read = self.runtime.read(path)
        if not read.executed or read.error or read.value is None:
            return ExplicitAgentResult(read.executed, False, None)
        value = read.value
        if tool_source:
            value = self.runtime.tool_output(tool_source, lambda: value.reveal(), reference=path, parent=value)
        value = apply_operations(value, operations, self.runtime.observe)
        if sink == "model":
            # Preserve an explicit escape as untracked rather than relabeling it.
            if isinstance(value, TaintedValue):
                value = json_serialize(make_dict({"messages": [{"role": "tool", "content": value}]}))
            else:
                import json
                value = json.dumps({"messages": [{"role": "tool", "content": value}]},
                                   ensure_ascii=False, separators=(",", ":"))
        outbound = self.runtime.send(url, value, sink=sink)
        completed = outbound.executed and outbound.error is None and outbound.receipt is not None
        return ExplicitAgentResult(True, completed, outbound)
