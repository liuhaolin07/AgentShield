"""Explicit flow semantics, conservative propagation and bounded metadata."""

import dataclasses
import json
import unittest

from security.taint import (MAX_CHARS, MAX_PROVENANCE, FrozenDict, SourceRecord,
                            ProvenanceRecord, SinkTarget, TaintError, TaintPolicy, TaintedValue,
                            base64_decode, base64_encode, concat, decide_taint, get_item,
                            json_deserialize, json_serialize, make_dict, make_list,
                            mark_lost, mark_unsupported, slice_value, url_decode, url_encode)
from security.scanner import inspect_sensitive


class TaintTests(unittest.TestCase):
    def setUp(self):
        self.raw = "orchard notes / synthetic confidential material"
        self.source = SourceRecord.create("file", "data/private-notes.txt")
        self.value = TaintedValue.from_source(self.raw, self.source, sensitive=True)
        self.sink = SinkTarget("http", "http://127.0.0.1:8765")

    def assertSensitive(self, value):
        self.assertTrue(value.sensitive)
        self.assertEqual(value.source_ids, (self.source.source_id,))
        self.assertFalse(decide_taint(value, self.sink).allowed)

    def test_unknown_format_is_source_sensitive_without_scanner_match(self):
        self.assertFalse(inspect_sensitive(self.raw).blocked)
        self.assertSensitive(self.value)

    def test_slice_rejoin_keeps_source_and_data(self):
        joined = concat(slice_value(self.value, 0, 9), slice_value(self.value, 9))
        self.assertEqual(joined.reveal(), self.raw)
        self.assertSensitive(joined)
        self.assertEqual(joined.provenance[-1].operation, "concat")
        self.assertSensitive(slice_value(self.value, 0, 0))
        self.assertSensitive(slice_value(self.value, step=-1))

    def test_encoding_roundtrips_keep_sources_and_transform_order(self):
        for encode, decode, name in ((base64_encode, base64_decode, "base64_encode"),
                                     (url_encode, url_decode, "url_encode")):
            with self.subTest(encoding=name):
                encoded = encode(self.value)
                self.assertSensitive(encoded)
                self.assertFalse(inspect_sensitive(encoded.reveal()).blocked)
                result = decode(encoded)
                self.assertEqual(result.reveal(), self.raw)
                self.assertSensitive(result)
                self.assertEqual(result.provenance[-2].operation, name)

    def test_json_list_dictionary_roundtrip_and_item_access(self):
        composed = make_dict({"envelope": make_list([make_dict({"value": self.value, "count": 2})])})
        restored = json_deserialize(json_serialize(composed))
        extracted = get_item(get_item(get_item(restored, "envelope"), 0), "value")
        self.assertEqual(extracted.reveal(), self.raw)
        self.assertSensitive(extracted)
        self.assertEqual(restored.reveal(), {"envelope": [{"value": self.raw, "count": 2}]})

    def test_json_preserves_aggregate_labels_with_duplicate_fields(self):
        text = TaintedValue.from_source('{"item":"private","item":"public"}', self.source, sensitive=True)
        result = get_item(json_deserialize(text), "item")
        self.assertEqual(result.reveal(), "public")
        self.assertSensitive(result)

    def test_mixed_sources_union_and_restrictive_permissions(self):
        other = SourceRecord.create("tool", "tool-output-1")
        public = TaintedValue.from_source("public", other, sensitive=False)
        mixed = concat(public, self.value)
        self.assertEqual(set(mixed.source_ids), {other.source_id, self.source.source_id})
        decision = decide_taint(mixed, self.sink)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.blocked_source_ids, (self.source.source_id,))

    def test_target_allowlist_is_specific_and_deny_overrides(self):
        scoped = TaintedValue.from_source(self.raw, self.source, sensitive=True,
                                          allowed_targets=frozenset({self.sink}), forbidden_targets=frozenset())
        self.assertTrue(decide_taint(scoped, self.sink).allowed)
        self.assertFalse(decide_taint(scoped, SinkTarget("model", self.sink.destination)).allowed)
        self.assertFalse(decide_taint(scoped, SinkTarget("http", "http://127.0.0.1:8766")).allowed)
        denied = TaintedValue.from_source(self.raw, self.source, sensitive=True, allowed_targets=frozenset({self.sink}))
        self.assertFalse(decide_taint(denied, self.sink).allowed)
        self.assertFalse(decide_taint(concat(scoped, denied), self.sink).allowed)

    def test_public_sources_and_trusted_literals_can_flow(self):
        for value in (TaintedValue.literal(self.raw), TaintedValue.from_source(self.raw, self.source, sensitive=False)):
            self.assertTrue(decide_taint(base64_encode(value), self.sink).allowed)
            self.assertFalse(value.sensitive)

    def test_mutable_inputs_are_copied_and_reveal_cannot_mutate_value(self):
        source = {"items": ["one"]}
        value = TaintedValue.literal(source)
        source["items"].append("two")
        revealed = value.reveal()
        revealed["items"].append("three")
        self.assertEqual(value.reveal(), {"items": ["one"]})
        self.assertIsInstance(value.value, FrozenDict)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            value.tracking = "lost"

    def test_literal_composition_cannot_drop_nested_labels(self):
        self.assertSensitive(TaintedValue.literal({"value": self.value}))
        with self.assertRaises(TaintError):
            TaintedValue({"value": self.value})

    def test_lost_and_unsupported_states_are_sticky(self):
        for value, reason in ((mark_lost(self.value), "taint_metadata_lost"),
                              (mark_unsupported(self.value), "taint_unsupported")):
            for transformed in (value, base64_encode(value), concat(value, TaintedValue.literal("normal"))):
                with self.subTest(reason=reason):
                    decision = decide_taint(transformed, self.sink)
                    self.assertFalse(decision.allowed)
                    self.assertEqual(decision.reason, reason)
                    self.assertTrue(transformed.sensitive)

    def test_unwrapped_values_are_explicitly_untracked(self):
        raw = self.value.reveal()
        decision = decide_taint(raw, self.sink)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.tracking, "untracked")
        self.assertEqual(decision.source_ids, ())
        self.assertTrue(decide_taint(raw, self.sink, TaintPolicy(require_tracked=False)).allowed)
        self.assertFalse(decide_taint(TaintedValue(raw), self.sink).allowed)

    def test_stable_ids_depend_on_logical_source_and_operation_not_values(self):
        again = TaintedValue.from_source("different content", SourceRecord.create("file", "data/private-notes.txt"), sensitive=True)
        self.assertEqual(again.source_ids, self.value.source_ids)
        self.assertEqual(base64_encode(again).provenance, base64_encode(self.value).provenance)
        self.assertNotEqual(slice_value(again, 0, 3).provenance, slice_value(again, 0, 4).provenance)
        self.assertNotEqual(SourceRecord.create("tool", "data/private-notes.txt").source_id, self.source.source_id)

    def test_explanation_contains_lineage_but_no_data_or_source_path(self):
        explanation = decide_taint(base64_encode(self.value), self.sink).explain()
        serialized = json.dumps(explanation)
        self.assertNotIn(self.raw, serialized)
        self.assertNotIn("private-notes.txt", serialized)
        self.assertNotIn(base64_encode(self.value).reveal(), serialized)
        self.assertIn(self.source.source_id, serialized)
        self.assertEqual(explanation["provenance"][-1]["operation"], "base64_encode")
        self.assertNotIn(self.raw, repr(self.value))

    def test_value_and_graph_budgets(self):
        for factory in (lambda: TaintedValue.literal("x" * (MAX_CHARS + 1)),
                        lambda: TaintedValue.literal([0] * 2049),
                        lambda: base64_encode(TaintedValue.literal("x" * 60000)),
                        lambda: json_deserialize(TaintedValue.literal("[" * 1000 + "]" * 1000)),
                        lambda: json_deserialize(TaintedValue.literal("9" * 10000))):
            with self.assertRaises(TaintError):
                factory()
        value = self.value
        with self.assertRaises(TaintError):
            for _ in range(MAX_PROVENANCE):
                value = slice_value(value)

    def test_invalid_operations_and_untrusted_metadata(self):
        for factory in (lambda: base64_decode(TaintedValue.literal("not base64!")),
                        lambda: json_deserialize(TaintedValue.literal("NaN")),
                        lambda: make_dict({1: "value"}),
                        lambda: slice_value(self.value, step=0),
                        lambda: concat(self.value, "raw"),
                        lambda: SourceRecord("raw-secret", "file", "raw-path"),
                        lambda: ProvenanceRecord("raw-secret", "arbitrary operation", ()),
                        lambda: SinkTarget("http", "https://user:fake@example.invalid"),
                        lambda: TaintPolicy(require_tracked="yes")):
            with self.assertRaises(TaintError):
                factory()


if __name__ == "__main__":
    unittest.main()
