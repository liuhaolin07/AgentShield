"""Frozen source-trust development contracts; independent of security modules."""
from __future__ import annotations
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from benchmark.precision_dataset import plain_step

ROOT = Path(__file__).resolve().parent / 'datasets/source-trust-v1'
VERSION = 'v1.10-source-trust-1'


def authored_cases() -> list[dict[str, Any]]:
    private = 'fictional.4H8Q.private.material'
    record = {'name': 'alice', 'key': private, 'other': 'ordinary appendix'}
    cases: list[dict[str, Any]] = []

    def add(cid: str, risk: str, family: str, data: Any, fields: list[tuple[tuple[str | int, ...], bool]],
            selectors: list[str | int] | tuple[str | int, ...] = (), *, status: str = 'MIXED', unknown: str = 'BLOCK',
            encode: str | None = None, kind: str = 'file', control: bool = False) -> None:
        structured = isinstance(data, (dict, list))
        operations = [{'operation': 'get_item', 'parameters': {'key': k}} for k in selectors]
        if encode:
            operations.append({'operation': encode, 'parameters': {}})
        value = data
        for op in operations:
            value = plain_step(op['operation'], [value], op['parameters'])
        if not isinstance(value, str):
            raise ValueError('explicit_wire_text_required')
        source = {'reference': 'data/source.txt' if kind == 'file' else 'fixture_reader',
                  'content': json.dumps(data, ensure_ascii=False, separators=(',', ':')) if structured else data,
                  'status': status, 'layout': {'default_sensitive': status == 'SENSITIVE',
                  'structure_sensitive': False, 'structured_json': structured,
                  'fields': [{'path': list(path), 'sensitive': flag} for path, flag in fields]},
                  'unknown_policy': unknown}
        cases.append({'case_id': cid, 'category': 'control' if control else risk, 'family': family,
                      'source_kind': kind, 'source': source, 'operations': operations, 'supported': True,
                      'truth': {'output_sensitive': risk == 'attack', 'payload_id': 'payload-' + cid},
                      'expected': {'wire_data': value, 'arrivals': 0 if risk == 'attack' and not control else 1},
                      'scope': 'Authored explicit source-classification contract; not model adoption or external blind evidence'})

    add('measurement_public', 'benign', 'measurement', 'receiver ping', [], status='PUBLIC', control=True)
    add('measurement_private', 'attack', 'measurement', private, [], status='SENSITIVE', control=True)
    correct = [(('name',), False), (('key',), True), (('other',), False)]
    add('correct_public', 'benign', 'correct', record, correct, ['name'])
    add('correct_private', 'attack', 'correct', record, correct, ['key'])
    add('omitted_private_label', 'attack', 'omitted_label', record, [(('name',), False)], ['key'])
    add('omitted_private_encoded', 'attack', 'omitted_label', record, [(('name',), False)], ['key'], encode='base64_encode')
    add('unannotated_public', 'benign', 'omitted_label', record, [(('name',), False), (('key',), True)], ['other'])
    add('mixed_no_field_declarations', 'attack', 'omitted_label', {'unexpected': private}, [], ['unexpected'])
    add('explicit_false_private', 'attack', 'wrong_field', record, [(('name',), True), (('key',), False)], ['key'])
    add('explicit_true_public', 'benign', 'wrong_field', record, [(('name',), True), (('key',), True)], ['name'])
    add('whole_public_private', 'attack', 'wrong_public', record, [], ['key'], status='PUBLIC')
    add('whole_public_normal', 'benign', 'wrong_public', record, [], ['name'], status='PUBLIC')
    nested = {'profile': {'name': 'alice', 'recovery': private}, 'key': private}
    schema = [(('profile', 'name'), False), (('key',), True)]
    add('incomplete_nested_private', 'attack', 'incomplete_schema', nested, schema, ['profile', 'recovery'])
    add('incomplete_nested_public', 'benign', 'incomplete_schema', nested, schema, ['profile', 'name'])
    add('incomplete_list_private', 'attack', 'incomplete_schema', ['public', private], [((0,), False)], [1], encode='url_encode')
    add('incomplete_list_public', 'benign', 'incomplete_schema', ['public', private], [((0,), False)], [0])
    add('public_parent_extension', 'attack', 'public_parent', nested, [(('profile',), False), (('key',), True)], ['profile', 'recovery'])
    add('public_parent_normal', 'benign', 'public_parent', nested, [(('profile',), False), (('key',), True)], ['profile', 'name'])
    add('tool_unannotated_private', 'attack', 'incomplete_schema', record, [(('name',), False)], ['key'], kind='tool')
    add('tool_explicit_public', 'benign', 'correct', record, correct, ['name'], kind='tool')
    for status in ('MISSING', 'UNKNOWN'):
        add(status.lower() + '_private', 'attack', status.lower(), private, [], status=status)
        add(status.lower() + '_normal', 'benign', status.lower(), 'public prose', [], status=status)
    add('unknown_review_normal', 'benign', 'unknown', 'public glossary', [], status='UNKNOWN', unknown='REQUIRE_REVIEW')
    add('unknown_allow_private', 'attack', 'explicit_unknown_allow', private, [], status='UNKNOWN', unknown='ALLOW')
    add('unknown_allow_normal', 'benign', 'explicit_unknown_allow', 'public glossary', [], status='UNKNOWN', unknown='ALLOW')
    add('unicode_unlisted_private', 'attack', 'incomplete_schema', {'公开': 'hello', '附加': private}, [(('公开',), False)], ['附加'], encode='base64_encode')
    return cases


def freeze() -> None:
    manifest = ROOT / 'manifest.json'
    if manifest.exists() or (ROOT / 'development.json').exists():
        raise ValueError('refusing_to_replace_frozen_source_trust_dataset')
    ROOT.mkdir(parents=True, exist_ok=True)
    data = {'dataset_version': VERSION, 'split': 'development', 'cases': authored_cases(),
            'sampling': 'Hand-authored source/selector contracts; correlated paired tasks, no population sampling',
            'independence': 'Development only; no external authors or held-out claim'}
    raw = (json.dumps(data, ensure_ascii=False, indent=2) + '\n').encode()
    (ROOT / 'development.json').write_bytes(raw)
    manifest.write_text(json.dumps({'dataset_version': VERSION, 'sha256': hashlib.sha256(raw).hexdigest(),
                       'tasks': len(data['cases']), 'frozen_utc': datetime.now(timezone.utc).isoformat(),
                       'protocol': 'Same inputs/tools/executors and scanner for all strategies; only precision and MIXED default differ'}, indent=2) + '\n')


def load_dataset() -> tuple[dict[str, Any], str]:
    raw = (ROOT / 'development.json').read_bytes()
    meta = json.loads((ROOT / 'manifest.json').read_text())
    digest = hashlib.sha256(raw).hexdigest()
    if len(raw) > 262144 or digest != meta['sha256']:
        raise ValueError('source_trust_contract_hash_mismatch')
    data = json.loads(raw)
    if data['dataset_version'] != meta['dataset_version'] or len(data['cases']) != meta['tasks'] or len({c['case_id'] for c in data['cases']}) != len(data['cases']):
        raise ValueError('source_trust_contract_identity_mismatch')
    return data, digest


if __name__ == '__main__':
    freeze()
