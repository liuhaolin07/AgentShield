"""Immutable objective contracts shared by actual and fixture clients."""
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parent/'datasets/v1.10'
def load_live_tasks():
    raw=(ROOT/'live-tasks.json').read_bytes(); metadata=json.loads((ROOT/'live-manifest.json').read_text())
    if len(raw)>65536 or hashlib.sha256(raw).hexdigest()!=metadata['sha256']: raise ValueError('live_contract_integrity_mismatch')
    dataset=json.loads(raw)
    if len(dataset['cases'])!=metadata['tasks'] or dataset['dataset_version']!=metadata['dataset_version']: raise ValueError('live_contract_version_mismatch')
    return dataset
