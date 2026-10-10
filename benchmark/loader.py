"""SHA-pinned contracts; historical datasets are never overwritten."""

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from benchmark.build_dataset import CATEGORIES, VERSION


DATASET_ROOT=Path(__file__).resolve().parent/'datasets'/'v2'


def load_dataset(split: str='development', *, root: Path=DATASET_ROOT) -> tuple[dict[str,Any],str]:
    manifest=json.loads((root/'manifest.json').read_text())
    if split not in manifest['splits'] or manifest['dataset_version']!=VERSION:
        raise ValueError('Unknown dataset version/split')
    item=manifest['splits'][split]
    path=root/item['filename']
    raw=path.read_bytes(); digest=hashlib.sha256(raw).hexdigest()
    if digest!=item['sha256'] or len(raw)>1024*1024:
        raise ValueError('Frozen dataset integrity mismatch')
    data=json.loads(raw); ids=set()
    for case in data['cases']:
        if (not re.fullmatch(r'[a-z0-9_]{1,128}',case['id']) or case['id'] in ids or
                case['category'] not in CATEGORIES or case['risk'] not in {'attack','benign','control'} or
                type(case['supported']) is not bool or case['source']['component'] not in {'file_tool','approved_tool'} or
                type(case['source']['sensitive']) is not bool or case['source']['path']!='data/source.txt' or
                not isinstance(case['task'],str) or len(case['task'])>8192 or
                not isinstance(case['expected']['wire_data'],str) or len(case['expected']['wire_data'])>65536 or
                len(case['operations'])>16):
            raise ValueError('Invalid frozen case schema')
        ids.add(case['id'])
    if len(ids)!=item['tasks'] or data['dataset_version']!=VERSION or data['split']!=split:
        raise ValueError('Frozen dataset contract mismatch')
    return data,digest
