"""Independent frozen-file and statistical CSV checks, not security efficacy."""
from __future__ import annotations
import argparse
import csv
import gzip
import hashlib
import io
import json
import math
from pathlib import Path
import re
import subprocess

ROOT = Path('docs/research/source-trust-methods')
LIMIT = 16*1024*1024


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)


def load_gzip(path: Path) -> bytes:
    with gzip.open(path, 'rb') as handle:
        data = handle.read(LIMIT+1)
    require(len(data) <= LIMIT, 'decompressed_input_limit')
    return data


def freeze_check(root: Path = ROOT) -> int:
    manifest = json.loads((root/'frozen-pr6.json').read_text())
    require(manifest['commit'] == 'b631d1c17c6d1125d4ffc9969f5e794926c49681', 'pr6_identity')
    files = manifest['tracked_files_sha256']
    require(len(files) == 266, 'freeze_count')
    for name, expected in files.items():
        require(hashlib.sha256(Path(name).read_bytes()).hexdigest() == expected, 'frozen_file_changed:'+name)
    return len(files)


def boolean(text: str) -> bool:
    require(text in ('True', 'False'), 'csv_boolean')
    return text == 'True'


def validate_calibration(report: dict, rows: list[dict]) -> dict:
    require(report['kind'] == 'STATISTICAL_SIMULATION_NOT_DEFENSE', 'not_defense')
    require(all(report[k] == 0 for k in ('actual_defense_executions', 'receiver_observations', 'model_requests')), 'no_execution_claim')
    require(report['full_joint_H5_power']['status'] == 'UNRUN', 'joint_power_not_observed')
    config = report['config']
    require(config['threshold_status'] == 'NOT_JUSTIFIED_BY_TASK_OWNER', 'value_basis_pending')
    expected_cells = {(f, g, s, m) for f in config['families'] for g in config['graphs']
                      for s in config['scenarios'] for m in ('family_percentile', 'graph_percentile', 'graph_hoeffding')}
    require(len(rows) == len(expected_cells)*config['trials'] == report['simulation_rows'], 'row_count')
    cells, identities = {}, set()
    for row in rows:
        require(row['kind'] == report['kind'], 'row_kind')
        key = (int(row['families']), int(row['graphs']), row['scenario'], row['method'])
        identity = (*key, int(row['trial']))
        require(key in expected_cells and identity not in identities and 0 <= identity[-1] < config['trials'], 'unique_trial_cell')
        identities.add(identity)
        truth, estimate, low, high = (float(row[k]) for k in ('true_mean', 'estimate', 'ci_low', 'ci_high'))
        require(all(math.isfinite(v) for v in (truth, estimate, low, high)) and low <= high, 'finite_interval')
        if key[2] in ('uniform_quota', 'template_block_quota'):
            # Independent analytic integral on the frozen six-point grid.
            grid = (0., .01, .05, .1, .25, .5)
            n = key[0]*10
            rates = [math.floor(p*n)/n for p in grid]
            analytic = -.5*sum((grid[i+1]-grid[i])*(rates[i]+rates[i+1]) for i in range(5))
            criterion = 'H5_safety_component_ONLY'
        else:
            require(key[2] in ('rare_global_fault', 'balanced_global_fault'), 'known_response')
            analytic = .025 if key[2] == 'rare_global_fault' else 0.
            criterion = 'H4_equivalence_component_ONLY'
        require(abs(truth-analytic) < 1e-12 and row['criterion'] == criterion, 'analytic_truth_or_criterion')
        require(boolean(row['covered']) == (low-1e-12 <= truth <= high+1e-12), 'coverage_recomputed')
        require(boolean(row['degenerate']) == (abs(high-low) < 1e-12), 'degeneracy_recomputed')
        resolved = key[3] == 'graph_hoeffding' or config['bootstrap_draws']*config['alpha']/(2*config['multiplicity']) >= 20
        require(boolean(row['adjusted_tail_resolved']) == resolved, 'tail_resolution')
        if resolved:
            a, b = float(row['adjusted_low']), float(row['adjusted_high'])
            require(a <= b and math.isfinite(a) and math.isfinite(b), 'adjusted_interval')
            passed = b < -.05 if criterion.startswith('H5') else -.02 < a <= b < .02
            require(boolean(row['component_gate_pass']) == passed, 'gate_recomputed')
        else:
            require(all(row[k] == '' for k in ('adjusted_low', 'adjusted_high', 'component_gate_pass')), 'unresolved_gate_excluded')
        cells.setdefault(key, []).append(row)
    require(set(cells) == expected_cells, 'complete_cells')
    summary_keys = set()
    for summary in report['summary']:
        key = (summary['families'], summary['graphs'], summary['scenario'], summary['method'])
        require(key in cells and key not in summary_keys, 'unique_summary')
        summary_keys.add(key)
        cell = cells[key]
        observed = [r for r in cell if r['component_gate_pass'] != '']
        count_checks = {'coverage_numerator': sum(boolean(r['covered']) for r in cell), 'coverage_denominator': len(cell),
                        'degenerate_numerator': sum(boolean(r['degenerate']) for r in cell), 'degenerate_denominator': len(cell),
                        'component_gate_numerator': sum(boolean(r['component_gate_pass']) for r in observed),
                        'component_gate_denominator': len(observed), 'component_excluded': len(cell)-len(observed)}
        require(all(summary[k] == v for k, v in count_checks.items()), 'summary_counts')
        require(abs(summary['coverage']-count_checks['coverage_numerator']/len(cell)) < 1e-12, 'summary_coverage')
        width = sum(float(r['ci_high'])-float(r['ci_low']) for r in cell)/len(cell)
        require(abs(summary['mean_width']-width) < 1e-12, 'summary_width')
        require(summary['component_status'] == ('MEASURED_TOY_ONLY' if observed else 'UNRUN_insufficient_adjusted_tail_resolution'), 'exclusions_status')
    require(summary_keys == expected_cells, 'complete_summary')
    return {'kind': 'STATISTICAL_CONSISTENCY_GATE_NOT_SECURITY_TEST', 'validated_simulation_rows': len(rows),
            'cells': len(cells), 'actual_defense_executions': 0, 'full_joint_H5_power': 'UNRUN'}


def validate_artifacts(root: Path = ROOT) -> dict:
    base = root/'statistical-calibration'
    report_blob = load_gzip(base/'report.json.gz')
    report = json.loads(report_blob)
    provenance = json.loads((base/'provenance.json').read_text())
    require(report['kind'] == provenance['kind'] == 'STATISTICAL_SIMULATION_NOT_DEFENSE', 'provenance_kind')
    for name in ('report.json', 'summary.csv', 'trials.csv'):
        blob = load_gzip(base/(name+'.gz'))
        require(hashlib.sha256(blob).hexdigest() == provenance['files'][name], 'raw_file_hash')
    config_blob = json.dumps(report['config'], sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()
    require(hashlib.sha256(config_blob).hexdigest() == report['config_sha256'] == provenance['config_sha256'], 'frozen_config_identity')
    require(json.loads((root/'statistical-calibration-config.json').read_text()) == report['config'], 'config_changed')
    commit = provenance['generation_commit']
    require(re.fullmatch('[0-9a-f]{40}', commit) is not None, 'generation_commit')
    code = subprocess.check_output(['git', 'show', commit+':evaluation/source_trust_statistics.py'])
    require(hashlib.sha256(code).hexdigest() == report['source_sha256'] == provenance['generation_source_sha256'], 'generation_git_object')
    rows = list(csv.DictReader(io.StringIO(load_gzip(base/'trials.csv.gz').decode())))
    return validate_calibration(report, rows)


def readiness_check(root: Path = ROOT) -> dict:
    packet = json.loads((root/'readiness.json').read_text())
    require(packet['status'] == 'NOT_READY_FOR_PREREGISTRATION_OR_PILOT', 'still_pending')
    require(packet['pilot']['status'] == packet['holdout']['status'] == 'UNRUN', 'no_pilot_or_holdout_claim')
    require(not packet['holdout']['material_acquired'], 'no_holdout_intake')
    require(all(packet['pilot'][k] == 0 for k in ('executions', 'receiver_observations', 'model_requests')), 'zero_pilot_executions')
    require(all(packet[k] == 0 for k in ('actual_human_annotators', 'actual_human_arbitrators', 'actual_independent_auditors')), 'no_invented_humans')
    return {'pilot': 'UNRUN', 'holdout': 'UNRUN', 'human_truth_verified': False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    print(json.dumps({'frozen_pr6_files': freeze_check(), 'calibration': validate_artifacts(), 'readiness': readiness_check()}, sort_keys=True))


if __name__ == '__main__':
    main()
