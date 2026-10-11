"""Independent analytic-inequality and full R3 Git-object gate; no engine imports."""
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
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'docs/research/source-trust-methods/r4'
R3 = '962390e6ea2c75b93534356dcef2110335da4742'
KIND = 'ANALYTIC_DESIGN_BOUND_NOT_POWER_OR_DEFENSE'


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def frozen_r3_check() -> int:
    frozen = json.loads((BASE / 'frozen-r3.json').read_text())
    require(frozen['commit'] == R3, 'R3_commit')
    names = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', R3], cwd=ROOT, text=True).splitlines()
    require(set(names) == set(frozen['tracked_files_sha256']) and len(names) == frozen['file_count'] == 409, 'complete_R3_freeze')
    for name, digest in frozen['tracked_files_sha256'].items():
        original = subprocess.check_output(['git', 'show', R3 + ':' + name], cwd=ROOT)
        require(hashlib.sha256(original).hexdigest() == digest == hashlib.sha256((ROOT / name).read_bytes()).hexdigest(),
                'R3_git_object_or_current_changed:' + name)
    return len(names)


def validate(report: dict[str, Any]) -> dict[str, Any]:
    require(report['kind'] == KIND and report['version'] == 'source-trust-analytic-feasibility-1'
            and report['frozen_R3_commit'] == R3, 'analytic_identity')
    require(all(type(report[k]) is int and report[k] == 0 for k in
                ('new_study_simulation_trials', 'new_Agent_experiment_rows', 'pilot_executions', 'holdout_executions', 'model_requests')),
            'no_simulation_or_execution_claim')
    require(report['approved_new_graph_budget'] is False
            and report['status'] == 'NOT_READY_FOR_PREREGISTRATION_OR_PILOT'
            and report['power_and_error_control_of_alternative_estimators'] == 'UNRUN_NOT_SELECTED', 'no_power_or_approval_claim')
    protocol_name = 'docs/research/source-trust/protocol-draft.json'
    original = subprocess.check_output(['git', 'show', R3 + ':' + protocol_name], cwd=ROOT)
    require(hashlib.sha256(original).hexdigest() == report['input_sha256'][protocol_name], 'external_R1_identity')
    protocol = json.loads(original)
    h5 = next(h for h in protocol['hypotheses'] if h['id'] == 'H5')
    alpha = protocol['inference']['familywise_alpha']; m = protocol['inference']['first_phase_statistic_count']
    threshold = h5['minimum_TCR']; grid = protocol['design']['rates']
    expected_contract = {'alpha': alpha, 'multiplicity': m, 'minimum_TCR': threshold,
                         'NI_margin': h5['TCR_noninferiority_margin'], 'safety_reduction': h5['minimum_ASR_AUC_reduction'], 'grid': grid}
    require(report['contract'] == expected_contract, 'unchanged_R1_thresholds_and_grid')
    log_term = math.log(2 * m / alpha)
    def half_width(n: int, width: float = 1.) -> float:
        return width * math.sqrt(log_term / (2 * n))
    def near(a: float, b: float) -> bool:
        return type(a) in (int, float) and math.isfinite(a) and abs(a - b) < 1e-12
    # Find crossings by a bounded integer scan, independently of the engine's
    # inverted formula. The largest reviewed center crossing is <3000.
    def crossing(gap: float, width: float, strict: bool = False) -> int | None:
        if gap <= 0:
            return None
        for n in range(1, 10001):
            if half_width(n, width) < gap if strict else half_width(n, width) <= gap:
                return n
        raise ValueError('independent_search_limit')
    expected_budgets = (5, 30, 81, 82, 120)
    require(len(report['best_case_budgets']) == len(expected_budgets), 'complete_budget_rows')
    for row, n in zip(report['best_case_budgets'], expected_budgets):
        lower = max(0., 1 - half_width(n))
        possible = lower >= threshold
        require(row['independent_graphs_per_nonzero_point'] == n and near(row['half_width'], half_width(n))
                and near(row['maximum_absolute_TCR_lower'], lower), 'best_case_bounds')
        require(row['absolute_TCR_mathematically_possible'] is possible
                and row['joint_status'] == ('NOT_RULED_OUT_BY_THIS_COMPONENT_NOT_A_POWER_CLAIM' if possible
                                           else 'MATHEMATICALLY_IMPOSSIBLE_UNDER_GHO1'), 'component_is_not_joint_power')
    require(report['minimum_best_case_component_graphs'] == crossing(1 - threshold, 1.) == 82
            and report['current_R3_calibration_budgets'] == [5, 30]
            and report['current_budget_joint_confirmation_mathematically_impossible'] is True, 'current_budget_impossibility')
    require(len(report['missingness_bounds']) == 4, 'complete_missingness_rows')
    for row, q in zip(report['missingness_bounds'], (0., .03, .05, .20)):
        expected_n = crossing(1 - q - threshold, 1.)
        require(row['observed_C_missing_fraction_at_one_point'] == q
                and row['minimum_graphs_for_best_case_absolute_TCR'] == expected_n, 'missingness_crossing')
        require(row['status'] == ('NECESSARY_COMPONENT_BOUND_NOT_APPROVED_BUDGET' if expected_n is not None
                                 else 'NO_FINITE_GHO1_BOUND_CROSSING'), 'missingness_not_budget')
    truth_name = 'docs/research/source-trust-methods/r3/joint-calibration/trials.csv.gz'
    with gzip.GzipFile(fileobj=io.BytesIO(subprocess.check_output(['git', 'show', R3 + ':' + truth_name], cwd=ROOT))) as handle:
        raw = handle.read(8 * 1024 * 1024 + 1)
    require(len(raw) <= 8 * 1024 * 1024, 'decompression_limit')
    record = next(r for r in csv.DictReader(io.StringIO(raw.decode()))
                  if r['scenario'] == 'beneficial_complete' and r['graphs'] == '30')
    truth = json.loads(record['true_vector'])
    require(len(report['retained_toy_center_diagnostics']) == 5, 'complete_center_rows')
    for index, (row, point) in enumerate(zip(report['retained_toy_center_diagnostics'], grid[1:]), 1):
        require(row['rate'] == point and near(row['true_delta_TCR'], truth[1 + index])
                and near(row['true_absolute_TCR'], truth[7 + index]), 'retained_mean_not_new_effect')
        require(row['graphs_for_expected_center_absolute_bound'] == crossing(truth[7 + index] - threshold, 1.)
                and row['graphs_for_expected_center_NI_bound_strict'] == crossing(truth[1 + index] + h5['TCR_noninferiority_margin'], 2., True),
                'center_crossing')
        require(row['kind'] == 'INTERVAL_AT_RETAINED_TOY_MEAN_NOT_POWER_OR_REQUIRED_REAL_SAMPLE_SIZE', 'centering_not_power')
    return {'kind': 'ANALYTIC_CONSISTENCY_NOT_STATISTICAL_VALIDATION', 'minimum_component_graphs': 82,
            'current_GHO1_budgets_impossible': [5, 30], 'new_study_simulation_trials': 0,
            'pilot_eligible': False, 'power_and_error_control_of_alternatives': 'UNRUN'}


def validate_artifacts() -> dict[str, Any]:
    base = BASE / 'analytic'
    provenance = json.loads((base / 'provenance.json').read_text())
    require(provenance['kind'] == KIND and provenance['approved_new_graph_budget'] is False
            and all(provenance[k] == 0 for k in ('new_study_simulation_trials', 'pilot_executions', 'holdout_executions')), 'provenance_scope')
    expected_files = {'report.json', 'budget-bounds.csv', 'missing-bounds.csv', 'toy-center-diagnostics.csv'}
    require(set(provenance['files']) == expected_files, 'complete_export_set')
    for name, digest in provenance['files'].items():
        require(hashlib.sha256((base / name).read_bytes()).hexdigest() == digest, 'export_hash')
    report = json.loads((base / 'report.json').read_text())
    commit = provenance['generation_commit']
    require(re.fullmatch('[0-9a-f]{40}', commit) is not None, 'generation_commit')
    source = subprocess.check_output(['git', 'show', commit + ':evaluation/source_trust_feasibility.py'], cwd=ROOT)
    require(hashlib.sha256(source).hexdigest() == report['source_sha256'], 'generation_source_object')
    expected_inputs = {'docs/research/source-trust/protocol-draft.json',
                       'docs/research/source-trust-methods/r3/joint-calibration-config.json',
                       'docs/research/source-trust-methods/r3/joint-calibration/trials.csv.gz',
                       'evaluation/source_trust_statistics.py', 'evaluation/source_trust_joint.py'}
    require(set(report['input_sha256']) == expected_inputs, 'complete_input_binding')
    for name, digest in report['input_sha256'].items():
        require(hashlib.sha256(subprocess.check_output(['git', 'show', R3 + ':' + name], cwd=ROOT)).hexdigest() == digest,
                'R3_input_git_object')
    verdict = validate(report)
    # Independently require CSV exports to have the same complete rows/types.
    for name, key in (('budget-bounds.csv', 'best_case_budgets'), ('missing-bounds.csv', 'missingness_bounds'),
                      ('toy-center-diagnostics.csv', 'retained_toy_center_diagnostics')):
        expected = report[key]
        rows = list(csv.DictReader(io.StringIO((base / name).read_text())))
        require(rows == [{k: '' if v is None else str(v) for k, v in row.items()} for row in expected], 'CSV_report_consistency')
    verdict['unchanged_R3_files'] = frozen_r3_check()
    return verdict


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    print(json.dumps(validate_artifacts()))


if __name__ == '__main__':
    main()
