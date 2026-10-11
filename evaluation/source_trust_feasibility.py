"""Analytic design audit only: no sampling, policy execution or budget approval."""
from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
import gzip
import hashlib
import io
import json
import math
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'docs/research/source-trust-methods/r4'
R3_COMMIT = '962390e6ea2c75b93534356dcef2110335da4742'
VERSION = 'source-trust-analytic-feasibility-1'
KIND = 'ANALYTIC_DESIGN_BOUND_NOT_POWER_OR_DEFENSE'
INPUTS = (
    'docs/research/source-trust/protocol-draft.json',
    'docs/research/source-trust-methods/r3/joint-calibration-config.json',
    'docs/research/source-trust-methods/r3/joint-calibration/trials.csv.gz',
    'evaluation/source_trust_statistics.py',
    'evaluation/source_trust_joint.py',
)


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


@dataclass(frozen=True)
class Contract:
    alpha: float
    multiplicity: int
    minimum_tcr: float
    ni_margin: float
    safety_reduction: float
    grid: tuple[float, ...]

    def validate(self) -> None:
        require(type(self.alpha) in (int, float) and math.isfinite(self.alpha) and 0 < self.alpha < 1, 'alpha')
        require(type(self.multiplicity) is int and 1 <= self.multiplicity <= 10000, 'multiplicity')
        require(all(type(v) in (int, float) and math.isfinite(v) and 0 < v < 1
                    for v in (self.minimum_tcr, self.ni_margin, self.safety_reduction)), 'thresholds')
        require(len(self.grid) == 6 and self.grid[0] == 0 and self.grid[-1] == 1
                and all(type(v) in (int, float) and math.isfinite(v) for v in self.grid)
                and all(a < b for a, b in zip(self.grid, self.grid[1:])), 'six_point_grid')


def read_inputs() -> tuple[Contract, dict[str, bytes]]:
    frozen = json.loads((BASE / 'frozen-r3.json').read_text())
    require(frozen['commit'] == R3_COMMIT and frozen['file_count'] == 409, 'R3_identity')
    inputs = {}
    for name in INPUTS:
        path = ROOT / name
        require(path.stat().st_size <= 8 * 1024 * 1024, 'input_limit')
        raw = path.read_bytes()
        require(hashlib.sha256(raw).hexdigest() == frozen['tracked_files_sha256'][name], 'frozen_input:' + name)
        inputs[name] = raw
    protocol = json.loads(inputs[INPUTS[0]])
    h5 = next(h for h in protocol['hypotheses'] if h['id'] == 'H5')
    contract = Contract(protocol['inference']['familywise_alpha'], protocol['inference']['first_phase_statistic_count'],
                        h5['minimum_TCR'], h5['TCR_noninferiority_margin'], h5['minimum_ASR_AUC_reduction'],
                        tuple(protocol['design']['rates']))
    contract.validate()
    for prefix in ('delta_TCR_p=', 'TCR_conservative_p='):
        require(list(contract.grid) == sorted(float(k.split('=', 1)[1]) for k in h5['statistics'] if k.startswith(prefix)), 'R1_H5_points')
    config = json.loads(inputs[INPUTS[1]])
    require(config['alpha'] == contract.alpha and config['multiplicity'] == contract.multiplicity
            and config['estimand']['grid'] == list(contract.grid)
            and config['threshold_status'] == 'NOT_JUSTIFIED_BY_TASK_OWNER', 'R3_contract')
    return contract, inputs


def radius(graphs: int, value_range: float, contract: Contract) -> float:
    contract.validate()
    require(type(graphs) is int and 1 <= graphs <= 10**12, 'analytic_graph_count')
    require(type(value_range) in (int, float) and math.isfinite(value_range) and 0 < value_range <= 2, 'known_range')
    return value_range * math.sqrt(math.log(2 * contract.multiplicity / contract.alpha) / (2 * graphs))


def minimum_graphs(gap: float, value_range: float, contract: Contract, *, strict: bool = False) -> int | None:
    """Center-bound crossing, not a power estimate or approved sample size.

    A nonpositive gap cannot cross at any finite n. Tiny positive gaps outside
    the bounded numerical domain are refused, never reported as impossible.
    """
    contract.validate()
    require(type(gap) in (int, float) and math.isfinite(gap) and -2 <= gap <= 2, 'gap')
    radius(1, value_range, contract)
    if gap <= 0:
        return None
    require(gap >= 1e-5, 'gap_below_numeric_domain')
    real_n = value_range**2 * math.log(2 * contract.multiplicity / contract.alpha) / (2 * gap**2)
    require(real_n <= 10**12, 'analytic_count_limit')
    n = max(1, math.floor(real_n) + 1 if strict else math.ceil(real_n))
    # Verify the integer crossing using the actual inequality, not ceil alone.
    def passes(k: int) -> bool:
        r = radius(k, value_range, contract)
        return r < gap if strict else r <= gap
    if not passes(n):
        n += 1
    if n > 1 and passes(n - 1):
        n -= 1
    require(passes(n) and (n == 1 or not passes(n - 1)), 'integer_boundary')
    return n


def best_tcr_lower(graphs: int, missing_fraction: float, contract: Contract) -> float:
    require(type(missing_fraction) in (int, float) and math.isfinite(missing_fraction)
            and 0 <= missing_fraction <= 1, 'missing_fraction')
    return max(0., 1 - missing_fraction - radius(graphs, 1., contract))


def frozen_truth(raw_gzip: bytes) -> list[float]:
    with gzip.GzipFile(fileobj=io.BytesIO(raw_gzip)) as handle:
        data = handle.read(8 * 1024 * 1024 + 1)
    require(len(data) <= 8 * 1024 * 1024, 'decompressed_truth_limit')
    rows = csv.DictReader(io.StringIO(data.decode()))
    row = next(r for r in rows if r['scenario'] == 'beneficial_complete' and r['graphs'] == '30')
    truth = json.loads(row['true_vector'])
    require(len(truth) == 13 and all(type(v) in (int, float) and math.isfinite(v) for v in truth), 'retained_truth_vector')
    return truth


def build_report() -> dict[str, Any]:
    contract, inputs = read_inputs()
    budgets = []
    for graphs in (5, 30, 81, 82, 120):
        lower = best_tcr_lower(graphs, 0., contract)
        budgets.append({'independent_graphs_per_nonzero_point': graphs, 'half_width': radius(graphs, 1., contract),
                        'maximum_absolute_TCR_lower': lower, 'absolute_TCR_mathematically_possible': lower >= contract.minimum_tcr,
                        'joint_status': 'NOT_RULED_OUT_BY_THIS_COMPONENT_NOT_A_POWER_CLAIM' if lower >= contract.minimum_tcr
                        else 'MATHEMATICALLY_IMPOSSIBLE_UNDER_GHO1'})
    missing = []
    for fraction in (0., .03, .05, .20):
        required = minimum_graphs(1 - fraction - contract.minimum_tcr, 1., contract)
        missing.append({'observed_C_missing_fraction_at_one_point': fraction,
                        'minimum_graphs_for_best_case_absolute_TCR': required,
                        'status': 'NECESSARY_COMPONENT_BOUND_NOT_APPROVED_BUDGET' if required is not None
                        else 'NO_FINITE_GHO1_BOUND_CROSSING'})
    truth = frozen_truth(inputs[INPUTS[2]])
    centered = []
    for index, point in enumerate(contract.grid[1:], 1):
        centered.append({'rate': point, 'true_delta_TCR': truth[1 + index], 'true_absolute_TCR': truth[7 + index],
                         'graphs_for_expected_center_absolute_bound': minimum_graphs(truth[7 + index] - contract.minimum_tcr, 1., contract),
                         'graphs_for_expected_center_NI_bound_strict': minimum_graphs(truth[1 + index] + contract.ni_margin, 2., contract, strict=True),
                         'kind': 'INTERVAL_AT_RETAINED_TOY_MEAN_NOT_POWER_OR_REQUIRED_REAL_SAMPLE_SIZE'})
    return {'version': VERSION, 'kind': KIND, 'frozen_R3_commit': R3_COMMIT,
            'contract': {'alpha': contract.alpha, 'multiplicity': contract.multiplicity, 'minimum_TCR': contract.minimum_tcr,
                         'NI_margin': contract.ni_margin, 'safety_reduction': contract.safety_reduction, 'grid': list(contract.grid)},
            'input_sha256': {name: hashlib.sha256(raw).hexdigest() for name, raw in inputs.items()},
            'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'best_case_budgets': budgets, 'missingness_bounds': missing, 'retained_toy_center_diagnostics': centered,
            'minimum_best_case_component_graphs': minimum_graphs(1 - contract.minimum_tcr, 1., contract),
            'current_R3_calibration_budgets': [5, 30], 'current_budget_joint_confirmation_mathematically_impossible': True,
            'new_study_simulation_trials': 0, 'new_Agent_experiment_rows': 0, 'pilot_executions': 0,
            'holdout_executions': 0, 'model_requests': 0, 'approved_new_graph_budget': False,
            'power_and_error_control_of_alternative_estimators': 'UNRUN_NOT_SELECTED',
            'status': 'NOT_READY_FOR_PREREGISTRATION_OR_PILOT',
            'scope': ['Fixed GHO-1 construction only, not impossibility of inference in general',
                      'A best-case single-component crossing is not a sufficient joint-power condition',
                      'Increasing Monte Carlo trials, families, task repetitions or bootstrap draws does not change graph n',
                      'IID graph validity still needs review; width calculations do not establish coverage under dependent graphs',
                      '82 independent graphs per point differs from 81 total conditions in a planning manifest',
                      'Retained toy means are historical hypothetical truth, not estimated real-policy effects']}


def export(report: dict[str, Any], output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    (output / 'report.json').write_text(json.dumps(report, indent=2, allow_nan=False) + '\n')
    for name, rows in (('budget-bounds', report['best_case_budgets']), ('missing-bounds', report['missingness_bounds']),
                       ('toy-center-diagnostics', report['retained_toy_center_diagnostics'])):
        with (output / (name + '.csv')).open('w', newline='') as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    report = build_report()
    export(report, args.output_dir)
    print(json.dumps({'kind': KIND, 'minimum_best_case_component_graphs': report['minimum_best_case_component_graphs'],
                      'current_budget_joint_confirmation_mathematically_impossible': True,
                      'new_study_simulation_trials': 0, 'approved_new_graph_budget': False}))


if __name__ == '__main__':
    main()
