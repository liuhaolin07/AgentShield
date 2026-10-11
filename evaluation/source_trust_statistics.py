"""Bounded offline statistical calibration; NEVER AgentShield defense results.

The cohort is fixed. Columns are independent global corruption graphs; rows
are fixed source families. Graph resampling keeps every row of a graph together.
Toy responses have analytic means. No tools, models, sockets or holdout inputs.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import platform
import random
import statistics
import sys
from typing import Sequence

VERSION = "source-trust-statistical-calibration-2"
# Keep the old independent streams so only the estimand changes in paired reruns.
RNG_VERSION = "source-trust-statistical-calibration-1"
PROTOCOL_PATH = Path(__file__).resolve().parents[1]/"docs/research/source-trust/protocol-draft.json"
PROTOCOL_SHA256 = "21468cf426f4b6aa0fd0671704fe38ea3442d0be45820a21b07092e0960b7d04"


def h5_binding() -> dict:
    blob = PROTOCOL_PATH.read_bytes()
    if len(blob) > 65536 or hashlib.sha256(blob).hexdigest() != PROTOCOL_SHA256:
        raise ValueError("frozen_R1_protocol_changed")
    protocol = json.loads(blob)
    grid = protocol["design"]["rates"]
    h5 = next(h for h in protocol["hypotheses"] if h["id"] == "H5")
    delta_points = sorted(float(v.split("=", 1)[1]) for v in h5["statistics"] if v.startswith("delta_TCR_p="))
    absolute_points = sorted(float(v.split("=", 1)[1]) for v in h5["statistics"] if v.startswith("TCR_conservative_p="))
    if len(grid) != 6 or grid != delta_points or grid != absolute_points or grid[0] != 0 or grid[-1] != 1:
        raise ValueError("R1_H5_grid_and_TCR_points_disagree")
    return {"hypothesis": "H5", "protocol_path": "docs/research/source-trust/protocol-draft.json",
            "protocol_sha256": PROTOCOL_SHA256, "grid": grid, "integration_domain": [grid[0], grid[-1]],
            "normalization_width": grid[-1]-grid[0], "scope": "toy_safety_component_only"}


GRID = tuple(h5_binding()["grid"])
SCENARIOS = ("uniform_quota", "template_block_quota", "rare_global_fault", "balanced_global_fault")
METHODS = ("family_percentile", "graph_percentile", "graph_hoeffding")


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def validate_config(config: dict) -> None:
    require(config.get("version") == VERSION, "config_version")
    require(config.get("estimand") == h5_binding() and tuple(config["estimand"]["grid"]) == GRID, "R1_H5_estimand_binding")
    require(config.get("kind") == "STATISTICAL_SIMULATION_NOT_DEFENSE", "simulation_only")
    require(type(config.get("seed")) is int and 0 <= config["seed"] < 2**32, "seed")
    require(type(config.get("trials")) is int and 20 <= config["trials"] <= 1000, "trials")
    require(type(config.get("bootstrap_draws")) is int and 100 <= config["bootstrap_draws"] <= 20000, "bootstrap_draws")
    for key, upper in (("families", 120), ("graphs", 120)):
        values = config.get(key)
        require(type(values) is list and 1 <= len(values) <= 3 and len(values) == len(set(values))
                and all(type(v) is int and 2 <= v <= upper for v in values), key)
    require(all(v % 2 == 0 for v in config["families"]), "paired_template_families")
    require(config.get("scenarios") == list(SCENARIOS), "frozen_toy_response_models")
    require(config.get("alpha") == .05 and config.get("multiplicity") == 17, "frozen_interval_parameters")
    require(config.get("thresholds") == {"safety_improvement": .05, "tcr_noninferiority": .05,
                                         "absolute_tcr": .8, "equivalence": .02}, "candidate_thresholds")
    require(config.get("threshold_status") == "NOT_JUSTIFIED_BY_TASK_OWNER", "no_fabricated_value_basis")
    work = config["trials"] * config["bootstrap_draws"] * (sum(config["families"])*len(config["graphs"]) + sum(config["graphs"])*len(config["families"])) * len(SCENARIOS)
    require(work <= 300_000_000, "simulation_work_budget")


def auc(values: Sequence[float]) -> float:
    require(len(values) == len(GRID), "auc_grid")
    return sum((GRID[j+1]-GRID[j])*(values[j]+values[j+1])/2 for j in range(len(GRID)-1)) / GRID[-1]


def toy_matrix(scenario: str, families: int, graphs: int, rng: random.Random) -> tuple[list[list[float]], float, tuple[float, float]]:
    """Return family x graph responses, analytic mean, known response range.

    Quota cases use ten leaves/family and one task-dependent sensitive leaf.
    Only even-numbered families are susceptible in this hypothetical response.
    Each graph has one order shared by all six corruption rates (nested quotas).
    No actual AgentShield strategy is evaluated by this response model.
    """
    require(scenario in SCENARIOS and type(families) is int and families >= 2 and families % 2 == 0
            and type(graphs) is int and graphs >= 2 and families*graphs <= 14400, "toy_dimensions")
    matrix = [[] for _ in range(families)]
    if scenario.endswith("quota"):
        total = families * 10
        # E[Y_i(p)] = -floor(p*N)/N for susceptible families, zero otherwise.
        truth = -.5 * auc([math.floor(p*total)/total for p in GRID])
        for _ in range(graphs):
            if scenario == "uniform_quota":
                order = list(range(total))
                rng.shuffle(order)
            else:
                # Each block contains two source families from one template.
                blocks = [list(range(i, i+20)) for i in range(0, total, 20)]
                rng.shuffle(blocks)
                for block in blocks:
                    rng.shuffle(block)
                order = [leaf for block in blocks for leaf in block]
            rank = {leaf: i for i, leaf in enumerate(order)}
            for family in range(families):
                curve = [-float(rank[family*10] < math.floor(p*total)) if family % 2 == 0 else 0. for p in GRID]
                matrix[family].append(auc(curve))
        return matrix, truth, (-.5, 0.)  # Whole-graph mean has at most half susceptible families.
    for _ in range(graphs):
        r = rng.random()
        if scenario == "rare_global_fault":
            value = .5 if r < .05 else 0.
        else:
            value = .5 if r < .05 else (-.5 if r < .10 else 0.)
        for family in matrix:
            family.append(value)
    return (matrix, .025, (0., .5)) if scenario == "rare_global_fault" else (matrix, 0., (-.5, .5))


def quantile(values: Sequence[float], p: float) -> float:
    require(bool(values) and 0 <= p <= 1, "quantile_input")
    ordered = sorted(values)
    at = (len(ordered)-1)*p
    lo = math.floor(at)
    hi = math.ceil(at)
    return ordered[lo] + (ordered[hi]-ordered[lo])*(at-lo)


def bootstrap_means(matrix: list[list[float]], *, unit: str, draws: int, rng: random.Random,
                    template_block: bool = False) -> list[float]:
    require(unit in ("graph", "family") and 100 <= draws <= 20000, "bootstrap_input")
    require(bool(matrix) and bool(matrix[0]) and all(len(row) == len(matrix[0]) for row in matrix), "rectangular_matrix")
    require(all(math.isfinite(v) for row in matrix for v in row), "finite_observations")
    if unit == "graph":
        # Do not independently resample graph seeds within each source family.
        observations = [statistics.fmean(column) for column in zip(*matrix)]
    else:
        observations = [statistics.fmean(row) for row in matrix]
        if template_block:
            require(len(observations) % 2 == 0, "template_blocks")
            observations = [statistics.fmean(observations[i:i+2]) for i in range(0, len(observations), 2)]
    n = len(observations)
    return [sum(observations[rng.randrange(n)] for _ in range(n))/n for _ in range(draws)]


def hoeffding_interval(mean: float, graphs: int, bounds: tuple[float, float], alpha: float, multiplicity: int = 1) -> tuple[float, float]:
    require(type(graphs) is int and graphs >= 1 and 0 < alpha < 1 and type(multiplicity) is int and multiplicity >= 1, "interval_parameters")
    low, high = bounds
    require(math.isfinite(mean) and math.isfinite(low) and math.isfinite(high) and low <= mean <= high and low < high, "known_graph_summary_range")
    width = (high-low)*math.sqrt(math.log(2*multiplicity/alpha)/(2*graphs))
    return max(low, mean-width), min(high, mean+width)


def wilson(successes: int, trials: int) -> tuple[float, float]:
    require(type(successes) is int and type(trials) is int and 0 <= successes <= trials and trials > 0, "mc_counts")
    z = 1.959963984540054
    p = successes/trials
    denominator = 1+z*z/trials
    middle = (p+z*z/(2*trials))/denominator
    radius = z*math.sqrt(p*(1-p)/trials+z*z/(4*trials*trials))/denominator
    return max(0., middle-radius), min(1., middle+radius)


def run(config: dict) -> tuple[dict, list[dict]]:
    validate_config(config)
    rows, summaries = [], []
    for families in config["families"]:
        for graphs in config["graphs"]:
            for scenario in SCENARIOS:
                for trial in range(config["trials"]):
                    # Cell/trial identity gives order-independent fixed streams.
                    stream = hashlib.sha256(canonical([RNG_VERSION, config["seed"], families, graphs, scenario, trial])).digest()
                    rng = random.Random(int.from_bytes(stream, "big"))
                    matrix, truth, bounds = toy_matrix(scenario, families, graphs, rng)
                    estimate = statistics.fmean(v for family in matrix for v in family)
                    for method in METHODS:
                        if method == "graph_hoeffding":
                            ci = hoeffding_interval(estimate, graphs, bounds, config["alpha"])
                            adjusted = hoeffding_interval(estimate, graphs, bounds, config["alpha"], config["multiplicity"])
                            tail_resolution = True
                        else:
                            method_stream = hashlib.sha256(stream+method.encode()).digest()
                            samples = bootstrap_means(matrix, unit="graph" if method == "graph_percentile" else "family",
                                                      draws=config["bootstrap_draws"], rng=random.Random(int.from_bytes(method_stream, "big")),
                                                      template_block=scenario == "template_block_quota")
                            tail = config["alpha"]/2
                            ci = (quantile(samples, tail), quantile(samples, 1-tail))
                            adjusted_tail = tail/config["multiplicity"]
                            # Require >=20 expected replicates in EACH adjusted tail.
                            tail_resolution = adjusted_tail*len(samples) >= 20
                            adjusted = (quantile(samples, adjusted_tail), quantile(samples, 1-adjusted_tail)) if tail_resolution else None
                        criterion = "H5_safety_component_ONLY" if scenario.endswith("quota") else "H4_equivalence_component_ONLY"
                        gate_pass = None if adjusted is None else (adjusted[1] < -.05 if scenario.endswith("quota") else -.02 < adjusted[0] and adjusted[1] < .02)
                        rows.append({"kind": "STATISTICAL_SIMULATION_NOT_DEFENSE", "families": families,
                                     "template_clusters": families//2 if scenario == "template_block_quota" else families,
                                     "graphs": graphs, "scenario": scenario, "method": method, "trial": trial,
                                     "true_mean": truth, "estimate": estimate, "ci_low": ci[0], "ci_high": ci[1],
                                     "covered": ci[0]-1e-12 <= truth <= ci[1]+1e-12, "degenerate": abs(ci[1]-ci[0]) < 1e-12,
                                     "criterion": criterion, "adjusted_tail_resolved": tail_resolution,
                                     "adjusted_low": None if adjusted is None else adjusted[0],
                                     "adjusted_high": None if adjusted is None else adjusted[1], "component_gate_pass": gate_pass})
                for method in METHODS:
                    cell = [r for r in rows if r["families"] == families and r["graphs"] == graphs and r["scenario"] == scenario and r["method"] == method]
                    n, covered = len(cell), sum(r["covered"] for r in cell)
                    eligible = [r for r in cell if r["component_gate_pass"] is not None]
                    passed = sum(r["component_gate_pass"] for r in eligible)
                    truth_supports_gate = cell[0]["true_mean"] < -.05 if scenario.endswith("quota") else abs(cell[0]["true_mean"]) < .02
                    summaries.append({"families": families, "graphs": graphs, "scenario": scenario, "method": method,
                                      "coverage_numerator": covered, "coverage_denominator": n,
                                      "coverage": covered/n, "coverage_mc95": wilson(covered, n),
                                      "degenerate_numerator": sum(r["degenerate"] for r in cell), "degenerate_denominator": n,
                                      "mean_width": statistics.fmean(r["ci_high"]-r["ci_low"] for r in cell),
                                      "criterion": cell[0]["criterion"], "component_power_or_typeI": "power" if truth_supports_gate else "typeI",
                                      "component_gate_numerator": passed, "component_gate_denominator": len(eligible),
                                      "component_excluded": n-len(eligible), "component_status": "MEASURED_TOY_ONLY" if eligible else "UNRUN_insufficient_adjusted_tail_resolution",
                                      "component_mc95": wilson(passed, len(eligible)) if eligible else None})
    report = {"version": VERSION, "kind": "STATISTICAL_SIMULATION_NOT_DEFENSE", "config": config,
              "config_sha256": hashlib.sha256(canonical(config)).hexdigest(),
              "estimand": h5_binding(), "rng_stream_version": RNG_VERSION,
              "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "environment": {"python": sys.version, "platform": platform.platform()}, "summary": summaries,
              "simulation_rows": len(rows), "actual_defense_executions": 0, "receiver_observations": 0, "model_requests": 0,
              "full_joint_H5_power": {"status": "UNRUN", "reason": "TCR nuisance, all points and full joint dependence not simulated"},
              "inference_scope": "random graphs conditional on a fixed hypothetical cohort; not source population or actual defense",
              "limitations": ["toy response models only", "finite Monte Carlo uncertainty", "PRNG reproducibility is not source-truth validation",
                              "family intervals condition on the sampled graphs", "Hoeffding uses known ranges and independent whole graphs",
                              "bootstrap pointwise coverage is not Bonferroni joint coverage", "threshold value basis and confirmatory budget remain unapproved"]}
    return report, rows


def export(report: dict, rows: list[dict], output: Path, charts: bool = False) -> None:
    output.mkdir(parents=True, exist_ok=True)
    (output/"report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False)+"\n")
    for name, records in (("trials.csv", rows), ("summary.csv", report["summary"])):
        with (output/name).open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(records[0]))
            writer.writeheader()
            writer.writerows(records)
    if charts:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, axes = plt.subplots(1, len(SCENARIOS), figsize=(16, 4), sharey=True)
        fixed = report["config"]["families"][-1]
        for ax, scenario in zip(axes, SCENARIOS):
            for method in METHODS:
                cells = [r for r in report["summary"] if r["families"] == fixed and r["scenario"] == scenario and r["method"] == method]
                x = [r["graphs"] for r in cells]
                y = [r["coverage"] for r in cells]
                errors = [[max(0., r["coverage"]-r["coverage_mc95"][0]) for r in cells], [max(0., r["coverage_mc95"][1]-r["coverage"]) for r in cells]]
                ax.errorbar(x, y, yerr=errors, marker="o", capsize=3, label=method)
            ax.axhline(.95, color="black", linestyle=":")
            ax.set(title=scenario.replace("_", "\n"), xlabel="Independent whole graphs", ylim=(-.02, 1.05))
        axes[0].set_ylabel("Pointwise interval coverage (Monte Carlo 95% bars)")
        axes[-1].legend(fontsize=7, loc="lower right")
        fig.suptitle(f"STATISTICAL TOY SIMULATION — no defense experiment; {fixed} fixed families")
        fig.tight_layout()
        fig.savefig(output/"coverage.svg")
        plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--charts", action="store_true")
    args = parser.parse_args()
    require(args.config.stat().st_size <= 65536, "config_file_limit")
    config = json.loads(args.config.read_text())
    report, rows = run(config)
    export(report, rows, args.output_dir, args.charts)
    print(json.dumps({"kind": report["kind"], "config_sha256": report["config_sha256"], "simulation_rows": len(rows),
                      "actual_defense_executions": 0, "full_joint_H5_power": "UNRUN"}))


if __name__ == "__main__":
    main()
