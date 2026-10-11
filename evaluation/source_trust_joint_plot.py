"""Plot retained joint-calibration counts; optional matplotlib, no new trials."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path


def plot(report_path: Path, output: Path) -> dict:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    raw = gzip.decompress(report_path.read_bytes()) if report_path.suffix == '.gz' else report_path.read_bytes()
    report = json.loads(raw)
    if report['kind'] != 'STATISTICAL_JOINT_TOY_NOT_DEFENSE':
        raise ValueError('plot requires a statistical toy report')
    cells = report['summary']
    labels = [f"{r['scenario'].replace('beneficial_', '').replace('_', ' ')} / G={r['graphs']}" for r in cells]
    y = list(range(len(cells)))
    fig, axes = plt.subplots(1, 2, figsize=(11, 5.5), sharey=True)
    for axis, field, title, color in (
        (axes[0], 'joint_confirmation_numerator', 'Joint H5 confirmation (toy only)', '#3366aa'),
        (axes[1], 'eligible_trials', 'Trials meeting observation gate', '#46856a'),
    ):
        values = [r[field] / r['denominator'] for r in cells]
        axis.barh(y, values, color=color)
        for index, (value, cell) in enumerate(zip(values, cells)):
            axis.text(min(value + .02, .85), index, f"{cell[field]}/{cell['denominator']}", va='center', fontsize=9)
        axis.set_xlim(0, 1.18)
        axis.set_xlabel('Fraction of all planned simulation trials')
        axis.set_title(title, fontsize=11)
    axes[0].set_yticks(y, labels)
    axes[0].invert_yaxis()
    fig.suptitle('Frozen candidate at G=5/30: zero observed joint power\nNot AgentShield defense performance', fontsize=12)
    fig.tight_layout()
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, metadata={'Date': None})
    plt.close(fig)
    return {
        'kind': 'RETAINED_STATISTICAL_COUNTS_PLOT_NOT_NEW_EXECUTION',
        'input_sha256': hashlib.sha256(raw).hexdigest(),
        'plot_sha256': hashlib.sha256(output.read_bytes()).hexdigest(),
        'plotter_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'cells': len(cells), 'actual_defense_executions': 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    print(json.dumps(plot(args.report, args.output)))


if __name__ == '__main__':
    main()
