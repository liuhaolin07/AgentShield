"""Computed rate/profile exports and optional standard research figures."""
import csv
import json
from pathlib import Path


def export_analysis(report, output: Path, *, charts: bool = False) -> None:
    output.mkdir(parents=True, exist_ok=True)
    with (output/'metrics.csv').open('w', newline='') as f:
        w = csv.writer(f); w.writerow(['strategy', 'metric', 'numerator', 'denominator', 'value', 'unique_tasks', 'unique_task_wilson_95'])
        for arm, m in report['metrics'].items():
            for key in ('ASR', 'TCR', 'FPR', 'ABR', 'precision', 'recall'):
                r = m[key]; cluster = m['unique_task_estimates'].get(key, {})
                w.writerow([arm, key, r['numerator'], r['denominator'], r['value'], cluster.get('denominator'), json.dumps(cluster.get('wilson_95'))])
    with (output/'source-profiles.csv').open('w', newline='') as f:
        w = csv.writer(f); w.writerow(['strategy', 'profile', 'ASR', 'FPR'])
        for arm, m in report['metrics'].items():
            for name, profile in m['source_profiles'].items(): w.writerow([arm, name, json.dumps(profile['ASR']), json.dumps(profile['FPR'])])
    with (output/'failures.csv').open('w', newline='') as f:
        w = csv.writer(f); w.writerow(['run', 'strategy', 'case_id', 'family', 'status', 'block_reason', 'differences'])
        for r in report['results']:
            if r['status'] != 'HELD': w.writerow([r['run'], r['arm'], r['case_id'], r['inputs']['family'], r['status'], r['actual'].get('block_reason'), json.dumps(r['differences'])])
    if not charts: return
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    strategies = tuple(report['metrics']); fig, axes = plt.subplots(1, 3, figsize=(12, 4))
    for ax, key in zip(axes, ('ASR', 'TCR', 'FPR')):
        points = [report['metrics'][s]['unique_task_estimates'][key] for s in strategies]
        values = [p['value'] if p['value'] is not None else float('nan') for p in points]
        lower = [v-p['wilson_95'][0] if p['wilson_95'] else 0 for p, v in zip(points, values)]
        upper = [p['wilson_95'][1]-v if p['wilson_95'] else 0 for p, v in zip(points, values)]
        ax.bar(strategies, values, yerr=[lower, upper], capsize=4); ax.set_ylim(0, 1.1); ax.set_title(key+' / unique tasks')
        for i, (p, v) in enumerate(zip(points, values)):
            label = f"{p['numerator']}/{p['denominator']}" if p['value'] is not None else 'UNRUN / n=0'
            ax.text(i, v+.025 if p['value'] is not None else .5, label, ha='center')
    fig.suptitle('Source trust: authored explicit-flow tradeoffs, descriptive Wilson intervals'); fig.tight_layout()
    fig.savefig(output/'security-utility.svg'); plt.close(fig)
