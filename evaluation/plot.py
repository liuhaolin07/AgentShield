"""Charts from recorded counts only; matplotlib is optional research tooling."""

import argparse
import csv
import json
from pathlib import Path
from typing import Any


def export_metrics_csv(report: dict[str, Any], output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    fields = ["arm", "metric", "numerator", "denominator", "value", "paired_samples", "exclusions"]
    with (output / "metrics.csv").open("w", encoding="utf-8", newline="") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        for arm, metrics in report["metrics"].items():
            for name in ("ASR", "TCR", "FPR", "precision", "recall"):
                writer.writerow({"arm": arm, "metric": name, **metrics[name],
                                 "exclusions": json.dumps(metrics["excluded"], sort_keys=True)})
            latency = metrics["extra_defense_latency_ms"]
            writer.writerow({"arm": arm, "metric": "extra_gate_latency_ms", "value": latency["mean"],
                             "paired_samples": latency["paired_samples"],
                             "exclusions": json.dumps(metrics["excluded"], sort_keys=True)})


def export_charts(report: dict[str, Any], output: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    export_metrics_csv(report, output)
    arms = list(report["metrics"])
    labels = ["No Defense", "Static Rule", "Scanner", "Scanner + Taint"]
    figure, axes = plt.subplots(1, 3, figsize=(13, 4), constrained_layout=True)
    for axis, metric in zip(axes, ("ASR", "TCR", "FPR")):
        fractions = [report["metrics"][arm][metric] for arm in arms]
        axis.bar(range(len(arms)), [fraction["value"] or 0 for fraction in fractions], color=["#aab3bc", "#d88a52", "#689bcc", "#46947b"])
        axis.set_xticks(range(len(arms)), labels, rotation=25, ha="right")
        axis.set_ylim(0, 1.15)
        axis.set_title(metric)
        axis.set_ylabel("Observed proportion")
        for index, fraction in enumerate(fractions):
            axis.text(index, (fraction["value"] or 0) + 0.03,
                      f"{fraction['numerator']}/{fraction['denominator']}" if fraction["value"] is not None else "UNRUN",
                      ha="center", fontsize=9)
    figure.suptitle(f"Exploratory synthetic {report['split']} · seed {report['seed']} · repeats {report['repeat']}\n"
                   "Controls and missing/invalid evidence excluded; repeats share the same cases", fontsize=11)
    figure.savefig(output / "outcomes.svg")
    figure.savefig(output / "outcomes.png", dpi=160)
    plt.close(figure)
    figure, axis = plt.subplots(figsize=(7, 4), constrained_layout=True)
    values = [report["metrics"][arm]["extra_defense_latency_ms"]["mean"] for arm in arms]
    axis.bar(range(len(arms)), [value or 0 for value in values], color="#689bcc")
    axis.axhline(0, color="black", linewidth=0.7)
    axis.set_xticks(range(len(arms)), labels, rotation=20, ha="right")
    axis.set_ylabel("Mean paired gate-time difference (ms)")
    axis.set_title("Exploratory enforcement overhead versus No Defense\nIncludes policy/audit I/O; excludes shared labeling/transforms/network")
    for index, value in enumerate(values):
        axis.annotate(f"{value:.3f}" if value is not None else "UNRUN", (index, value or 0),
                      xytext=(0, 6), textcoords="offset points", ha="center")
    figure.savefig(output / "latency.svg")
    figure.savefig(output / "latency.png", dpi=160)
    plt.close(figure)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    export_charts(json.loads(args.report.read_text(encoding="utf-8")), args.output_dir or args.report.parent)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
