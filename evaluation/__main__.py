"""Run synthetic independent evaluation and export reviewable evidence."""

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from evaluation.runner import run_evaluation


def export_report(report: dict[str, Any], output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    fields = ["run", "case_id", "principle", "category", "status", "block_source",
              "defense_credit", "duration_ms", "inputs", "policy", "expected", "actual", "trace", "differences", "limitations"]
    if any("arm" in result for result in report["results"]):
        fields = ["arm", *fields]
    with (output / "cases.csv").open("w", encoding="utf-8", newline="") as destination:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        for result in report["results"]:
            writer.writerow({key: json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else value
                             for key, value in result.items()})


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate AgentShield using fabricated fixtures and loopback HTTP only")
    parser.add_argument("--output-dir", type=Path, default=Path("logs/evaluation"))
    parser.add_argument("--seed", type=int, default=17)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--experiment", choices=["v1.7", "v1.8", "v1.9"], default="v1.7")
    parser.add_argument("--split", choices=["development", "holdout", "reserved"], default="development")
    parser.add_argument("--charts", action="store_true", help="Export research charts (optional matplotlib dependency)")
    args = parser.parse_args()
    if args.repeat < 1:
        parser.error("--repeat must be positive")
    if args.experiment == "v1.9":
        if args.split == "holdout":
            parser.error("V1.9 uses its new reserved split; V1.8 holdout remains historical")
        from evaluation.research import run_research
        report = run_research(split=args.split, seed=args.seed, repeat=args.repeat)
    elif args.experiment == "v1.8":
        if args.split == "reserved":
            parser.error("V1.8 uses development/holdout")
        from evaluation.experiment import run_experiment
        report = run_experiment(split=args.split, seed=args.seed, repeat=args.repeat)
    else:
        report = run_evaluation(seed=args.seed, repeat=args.repeat)
    export_report(report, args.output_dir)
    if report.get("experiment") == "v1.9":
        from evaluation.research_plot import export_metrics_csv as export_research_csv
        export_research_csv(report, args.output_dir)
        if args.charts:
            from evaluation.research_plot import export_charts as export_research_charts
            export_research_charts(report, args.output_dir)
    if report.get("experiment") == "v1.8":
        from evaluation.plot import export_metrics_csv
        export_metrics_csv(report, args.output_dir)
        if args.charts:
            from evaluation.plot import export_charts
            export_charts(report, args.output_dir)
    print(json.dumps(report["summary"]))
    for result in report["results"]:
        if result["status"] != "HELD":
            reason = "; ".join(result["differences"]) or result["actual"].get("unrun_reason", "")
            print(f"{result['status']} {result['case_id']}: {reason}")
    print(f"Evidence: {args.output_dir / 'report.json'}")
    if report["summary"]["FAILED"]:
        return 1
    return 2 if report["summary"]["UNRUN"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
