"""Pre-outcome freeze and read-only validation of the D5 v2 contract."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys

# Isolation must happen before any project or numerical imports.
os.environ.pop("PYTHONPATH", None)
for _name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ[_name] = "1"
HERE = Path(__file__).resolve().parent
sys.path[:] = [p for p in sys.path if p and "hermes" not in p.casefold()]
sys.path[:0] = [str(HERE), str(HERE.parent)]

from d5_contract import require, validate_contract


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite_json")))


def git(repo, *args, input=None):
    return subprocess.check_output(["git", "-C", str(repo), *args], input=input)


def tracked_files(repo):
    return [p.decode("utf-8") for p in git(repo, "ls-files", "-z").split(b"\0") if p]


def input_hashes(repo, names):
    result = {}
    for name in names:
        path = repo / name
        require(path.resolve().is_relative_to(repo.resolve()) and path.is_file() and not path.is_symlink(),
                "input_must_be_regular_file_inside_repo")
        result[name] = sha(path.read_bytes())
    return result


def committed_hashes(repo, commit, names):
    request = "".join(f"{commit}:{name}\n" for name in names).encode("utf-8")
    stream = io.BytesIO(git(repo, "cat-file", "--batch", input=request))
    result = {}
    for name in names:
        header = stream.readline().split()
        require(len(header) == 3 and header[1] == b"blob", "frozen_commit_input_missing")
        data = stream.read(int(header[2]))
        require(stream.read(1) == b"\n", "git_batch_framing")
        result[name] = sha(data)
    require(stream.read() == b"", "git_batch_trailing_data")
    return result


def freeze_inputs(output, repo, config_path):
    output, repo, config_path = Path(output), Path(repo).resolve(), Path(config_path).resolve()
    require(not output.exists(), "new_output_directory_required")
    config = validate_contract(load_json(config_path))
    require(git(repo, "status", "--porcelain", "--untracked-files=all").strip() == b"", "clean_committed_tree_required")
    commit = git(repo, "rev-parse", "HEAD").decode().strip()
    names = tracked_files(repo)
    config_ref = config_path.relative_to(repo).as_posix()
    require(config_ref in names, "contract_must_be_committed")
    hashes = input_hashes(repo, names)
    require(hashes == committed_hashes(repo, commit, names), "committed_bytes_required_no_CRLF_translation")
    manifest = {"scope": "LOCAL_PRE_OUTCOME_FREEZE_NOT_PROJECT_PREREGISTRATION",
                "frozen_at": datetime.now(timezone.utc).isoformat(), "verified_tree_commit": commit,
                "contract_ref": config_ref, "contract_sha256": hashes[config_ref],
                "input_sha256": hashes, "project_preregistered": False,
                "simulation_seed": config["simulation_seed"], "experiment_authorized": False}
    output.mkdir(parents=True)
    (output / "frozen-config.json").write_bytes(config_path.read_bytes())
    raw = canonical(manifest) + b"\n"
    (output / "freeze.json").write_bytes(raw)
    (output / "freeze.sha256").write_text(sha(raw) + "\n", encoding="ascii")
    return manifest


def verify_freeze(output, repo):
    output, repo = Path(output), Path(repo).resolve()
    raw = (output / "freeze.json").read_bytes()
    require(sha(raw) == (output / "freeze.sha256").read_text(encoding="ascii").strip(), "freeze_digest_mismatch")
    manifest = load_json(output / "freeze.json")
    names = list(manifest["input_sha256"])
    require(manifest["scope"] == "LOCAL_PRE_OUTCOME_FREEZE_NOT_PROJECT_PREREGISTRATION"
            and manifest["experiment_authorized"] is False and manifest["project_preregistered"] is False,
            "freeze_is_not_experiment_authorization")
    require(input_hashes(repo, names) == manifest["input_sha256"], "frozen_inputs_changed")
    require(committed_hashes(repo, manifest["verified_tree_commit"], names) == manifest["input_sha256"],
            "freeze_not_reproducible_at_bound_commit")
    require(sha((output / "frozen-config.json").read_bytes()) == manifest["contract_sha256"]
            == manifest["input_sha256"][manifest["contract_ref"]], "frozen_config_changed")
    validate_contract(load_json(output / "frozen-config.json"))
    return manifest


def write_archive(path, rows):
    import gzip
    previous = "0" * 64
    with Path(path).open("xb") as raw:
        with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as archive:
            for row in rows:
                envelope = {"payload": row, "prev_sha256": previous}
                digest = sha(canonical(envelope))
                archive.write(canonical({**envelope, "sha256": digest}) + b"\n")
                previous = digest
    return {"sha256": sha(Path(path).read_bytes()), "last_row_sha256": previous}


def read_archive(path):
    import gzip
    previous = "0" * 64
    with gzip.open(path, "rt", encoding="utf-8") as archive:
        for line in archive:
            envelope = json.loads(line)
            require(set(envelope) == {"payload", "prev_sha256", "sha256"}, "archive_envelope_schema")
            require(envelope["prev_sha256"] == previous, "archive_chain_mismatch")
            require(sha(canonical({"payload": envelope["payload"], "prev_sha256": previous})) == envelope["sha256"],
                    "archive_payload_digest_mismatch")
            previous = envelope["sha256"]
            yield envelope["payload"]


def dataset_rng(master_seed, scenario_id, dataset_index):
    import numpy as np
    require(type(master_seed) is int and master_seed >= 0, "integer_master_seed")
    require(isinstance(scenario_id, str) and bool(scenario_id), "scenario_seed_identity")
    require(type(dataset_index) is int and dataset_index >= 0, "nonnegative_dataset_index")
    digest = hashlib.sha256(scenario_id.encode("utf-8")).digest()
    words = [int.from_bytes(digest[i:i+4], "little") for i in range(0, 32, 4)]
    return np.random.default_rng(np.random.SeedSequence([master_seed, *words, dataset_index]))


def write_json_exclusive(path, value):
    with Path(path).open("xb") as stream:
        stream.write(canonical(value) + b"\n")


def dataset_row(dataset, index, evaluated, offset):
    import numpy as np
    ci = evaluated["intervals"][offset]
    truth = np.asarray(dataset["truth"], dtype=float)
    require(truth.shape == (17,) and np.isfinite(truth).all(), "finite_frozen_analytic_truth")
    return {"dataset_index": index,
            "intervals": [[float(x) if np.isfinite(x) else None for x in pair] for pair in ci],
            "truth": truth.tolist(),
            "eligible_clusters": evaluated["eligible_clusters"][offset].astype(int).tolist(),
            "degenerate": evaluated["degenerate"][offset].astype(bool).tolist(),
            "undefined_draws": evaluated["undefined"][offset].astype(int).tolist(),
            "metadata": dataset["metadata"]}


def simulate_scenario(scenario, output, config):
    from d5_models import generate_dataset, evaluate_batch
    from d5_results import summarize_rows
    output = Path(output)
    n = config["datasets_per_primary_scenario"] if scenario["role"] == "primary" else config["datasets_per_negative_control"]
    batch_size = config["processing_batch_size"]
    def rows():
        for start in range(0, n, batch_size):
            indices = range(start, min(n, start + batch_size))
            datasets = [generate_dataset(scenario, dataset_rng(config["simulation_seed"], scenario["id"], i)) for i in indices]
            evaluated = evaluate_batch(datasets)
            for offset, (i, dataset) in enumerate(zip(indices, datasets)):
                yield dataset_row(dataset, i, evaluated, offset)
            if min(n, start + batch_size) % 256 == 0 or start + batch_size >= n:
                print(json.dumps({"scenario": scenario["id"], "completed": min(n, start + batch_size), "planned": n}), flush=True)
    archive = output / (scenario["id"] + ".jsonl.gz")
    write_archive(archive, rows())
    summary = summarize_rows(scenario, read_archive(archive))
    write_json_exclusive(output / (scenario["id"] + ".json"), summary)
    return summary


def simulate(output, repo, workers=4):
    output, repo = Path(output), Path(repo)
    # This is deliberately before started marker, material generation or pools.
    frozen = verify_freeze(output, repo)
    from concurrent.futures import ProcessPoolExecutor
    from d5_results import assemble_report, render_markdown
    import numpy as np
    import scipy
    config = load_json(output / "frozen-config.json")
    require(type(workers) is int and 1 <= workers <= 4, "one_to_four_offline_workers")
    write_json_exclusive(output / "started.json", {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "freeze_sha256": sha((output / "freeze.json").read_bytes()),
        "verified_tree_commit": frozen["verified_tree_commit"],
        "python": sys.version, "numpy": np.__version__, "scipy": scipy.__version__,
        "workers": workers, "experiment_authorized": False})
    arguments = [(s, output, config) for s in config["scenarios"]]
    if workers == 1:
        scenarios = [simulate_scenario(*args) for args in arguments]
    else:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(simulate_scenario, *args) for args in arguments]
            scenarios = [f.result() for f in futures]
    verify_freeze(output, repo)
    freeze_info = {"verified_tree_commit": frozen["verified_tree_commit"],
                   "contract_sha256": frozen["contract_sha256"],
                   "freeze_sha256": sha((output / "freeze.json").read_bytes())}
    report = assemble_report(config, scenarios, freeze_info)
    write_json_exclusive(output / "report.json", report)
    with (output / "REPORT.md").open("x", encoding="utf-8", newline="") as stream:
        stream.write(render_markdown(report))
    names = ["freeze.json", "freeze.sha256", "frozen-config.json", "started.json", "report.json", "REPORT.md"]
    names += [s["id"] + suffix for s in config["scenarios"] for suffix in (".jsonl.gz", ".json")]
    write_json_exclusive(output / "completion.json", {
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "artifact_sha256": {name: sha((output / name).read_bytes()) for name in names},
        "experiment_authorized": False})
    return report


def replay_indices(config, scenario):
    n = config["datasets_per_primary_scenario"] if scenario["role"] == "primary" else config["datasets_per_negative_control"]
    seed = config["replay_selection_seed"]
    return sorted(range(n), key=lambda i: sha(f"{seed}:{scenario['id']}:{i}".encode()))[:config["replay_per_scenario"]]


def verify_results(output, repo, replay=False):
    import numpy as np
    from d5_results import assemble_report, render_markdown, summarize_rows
    from d5_models import evaluate_batch, generate_dataset
    output, repo = Path(output), Path(repo)
    frozen = verify_freeze(output, repo)
    completion = load_json(output / "completion.json")
    require(completion.get("experiment_authorized") is False, "completion_is_not_authorization")
    config = load_json(output / "frozen-config.json")
    names = ["freeze.json", "freeze.sha256", "frozen-config.json", "started.json", "report.json", "REPORT.md"]
    names += [s["id"] + suffix for s in config["scenarios"] for suffix in (".jsonl.gz", ".json")]
    require(set(completion["artifact_sha256"]) == set(names), "complete_artifact_inventory_required")
    for name in names:
        require(sha((output / name).read_bytes()) == completion["artifact_sha256"][name], f"artifact_changed:{name}")
    scenarios, replayed = [], 0
    for scenario in config["scenarios"]:
        archive = output / (scenario["id"] + ".jsonl.gz")
        rebuilt = summarize_rows(scenario, read_archive(archive))
        require(rebuilt == load_json(output / (scenario["id"] + ".json")), "scenario_summary_not_derived_from_rows")
        scenarios.append(rebuilt)
        if replay:
            selected = set(replay_indices(config, scenario))
            for row in read_archive(archive):
                if row["dataset_index"] not in selected:
                    continue
                dataset = generate_dataset(scenario, dataset_rng(config["simulation_seed"], scenario["id"], row["dataset_index"]))
                actual = dataset_row(dataset, row["dataset_index"], evaluate_batch([dataset]), 0)
                for field in ("intervals", "truth"):
                    archived_numbers = np.asarray(row[field], dtype=float)
                    current_numbers = np.asarray(actual[field], dtype=float)
                    require(np.allclose(archived_numbers, current_numbers, atol=1e-10, rtol=0, equal_nan=True), f"replay_numeric_mismatch:{field}")
                for field in ("eligible_clusters", "degenerate", "undefined_draws", "metadata"):
                    require(actual[field] == row[field], f"replay_mismatch:{field}")
                replayed += 1
            require(len(selected) == config["replay_per_scenario"], "full_replay_selection_required")
    freeze_info = {"verified_tree_commit": frozen["verified_tree_commit"], "contract_sha256": frozen["contract_sha256"],
                   "freeze_sha256": sha((output / "freeze.json").read_bytes())}
    rebuilt_report = assemble_report(config, scenarios, freeze_info)
    require(rebuilt_report == load_json(output / "report.json"), "report_not_derived_from_all_scenarios")
    require(render_markdown(rebuilt_report) == (output / "REPORT.md").read_text(encoding="utf-8"), "markdown_not_derived_from_report")
    return {"verification_passed": True, "state": rebuilt_report["state"],
            "synthetic_coverage_gate_passed": rebuilt_report["synthetic_coverage_gate_passed"],
            "verified_tree_commit": frozen["verified_tree_commit"], "contract_sha256": frozen["contract_sha256"],
            "archived_datasets": sum(s["datasets"] for s in scenarios), "replayed_datasets": replayed,
            "experiment_authorized": False, "confirmatory_success": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("freeze", "verify-freeze", "simulate", "verify", "replay"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args()
    repo = Path(git(HERE, "rev-parse", "--show-toplevel").decode().strip())
    try:
        if args.command in ("freeze", "verify-freeze"):
            result = (freeze_inputs(args.output, repo, HERE / "config.json") if args.command == "freeze"
                      else verify_freeze(args.output, repo))
            print(json.dumps({"status": "FROZEN", "verified_tree_commit": result["verified_tree_commit"],
                              "contract_sha256": result["contract_sha256"], "experiment_authorized": False}))
            return 0
        if args.command == "simulate":
            result = simulate(args.output, repo, args.workers)
            print(json.dumps({"state": result["state"], "synthetic_coverage_gate_passed": result["synthetic_coverage_gate_passed"],
                              "experiment_authorized": False, "confirmatory_success": False}))
        else:
            result = verify_results(args.output, repo, replay=args.command == "replay")
            print(json.dumps(result))
        return 0 if result["synthetic_coverage_gate_passed"] else 2
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError) as exc:
        print(json.dumps({"status": "INVALID", "error": str(exc), "experiment_authorized": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
