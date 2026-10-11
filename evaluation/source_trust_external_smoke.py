"""Offline smoke of pinned FIDES lattice cell; not a runtime/benchmark adapter."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys


FIDES_CELL_SHA256 = "72f56eed66b66c622bf80ffcd2b1400b57e81140674989daa291316df03bf43f"


def verify_intake(root: Path) -> dict:
    root = root.resolve()
    manifest_file = root/'manifest.json'
    if manifest_file.stat().st_size > 65536:
        raise ValueError('manifest_limit')
    manifest = json.loads(manifest_file.read_text())
    if manifest['kind'] != 'SOURCE_INTAKE_NOT_DEFENSE_EVALUATION' or not 1 <= len(manifest['files']) <= 32:
        raise ValueError('intake_kind_or_limit')
    seen = set()
    for record in manifest['files']:
        path = (root/record['local_path']).resolve()
        if not path.is_relative_to(root) or path in seen or path.stat().st_size > 1024*1024:
            raise ValueError('artifact_path_or_limit')
        seen.add(path)
        if hashlib.sha256(path.read_bytes()).hexdigest() != record['sha256']:
            raise ValueError('upstream_artifact_changed')
    return manifest


def run(root: Path) -> dict:
    manifest = verify_intake(root)
    lattice_file = root/'fides/lattice_cell_21.py'
    # This reviewed executable pin is independent of the mutable intake manifest.
    if hashlib.sha256(lattice_file.read_bytes()).hexdigest() != FIDES_CELL_SHA256:
        raise ValueError('reviewed_executable_pin_changed')
    spec = importlib.util.spec_from_file_location('pinned_fides_lattice', lattice_file)
    if spec is None or spec.loader is None:
        raise ValueError('lattice_module_missing')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    universe = frozenset({'internal', 'public_sink'})
    def readers(names):
        return module.InverseLattice(module.PowersetLattice(frozenset(names), universe))
    private = readers({'internal'})
    public = readers(universe)
    sink = readers({'public_sink'})
    internal = readers({'internal'})
    cases = [
        {'case': 'private_to_public', 'expected': False, 'actual': private <= sink},
        {'case': 'public_to_public', 'expected': True, 'actual': public <= sink},
        {'case': 'private_to_authorized', 'expected': True, 'actual': private <= internal},
        {'case': 'mixed_join_to_public', 'expected': False, 'actual': private.join(public) <= sink},
        # IFC sees declarations, not evaluator truth: a false public label permits.
        {'case': 'incorrect_explicit_public', 'expected': True, 'actual': public <= sink},
    ]
    if any(record['expected'] != record['actual'] for record in cases):
        raise AssertionError('upstream_lattice_smoke_failed')
    cargo = shutil.which('cargo')
    if cargo is None:
        build_probe = {'status': 'UNRUN', 'reason': 'cargo_not_installed', 'build_attempts': 0}
    else:
        probe = subprocess.run([cargo, '--version'], capture_output=True, text=True, timeout=10)
        build_probe = {'status': 'UNRUN', 'reason': 'full_rust_runtime_not_built_or_mapped', 'build_attempts': 0,
                       'cargo_probe_returncode': probe.returncode, 'cargo_version': probe.stdout.strip()}
    return {'kind': 'UPSTREAM_PRIMITIVE_SMOKE_NOT_DEFENSE_EVALUATION',
            'environment': {'python': sys.version, 'platform': platform.platform()},
            'intake_manifest_sha256': hashlib.sha256((root/'manifest.json').read_bytes()).hexdigest(),
            'verified_source_files': len(manifest['files']),
            'fides': {'status': 'PRIMITIVE_SMOKE_ONLY', 'assertions_passed': len(cases), 'cases': cases,
                      'full_tutorial_status': 'UNRUN_provider_dependencies_not_installed',
                      'official_minimum_python': '3.13', 'runtime_adapter_status': 'UNRUN'},
            'appa': {'status': 'SOURCE_REVIEW_ONLY', 'python_binding_installed': importlib.util.find_spec('appa_agent_python') is not None,
                     'runtime_smoke': build_probe, 'paired_runtime_adapter_status': 'UNRUN'},
            'actual_network_sink_executions': 0, 'receiver_observations': 0, 'model_requests': 0,
            'benchmark_scores': None, 'holdout_tasks_executed': 0}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--intake', type=Path, default=Path('docs/research/source-trust-methods/external-artifacts'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = run(args.intake)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
