# Frozen V1.10 follow-up evidence / 后续实验原始证据

The original V1.10 tree is immutable. This directory records a separate authored
development study, not replacement scores, a reserved evaluation or V2.0.
See [protocol](../../../SOURCE_TRUST_STUDY.md) and
[Chinese/English findings](../../../SOURCE_TRUST_REPORT.md).

- `frozen-v110.json`: exact baseline commit and SHA-256 of all 212 original files.
- `baseline-tests.txt.gz`, `baseline-validation.json`: original 271-test baseline.
- `policy-tests.txt.gz`, `policy-validation.json`: six real conservative-policy tests.
- `report.json.gz`, `cases.csv.gz`: all 252 raw observations, including 123 FAILED.
- `summary.json`: dataset/version/environment/source hashes and computed metrics.
- `metrics.csv`, `source-profiles.csv`, `failures.csv`: computed fractions, source-condition impact and all failures.
- `security-utility.svg`: standard plot from actual unique-task observations.
- `validation.json`, `gate.txt.gz`, `run.txt.gz`: independent receiver/audit/metric validation and actual CLI output.
- `development-history/`: initial and precommit reports/logs, full 286-test output and corrected test invocation; no discarded failed development record.
- `legacy-compatibility-report.json.gz`: unchanged original CLI, 82 HELD / 0 FAILED / 4 UNRUN.
- `live-disabled-report.json.gz`: new opt-out observation, 36 UNRUN, zero API requests. The old historical report remains unchanged.
- `external-source-material/`: unmodified pinned upstream attack source and MIT notice, intake only, UNRUN.

ASR/TCR/FPR exclude two controls per strategy per repetition. Missing or invalid
observations are excluded with no defense credit; the strict CI evidence gate
does not accept an incomplete report. Precision is TP/(TP+FP), recall TP/attacks.
Unique-task intervals are descriptive; repeated and paired contracts are not
independent population samples. Model costs and additional defense latency are
null when unmeasured. Synthetic payloads in research reports are fictitious;
audit logs contain identifiers/decisions, not the raw private payload.

Reproduce from the implementation commit recorded in `summary.json`:

```sh
python -m unittest discover -s test -p 'test_*.py' -v
python -m evaluation.source_trust --seed 17 --repeat 3 --output-dir logs/reproduction
python -m ci.validate_source_trust logs/reproduction/report.json
```

The experiment CLI exits 1 for retained FAILED contracts and 2 for UNRUN.
Continue to the independent gate after either exit; do not change expected
answers to obtain exit 0. To plot, install existing `requirements-research.txt`
and add `--charts`. Inspect committed data without decompressing it in place:

```sh
python - <<'PY'
import gzip, json
from pathlib import Path
from ci.validate_source_trust import validate
report = json.loads(gzip.decompress(Path('docs/results/source-trust/v1/report.json.gz').read_bytes()))
print(validate(report))
PY
```

中文说明：这里保留全部真实失败、误阻断与缺失观测。保守 MIXED 默认可减少
漏标泄露，但不能纠正显式错误 PUBLIC。真实模型与外部基准没有执行证据，
不可用这些 UNRUN 或人工脚本结果宣称模型防御成功。
