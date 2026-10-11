# 来源可信性方法学 R3 / Source-trust methods R3

PR #7 保持 Draft，冻结基线仍为 PR #6 的 `b631d1c17c6d1125d4ffc9969f5e794926c49681`。
266个冻结文件、历史实验原始结果与生产策略保持原字节。当前状态：**不可预注册、不可启动984行pilot或保留集**。
测量贡献与系统优越性分开；H5不成立不否定测量研究的价值。

## 当前修正与证据

- [P1勘误](r3/ERRATUM_H5_GRID.md)：撤回R2定额场景的H5命名。
  正式网格改为 `[0,.05,.10,.25,.50,1]`、[0,1]积分；生成器与独立门禁均外部绑定冻结R1。
  [新9,600行统计复跑](r3/statistical-calibration/RESULTS.md)保留全部CSV/JSON与图，
  4,800行共同故障记录与旧版逐字段相同，48/200、156/200的欠覆盖警告仍成立。
- [完整规划清单](r3/E3_MANIFEST.md)：32MiB等原资源界保持，图上限81；
  同一清单含76个E0/E1和5个E3，定向图必须携带其随机父图，不能借用其他清单的图。
  12作者控制家族的5,832个计划绑定没有工具执行或接收证据。
- [TA-2原始标注转换与量化审计门禁](r3/TRUTH_TRANSFORMATION_TA2.md)：
  原始双稿、UNCERTAIN、证据、仲裁、D_read/D_out、审计→可验证哈希链→布尔cohort。
  未裁决不投影；任意分类/授权/依赖等关键错误全量重做，任意发现暂停pilot。
  fixture验证只证明结构，真实人类标注者/仲裁者/审计者均0。
- [预先冻结的GHO-1候选](r3/JOINT_ESTIMATOR_GHO1.md)和[完整六点联合统计校准](r3/joint-calibration/RESULTS.md)：
  2,000次试验、35,000原始整图计数和2,000一次E0记录。所有十格联合确认0/200，
  当前5/30图预算下功效不可用；全拒绝控制不获胜，MNAR缺失不算成功。
- [当前门禁](r3/readiness.json)：实际策略联合功效UNRUN；候选阈值缺任务价值依据、
  真人人员回执未获、跨图相关未验证、外部配对执行器未完成。统计模拟不能代替实际防御证据。
- [R3改进报告](r3/RESEARCH_REPORT_ZH.md)、[变更记录](CHANGELOG.md)及
  [最终验证记录](r3/final-verification.json)：完整本地测试、真实旧版252行回归与不变性核验。

## English scope

R3 corrects the P1 grid mismatch by binding the formal six-point H5 grid and integration domain
from the externally frozen R1 protocol. The prior low-rate exploratory AUC artifacts remain intact,
but their H5 name is retracted. A formal-grid rerun retains 9,600 statistical rows; all 4,800 common-fault
rows exactly match the old run, preserving the independent undercoverage finding.

The bounded 81-graph planner includes E0/E1 and paired E3 parents in one manifest. A traceable raw
annotation-to-cohort projection preserves uncertainty, evidence, adjudication and output dependencies.
Its synthetic fixture does not establish independent human judgment. Any audit finding blocks progress;
a single critical error requires full-cohort rework. Real annotators and auditors remain absent.

A whole-graph Hoeffding candidate was committed before **full six-point joint toy calibration**.
The 2,000 trial records preserve raw paired counts, shared graph faults, MNAR bounds and one E0 per trial.
All ten cells confirm 0/200: the candidate is underpowered at both tested graph budgets. This is not
measured AgentShield policy power or defense performance. Measurement findings do not require H5;
a policy superiority claim must pass every joint H5 condition.

No preregistration, pilot, holdout intake/execution, paid model experiment, merge or release occurred.
All 266 PR #6 baseline files and historical raw evidence remain unchanged. Root project README/CHANGELOG
are frozen baseline files; bilingual changes for this research branch live in this directory.

## Reproduce independent gates

```sh
python -m unittest discover -s test -p 'test_*.py' -v
python -m ci.validate_source_trust_methods
python -m ci.validate_source_trust_joint docs/research/source-trust-methods/r3/joint-calibration
python -m benchmark.source_trust_corruption --r1-panel --output logs/r1-panel.json
python -m ci.validate_source_trust_corruption logs/r1-panel.json --r1-panel --cohort-sha256 e634769553d110093104d52c2d395020e848adf72409179facfd2cdc7d361bc0
python -m benchmark.source_trust_truth docs/research/source-trust-methods/r3/truth-chain-fixture/raw-ledger.json --output logs/projection.json
python -m ci.validate_source_trust_truth docs/research/source-trust-methods/r3/truth-chain-fixture/raw-ledger.json logs/projection.json --ledger-sha256 7cfd662cc94a05dcde2788794ed73a3f8a75858e7b3745dddf20d31377f911c7
python -m benchmark.source_trust_corruption --cohort logs/projection.json --output logs/truth-graphs.json
python -m ci.validate_source_trust_corruption logs/truth-graphs.json --cohort-sha256 42511904ac606bcdba3861e19f8c9e16715e196565356cb2324e105c8103f341
```

The SHA pins above refer only to the retained author fixture. New real records require new independently
frozen pins and semantic review; recomputing a self-hash is not trusted labeling.
Matplotlib is optional for plots; all calculations, exports, tests and evidence gates use the standard library.
CI audits retained evidence on Python3.10–3.12; it never launches the pilot or requires zero defense failures.

## Historical R2 archive

[R2 design](STATISTICAL_ANALYSIS.md), [R2 report](RESEARCH_REPORT_ZH.md),
[raw low-rate statistics](statistical-calibration/RESULTS.md), [TA-1](TRUTH_ANNOTATION_PROTOCOL.md),
[R2 readiness](readiness.json) and [external feasibility](EXTERNAL_FEASIBILITY.md) describe their historical execution.
Read R2 grid statements together with the R3 erratum. R2 joint power was UNRUN then; R3 measures only
hypothetical-model joint power. FIDES five lattice assertions remain primitive smoke checks; complete
FIDES/OpenAPPA paired runtime experiments and real-model tests remain UNRUN.
