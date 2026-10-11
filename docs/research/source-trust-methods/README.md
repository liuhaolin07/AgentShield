# Source-trust methods development R2

以 PR #6 的 `b631d1c17c6d1125d4ffc9969f5e794926c49681` 为冻结基线的新分支。
PR #6、PR #5、V1.10 和所有历史结果不变；`frozen-pr6.json` 覆盖该提交的 266 个文件。

本工作线实现方法学与开发校准；尚未注册、不运行保留集。
将测量贡献（曲线、暴露与边界）与 H5 内部策略优越性结论分开：H5 不支持不等于测量失败。
以整张全局腐化图为随机化单位，任务 cohort 固定；不推断一般来源总体。
固定五张图的结果只作有限图的描述，不能用家族 bootstrap 冒充随机错标过程的区间。

新增覆盖率/功效模拟属于统计方法压力测试，不是 AgentShield 防御实验。
5% 改善/非劣、80% 完成率、2% 等效界仍缺外部风险/任务价值依据；
保持为候选，不能按开发或模拟观察到的策略效果调整。真正注册前还需独立评审和覆盖/功效门禁。

双人真值标注、盲化、仲裁和抽样核查未完成前，984 行 pilot 保持 UNRUN。
No Defense 只校准载荷与观测，不从其结果决定任务入选或修改真值/依赖。
内部合成控制不能冒充经过两位独立作者/标注者验证的保留材料。

本目录保留本轮真实原始日志。`baseline-unit-tests.txt.gz` 是新执行的完整基线单测；
`baseline-evidence-gate.json` / `.txt` 是历史 252 行的重新校验，明确不是新实验执行。
后续每阶段测试日志与代码提交分别记录。未合并、未发布。

## 本轮交付与证据索引

- `benchmark/source_trust_corruption.py`：有界显式叶声明腐化；精确定额、方向分母、
  稳定排名/嵌套比例、同家族预算的定向配对、执行前的 X_any/X_all/Z_any。
- `ci/validate_source_trust_corruption.py`：不导入生成器/防御的独立重算；
  13 张图、936 个三个策略共享图的**计划绑定**。无执行，不是 984 行 pilot。
- [统计设计](STATISTICAL_ANALYSIS.md)、[实际校准与不足](statistical-calibration/RESULTS.md)：
  9,600 行离线统计试验及完整 JSON/CSV/图，保留欠覆盖、退化、UNRUN 与首次绘图失败。
- [双人真值与依赖协议](TRUTH_ANNOTATION_PROTOCOL.md)：读者/用途/叶路径、D_read/D_out、
  A/B 盲化独立原稿、第三人仲裁、分层审计及 No Defense 不得筛选任务。
- [外部可行性](EXTERNAL_FEASIBILITY.md)：固定 FIDES/OpenAPPA 工件及许可证；
  FIDES 五个原始 lattice 断言实际通过，完整配对执行适配仍 UNRUN。
- [未完成门禁](readiness.json)：完整 H5 联合功效、阈值价值依据和真实双人标注未完成；
  开发 pilot 与保留集均 UNRUN，无模型请求。
- `ci/validate_source_trust_methods.py`：266 文件冻结、生成提交 Git 对象、原始 CSV 行/分母/
  排除规则独立校验。新 CI 覆盖 Python3.10–3.12，检查方法一致性，不要求安全零失败。

生产策略、V1.10、PR #5 与 PR #6 文档均保持原字节。本目录是方法学开发，未升级 V2.0。

## English scope and reproduction

This additive development branch preserves all 266 files at PR #6 commit `b631d1c`.
It separates finite frozen-graph descriptions from random-graph inference conditional on a fixed cohort.
Whole graphs, rather than individual family/seed rows, are the proposed randomization units.
The corruption planner and its independent checker never execute tools or use evaluator truth as a runtime policy.
The 936 bindings are development measurement controls, not executed pilot observations.

The 9,600 retained Monte Carlo rows are **statistical toy calibration, not defense performance**.
They show that graph percentile intervals still under-cover rare shared failures; conservative bounds are wide.
Adjusted bootstrap component power is UNRUN because of inadequate tail resolution, and full joint H5 power
is UNRUN because the TCR dependence has not been simulated. Candidate thresholds still lack task-owner value justification.
No preregistration, holdout acquisition, pilot execution, model experiment, merge or release is authorized by these files.

The locked annotation procedure requires two real independent human submissions, blinded from policies and outcomes,
with leaf reader/purpose truth, explicit output dependencies, adjudication and audited receipts.
No Defense calibrates observability after enrollment; it cannot select tasks or redefine truth.
The upstream FIDES lattice smoke and OpenAPPA source review establish only partial artifact feasibility,
not full runtime adapters or reproduced benchmark results. Both paired external experiments remain UNRUN.
Measurement results need not satisfy H5; a superiority claim must satisfy all joint H5 conditions.

```sh
python -m unittest discover -s test -p 'test_*.py' -v
python -m ci.validate_source_trust_methods
python -m benchmark.source_trust_corruption --output logs/methods-manifest.json
python -m ci.validate_source_trust_corruption logs/methods-manifest.json \
  --cohort-sha256 e634769553d110093104d52c2d395020e848adf72409179facfd2cdc7d361bc0
python -m evaluation.source_trust_external_smoke --output logs/upstream-primitive.json
```

Use `STATISTICAL_ANALYSIS.md` to reproduce statistical calibration. The plot dependency is optional;
without `--charts` all calculation and exports use the Python standard library.
