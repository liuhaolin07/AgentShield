# R4：GHO-1统计方法可行性复审

从R3 `962390e` 继续，全部409个文件冻结；本轮仅新增路径。
没有新版本号、估计器替换、统计研究试验、pilot、保留集或模型请求。

**正式结论：GHO-1在5/30独立图预算下的完整H5确认概率必为零。**
原因是区间构造的数学上界，不只是200次模拟未观察到确认。
更改试验次数、任务数或bootstrap次数不会改变这一结论。

| 每个非零点的独立图数 | 绝对TCR半宽度 | 全成功无缺失时最高下界 |
|---:|---:|---:|
| 5 | 0.807595 | 0.192405 |
| 30 | 0.329699 | 0.670301 |
| 81 | 0.200649 | 0.799351 |
| 82 | 0.199421 | 0.800579 |
| 120 | 0.164850 | 0.835150 |

82只是单项最有利必要界，不是联合功效充分预算。3%/5%平均缺失下该单项必要界113/145。
冻结有利假想真值处的非劣区间中心跨线需2740图；这也是**中心诊断，不是功效、实际效应或预算建议**。
81个清单总条件与每点独立图数不同，不能互相替代。

交付：

- [数学证明与范围](SCOPE.md)及 `evaluation/source_trust_feasibility.py`：只做有界解析运算。
- [完整解析JSON](analytic/report.json)及 [预算界CSV](analytic/budget-bounds.csv)、
  [缺失界CSV](analytic/missing-bounds.csv)、[中心诊断CSV](analytic/toy-center-diagnostics.csv)。不是模拟行。
- `ci/validate_source_trust_feasibility.py`：独立读取冻结R1，用整数扫描复核跨线，验证409个Git对象与CSV一致性。
- [候选方法核查](CANDIDATE_METHODS.md)：配对、有限样本经验Bernstein及联合决策/同时区间的区别。
  核查原文和代数，不把候选叫作已实现/已验证。
- [未来验证问题](VALIDATION_DESIGN.md)：结构可能性、完整向量功效、覆盖/错误确认三层分开。
- [当前门禁](readiness.json)、[最终本地验证](final-verification.json)、[变更记录](CHANGELOG.md)。

R3的9,600正式网格行、2,000联合试验、48/200与156/200欠覆盖、252行真实旧版HTTP结果均原字节保留。
它们是历史结果；本轮不将读取或重新检查描述为新的实验执行。
完整回归测试会执行既有单测控制；它们也不计作新增研究实验或984行pilot。

## English scope

R4 proves a deterministic limitation of the **fixed GHO-1 construction**: with fewer than 82 independent
graphs at a nonzero point, even perfect observed TCR cannot meet its 80% lower-bound requirement.
Consequently, no input at the frozen 5/30-graph budgets can confirm joint H5. This is stronger than an
observed zero in Monte Carlo, but says nothing about the impossibility of inference using other methods.

The analytic single-component bound does not authorize 82 graphs or guarantee joint power. Missingness
widens it; a center crossing at a retained hypothetical mean is not a sample-size or power estimate.
Paired graph sampling is necessary for the estimand but does not by itself guarantee interval coverage.
The reviewed empirical Bernstein bound also cannot rescue 30 graphs at zero variance. IUT decisions
and simultaneous confidence bands have different guarantees and would require explicit protocol review.
No alternative estimator is selected or calibrated; all human and external-runtime gates remain pending.

All 409 R3 files remain unchanged. Calculations are deterministic JSON/CSV, not new simulation trials,
defense performance or independent observed graphs. No preregistration, pilot/holdout intake, paid model
request, merge or release is performed. The current Draft PR is a methods artifact, not an approved protocol.

```sh
python -m evaluation.source_trust_feasibility --output-dir logs/feasibility
python -m ci.validate_source_trust_feasibility
python -m unittest discover -s test -p 'test_source_trust_feasibility*.py' -v
python -m unittest discover -s test -p 'test_*.py' -v
```

Standard library only. The new CI audits structural arithmetic and retained evidence; the existing
R3 workflow continues to run the entire regression suite. Neither workflow launches research trials.
