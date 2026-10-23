# 稀有事件问题：保守候选已有实现，正式统计方法仍待选择

[比较结果](run-001/REPORT.md)、[机器报告](run-001/report.json)、[条件性证明](PROOF.md)、
[未应用的方法修订候选](candidate-amendment.json)。

本工作包针对原percentile bootstrap在稀有事件场景中的覆盖失效，增加了两项限定工具：

- 加权簇Hoeffding区间：适用于有界家族组件、独立簇及预先固定的权重/合格集合，保留17项共同校正。
- Clopper–Pearson尾部反演：仅诊断真正的iid二元簇事件计数，不用于一般多种子、配对差值和AUC。

对原有固定生成过程重新构建700个数学数据集，没有重跑原7,000,000次bootstrap重采样。
原bootstrap代码、输入及报告摘要在比较前校验；原结果保留。
Hoeffding在这700次中全部覆盖真值；27组二项(n,p)枚举覆盖均达到其单参数名义水平。
这些计算和作者证明仍须独立审查，不能代替对真实材料采样模型及簇间独立性的论证。

## 收敛结论

原percentile在该稀有事件场景下失效；Hoeffding解决了未观察到事件时区间塌缩的问题，
同时暴露精度不足：60个等权独立簇、TCR全为1时，下界仍只有约.767。
因此当前候选作为保守参照，尚未替换有效协议；不通过扩大预算、改阈值或恢复H5优越性主张来取得成功。

后续工作应先定义目标总体、材料采样方式和可辩护的独立簇，再验证适合该数据结构的区间方法及功效。
最小完成标准包括：独立证明/实现审查、账本端点适配与split/图/掩码绑定、二元任务与缺失联合验证，
以及现有预算内的精度论证。G09/G10继续保持待完成。

本包没有新增正式材料、模型请求、HTTP或运行时实验行；H1–H5数值边界、H5已有角色修订、
54,720行E0/E1、3,600行E3及984行正式pilot预算保持。

## 复现

使用已记录的Python 3.12.14与NumPy 2.3.5环境，从仓库根目录运行，输出到新目录：

```sh
python docs/research/source-trust/convergence/compare_rare_intervals.py --output /tmp/agentshield-rare-intervals-check
python -m unittest discover -s docs/research/source-trust/convergence -p 'test_finite_sample_intervals.py' -v
```

端点组件沿用`paired_inference.py`的固定17项顺序；矩阵范围为差值[-1,1]、绝对TCR[0,1]。
显式传入的独立簇等假设仅是调用者声明，程序始终输出`assumptions_independently_verified=false`。
`confirmatory_success`、`experiment_authorized`及`applied_to_protocol`均为false。
