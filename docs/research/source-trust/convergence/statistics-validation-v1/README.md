# 统计工作包：实现已落地，覆盖尚未验证通过

[结果、图表与下一步标准](run-001/REPORT.md) / [机器报告](run-001/report.json) /
[执行前固定的压力配置](config.json) / [实现](../paired_inference.py)

首轮17统计量、10,000次配对簇重采样、种子1729及Bonferroni校正均遵循原草案。
本次只增加离线数学计算；原54,720行E0/E1、3,600行E3及984行正式pilot预算不变，
未使用模型、HTTP或holdout。700个模拟数据集与7,000,000次bootstrap重采样不计作研究执行行。

## 发现

连续有界组件场景的共同覆盖为96%–98%，但每场景仅100次，Monte Carlo区间较宽，
不能据此认证95%覆盖。稀有事件场景（簇事件概率1%、30簇、每簇2家族）的共同覆盖仅29/100，
71/100次发生退化。该反例有解析解释：30个独立簇都未观察到事件的概率为
`(1 - 0.01)^30 ≈ 0.7397`。此时经验分布只含零，percentile重采样不能生成未观测到的事件，
区间不会包含正的真实事件率。增加bootstrap次数不能消除这个问题。

因此保留原方法实现和全部模拟结果，**G09/G10均未关闭**；不自动切换统计方法、降低阈值或扩大正式预算。
常数场景共同覆盖100%也不能通过退化诊断；单模板场景不输出区间。

后续[有限样本候选比较](../rare-event-validation-v1/README.md)已提供条件性覆盖推导和精度成本。
候选尚未应用；本目录原始实现、配置与结果仍作为历史证据保留。

## 输入契约与未完成部分

`analyze_families()`接收已核验的家族级端点，不能直接传入原始执行账本。
每个家族包含唯一`family_id`、明确的`template_cluster_id`（无共享模板时显式null）、
五个种子的执行前`H3_eligible_by_seed`及完整`values`网格。
`required_keys()`列出当前17统计量所需端点，键为`panel|rate|seed|policy|metric`；
E0只出现一次，SP含完整六点网格、PS含p=.25、targeted含p=.10。
每个值为`{"value": 0或1或null, "observed": true或false}`。
已知送达但观测链异常可保留ASR=1、observed=false；未知值必须observed=false。
实际观察到的工具失败可为TCR=0、observed=true，不把所有未完成都当作UNRUN。

处理次序是：家族内对种子等权汇总→组成配对差值/绝对TCR/梯形AUC→整模板重采样→
重新按被采样家族总数归一化→对缺失下界和上界分别取校正分位数。
多簇但退化的数值区间可以用于诊断，输出同时带失败标记；不足两簇则区间为null。
所有输出的`confirmatory_success`和`experiment_authorized`恒为false。

以下细节仍是明确列出的草案实现约定：NumPy PCG64随机数生成器、type-7线性分位数，
以及H3按家族等权、家族内合格种子等权（全零预算家族仅从H3排除）。必须在冻结时确认，不能按结果换算法。
完整观测家族敏感性分析会改变cohort，始终作为次要输出。

仍缺验证过的账本适配器、图/掩码绑定、split隔离和独立材料；这里的组件模拟不是二元任务过程的覆盖证据。
缺失机制联合模拟、功效/MDE、真实ICC不确定性和尾部分位数稳定性尚未完成。
当前12家族候选演练只有一个模板且缺少完整六点/五种子/E3，不能补零凑齐后喂给确认性分析。

## 复现

已安装环境：Python 3.12.14、NumPy 2.3.5、Matplotlib 3.10.8；
[可选统计依赖](../requirements-statistics.txt)单列，不修改运行时依赖。
输出到新目录，保留`run-001`及其输入/代码摘要。

```sh
MPLCONFIGDIR=/tmp/agentshield-statistics-mpl XDG_CACHE_HOME=/tmp/agentshield-font-cache python docs/research/source-trust/convergence/validate_statistics.py --output /tmp/agentshield-statistics-check
python -m unittest discover -s docs/research/source-trust/convergence -p 'test_paired_inference.py' -v
python -m unittest discover -s docs/research/source-trust/convergence -p 'test_statistics_validation.py' -v
```

仓库内SVG仅去除每行末尾空白；[格式记录](run-001/plot-formatting.json)保留渲染原件与规范化文件的摘要，统计结果和图形几何未改动。
