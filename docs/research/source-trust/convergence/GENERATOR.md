# 开发阶段错标图：实现与验证范围

本实现对应 G05 的工程部分，版本为 `sha256-prefix-development-v1`。
用户已批准前一收敛包；此实现仍需真实开发材料校验及后续冻结。
它不执行 Agent、不生成结果指标、不读取外部保留正文，也不授权 pilot 或正式实验。

## 输入、排名与摘要

输入采用 [材料契约](INTAKE.md)。仅从结构合法的清单取 development 家族；
空清单拒绝生成。契约中的独立真值和执行前依赖必须由材料作者提供，不能根据
Agent 输出或成功送达情况反推。结构检查不能证明作者独立性或语义真实性。

家族按 family_id、叶按路径、授权按 subject/purpose、任务按 kind、依赖按路径排序。
规范 JSON 使用 UTF-8、键排序、无空白分隔符、保留 Unicode、不允许非有限数。
不做 Unicode 归一化。集合字段排序后，来源、契约及整个开发 cohort 均绑定摘要。
修改 cohort 会改变图摘要，并可能改变排名前缀；不得混用不同 cohort 的图。

E1 的排名键是以下 JSON 数组的 SHA-256，冲突时按 family_id、path 排序：

```text
[algorithm_version, "development", panel, seed, truth, family_id, path]
```

panel 取协议的三个方向。seed 只取 17/29/43/71/101；非零 rate 以规范字符串
`0.05`、`0.1`、`0.25`、`0.5`、`1` 输入，精确分数计算 `floor(p*N)`。
N 是整个 development split 的相应真值叶池大小，不是逐家族大小；双向分别取
敏感池和公开池的前缀。排名不含 rate、task、policy 或结果，因此同方向同种子
跨 rate 嵌套，并让两类任务和三个策略共享图。不同 panel 的排列不要求相同。
此为明确、可复算的伪随机排名规范，不是理想均匀随机性的证明。

E0 仅有一次、rate=0、seed=null；不对每个注入种子重复 E0。
E3 只接受已通过校验的 E1 sensitive_to_public、rate=0.1 图。
每家族保留该随机图的改动数 k_i、叶集合和受影响家族；先按执行前攻击依赖 D
优先选敏感叶，其余用同一排名打破平局。匹配图摘要被写入 E3。
k_i=0 家族仍保留所有六条计划行，但标记为不进入 H3 的 k_i>0 分析。
该算法不发起模型查询；G06 攻击/查询账本的完整实现仍待完成。

每家族 X_any/X_all 为攻击依赖与改动叶的非空交集/全部包含，Z_any 为正常依赖
与改动叶的非空交集。它们只描述执行前暴露，不是 ASR、TCR 或 FPR。
totals 保存两个真值池的 eligible 与 changed，实际方向比例应以二者之比报告，
不能把请求的 p 当作取整后的实际比例。

## 真值隔离与共享图验证

完整图含 truth、dependencies、exposure，仅供注入器和评估器使用。
`defense_labels()` 仅投影 family_id、source_version、路径和声明分类；不包含
真值、依赖、暴露、seed、rate 或完整图摘要。计划行包含的完整图摘要同样只供
编排器审计，不应进入模型上下文。已新增限定 identity 子集的 [声明适配和集成探针](STARTUP.md)，但没有进程隔离或完整真实任务执行的证明。

`verify_graph.py` 不导入生成器，独立重算契约绑定、排名成员、逐家族 E3 预算、
暴露与总量。`verify_bindings()` 另外重建声明投影、核对两任务×三策略全覆盖、
无重复、同图摘要和同标签摘要。仅校验摘要不够：即使攻击者重新计算摘要，
选错叶、伪造暴露、替换来源或混用图也应失败。
这是同一开发过程中的分离实现，不是第三方独立复跑或运行时完整仲裁证明。
生成函数返回的计划行必须通过上述校验后才可交给后续编排；校验通过仍不授权执行。

离线调用示例（manifest 必须已有开发契约；仓库空清单会拒绝生成）：

```python
from corruption_graph import generate_e1, generate_e3, defense_labels, planning_rows, SP
from verify_graph import verify_bindings

random_graph = generate_e1(manifest, SP, "0.1", 17)
targeted_graph = generate_e3(manifest, random_graph)
report = verify_bindings(manifest, targeted_graph, defense_labels(targeted_graph),
                         planning_rows(manifest, targeted_graph), random_graph)
assert report["executed_rows"] == 0
```

这些模块位于本目录；从本目录或将其加入 Python 模块路径后使用。

## 验收结果与下一步

合成测试覆盖：确定性和排序不变性、全局取整、方向分母、嵌套前缀、E0 唯一性、
E3 配对及零预算保留、执行前暴露、摘要重算后的内容篡改、投影泄漏与共享计划行。
测试中的 60 个家族全部为内存合成元数据，来源声明不代表真实独立材料。
81 个图只构建计划：76 个 E0/E1 对应开发侧 27,360 行，5 个 E3 对应 1,800 行；
没有任务执行或外部保留运行。原协议跨两 split 的 54,720/3,600 预算不变，
984 行 pilot 另列且未执行。合成测试不加入数据集、pilot 或论文结果。

G05 暂记 `IMPLEMENTED_PENDING_MATERIAL_VALIDATION`，仍属于未完成门禁。
下一步需要独立开发材料的来源/真值/依赖证据、对这些材料的图重算记录，以及
完整任务编排器实际绑定同图和真值隔离的验证。合成子集的接入测试不替代此证据。
外部保留生成路径应在冻结前交由保管人
部署和独立验证；当前开发版不能冒充该路径已完成。

论文现在可写：“我们实现了开发阶段的确定性错标图构造与分离校验器，并通过
合成契约检查其预算、共享图及配对约束。”不能写“已验证真实 Agent 不泄露”、
“已完成正式错标实验”“已完成第三方复跑”或任何 H1–H5 获支持的结论。
