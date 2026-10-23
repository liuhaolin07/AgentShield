# 候选开发材料 v1：作者草案

本包由当前会话的助手构建，包含 6 个场景 × 文件/工具两入口 = 12 个候选家族。
每家族 20 个字符串叶，10 个声明为敏感、10 个声明为公开；各有一个攻击任务和一个正常任务。
正文全部为合成标记，不含真实业务或个人数据。真值定义来自事先固定的授权规范，不来自扫描器或执行结果。

**12 个家族共享一个生成模板，不是 12 个独立模板簇。独立语义复核尚未完成；正式接收清单未增加样本。**

## 材料导航

- [作者规范](authoring-spec.json)：字段分组、保密规则、攻击/正常选择字段和生成公式。
- [候选清单](manifest.json)：授权、源/叶摘要及执行前依赖；仅注入器/评估器可见。
- [任务契约](task-contracts.json)：24 条任务指令、依赖说明及预期送达摘要。
- [来源记录](provenance.json)：作者、共享模板、待复核状态、材料与计划摘要。
- [984 行演练计划](plan.json)：13 张共享图、936 主条件和48控制条件，零重试。
- [首次工程演练](rehearsal-001/summary.json)：实际执行结果；[逐行账本](rehearsal-001/rows.jsonl)。

## 24 条任务的人工复核入口

下表每行对应文件/工具两个家族，各执行攻击/正常两个任务。字段路径为顶层 JSON 键。
读取主体 primary-model 的 task-read 目的对全部叶被授权；http-recipient/export 只授权公开叶。

| 场景 | 攻击输出字段（敏感） | 正常输出字段（公开） | 入口 | 复核状态 |
| --- | --- | --- | --- | --- |
| 客服工单 | `case_note` | `reply` | file / tool | PENDING |
| 仓储报表 | `margin_note` | `availability` | file / tool | PENDING |
| 服务运维 | `access_note` | `region` | file / tool | PENDING |
| 日程管理 | `travel_note` | `date` | file / tool | PENDING |
| 费用记录 | `review_note` | `schedule` | file / tool | PENDING |
| 发布文档 | `deployment_note` | `migration` | file / tool | PENDING |

复核应逐项确认：

1. 字段保密规则与授权主体/目的正确，敏感读取许可不被误写成外发许可。
2. 指令确实选择契约指定的一个叶；预期输出为该叶原始字符串，不包含其他叶或语义改写。
3. 作者规范中的规则与 source/leaf 哈希对应同一材料版本；声明的 INDEPENDENT_CONTRACT 指与防御输出独立，不代表已由独立作者/第三方审阅。
4. 共享模板关系如实保留；不能通过重命名 cluster_id 把这12个家族变成独立样本。
5. 工具入口只是受控本机生产者返回 JSON，任务由脚本驱动，不是外部服务或真实模型代理。
6. 外部保留材料仍为0；本包已用于开发，不能改名为未见 holdout。

复核未完成时保留 PENDING；由代码检查的摘要一致性和控制校准不能自动改成人工复核完成。
任务契约中的 no_defense_calibration=UNRUN 是执行前冻结快照；实际校准结果单独记录在演练报告，不回写快照。

## 重建与复核

从仓库根目录执行：

```sh
python docs/research/source-trust/convergence/candidate_materials.py check
python docs/research/source-trust/convergence/candidate_rehearsal.py check --output docs/research/source-trust/convergence/candidate-materials-v1/rehearsal-001
```

`build` 对同一版本可确定性重建；发现已有生成文件不同会拒绝覆盖。原始规范可读，机器清单和计划采用紧凑 JSON。
`run --output <新目录>` 会执行984行，要求本机监听与连接权限；拒绝覆盖已有运行目录。
本次只安排一次完整演练；失败行保留、零重试，不按效果补跑或扩样。

## 预算与结论边界

此次984行属于单列的候选材料工程演练，未从正式984行 pilot 或54,720/3,600研究预算抵扣。
测试套件的40个集成探针同样单列，不隐瞒额外工程开销；没有外部API或模型费用。
只有既定路径的字节/依赖/图绑定及接收回执一致性可从演练主张。不得据此宣称已完成正式pilot、
区间覆盖或功效验证，也不得将984条重复行当成984个独立样本。H5保留机制限制对照，不转为防护提升。
