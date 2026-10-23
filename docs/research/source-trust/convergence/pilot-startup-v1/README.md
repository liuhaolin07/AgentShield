# 正式 pilot 启动预检

本次已受理“开始 pilot”请求，完成材料预检与预算排程；**正式执行尚未启动**。
[当前检查记录](startup-check.json)来自现有文件的重新读取，所有输入均记录摘要。

| 项目 | 当前状态 | 启动所需 |
| --- | --- | --- |
| D6 新材料 | 接收清单与开发交付均为空，可用家族 0 | 12 个已接收、独立复核、依赖校准的新开发家族，6 file + 6 tool |
| C2 盲评 | 现有复核记录为 PENDING，已审字段/任务均为 0 | ≥3 名合格盲评者；240 个现有字段及新增材料全部字段的评分、Fleiss κ、全部分歧裁定；冻结收集和签发角色 |
| 正式执行清单 | 当前模型入口仅绑定 8 行已知作者夹具、模拟传输、0 次 live 调用 | 在新材料接收后绑定任务、授权、错标图、防御配置、执行器、提供方和请求/费用限制 |
| F4 提供方原文捕获 | `provider_capture_verified=false`、证据引用为 null | 真实提供方边界捕获验收；此项未 true 时程序计算的 dispatchable 恒为 false |

约束来自用户已批准的 [C2 与 D6](../development-v2/REVIEW_CONDITIONS.md)：

> 正式984行pilot只接受经接收、独立复核及依赖校准的材料；禁止使用D1–D4已运行的作者夹具。

历史 984 行作者工程演练的 324 次送达、660 次阻断仍是已知夹具结果，正式 pilot 计数保持 0。
本次排程为 [984 个未绑定槽位](schedule-slots.csv)，不是可执行结果清单：

- 控制臂先列 48 行：12 家族 × 2 任务 × no_defense/reject_all。
- 主条件 936 行：12 家族 × 2 任务 × 3 策略 × 13 条件。
- 13 条件为 E0 一次，加 SP/PS/双向 × .10/.25 × 种子 17/29。
- 每家族槽位 82 行，file/tool 各 492 行；实际 family/task/graph/config 摘要尚未绑定。

排程算术和控制臂顺序已用断言核验。本次未创建正式实验结果账本，不计算 ASR/TCR/FPR，
也不将这些尚未绑定、未派发的槽位计为 984 个实验缺失结果。
新模型请求、工具执行、费用、正式 pilot 行数均为 **0**；没有改动材料接收清单。

下一项实际工作是取得并复核新材料。开发交付结构可沿用
[空交付模板](../independent-development-v1/template)，并按 C2 补齐评分/裁定证据；
该模板目前为空，结构预检通过也不能代替接收决定。
现有带作者答案的评审包不能充当盲评表，未提供的评分者或评分记录保持缺失。

本次不把全部 60 个开发家族或外部 holdout 到位作为 12 家族开发 pilot 的新增门槛。
C3 阈值、C6 统计验收与 H4 延期另行保留，未在本次悄然定稿。
启动资格由 [机器检查](../pilot_readiness.py) 重算；正式平台见 [D1 环境契约](../review-fixes-v1/D1_ENVIRONMENT.md)。
E0/E1 54,720、E3 另计 3,600、pilot 单列 984 的预算不变；未读取保留材料正文。

重新核对当前材料结构：

```sh
python docs/research/source-trust/convergence/validate_intake.py \
  docs/research/source-trust/convergence/intake-manifest.json
```

该检查只验证结构和引用，不能自动证明材料独立性、语义正确性或执行资格。
[开发交付预检](delivery-check.json)和[材料结构预检](intake-check.json)作为本次快照随附。
