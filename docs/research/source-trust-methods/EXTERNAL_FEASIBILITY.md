# FIDES / APPA 工件级适配可行性核查

实际检索日期、下载路径、固定提交、逐文件 SHA256 与许可证在
`external-artifacts/manifest.json`；不复制或运行外部 benchmark 任务/保留材料。
网站/README 的性能数字属于上游声明，本轮未验证，不能加入 AgentShield 实验表。

| 工件 | 固定版本 | 本轮实际验证 | 未完成 |
|---|---|---|---|
| Microsoft FIDES 教程 | `669c046c4adbc56ee49c9672fdd30c54937ea062` | 未改动 notebook 第21代码单元的 lattice；五个实际判定断言 | 全教程/真实 Agent/共同工具执行器与本机接收适配 |
| OpenAPPA | `1c52575176330bc88a3c346abe678af5d42083b3`（workspace 0.31.1） | 阅读 Python/Rust接口、标签、形状与判定代码，15个合计来源文件一致性检查 | Rust 构建/策略翻译/运行时 smoke/共同执行证据 |

## FIDES

官方仓库是 notebook 教程，pyproject 要求 Python ≥3.13 及 Azure/OpenAI、Pydantic相关依赖。
本轮仅执行无第三方依赖的**原始 lattice 单元**（本机 Python3.12），不改写算法，
不执行 notebook 的模型配置、示例数据/输出或网络请求。保留 MIT License。
可复现 `python -m evaluation.source_trust_external_smoke --output logs/fides-smoke.json`。
可执行单元除 manifest 散列外再用 harness 内的审核后固定散列校验，
避免同时伪造代码与 manifest 即执行其他代码；散列不证明标签语义。

五个断言：私有→公开不允许，公开→公开允许，私有→授权内部允许，
混合 join→公开不允许，错误显式公开→公开**允许**。
最后一项说明声明错误会改变 primitive 判定，不构成完整 FIDES 安全漏洞结论。
这里“断言通过”表示原始 primitive 的实际行为符合该离线检查，
**不是五个 HELD/网络防御测试**；没有工具执行和独立接收证据。

OpenAPPA 仓库另有基于 `agent_framework.security` 的 FIDES adapter，
但它与原始 notebook 并非同一工件，源码对 coarse 标签表达能力和串行轨迹约束有明确说明。
后续需另固定 Microsoft Agent Framework 官方版本、许可证和 policy enforcement 路径，
不能将第三方 adapter 的性能数字或标签范围直接当作原始 FIDES 的复现结果。

## OpenAPPA

官方网站指向 `archestra-ai/OpenAPPA`，MIT，Rust edition2024 workspace；
Python 包为 `appa_agent_python`、Python≥3.11、PyO3/maturin，与 runtime/engine/policy 多 crate 关联。
API 中存在 check/admit 和 ReturnShape::validate；原则上可用本地 sidecar/replay 或 Python bindings
适配统一执行器，保持任务/工具/sink/授权契约不变。

本环境没有 cargo，也没有该 Python binding。报告明确 `runtime_smoke=UNRUN`、
`build_attempts=0`；未运行下载安装脚本，未用 Python 重写 Rust 判定冒充上游机制。
下一次适配需独立可控 Rust 构建环境，先以普通数据 allow、私有数据 deny、用途/主体授权
做真实本机接收验证，再比较其 contract 不完整/错误 PUBLIC 行为。
还需检查 runtime 绑定事件日志、返回形状/字段继承及恢复策略，避免 adapter 引入不公平语义。

## 论文定位门禁

目前**均无共同运行时对照结果**。FIDES 有 primitive 可执行证据，APPA 有明确 API 工件；
这不是“两个机制无法落地”的证据，也不是跨系统优越性的证据。
当前结论只限 AgentShield 内部来源错标测量与统计方法研究。
若有界适配试验最终证明两个外部机制都不能共同运行，必须在大规模/保留集前公开修订
为内部测量研究，不保留未经验证的跨系统系统贡献。即便适配成功，
新颖性仍需工件级核查其腐化干预/暴露条件实验，不能靠无类似标题来证明首次贡献。
