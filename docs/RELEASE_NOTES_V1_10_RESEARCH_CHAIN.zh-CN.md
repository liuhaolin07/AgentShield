# V1.10 研究链发布说明（v1.10.1-rc，`5c2b86c`）

> 本文件为**纯附加**文档：`docs/results/source-trust/v1/frozen-v110.json`
> 预注册冻结了 212 个文件（含原 README、CHANGELOG 与 CI 工作流），
> 其 SHA-256 由独立证据 gate `ci/validate_source_trust.py::check_v110_freeze`
> 校验。为不破坏该完整性保证，本发布说明不改动任何被冻结文件。

## 这条链是什么

`codex/v1.7-independent-evaluation` → `v1.8-taint-tracking` →
`v1.9-research-hardening` → `v1.10-precision-evaluation` →
`v1.10-source-trust-study` 是一条**严格线性**的分支链（已验证祖先关系），
在原 v1.6.1（`d670276`，tag `v1.6.1`）之上演进了四代安全机制：

| Tag | Commit | 机制 | 测试 |
|---|---|---|---|
| `v1.7.0-rc` | `d1e0552` | 预算化多视图扫描器（JSON / percent / Base64 解码，深度 4，超限 `scan_limit` fail-closed）、独立评估框架（HELD/FAILED/UNRUN）、本机回环 HTTP 证据传输 | 92 |
| `v1.8.0-rc` | `ecfa751` | 显式污点追踪：不可变来源标签、转换 provenance 链、`scanner_taint` 防御模式、冻结四组实验（143 tests） | 143 |
| `v1.9.0-rc` | `5cd8470` | 研究加固：会话签发不透明句柄、仅数据接口 AgentPort、120/40 冻结基准（199 tests） | 199 |
| `v1.10.0-rc` | `f7c706f` | 精细来源追踪：字段/元素/字符范围依赖、来源分类与不确定性、独立 Agent Oracle（271 tests） | 271 |
| `v1.10.1-rc` | `5c2b86c` | source-trust 三策略对比研究（286 tests） | 286 |

## 已知的诚实失败（保留，未修饰）

- **保留集泄露增加**：错误公开字段/元素声明导致精细组真实外泄（V1.10 首次
  保留运行 Coarse ASR 3/24 vs Precision 6/24）。
- **source-trust 三策略**（seed 17 × 3，`v1.10-source-trust-1`）：
  conservative 把未分类 MIXED 来源默认视为敏感，ASR 12/42 最低，
  代价 TCR 21/36 / FPR 15/36；precision FPR 12/36 最低但 ASR 33/42 最高。
  显式 PUBLIC 声明仍是信任声明，错误声明可外泄。
- **真实模型评估 36 UNRUN、0 API 调用**：凭据缺失，成本未知，
  从未编造模型成绩；CI 每次运行都验证"零付费请求"这一事实。
- 隐式信息流、审计日志防篡改不在保护范围内（README/SECURITY 边界文档如实声明）。

## 发布物

- Tags：`v1.7.0-rc` `v1.8.0-rc` `v1.9.0-rc` `v1.10.0-rc` `v1.10.1-rc`
  （附注标签，锚定各里程碑 tip）
- 集成分支：`research/agentshield-v110`（= `v1.10.1-rc`）
- 独立证据：`docs/results/v1.10/`、`docs/results/source-trust/v1/`
  （含 baseline-freeze / reserved-candidate 哈希清单，
  CI 校验"候选提交后实现未变"）

## Windows 检出注意

本分支链发布时**尚无 `.gitattributes`**。用 Windows 默认
`core.autocrlf=true` 检出会把冻结数据集改写成 CRLF，
触发 `Frozen dataset SHA-256 mismatch` /
`live_contract_integrity_mismatch`——这是检出环境问题，不是证据损坏。
请使用 `git -c core.autocrlf=false clone ...` 或对照
`git ls-tree` 中的 blob 哈希。此问题在研究链合并前应以
`.gitattributes` 修复（冻结文件本体不可改，需附加式处理）。

## 关于"271 项测试"与 286

原 README 中"271 项测试通过"对应 **`v1.10.0-rc`（`f7c706f`）冻结点**，冻结后
不可修改；source-trust 分支（`v1.10.1-rc`）在其上新增 15 项测试至 **286**，
详见上方表格。两数均真实，分别对应各自里程碑。

## 与 main 的关系

main 停在 v1.6.1（`d670276`）。经独立审计（2026-10-12）确认：
v1.6.1 的敏感数据扫描存在 **URL 百分号编码绕过**
（`https://example.com/leak?k=sk%2Dlive...` → ALLOW，端到端复现），
本链自 v1.7 起已修复（多视图解码）。合并本链至 main 前应知悉此差异。
