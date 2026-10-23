# 独立开发材料交付与接收

本包提供可直接交给贡献者的文件约定与只读预检入口。目前没有真实独立贡献者交付，
[模板清单](template/manifest.json)和[证据索引](template/delivery.json)均为空。
它们不包含新样本、虚构署名、已完成审查或事前承诺。

## 贡献者需要交付什么

当前协议需要60个开发家族，每家族攻击和正常任务各1条，至少20个JSON叶，
敏感与公开各半；真值、读取授权、接收授权和执行前所需输出依赖必须有规范依据。
可以先交小批供核对，目标总量和预算不变。主题改名、file/tool换入口、字符串替换不自动产生独立模板。
样本选择框、作者/模板派生和结果暴露情况须如实记录，不能把方便取样包装成概率样本。

贡献者负责材料来源、授权依据和依赖契约；另一位真实审查人负责语义、作者关系、
模板派生及分歧处置的复核。审查完成后仍需项目方查证引用，文件存在和摘要一致只证明字节绑定。

当前正文适配器仅支持20–31叶的平坦字符串JSON及单叶identity输出；主面板还要求叶数为偶数、
分类50/50。该约束是当前工程能力，不是将原研究范围改成该子集。
较复杂任务或真实工具的适配需要单独验证，不应静默删减材料以通过预检。
声明`source_kind=tool`也不证明其真实工具调用契约已经验证。

## 从空模板开始

从仓库根目录运行，输出目录必须不存在：

```sh
python docs/research/source-trust/convergence/development_intake.py init \
  --output /tmp/agentshield-development-delivery
```

此命令复制固定协议引用，生成空的`manifest.json`与`delivery.json`，预期退出码为`2`。
贡献者只修改自己的交付目录，不写主接收清单或冻结研究材料。

交付目录格式：

```text
delivery/
  manifest.json
  delivery.json
  payloads/<family_id>.json
  evidence/<evidence_ref>.md  （也可为.txt或.json）
```

`manifest.json`遵循既有[材料契约](../INTAKE.md)：仅放`split=development`家族，
保持`holdout_custody.status=NOT_RECEIVED`。`source_sha256`绑定源文件完整字节，
`value_sha256`按[现有适配器](../material_adapter.py)的JSON值规范编码计算；这两种摘要不能互换。
提交前修改任何文件都需更新相应摘要。不得将外部保留正文或密封包放入这条接收路径。

## 证据索引

`delivery.json`根字段为`schema_version=development-delivery-v1`、
`purpose=DEVELOPMENT_ONLY_PREFLIGHT`、`manifest_sha256`、`evidence_inventory`、`family_evidence`。
`manifest_sha256`是交付清单完整字节的SHA256。

每个证据文件在`evidence_inventory`中登记一次：

```json
{
  "ref": "source-owner-policy-v1",
  "kind": "authorization",
  "path": "evidence/source-owner-policy-v1.md",
  "sha256": "填入该文件完整字节的64位小写SHA256"
}
```

每家族在`family_evidence`中登记一个条目。可复制[空白条目](family-evidence-template.json)填写，
`source_file`须为`payloads/<family_id>.json`，`receipt_refs`必须包含该家族的两个任务ID。
引用尚未取得时保留`null`；不得使用空文件、占位文案或自行虚构的第三方记录冒充证据。

| 条目字段 | 证据`kind` | 需要说明的内容 |
| --- | --- | --- |
| `truth_ref` | `truth` | 分类依据、适用叶、来源所有者/规范版本；不得以检测器、策略或外发结果定义真值 |
| `authorization_ref` | `authorization` | 明确的主体与目的对、读取和外发授权及其依据；读取授权不等于外发授权 |
| `dependency_ref` | `dependency` | 从任务定义推导Dᵃ/Dᵇ、变换支持及上下文输入；引用须与清单`dependency_evidence_ref`相同 |
| `receipt_refs.<task_id>` | `receipt` | 真实接收/任务完成判据、预期输出摘要、观察窗口和失败/缺失语义；引用须与该任务`receipt_contract_ref`相同 |
| `lineage_ref` | `lineage` | 原作者、模板/生成器/上游派生、共享模板关系与分集审计；不同ID不证明独立 |
| `authorship_ref` | `authorship` | 可追溯作者身份及与项目/审查人的关系、材料来源与授权交付依据、既往结果访问情况 |
| `review_ref` | `independent_review` | 真实审查人、所审源/契约摘要、审查内容、时间、分歧和处置；助手自查不算独立审查 |
| `pre_execution_commitment_ref` | `pre_execution_commitment` | 对源与契约摘要的可核验事前时间承诺；文件时间或结果产生后补写的声明不等于事前承诺 |

同一证据可被多个家族引用，但跨类型不能共用一个引用。所有引用均需对应实际文件和完整字节摘要。
预检只读取已被条目引用的证据，拒绝悬空、重复、类型错配或未使用的索引。
各文档不需要把自身摘要写进自己的正文；事前承诺应绑定目标源、契约和相关规范，而非自我引用。
预期回执契约不代表No Defense校准已执行；后续校准需独立记录真实结果，不能将工具格式检查当送达。

## 运行预检

```sh
python docs/research/source-trust/convergence/development_intake.py check \
  --root /tmp/agentshield-development-delivery \
  --output /tmp/agentshield-development-preflight.json
```

| 退出码 | 含义 |
| --- | --- |
| `0` | 已交家族的正文和全部引用文件通过结构/摘要核对，状态`MANUAL_REVIEW_REQUIRED`；总量可能不足60，人工核验仍未完成 |
| `2` | 空交付或有`null`证据引用，状态`PENDING_FILES_OR_FAMILIES`；查看缺口 |
| `1` | 格式、引用、文件、正文适配、摘要或预算错误；不能计为接收成功 |

文件路径固定在指定开发目录内，拒绝符号链接、特殊文件和路径越界。
单个证据最多1MiB，单个源最多64KiB，读取总量最多16MiB；不递归扫描目录或打开未列出的材料。
输出只包含计数、缺口和摘要，不输出源正文或证据原文；输出文件必须尚不存在。

预检始终报告`semantics_verified=false`、`independence_verified=false`、
`pre_execution_timing_verified=false`、`formal_families_admitted=0`与`experiment_authorized=false`。
证据文件内容的真实性、作者身份、跨批次/开发与保留集模板关系及承诺时间都需要人工核验。
通过预检不会自动登记正式材料、关闭门禁或启动实验。

## 接收完成标准

1. 按既有数量和来源要求收齐开发材料；源、真值、授权、依赖、回执与派生记录逐一绑定。
2. 真实独立审查人完成语义及派生核验，身份与引用经查证，分歧保留并处理；不以文件齐备代替此项。
3. 在未来执行前固定材料及有效契约，核验承诺和执行时序。现有作者工程结果不能追认为事前研究证据。
4. 项目方对整批材料作有记录的接收决定，再进入依赖校准与后续pilot准备。

外部保留集仍走独立保管和元数据交接流程，不交给此预检工具读取。
本包不改变H1–H5、54,720行E0/E1、3,600行E3及单列984行pilot预算。
当前9项离线测试通过；[空模板预检](template-preflight.json)仍为待交付。
