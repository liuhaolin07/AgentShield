# P1 材料接收契约 v1（草案）

该格式只服务首轮二值、平衡真值、显式流面板。不是运行时策略格式，不承载执行许可。
修改面板、样本数或阈值需要先修订协议；不得通过修改清单绕过预算。

## 文件与数据分离

`intake-manifest.json` 初始没有任何家族。根字段固定为：

| 字段 | 含义 |
| --- | --- |
| schema_version | `source-trust-intake-v1` |
| purpose | `DRAFT_INTAKE_NOT_EXECUTION_MANIFEST` |
| reference | PR号、确切头提交、上游 protocol-draft.json 的 SHA256；变更参考协议必须显式更新 |
| families | 开发契约或外部保留的封存元数据；两者结构不同 |
| holdout_custody | 保管状态、保管人引用、包承诺摘要、模板审计引用、结果是否已揭示 |

所有标识与证据引用是1–128字符的 ASCII 名称（字母、数字、下划线、点、冒号、连字符），
摘要为64位小写SHA256。引用是供后续人工查证的索引，不是校验器已经读取的证据。
`NOT_RECEIVED` 时三个证据字段必须为 null，不得填“某某保管人”来假装已经取得材料。

## 开发家族

每条记录含 `family_id`、`template_cluster_id`、`split=development`、
`source_kind=file|tool` 和 `contract`。family/task ID 全局唯一。

开发 `contract` 字段：

- `truth_basis=INDEPENDENT_CONTRACT`、`truth_visibility=INJECTOR_EVALUATOR_ONLY`。
  真值由独立契约规定；扫描器、策略输出或送达结果不能充当真值。
- `source_sha256`：源包摘要。源正文放在另行管理的材料包，不在此清单。
- `dependency_evidence_ref`：执行前依赖契约和 No Defense 校准证据的引用。
  当前只有引用结构，未实现依赖提取或校准，不能自行声称依赖已验证。
- `leaves`：至少20叶、敏感与公开各半；每叶含 `path`、`classification`、
  `value_sha256`、`grants`。路径采用唯一、无父子重叠的JSON Pointer，转义仅 `~0/~1`；
  本格式不接受空路径段，超出这个子集的来源需先制定映射并评审。
- `grants`：`{subject, purpose}` 对的列表。**不要把两个集合的笛卡尔积当授权**。
  即使分类为敏感，也可明确允许主模型为任务阅读；这不等于允许HTTP收件主体外发。
- `tasks`：攻击/正常各一条，含 `task_id`、`kind`、`dependency_paths`、`read_scope`、
  `sink_scope`、`supported_transform_ids` 和 `receipt_contract_ref`。

`dependency_paths` 分别表示协议 Dᵃ（敏感输出依赖）/Dᵇ（公开正常依赖），不是从某个
防御的运行结果反推的集合；其他上下文输入应记录在关联契约中。集合必须非空、无重复、
且叶存在。读取scope必须被授权；攻击Dᵃ叶为敏感且不授权目标sink scope；正常Dᵇ叶
为公开且授权目标sink scope。第一版只接受这种规范化首面板契约，不把复杂授权关系
偷偷简化后作为同一个实验。

变换ID须对应冻结运行时真实支持的操作，实际绑定与依赖关系由后续独立审查验证。
校验器只检查非空标识，不声称任意填入的变换均已实现。回执契约须说明真实执行、
授权接收/任务状态和失败窗口；模型自称成功不是回执。

早期格式演示存在于 `test_intake.py` 的内存夹具，不计入研究材料。另已新建
[candidate-materials-v1](candidate-materials-v1/README.md)作者候选包，附独立于防御输出的
授权真值规范和工程演练；作者/模板不独立、语义复核待完成，尚未写入主接收清单。

## 外部保留元数据

每条记录仅允许：`family_id`、`template_cluster_id`、`split=external_holdout`、
`source_kind`、`sealed_bundle_sha256`。**不得包含 payload、leaves、contract 或任务正文。**
清单中的保管状态须为 `SEALED_METADATA_ONLY`，附真实保管人与模板独立审计引用。
校验器不打开密封包，也不能验证声明的摘要对应什么内容。

独立保管人负责私有契约质量检查、作者/模板派生审计和封存；对研发侧只交接必要元数据。
开发/保留不得共享模板；检查相同 cluster ID 只能发现显式冲突，改名不能证明独立。
实际模板独立性、外部作者身份、60家族质量和至少30独立簇仍需独立证据。
结果访问标志为 true 时，本版拒收该保留声明；如果之后调整实现/生成器/攻击，必须
降为开发材料并取得新的保留集，不能把标志重置 false。

保管日志至少记录：包版本与承诺摘要、作者与保管角色、模板审计引用、接收时间、
每次材料/结果访问的主体、时间、目的和授权依据。时间应带时区。
尚无这些证据时保持 null/PENDING，不以“已定义格式”冒充“已获得外部材料”。

## 判定规则与下一步

本版本拒绝未知字段、重复JSON键、重复家族/任务/叶、预算超额、模板跨集重叠、
空依赖、越权正常任务、被允许外发的攻击目标、未接收却声明有保留家族等结构冲突。
主面板数量不足会报告缺口，不虚构补齐。即使数量与结构完整，输出仍为
`experiment_authorized=false`，语义与独立性仍标记未由该工具验证。

材料格式与错标算法分开验证。P1c 已加入 [开发生成器及分离校验器](GENERATOR.md)，
覆盖 split 内方向叶池、floor(pN)、图共享与 E3 成本；当前仅通过合成契约检查，
真实材料、外部保留路径和执行器适配尚未完成，不能以材料结构检查替代。
开发源正文的字节/叶摘要校验与限定运行时适配已加入，见 [接入说明](STARTUP.md)。
其平坦字符串/identity 子集及摘要编码是明确的适配约定，不扩大材料真实性主张。
统计引擎和区间候选已单列实现，正式分析、功效和实际材料覆盖验证仍未完成。
当前候选的[采样声明与账本端点适配](ledger-input-validation-v1/README.md)只服务开发identity工程路径，
明确保留完整计划、采样设计与独立复核缺口，不能代替主清单材料接收。
