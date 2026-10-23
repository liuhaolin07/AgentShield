# 候选材料语义审查交接包

本目录已准备好供真实审查人使用的[输入材料](packet.json)和[空白回填表](response-template.json)。
范围是现有12个作者合成家族、240叶、24任务、1个共享模板。尚无人提交审查结果；
[当前检查](pending-check.json)为`PENDING`，已审查叶/任务均为0，正式接收仍为0。

这项审查用于发现作者规范、授权标注和任务依赖之间的错误。它不能补出60个独立开发家族，
也不证明作者规范符合真实机构的权限制度。材料已有工程和模型运行结果，
此次审查发生在这些结果产生之后，不能追认为事前审查或984行正式pilot。

## 交给审查人的文件

只需交接本说明、`packet.json`、`response-template.json`。输入材料内含源JSON的准确UTF-8正文、
作者规范、任务指令、读取和接收scope及源文件摘要；无需读取仓库历史执行结果。
任务名和规范会暴露作者意图，本流程没有盲法。作者的逐叶标注、依赖答案和执行结果未列为待填答案。
`packet_sha256`绑定本次材料版本，回填时必须保持不变。

本包没有自动联系任何审查人。独立性需要真实身份、关系与证据核验；把同一助手换名称、
换模型或自行填写`independent_of_author=true`不能完成独立审查。

## 回填方法

将`response-template.json`另存为`response-<reviewer>.json`，保留全部家族、叶和任务。
输入规范中存在疑点时记录分歧，不为了通过校验而复制作者答案。

| 位置 | 审查人填写内容 |
| --- | --- |
| `reviewer.identity_ref` | 可追溯的审查人身份引用；非密钥、令牌或账号凭据 |
| `reviewer.independent_of_author` | 与材料作者独立则为布尔`true`，否则`false` |
| `reviewer.prior_outcome_access` | 是否看过这些材料的策略输出、模型或工程实验结果；未知时保留`null` |
| `reviewer.declaration_evidence_ref` | 支持身份、角色关系及既往访问声明的证据索引，须另行查证 |
| `reviewer.completed_at` | 带时区的ISO 8601时间，如`2026-10-23T09:00:00+08:00` |
| 每家族`template_assessment` / `template_rationale` | 是否同意作者声明的共享模板归属：`AGREE`或`DISAGREE`及理由；改主题或来源类型不自动产生独立模板 |
| 每叶`classification` | 根据作者的规范评定`PUBLIC`或`SENSITIVE`；不从策略或送达结果反推 |
| 每叶`grants` | 完整的`{"subject": "…", "purpose": "…"}`对列表；空列表表示无授权，`null`表示未审查 |
| 每叶`rationale` | 分类与授权理由，引用`packet.authority`相应场景规则；如有歧义必须说明 |
| 每任务`dependency_paths` | 从任务指令推导需要输出的JSON Pointer集合；本子集是一叶identity，不能从哪个字段曾被阻断推导 |
| 每任务`expected_body_sha256` | 预期输出字符串的UTF-8字节SHA256，**不含JSON引号，不加换行** |
| 每任务`rationale` | 为什么这些字段是所需输出依赖及为什么预期字节成立 |

这里的预期输出摘要是语义契约核对，不是实际送达回执，也不替代No Defense执行前校准。
本包不收集真实个人敏感数据。所有源值均为原有合成字符串。

## 收到真实回填后的比对

从仓库根目录运行，输出路径须尚不存在：

```sh
python docs/research/source-trust/convergence/material_review.py compare \
  --packet docs/research/source-trust/convergence/material-review-v1/packet.json \
  --response /tmp/response-reviewer.json \
  --output /tmp/material-review-comparison.json
```

| 退出码 | 解释 |
| --- | --- |
| `0` | 所有必填项已填写，审查答案与作者标注一致；仍须人工查证身份、独立性及引用证据 |
| `2` | 有未填项或语义分歧；查看输出`pending`和`differences`，保留原始回填及处理记录 |
| `1` | 材料绑定、结构、JSON或文件错误，不能当作已审查 |

比对器会重读明确列出的开发输入，核对源字节及原契约。材料改动后旧回填不再适用。
输出始终保留`independent_review_verified=false`、`formal_families_admitted=0`、
`experiment_authorized=false`；`ANNOTATIONS_AGREE`只表示答案一致。
独立性声明为false或存在既往结果访问时应如实保留，不能重填为无暴露。
独立核验、分歧处置及正式接收是后续有证据的人工决定，工具不会改写主清单或门禁。

重新准备包可使用`material_review.py prepare --output /tmp/new-material-review`；
输出目录须不存在。由于初始表单为空，该命令生成文件后以`2`退出，这是预期状态。

## 当前验收结果与下一依赖

6项离线测试通过，覆盖空表、全量合成一致回填、五类语义分歧、源/包/响应变更、
重复或缺失记录、重复授权对、无时区时间、重复JSON键和禁止覆盖输出。
测试的已填答案仅在内存中作为作者夹具使用，没有保存为真实审查证据。
原39项设计检查通过，正式主清单仍为开发0/60、保留0/60；本工作包新增API请求和工具执行均为0。

当前可以交付此包供独立审查人找出候选错误。研究材料仍需按[接收契约](../INTAKE.md)
提供60个开发家族的独立真值、授权和依赖证据，并由外部保管人另行准备未揭示保留集。
此包不自动把现有12家族转正。H1–H5、54,720行E0/E1、3,600行E3及单列984行pilot预算保持原约束。
