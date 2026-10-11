# TA-2：原稿 → 仲裁 → 审计 → 真值 cohort

开发协议文本/机器规则在标注者到岗前提交；未获独立审核，不是预注册或真实标注证据。
TA-1 的自然人身份、盲化、叶级授权和 D_read/D_out 要求继续有效。

## 可运行的有界转换

`benchmark/source_trust_truth.py` 接受开发 inventory（无标签/策略/执行结果）、
两份独立提交声明、证据文件 SHA256 引用、第三人仲裁和审计原稿。
支持叶级 SENSITIVE / PUBLIC / UNCERTAIN、读者/用途、理由/置信度、
任务 D_read/D_out。原稿必须完整覆盖全部叶与任务；不因 No Defense 或防御效果选择任务。
未裁决冲突/不确定值返回 `UNRESOLVED`、projection=null；审计发现错误返回 `AUDIT_FAILED`。
不能将 UNCERTAIN 映射为 PUBLIC，也不能静默删除任务。

仲裁 MVP 只选择 A/B 中一份已经确定的判断，并引用证据和裁决理由。
若两份都是不确定或裁决需新的判断，必须提交带新证据的新原稿版本，保留旧稿；
当前不支持仲裁者在原稿之外静默创造第三种真值。
投影 uses D_out as graph dependencies；D_read、证据和裁决仍完整保存在原始 ledger，
投影不能通过丢弃 D_read 冒充原始任务执行轨迹。

散列链绑定 inventory、证据清单、两份原稿、仲裁、审计、整个原始 ledger 和投影 cohort。
`ci/validate_source_trust_truth.py` 不导入转换器或防御代码，接受外部冻结 ledger SHA256，
重算链及逐字段投影、D_out、审计采样覆盖。随后以该投影 SHA256 作为腐化图门禁的
`--cohort-sha256`，因此更改评估真值、投影或图的来源都会改变链并被检查。
证明的是完整性/语法一致性，**不证明证据真实、自然人独立或授权标签正确**。

新来源状态 `adjudicated_development_NOT_human_verified` 仅支持开发规划；
所有机器输出 pilot_eligible=false / human_identity_or_semantics_verified=false。
仍拒绝保留输入及“independently_reviewed”一类虚假状态。生产默认策略不变。
资源限制：8MiB ledger、4096证据引用、4352单位（4096叶+256任务）、原路径和cohort边界。
不允许标注原稿夹带策略/执行结果，也不记录原始合成值或真实凭据。

## 在人员开始前固定的审计失败规则

审计种子314159。按 file/tool 分层，按稳定SHA排名抽取 ceil(10%家族)，每非空层至少一家族，
该家族全部单位审计。所有任务的依赖契约、全部裁决/不确定冲突及 **全部 PUBLIC 叶** 额外100%审计。
全 PUBLIC 审计是当前保守质量干预，不能声称它免费或已证明误标上界；后续必须计审查成本。
抽样单位ID、分母、种子和独立审计角色声明进入原稿/散列链。

| 情况 | 机器门禁及重做范围 |
|---|---|
| A/B 不一致或 UNCERTAIN | 未裁决前阻断投影；分歧本身不等于审计失败 |
| 任意分类、读者、用途、D_read/D_out、证据、inventory 身份、盲化/人员隔离错误 | **1项即失败，整个 cohort 全量重做** |
| 仅解释文字错字，且不改变事实/证据/授权/依赖 | 1项即暂停；版本化修复、涉事家族100%复核，再走冻结抽样 |
| 错字涉及≥2家族，或超过已审计单位的1% | 视为系统性，整个 cohort 全量重做 |
| 漏审应审单位、伪造计数/样本、缺证据/回执 | 失败；完整补齐及独立复核之前不得放行 |
| 未发现错误但仅有机器结构检查 | 仍等待真人身份/语义审核，不能启动pilot |

“全量重做”须修复编制/证据根因、重新盲化的A/B原稿、仲裁和全量审计，产生新cohort版本；
不覆盖失败原稿。人员/盲化泄露时需更换独立标注人员。
1%仅区分局部修复与全量重做，不允许留下任何错误后开始pilot。
这些是开发质量规则，尚需独立审核，不是风险价值阈值授权。

## 本轮真实证据及限制

只运行明确标为 `SYNTHETIC_AUTHOR_METHOD_FIXTURE_NOT_HUMAN_ANNOTATION` 的2家族、40叶、4任务控制。
“第二份原稿”同样由作者程序构造，不计算为第二位自然人；真实标注者/仲裁者/审计者均0。
原始fixture、投影、验证结果及日志在 `truth-chain-fixture/`。
测试发现fixture的D_read/D_out列表别名错误，已改为独立副本并保留首次失败日志。
11项转换/篡改/审计/不确定处理单测和26项图回归通过。
没有网络执行、模型请求、保留材料或pilot执行。

```sh
python -m benchmark.source_trust_truth raw-ledger.json --output projection.json
python -m ci.validate_source_trust_truth raw-ledger.json projection.json --ledger-sha256 <frozen-ledger-sha256>
```
