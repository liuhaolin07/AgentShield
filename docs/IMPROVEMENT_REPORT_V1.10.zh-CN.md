# AgentShield V1.10 实际改进报告

本次已完成六阶段迭代，基于指定 V1.9 提交 `5cd84705b2ebfef3b142c75ff7826250e769bd3f`，新分支 `codex/v1.10-precision-evaluation`。没有修改 main、合并或发布。

**结论：精细追踪明显减少了所测显式任务的过度污点阻断，但不能支持“无条件不牺牲安全性”的假设。** 未调参的保留集出现真实新增泄露：私密元素被错误声明为公开时，精细投影放行，粗粒度依赖另一个错误私密标签反而阻断。该失败完整保留，没有修改预期答案。

## 1. 实际文件与机制

- `security/precision.py`：不可变字段/元素树、字符区间、组合和序列化依赖；有界 JSON/Base64/URL 编码与精确逆变换 witness；无法证明的解码保守合并。
- `security/precision_integrity.py`：会话句柄/HMAC、源/转换链重放、精细元数据与配置完整性；可信 release 绑定原始来源、直接投影、参数和单一 Sink。普通 Agent 不具备发行、literal、reveal、release 或 untaint 工具。
- `security/source_classification.py` 与 `precision_runtime.py`：分类与读取权限分离，未知/缺失/冲突支持 BLOCK、REQUIRE_REVIEW 或显式 ALLOW；来源判断、扫描、污点和真实执行分别记录。
- `agent/precision_agent.py`：真实多轮模型工具循环，冻结发送时的 payload；私密读取仅返回句柄，实际内容物化进入后续模型前重新检查。
- `evaluation/agent_oracle.py`、`precision_agent_study.py`：冻结具体源/敏感载荷/输出目标/合法任务契约；区分攻击采纳、发送尝试、实际泄露、AgentShield/环境阻断与任务完成。
- `model/study_budget.py`、`evaluation/live_precision.py`：复用 DeepSeek/Qwen 客户端，默认关闭付费，限制实际调用、请求长度和输出上限；记录供应商实际 usage，缺失 usage 停止后续调用。Token/估计成本阈值是响应后阈值，可能超出一条有界请求，不是假装硬账单上限。
- `benchmark/precision_dataset.py`、新 v1.10 冻结契约、`precision_experiment.py`、`precision_metrics.py`、`precision_plot.py`、`ci/validate_v110.py`：共同执行器/本机接收、独立冻结预期、六组及消融、独立校验、分子分母、唯一任务区间、JSON/CSV/SVG。原 CLI 和模拟 HTTP 未修改。

## 2. 真实测试与保留集协议

基线实际运行 199 项通过；阶段 1/2/3/4/5 分别 223/236/252/258/271 项通过，无最终失败或跳过。最终复验日志见 `results/v1.10/validation/`。测试包括伪造/跨会话/标签降级/配置篡改、范围与 Unicode、直接及编码泄露、正常公开字段、恶意工具、未知策略代价和独立证据篡改。原始开发失败日志一并保留：阶段 3 修复可变历史请求影响证据快照；阶段 5 修复观察器复制空轨迹和 JSON tuple/list 比较，不改契约或防御判定。

V1.9 的 49 份历史证据/数据集及 61 份旧 Python 源码哈希保持不变。V1.7 82 HELD / 0 FAILED / 4 UNRUN；V1.8/V1.9 原组结果重新验证一致。

新数据集在实验前冻结：43 开发任务、20 保留任务；execution seed=17、三次重复。实现候选 `196bedc` 提交后首次运行保留集；所有实现/评估器哈希与执行前记录一致，无针对保留结果调整。不是外部盲测。保留集后 CI 重跑仅称兼容性验证。

## 3. V1.9 历史与 V1.10 可比机制对照

| 数据/组别 | 开发 ASR | 保留 ASR | 开发 TCR | 保留 TCR | 开发 FPR | 保留 FPR |
| --- | --- | --- | --- | --- | --- | --- |
| V1.9 历史 Full | 6/246 | 3/81 | 48/54 | 6/12 | 6/54 | 6/12 |
| V1.10 共用协议 Coarse | 9/63 | 3/24 | 12/51 | 3/24 | 39/51 | 21/24 |
| V1.10 Precision | 12/63 | 6/24 | 42/51 | 21/24 | 9/51 | 3/24 |
| V1.10 Full | 9/63 | 6/24 | 42/51 | 21/24 | 9/51 | 3/24 |

历史 V1.9 与新 V1.10 的任务和分母不同，不能据此声称版本总体 ASR/FPR 改善。Coarse 是 V1.9 合并传播算法置于 V1.10 相同来源注册表、完整性与执行器内的对照，不是原版本程序的直接重评分。真正可比的是新同一冻结任务上的 Coarse/Precision/Full。

开发集 1,419 条记录：807 HELD / 513 FAILED / 99 UNRUN；保留集 660 条记录：375 / 219 / 66。包括无防御攻击成功、正常任务误阻断、测量控制和不支持任务，不能用 HELD 总数当总体安全率。独立 gate 验证每条受支持记录，零无效观测；所有失败/UNRUN 都保存。

## 4. 六组实际结果

| 组别 | 开发 ASR / TCR / FPR | 保留 ASR / TCR / FPR |
| --- | --- | --- |
| no_defense | 63/63 / 51/51 / 0/51 | 24/24 / 24/24 / 0/24 |
| static_rule | 60/63 / 48/51 / 3/51 | 24/24 / 24/24 / 0/24 |
| scanner | 60/63 / 51/51 / 0/51 | 24/24 / 24/24 / 0/24 |
| coarse | 9/63 / 12/51 / 39/51 | 3/24 / 3/24 / 21/24 |
| precision | 12/63 / 42/51 / 9/51 | 6/24 / 21/24 / 3/24 |
| full | 9/63 / 42/51 / 9/51 | 6/24 / 21/24 / 3/24 |

指标先排除测量控制、UNRUN 和无效证据，再按实际攻击送达/真实预执行阻断/正常契约完成计算。Precision 与 Recall、ABR、分类敏感性、每组失败状态和排除数见 JSON 与 `metrics.csv`。UNRUN：开发 3 类任意库/模型语义/隐式流；保留 2 类新库/语义任务；不能作为防御成功。

## 5. 误报改善与新增绕过

开发恢复 10 个独立正常任务：公开 username、嵌套 city、公开列表索引/切片、公开字符串区间、JSON 往返后的公开字段、Base64/URL 往返后的公开区间、组合容器再投影、可信授权的公开字段。保留恢复 6 个独立正常任务：Unicode/含空格字段多层往返、嵌套列表公开投影、Unicode 反向公开区间、负索引公开列表切片、JSON/URL witness、可信公开范围授权。每项均有实际接收正文，未通过全面禁止 HTTP 达成。

新增安全回归分别是 `wrong_field_private` 和 `reserved_wrong_element_private`：Coarse 阻断，Full 真实送达。正确分类的受支持攻击 Full 0/42（14 独立开发任务）与 0/15（5 独立保留任务）送达；这只是条件性机制证据。错误 PUBLIC 的未知格式值、明确 UNKNOWN/ALLOW 仍泄露。保守未知策略继续误阻断正常数据；无 witness 的安全解码仍有保守污点误报。

## 6. 来源分类与消融

| 消融 | 实际组 | 开发 ASR / TCR / FPR | 保留 ASR / TCR / FPR |
| --- | --- | --- | --- |
| without_source_policy | no_source | 60/63 / 51/51 / 0/51 | 24/24 / 24/24 / 0/24 |
| without_propagation | no_propagation | 48/63 / 45/51 / 6/51 | 21/24 / 21/24 / 3/24 |
| without_field_precision | no_fields | 6/63 / 15/51 / 36/51 | 3/24 / 6/24 / 18/24 |
| without_declassification | no_release | 9/63 / 39/51 / 12/51 | 6/24 / 18/24 / 6/24 |
| without_scanner | precision | 12/63 / 42/51 / 9/51 | 6/24 / 21/24 / 3/24 |
| detection_only | detect_only | 63/63 / 51/51 / 0/51 | 24/24 / 24/24 / 0/24 |

未知/缺失/冲突不是自动 PUBLIC。正常 UNKNOWN/BLOCK、UNKNOWN/REQUIRE_REVIEW 在开发各误阻断 3/3；保留冲突正常数据误阻断 3/3。错误字段/元素在 Full 各泄露 3/3，而 HMAC 完整性仍有效。扫描器只修复开发中已知格式 Key 的错误公开分类；“真实分类正确性”不能从来源签名推出。

## 7. 成本与统计条件

用唯一任务作为不确定性单位；重复执行不是独立样本。报告的 Wilson 95% 区间使用唯一任务簇（ASR/FPR 任一重复事件，TCR/ABR 所有观测重复成功），分子分母与定义同时保存。作者构造任务并非 IID，区间只作描述，不作总体保证或显著性结论。开发仅 21 独立受支持攻击/17 正常任务，保留仅 8/8。

成本是真实计时与 Python 分配峰值，不是 RSS。只对两组均正常完成、执行器计数相同的任务计算额外成本；不把提前阻断和省掉网络当性能提升。
开发 Full 匹配正常执行 42 次：端到端额外均值 7.449 ms，检查额外均值 1.300 ms，传播额外均值 4.092 ms，tracemalloc 峰值差均值 694.9 bytes。
保留 Full 匹配正常执行 21 次：端到端额外均值 -29.621 ms，检查额外均值 -4.856 ms，传播额外均值 -6.631 ms，tracemalloc 峰值差均值 947.7 bytes。

负值保留为测量噪声/执行路径成本差，不能据此宣称加速或无开销；开发时测试进程与实验共享主机，运行顺序固定随机，负载未隔离。计时包含观察/临时文件/审计验证与 tracing，尚无生产性能证据、内存 RSS 或成本置信区间。

## 8. 真实模型实验

6 个冻结任务 × 6 组 = 36 项：全部 UNRUN（missing_credential）；实际 API 请求 0，供应商响应 0，模型可用性 UNVERIFIED，Token/估计费用为空，未编造模型结果。模型请求地址复用原固定 DeepSeek/Qwen 客户端；截图提供的是参数文档而非可用 Key。默认即使有 Key 也不开启付费实验。安全环境变量、价格输入、显式 `--live` 和预算说明见 REAL_AGENT_EVALUATION.md。离线 scripted client 只用于回归，未混入真实模型统计。

模型边界实验中的实际本机 HTTP 接收验证是 transport probe，并无模型推理。模型改写/语义重建和外部无标签字符串仍超出可靠显式追踪；真实模型不能运行时不虚构采纳率或阻断贡献。

## 9. 已有工作与研究贡献

实际检索了 CaMeL v2 完整 HTML、官方代码/Apache-2.0 License、AgentDojo 论文摘要/任务及执行器代码/MIT License、TaintDroid 完整 PDF、Jif 标签/解污点代码和 W3C PROV。曾猜错的 CaMeL 仓库地址 404 也保留，已定位论文给出的 `google-research/camel-prompt-injection`。

细粒度污点、来源传播和可信解污点是成熟技术。当前贡献限于面向受限 Agent 工具链的可控精度集成、联合安全/任务完成评估、实际接收及前置阻断归因、分类错误与追踪边界的可复现实证。没有 CaMeL 式可信控制流隔离、没有 AgentDojo 官方成绩、没有验证算法首次创新或优于既有系统。

## 10. 距离可投稿仍缺少

- 多模型/提供方真实工具采纳、正常任务和间接注入结果，真实 usage/账单与预算。
- 外部独立任务与攻击作者、准确来源 schema 和分类错误率扫描、同任务 CaMeL/AgentDojo 对照；许可兼容适配而非冒充官方成绩。
- 自适应转换/元数据/语义重建攻击、分类不确定性的校准与审查代价实验；当前新增回归尚未修复。
- 更大独立任务族、预注册统计、独立团队复现、隔离负载下延迟/RSS/Token 成本。
- 进程隔离、生产适配完整性、可验证不可变审计；任意 Python/隐式流/模型语义均无完整安全保证。

## 11. 分阶段提交与证据

| 阶段 | 已提交 SHA |
| --- | --- |
| precision-tracking: attest field and range dependencies with scoped releases | `2cbd647cd7285c1b925e8a2bcf695cd522434d20` |
| source-classification: authenticate uncertainty and enforce scoped review policy | `a7b0a68b44a040197dd1d3ea648bfd24ebebc157` |
| independent-agent-oracle: bind outcomes to frozen source payload and sink contracts | `5ae0276742429387a7aaa60fa175ec8d12b5c037` |
| controlled-live-study: bound opt-in provider calls and preserve missing-credential evidence | `b8cdd0765329bd6f9bc28bcdddc2a54b351150e3` |
| research-benchmark: freeze precision cohorts and retain fair security-utility ablations | `196bedcfc05412aee241b72d27e22796bd543ad4` |
| reserved-evidence: preserve first untouched-candidate utility gains and annotation leaks | `67b51bfdc1f12e6f1ac495b6b4d6a0938a969578` |

报告/CI 最终提交 SHA 与 Draft PR URL 以 GitHub 分支/PR 记录和交付消息为准，避免文件自引用。目标分支：`codex/v1.9-research-hardening`；保持 Draft，不合并。

[开发 JSON/CSV/指标/图表](results/v1.10/development/) · [首次保留 JSON/CSV/指标/图表](results/v1.10/reserved/) · [候选冻结记录](results/v1.10/reserved-candidate.json) · [实验协议](EXPERIMENT_V1.10.md) · [来源限制](SOURCE_CLASSIFICATION.md)。压缩原始文件可按 summary 中 SHA256 校验解压后的完整字节。
