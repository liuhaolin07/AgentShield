# AgentShield：供导师与统计研究者审阅的研究设计短报告

**状态：R4 方法学开发阶段结束；等待正式的独立设计评审。** 本文汇总既有证据与待决问题，不构成新协议、预注册或实验授权。拟邀请的导师／统计研究者尚未确定，仓库尚无其具名评审决定。

证据快照：[R4 `0c4c635`](https://github.com/liuhaolin07/AgentShield/tree/0c4c63597fce79b1e698bfa26f60f10bb883934e)，[Draft PR #7](https://github.com/liuhaolin07/AgentShield/pull/7)。下文数字均来自该快照；新增本文没有产生新的防御实验或统计模拟。

## Executive Summary（供首次讨论的一页摘要）

**研究问题：** 来源标注不完整、过时或错误时，来源感知 Agent 的安全—可用性边界如何变化？H5 是候选系统优越性判据，不是整个研究问题。

1. **已证明：** 固定 GHO-1 区间构造在每个非零比例点 5／30 张独立图的预算下，无论观测结果多么理想，都无法确认完整 H5。82 张只是全成功、无缺失时一个必要条件的跨线数，不是联合功效或预算建议。
2. **未证明：** AgentShield 防御无效、其他估计器不可行，或保守策略在真实场景更优。当前没有新增真实 Agent、真人真值或外部系统配对证据。
3. **当前阻塞：** estimand（估计对象与独立单位）、threshold（任务价值依据）、estimator（声明族、有效性与联合功效）、ground truth（独立语义标注与审计）。这些问题不能靠增加相同模拟次数解决。
4. **请求评审：** 先决定暂停、收窄为探索性测量研究，或要求制定新协议。保留 H5 并研究其他预算也只能作为待审方案；修订方法或阈值必须公开版本化。当前协议尚不支持预注册、984 行 pilot 或保留集执行。

建议统计研究者审查 H5、抽样单位与错误率声明；Agent 安全研究者审查威胁模型、来源授权和 sink 契约；任务所有者提供阈值价值依据。机器校验与作者 fixture 不替代这些人的判断。

讨论入口：[外部评审清单与 Reviewer Decision Form](R4_EXTERNAL_REVIEW_CHECKLIST.md)。表格尚未填写，尚无具名正式评审决定。

## 1. 研究问题与可以主张的贡献

**当来源标注不完整、过时或错误时，来源感知 Agent 如何维持可解释的安全—可用性边界？** 污点传播正确并不保证输入标签正确；签名或 HMAC 只能证明声明未被修改，不能证明将敏感内容声明为 `PUBLIC` 是合法的。

候选测量贡献是：对同一冻结任务集施加随机错标、结构漂移和匹配定向干预，区分“错误是否命中任务依赖”与“命中后策略是否稳健”，估计 ASR/TCR 曲线及暴露条件效果。其新颖性仍需 APPA、FIDES、AgentFlow 等工件级核对，不能声称首次解决来源信任。

测量结论与系统优越性须分开。即使保守策略未通过 H5，忠实描述失真边界仍可能有研究价值；只有通过经审查的联合条件，才能主张该策略在预定意义下更优。

当前方法讨论的估计对象是**固定 cohort 上随机全局腐化图的期望**，不是所有真实任务或来源总体。每图产生配对策略、比例和任务的联合响应；图内允许相关，图间 IID 是统计保证的待审前提。任务数、家族数和模拟次数不能替代独立图数；跨图共享随机块时需重新确定独立单位。

## 2. 已证明的设计矛盾

冻结的 [R1 参数](../../source-trust/protocol-draft.json)使用网格 `[0, .05, .10, .25, .50, 1]`，在 `[0,1]` 上积分。令 C 为保守精细化、P 为当前精细化，H5 要求：

- `upper(ASR_AUC_C − ASR_AUC_P) < −.05`；
- 六点均有 `lower(TCR_C − TCR_P) > −.05`；
- 六点均有 `lower(TCR_C) >= .80`。

H5 含 13 项统计量；第一阶段 H1/H2/H3/H5 共要求 17 项同时区间，族错误率 `alpha=.05`。GHO-1 对非零比例点 TCR 的半宽度为

\[
r_n=\sqrt{\frac{\ln(2M/\alpha)}{2n}},\qquad M=17.
\]

任何合法输入的识别下界均值至多为 1。因此，即使全成功且无缺失，其区间下界也至多为

\[
L_{\max}(n)=\max(0,1-r_n).
\]

| 每个非零比例点的独立图数 | 最佳 TCR 下界 | 单项 80% 条件 |
|---:|---:|---|
| 5 | 19.24% | 不可能满足 |
| 30 | 67.03% | 不可能满足 |
| 81 | 79.94% | 不可能满足 |
| 82 | 80.06% | 仅此必要条件可能满足 |

由 `n >= ceil(ln(680)/(2 × .20²)) = 82`，现有 5/30 图预算下**完整 H5 对任何观测输入都不可能确认**。这是固定区间构造的代数性质，无需假定响应模型或图间独立；它不证明其他推断方法也不可行。增加相同配置的 Monte Carlo 次数不会改变这个零。

若 C 的平均缺失比例为 q，最优下界进一步降至 `max(0,1−q−r_n)`。q 为 3%/5% 时，单项必要数变成 113/145。这些数均不保证联合功效，也不是获批预算。E0 是一次固定 cohort 的识别界；清单的 81 个总条件也不是每点 81 张独立图。推导与整数搜索记录见 [SCOPE](SCOPE.md) 和 [解析结果](analytic/report.json)。

必须分别回答：**数学上能否通过、合理效应下有多少联合功效、错误确认率是否受控**。第一项可行不能代替后两项；算法无法确认也不能据此断言真实防御无效。

## 3. 证据账本与边界

| 已保留的证据 | 支持的判断 | 不支持的判断 |
|---|---|---|
| R4 解析界、独立整数搜索、409 个 R3 文件未变 | 构造不可行性及工程一致性 | 第三方独立证明、统计覆盖保证 |
| R3 稀有共同故障模拟：整图 percentile 覆盖 48/200（5 图）、156/200（30 图） | 该模拟条件下存在严重欠覆盖 | 所有 bootstrap 或真实场景都无效 |
| R3 2,000 次 GHO-1 联合模拟，十个条件均确认 0/200 | 冻结模拟的实际输出；R4 解释其结构障碍 | AgentShield 真实防御率、替代方法有效性 |
| R4 完整单测记录 385 通过、0 失败；旧 HTTP 129 HELD / 123 FAILED / 0 UNRUN | 已记录的回归结果；HTTP 为 R3 历史实测 | 本文新增执行、泛化或模型防御效果 |
| TA-2 标注/仲裁/审计/投影哈希链及作者 fixture | 冻结记录可验证，工程流程可运行 | 真人独立标注或 `PUBLIC` 语义正确 |

上述数据分别见 [最终验证记录](final-verification.json)、[R3 报告](../r3/RESEARCH_REPORT_ZH.md)。385 项是既有单测数量，不是 385 次独立安全研究实验。真人真值记录、新 pilot、保留集及 R4 模型请求均为零；替代方法校准和 FIDES/APPA 完整配对运行仍为 **UNRUN**。历史真实模型的 36 项 UNRUN 不能用于估计模型防御效果。

现有实验限于显式包装数据流、受控运行时和本机接收端。错误的明确 `PUBLIC` 授权仍可能泄露；任意 Python 运算、第三方内部转换、模型改写及隐式流不属于完整追踪保证。

## 4. 候选方法应按保证选择

以下仅供讨论，尚未选择、实现或联合校准替代估计器；详见 [候选核查](CANDIDATE_METHODS.md)。

| 候选 | 可以利用什么 | 评审必须排除的误解 |
|---|---|---|
| 配对整图 bootstrap / studentized 方法 | 同图配对、协方差和联合响应 | 配对不自动保证有限样本覆盖；少图、零方差和共同故障不能忽略 |
| 有限样本经验 Bernstein | 已知范围、IID 图与样本方差 | 必须保留原定理小样本修正；所核查构造在 30 图零方差时仍不能满足单项 80% 门槛 |
| H5 交并检验（IUT） | H5 备择要求所有分量成立 | 有效分量检验可控制错误联合确认，但不提供原协议要求的 17 项同时覆盖 |

经验 Bernstein 原文是 Maurer & Pontil (2009)，[Theorem 4](https://arxiv.org/abs/0907.3740v1)；本项目仅核对了假设、公式和代数，未复现替代估计器。IUT 不需假定分量独立，但仍需每个分量检验有效，并另行处理 H1/H2/H3、独立分量结论与测量曲线的错误率分配。若改变声明或推断方法，必须公开产生新协议版本，不能静默替换冻结的同时区间要求。

## 5. 请独立评审作出的决策

| 决策与具体问题 | 需要的依据 | 建议审阅角色 |
|---|---|---|
| 研究目标：固定 cohort 的测量研究，还是系统优越性及任务总体推广？ | 估计对象、抽样单位、可推广范围；允许测量结论独立于 H5 成败 | 研究导师、统计研究者 |
| 阈值：5% AUC 改善、80% TCR、5% 非劣及 2% 等效为何有价值？ | 预定任务中的泄露损失、未完成损失与最低可接受效用；明确由谁承担风险并认可阈值 | 任务所有者、安全研究者 |
| 声明：保留 17 项同时区间，还是另设 H5 联合决策？ | 各声明族、alpha 分配、有限样本定理与适用前提；不能以窄区间作为选法理由 | 统计研究者 |
| 方法与预算：哪个候选在预定条件下可用？ | 先审结构可行性，再锁定完整六点响应、缺失与跨图相关模型；审查联合功效、覆盖和错误确认的校准精度 | 统计研究者、复现审阅者 |
| 真值：谁有权判定哪些数据对哪些读者/用途公开？ | 叶级标签、读者/用途、`D_read/D_out` 独立盲化标注，第三人仲裁与独立审计；执行已冻结的严重错误/全量重做规则 | 数据领域人员、安全研究者 |
| 外部验证：FIDES/APPA 能否以相同任务契约配对运行？ | 机制与版本映射、执行证据和可比性；无法落地时先收窄为内部测量研究 | 外部系统研究者 |

这些角色尚未落实，表格不是已获得的审批。标注争议与 `UNCERTAIN` 不能投影成 `PUBLIC`；No Defense 只验证载荷和可观测性，不能按其结果反向选择入组任务。哈希、机器门禁和作者 fixture 都不能代替人的独立判断。

建议一次评审给出明确选择：**暂停；收窄为探索性测量研究；或要求制定经审阅的新协议**，并记录异议、条件和责任人。只有估计方法、阈值、预算与真人真值流程获得实质审查后，才决定是否开展真实策略 pilot；pilot 不能充当确认性保留证据。外部保留材料须在协议冻结后一次性评估；真实 Agent 与外部系统配对各自还需满足独立执行条件。

当前决定是结束 R4 工程迭代并提交本报告供人审阅，不新增方法脚本或模拟，不启动预注册、984 行 pilot 或保留集。正式设计评审决定尚未形成，本文也不声称项目已经达到投稿标准。

## Reviewer Decision Form

请使用[外部评审清单末尾的空白决策表](R4_EXTERNAL_REVIEW_CHECKLIST.md#reviewer-decision-form)，记录审阅提交、专业领域、证据、异议和待决条件。建议修改协议与接受特定新版本的 pilot 设计分别记录；所有勾选项均为空，不代表已有批准，也不自动改变当前执行暂停状态。

## English abstract

AgentShield's candidate research question is how imperfect source annotations affect security and utility under explicit provenance tracking. R4 proves that the fixed GHO-1 interval construction cannot confirm joint H5 at either the 5- or 30-graph budget, even with perfect observations. The 82-graph crossing is a necessary best-case bound for one component, not a power guarantee or an authorized budget. Existing simulations and regression evidence remain frozen. No alternative estimator has been selected or validated, and human semantic ground truth and paired external-system experiments remain pending. This brief requests independent review of estimands, task-value thresholds, simultaneous coverage versus joint decisions, dependence, missingness, and execution gates before any new protocol or pilot.
