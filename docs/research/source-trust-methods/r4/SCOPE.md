# R4：先检查数学可行性，不申请新执行预算

冻结整个R3提交 `962390e6ea2c75b93534356dcef2110335da4742` 的409个文件。
R4仅新增路径；旧源码、配置、数据、结果与原始失败日志不改写。
这轮是对既有构造的事后方法核查，不是新预注册、独立保留实验或候选方法胜出证据。

## GHO-1结构性限制

令 `L=ln(2M/alpha)`，保持R1 `M=17, alpha=.05, t=.80`。
非零比例点的绝对TCR下界由GHO-1计算为
`max(0, mean(lower_identification_bound)-sqrt(L/(2n)))`。
任何有界数据的该均值≤1，所以

`lower(TCR) <= max(0,1-sqrt(L/(2n)))`。

因此 `n < ceil(L/(2(1-t)^2)) = 82` 时，至少一个非零点必不满足绝对TCR门禁，
完整H5不可能确认。对5/30图，这对所有观测样本成立，甚至不需要独立性或响应模型假设；
它是区间**构造的代数性质**，不是覆盖保证，也不是模拟功效估计。
增加同配置Monte Carlo试验次数只能更精确地计数这个零，不改变结构性限制。

这里的82是单个必要条件、全成功无缺失的最优界；不是保证联合功效的充分样本量。
E0在GHO-1中是一次固定cohort的识别区间，不使用这个随机图半宽度。
共享真实图内任务、比例、策略的相关性不能通过扩充家族/任务/重复或复制图解决。
81个总清单条件不等于每个比例点81张独立图：原清单包含76个E0/E1和5个E3条件。
不得将清单容量、200次Monte Carlo试验或120个任务当成独立图数。

若一非零点C有平均缺失比例q，已观测结果全成功时，均值下界也最多1-q。
`n >= ceil(L/(2(1-q-t)^2))` 仅在 `q < 1-t` 时有有限解；
q=.03/.05的单项必要下限为113/145。q≥.20时有限n均无法跨过该下界。
这并不声称真实缺失独立、是MAR，或达到了95%观测门禁。

R4诊断还会在**冻结的有利假想真值**处计算区间跨线条件；
例如非零点的delta_TCR=.019时，严格非劣需要 `2*r_n < .019+.05`，中心跨线需2740图。
这不是“至少2740图才可能通过任意随机样本”，也不是实际策略效应、功效估计或预算建议。
真实样本均值具有随机性；联合功效须另按完整响应和观测机制验证。

## 三项分开的评审问题

1. **结构性可行性**：样本空间中的任何合法输入是否可能通过？GHO-1在5/30图：否。
2. **合理效应下的功效**：即使可通过，有多大概率确认完整H5？替代候选尚未选定/运行。
3. **错误率控制**：当IID图或缺失假设变化时，错误确认是否受控？替代候选尚未验证。

第一项通过不能替代后两项；更窄区间或没有错误确认均不能单独证明有效方法。
不修改5%改善/非劣、80%TCR、2%等效或17项校正；其任务价值仍需独立授权。
人类真值、FIDES/APPA配对和真实Agent各自仍待完成，不用数学门禁替代。

## Engineering scope

`evaluation/source_trust_feasibility.py` uses deterministic bounded arithmetic and retained R1/R3 inputs.
It produces analytic JSON/CSV, not simulation rows, defense decisions or independent observed graphs.
Regression witnesses exercise the existing estimator on constructed extreme values solely to verify its algebra.
No candidate estimator is replaced, no resource/execution budget is increased, and no pilot/holdout is launched.
All 409 R3 paths are pinned to Git objects; this research revision is not an AgentShield version increment.
