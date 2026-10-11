# 统计候选复审：先明确信息与声明，暂不选择新估计器

这是事后开发评审；所有候选的完整覆盖/功效/联合错误率校准均 **UNRUN**。
未替换GHO-1，未修订冻结R1/R3参数，未请求新预算；更窄不是更正确。

## 估计对象和随机化单位

沿用固定cohort上的随机全局腐化图期望。每图产生配对策略、比例、任务的13维向量，
同图内家族、比例和策略允许任意相关；图间IID仍需机制证明/独立审查。
家族数、任务数、重复次数、Monte Carlo次数不能代替图数。
若跨图共享一个随机效应或种子块，必须把独立块作为单位，不能直接套IID整图界。

考虑方法时先写出完整接口：输入每图L/U识别界、一次E0识别界和全分母；
输出13项区间、95%逐格观测门禁及联合判定，并保留不足/缺失，不筛选完成案例。
固定cohort不保证可以推广到随机来源/任务总体；该推广是另一抽样设计。

| 候选 | 可能利用的信息 | 目前的限制与状态 |
|---|---|---|
| GHO-1 | 已知范围、IID图 | 5/30图绝对TCR数学不可通过；现预算不宜继续增加相同MC次数 |
| 配对整图percentile / studentized bootstrap | 整图配对和方差；同一重采样索引作用于全向量 | 前者已有稀有共同故障欠覆盖；后者需新推导/校准，零方差和少簇不能当成功 |
| 有限样本经验Bernstein界 | 每图配对差的样本方差及已知范围 | 可有IID有限样本界，但小n修正不可删；零方差也不为零宽；尚未集成/校准 |
| H5交并检验（IUT）作为决策层 | H5是13条件全成立的联合备择 | 与同时13/17项区间不同；须公开改协议并处理其他假设族，不能暗改当前17倍校正 |

配对可以减少差值方差，不能将真实共享故障当作不存在。
直接给所有`family × graph`行做簇t检验也不解决全局图相关。
常规t/正态区间不是此处任意有界分布的小样本覆盖定理。

## 一个经原文核对的方差敏感界

Maurer & Pontil (2009), *Empirical Bernstein Bounds and Sample Variance Penalization*,
[arXiv:0907.3740v1](https://arxiv.org/abs/0907.3740v1)，Theorem 4（PDF第2页）。
核对了原文的IID、[0,1]、无偏样本方差和`7/(3(n-1))`项。
下载散列/版本/定位在 `literature-evidence.json`，不把未验证的工件实现称为复现。

对长度R的范围与原尺度样本方差s²，取每个单侧尾部`delta=alpha/(2M)`，
由归一化及对补变量使用同一定理可得到双侧半宽候选

`r_EB = sqrt(2*s²*ln(4M/alpha)/n) + 7*R*ln(4M/alpha)/(3*(n-1))`。

这里保留当前 `M=17, alpha=.05`。对不同的L/U识别端点分别控制所需的一侧尾部，
不能错误地令缺失识别界的上下端点共用一个更小的尾部预算。
此处仅讨论定理和零方差时的代数，并未实现新的联合估计器。

R=1、s²=0时，n=30的半宽仍为0.580537（比GHO-1的0.329699更宽）；
n=85为0.200423、n=86为0.198065。
因此这个具体经验Bernstein构造在最有利零方差条件下也需要86图才跨过单项80%门槛。
这不是所有方差敏感方法的下界，更不是86图的联合功效/预算建议。
若删除小n修正再报告漂亮功效，会失去引用的有限样本保证。

零观测方差不证明没有共同故障。例如IID二值图结果以.95概率为1，
30图全部为1的概率`.95**30=0.214639`。若用零宽区间[1,1]，该事件必漏掉真实均值.95。
这是解析的覆盖反例，不是新增的模拟结果，也不直接等同于H5错误确认率。

## 联合决策与同时区间不应混淆

H5的备择是所有13个条件同时成立，其原假设是至少一条件不成立。
若每个所需单侧检验在其对应分量原假设下有level `alpha_H5`，
拒绝整个原假设要求全部拒绝。因此错误确认事件是某个真分量原假设被拒绝事件的子集，
H5决策可控制在`alpha_H5`，并不要求分量独立。
但这**不给出同时13个区间覆盖**，也不控制同时报告H1/H2/H3及独立分量结论的错误率。

冻结R1要求17项同时区间；R4不改变它。若未来采用IUT，须分别声明：
(a) 测量曲线/区间的覆盖族；(b) H5系统优越性这一决策；(c) 其他假设的族与alpha分配。
不得用IUT来给原17项同时区间的解释背书。

即使只做H5、用单侧Hoeffding且不再分配到17项，在alpha_H5=.05时，
全成功单项仍需 `ceil(ln(20)/(2*.2²))=38` 图；30图仍不可过80%门槛。
若将首阶段4个假设族各分配.05/4，该单项必要数为55。
这两个数只展示拟议声明改变对数学宽度的影响；当前R1参数、预算、图生成器都未改变。

## 不适用的捷径

Clopper–Pearson适用于IID二值试验；每图平均TCR是[0,1]中的分数，不能把图×任务
当作独立Bernoulli来获得“精确区间”。若改用随机抽一任务或“整图全部任务完成”二值化，
须证明对原估计对象的关系、重建配对/依赖契约并评估信息损失，不能悄悄改变TCR定义。
同样，策略名称不能在复合均值原假设下任意交换为“精确随机化检验”；
需明确真实分配机制和可检验的原假设。当前均未实现或运行。

## English interpretation

Whole-graph pairing identifies the sampling unit, not a finite-sample interval guarantee.
The inspected empirical Bernstein theorem retains a nonzero small-sample correction; it does
not rescue the current 30-graph budget even at zero observed variance. An intersection–union
decision can control false joint confirmation under valid component tests, but does not furnish
the simultaneous coverage required by the frozen protocol. Any such change needs an explicit
new protocol version and review. No alternative estimator has been selected or calibrated here.
