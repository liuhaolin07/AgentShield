# 候选材料作者复核与离线描述分析

240 个叶字段的契约真值/授权、24 个单字段任务的执行前依赖与正文摘要通过一致性检查。这是作者自查和自动检查；独立语义复核仍为 PENDING，正式接收仍为 0。

下表分母均为每条件每任务类型的 12 个家族；保留种子，不跨条件汇总。12 个家族共用 1 个模板，984 行不是独立样本。

ASR=未授权攻击正文实际送达/计划攻击任务；TCR=有完整证据的正常完成/计划正常任务；FPR=有证据的正常任务误拒/计划正常任务。控制臂单列。

| 条件 | p | seed | 策略 | ASR | TCR | FPR |
|---|---:|---:|---|---:|---:|---:|
| correct | 0 | None | coarse | 0/12 | 0/12 | 12/12 |
| correct | 0 | None | precision | 0/12 | 12/12 | 0/12 |
| correct | 0 | None | conservative | 0/12 | 12/12 | 0/12 |
| sensitive_to_public | 0.1 | 17 | coarse | 0/12 | 0/12 | 12/12 |
| sensitive_to_public | 0.1 | 17 | precision | 1/12 | 12/12 | 0/12 |
| sensitive_to_public | 0.1 | 17 | conservative | 1/12 | 12/12 | 0/12 |
| sensitive_to_public | 0.1 | 29 | coarse | 0/12 | 0/12 | 12/12 |
| sensitive_to_public | 0.1 | 29 | precision | 0/12 | 12/12 | 0/12 |
| sensitive_to_public | 0.1 | 29 | conservative | 0/12 | 12/12 | 0/12 |
| sensitive_to_public | 0.25 | 17 | coarse | 0/12 | 0/12 | 12/12 |
| sensitive_to_public | 0.25 | 17 | precision | 3/12 | 12/12 | 0/12 |
| sensitive_to_public | 0.25 | 17 | conservative | 3/12 | 12/12 | 0/12 |
| sensitive_to_public | 0.25 | 29 | coarse | 0/12 | 0/12 | 12/12 |
| sensitive_to_public | 0.25 | 29 | precision | 2/12 | 12/12 | 0/12 |
| sensitive_to_public | 0.25 | 29 | conservative | 2/12 | 12/12 | 0/12 |
| public_to_sensitive | 0.1 | 17 | coarse | 0/12 | 0/12 | 12/12 |
| public_to_sensitive | 0.1 | 17 | precision | 0/12 | 11/12 | 1/12 |
| public_to_sensitive | 0.1 | 17 | conservative | 0/12 | 11/12 | 1/12 |
| public_to_sensitive | 0.1 | 29 | coarse | 0/12 | 0/12 | 12/12 |
| public_to_sensitive | 0.1 | 29 | precision | 0/12 | 11/12 | 1/12 |
| public_to_sensitive | 0.1 | 29 | conservative | 0/12 | 11/12 | 1/12 |
| public_to_sensitive | 0.25 | 17 | coarse | 0/12 | 0/12 | 12/12 |
| public_to_sensitive | 0.25 | 17 | precision | 0/12 | 10/12 | 2/12 |
| public_to_sensitive | 0.25 | 17 | conservative | 0/12 | 10/12 | 2/12 |
| public_to_sensitive | 0.25 | 29 | coarse | 0/12 | 0/12 | 12/12 |
| public_to_sensitive | 0.25 | 29 | precision | 0/12 | 11/12 | 1/12 |
| public_to_sensitive | 0.25 | 29 | conservative | 0/12 | 11/12 | 1/12 |
| bidirectional | 0.1 | 17 | coarse | 0/12 | 0/12 | 12/12 |
| bidirectional | 0.1 | 17 | precision | 1/12 | 9/12 | 3/12 |
| bidirectional | 0.1 | 17 | conservative | 1/12 | 9/12 | 3/12 |
| bidirectional | 0.1 | 29 | coarse | 0/12 | 0/12 | 12/12 |
| bidirectional | 0.1 | 29 | precision | 0/12 | 10/12 | 2/12 |
| bidirectional | 0.1 | 29 | conservative | 0/12 | 10/12 | 2/12 |
| bidirectional | 0.25 | 17 | coarse | 0/12 | 0/12 | 12/12 |
| bidirectional | 0.25 | 17 | precision | 3/12 | 8/12 | 4/12 |
| bidirectional | 0.25 | 17 | conservative | 3/12 | 8/12 | 4/12 |
| bidirectional | 0.25 | 29 | coarse | 0/12 | 0/12 | 12/12 |
| bidirectional | 0.25 | 29 | precision | 0/12 | 10/12 | 2/12 |
| bidirectional | 0.25 | 29 | conservative | 0/12 | 10/12 | 2/12 |
| control | 0 | None | no_defense | 12/12 | 12/12 | 0/12 |
| control | 0 | None | reject_all | 0/12 | 0/12 | 12/12 |

全部 82 个任务类型单元均为 12/12 有效观测。JSON 另报 X_any/X_all 条件 ASR；暴露分母为零时为 null。缺失处理使用计划分母，逐指标报告 [已知成功/n, (已知成功+未知)/n]；这只是识别界，不是置信区间。评分异常不会抹掉已有攻击送达证据，未运行不能计作阻断。

## 可写入论文的工程事实

在作者定义的合成单字段 identity 子集，冻结运行时完成 936 行主条件与 48 行控制的工程演练；接收记录确认 324 次送达、660 次阻断且无缺失。正确标签下 coarse 同时阻断全部正常任务；precision/conservative 的正确标签 ASR=0、TCR=1、FPR=0。两者在本子集的 312 对观测一致，结合执行前机制检查仅支持适用范围说明，不能宣称 H5 优越性或跨范围等价。

敏感→公开错标率 p=0.25 时，precision 与 conservative 在种子 17/29 下的 ASR 分别为 3/12、2/12；公开→敏感错标率 p=0.25 时，两者的 TCR 分别为 10/12、11/12，FPR 分别为 2/12、1/12。这些数值只描述指定条件，不能从两个种子推出显著性或总体效果。

## 尚缺证据与下一步完成标准

1. P0 独立材料复核：由非本次作者逐项核验真值、授权和 D，记录身份、材料摘要、争议及处置；当前未有该证据。补齐 60 个开发家族，独立核验模板结构，不能以改字段名扩充独立样本。
2. P1 评测实现验证：本次完成描述指标与逐单元缺失界，后续仍须实现配对差值/曲线/多重校正、模板聚类区间及覆盖率仿真，固定缺失门禁和阈值依据；单模板不能提供功效、ICC 或区间覆盖证据。
3. P2 正式开发 pilot：在材料和执行前依赖校准完成后，单列执行 984 行 pilot 并验证功效/覆盖标准；本次工程演练不抵扣该预算。H4 机制仍须按协议选择，不能以当前 identity 结果代替。
4. P3 注册与独立复跑：补齐外部封存保留材料、分析代码与所有证据门禁，冻结并注册后按原预算开展确认性实验；再由独立环境复跑并核对摘要和结果。

本报告未调用模型、未新发 HTTP、未重新演练。原 H1–H5 数值边界、54,720 行 E0/E1 与 3,600 行 E3预算保持；H5 角色仅引用已有显式修订。本报告为观察结果后的描述分析，不是事前注册。

真实模型行为、FIDES/APPA 适配以及未接入中间件的网络/文件/进程/最终回复外发路径，仍只能作为未覆盖范围或 future work；当前不能声称完整信息流隔离、通用 Agent 安全或 H1–H5 得到确认。

## 离线复核

在仓库根目录执行以下命令，无需模型或接收器；已有输出只允许相同字节重建。

```sh
python docs/research/source-trust/convergence/candidate_analysis.py --output docs/research/source-trust/convergence/candidate-materials-v1/review-analysis-v1
python -m unittest discover -s docs/research/source-trust/convergence -p 'test_candidate_analysis.py' -v
```
