# D5 v2：事前冻结的校准验收

本目录只做离线数学模拟，不是正式材料、模型实验或 pilot。旧 `statistics-validation-v1`、`rare-event-validation-v1` 和原估计器不改字节。

## 本轮合同

用户在生成校准结果前明确接受以下 C6 澄清，旧 C6 文本仍保留为历史原文：

- 9 个覆盖验证情境，每情境 4,000 个数学数据集。原 `rare_event_30` 仍在必须通过的验证域，不改列为负控制。
- 4 个负控制，每情境 100 个数学数据集。单模板和 H3 只有 29 个合格簇必须拒绝确认推断；常数与全零必须触发退化拒绝。原始覆盖仍报告。
- 每个验证情境的 17 项共同覆盖比例使用 Clopper–Pearson 区间，Monte Carlo alpha=.05/9，同时覆盖 9 个共同覆盖率。只有整个 MC 区间落在 [93%,97%] 才通过；与边界重叠为证据不足，也不通过。
- 每分量另报边际 MC95 区间，明确不是分量间或情境间的同时区间。Bonferroni 分量名义覆盖为 `1-.05/17`，不能替代共同覆盖。
- 所有计划数据集都进入分母。无区间按未覆盖计；逐分量独立计数，不以其他分量是否可用来决定该分量是否记账。
- 每统计量至少 30 个独立模板簇；不足时保持描述性。不能换家族单位绕开共享模板。
- 正式预算仍为 E0/E1=54,720、E3=3,600、pilot=984。本目录的数学模拟数不是新正式样本量。

`config.json` 冻结偏差模型、采样假设、模拟数量、seed、接收带和重放抽样。源代码与 config 一起先提交，再用 `freeze` 绑定实际 commit、全部已跟踪文件的 SHA-256 和带时区的真实冻结时间；有未提交改动、检出字节与 commit 不一致、旧输出目录已存在都拒绝。

这只是本地事前冻结，不冒充项目最终注册或第三方时间公证。冻结后改变代码或合同会使验证拒绝；必须保留原尝试，并以新版本、新目录明确记录修订。

## 模型与真值

保留原 7 种组件情境；另加全零负控制、4 种可实现二元端点过程及 H3 合格簇负控制。可实现模型逐家族生成原配方要求的 120 个 ASR/TCR/FPR 端点，而不是随意拼 17 个独立数。

每个 condition/policy/seed 下，正常任务由同一个 U 形成三个互斥结果：TCR 成功、FPR 阻断、其他。攻击 ASR 是二元结果。共享 cluster U、family U 与独立 U 之间采用分类选源，不做 U 的线性加权；每个源本身均匀，因此边际仍均匀。q~Bernoulli(.2) 与这些 U 分开生成，错误冲击在概率尺度上加 `scale*p*(q-.2)`，不做 logit 或裁剪。对 q=0/1 的全部支持点验证概率合法和 TCR+FPR<=1，因而积分后的边际仍是源码中的基线概率。

差异缺失是**任务级观测缺失**：攻击 ASR=1 或正常 TCR=0 时缺失概率 .25，否则 .02。一个正常任务的 TCR/FPR 使用同一个缺失指示。缺失后保持家族与计划分母，把端点留为 [0,1] 识别界，按原配方的系数符号传播。

真值先积分潜在错误与随机 U，再按固定家族等权、合格种子、原 `recipes()` 汇总；不是每次实现的 q 均值、完整案例均值或簇等权。E0 只有原配方的一份；H3 合格集按簇序号事前确定。

`d5_models.py` 的快速路径与可检查的 `families` 参考路径做逐项差分；批量 bootstrap 与原 `bootstrap_bounds()` 做全部 17 项差分。加速不修改 10,000 次重采样、seed=1729、校正尾概率、type-7 分位数和未定义 draw 的拒绝规则。

## 命令与退出码

仓库根目录，Python 3.12，依赖见 `requirements.txt`。Hermes 环境用隔离模式并显式启用 UTF-8；脚本也清理 PYTHONPATH 和 sys.path。原 212 项套件不递归发现本目录无 `__init__.py` 的独立工程测试。

```bash
python -I -X utf8 -m unittest discover -s docs/research/source-trust/convergence/d5-calibration-v2/tests -p 'test_*.py' -v

# 只能在代码和合同已提交、worktree 干净时执行。输出路径必须全新。
python -I -X utf8 docs/research/source-trust/convergence/d5-calibration-v2/run_d5.py freeze --output <新目录>
python -I -X utf8 docs/research/source-trust/convergence/d5-calibration-v2/run_d5.py simulate --output <同一目录> --workers 4
python -I -X utf8 docs/research/source-trust/convergence/d5-calibration-v2/run_d5.py verify --output <同一目录>
python -I -X utf8 docs/research/source-trust/convergence/d5-calibration-v2/run_d5.py replay --output <同一目录>
```

- 0：冻结成功，或校准门通过。不是全 D5/实验授权。
- 1：代码、输入、工件或记录无效，属于工程/证据错误。
- 2：工件有效但统计验收不通过或证据不足。不能把该码当工程崩溃，也不能消音改为“方法通过”。

每情境保留 gzip JSONL：逐数据集的 seed 索引、真值、全部区间、合格簇、退化与未定义信息。顺序哈希链和总工件摘要用于检查完整性；不是来源真实性签名。`verify` 从逐行工件重新聚合所有计数、判定和中文表格；`replay` 另按预先固定的 hash 排名每情境选 10 个索引，重新生成相同数据并重算区间，而非新增样本。输出不能覆盖，部分失败尝试也保留。

## 保持关闭的门

`coverage_certified`、`power_validated`、`precision_validated`、`tail_precision_validated`、`D5_complete`、`experiment_authorized`、`confirmatory_success` 均不由此目录自动打开。即使合成校准门通过，也只写合成校准通过；功效、MDE、宽度验收与尾部精度需要各自事前设计和证据。真实材料的独立性、盲评、接收和 provider 捕获仍是外部硬门。
