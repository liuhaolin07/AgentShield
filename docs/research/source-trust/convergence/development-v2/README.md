# 条件批准后的D1–D4开发链 v2

用户基于消息正文有条件批准R1–R5、立即启动D1–D4。[批准记录](review-decision.json)
不声称用户读过旧PDF/ZIP。[C1–C7与D6门槛](REVIEW_CONDITIONS.md)作为本版本验收约束。

本版已实现：candidate-ID图与名称控制、逐行防御模式及配置绑定、固定工具RPC字节归档、
实际本机接收与回执、原文重评分、五类按臂记账、偏离率可比性门禁、缺失/暴露端点、
有限开发查询账本。三策略与控制臂仍调用冻结运行时，旧图、旧结果与原协议保留原样。
当前任务支持范围仍为平坦字符串来源的单叶identity；未宣称全部真实工具/变换已覆盖。

| 工作包 | 当前实现 | 尚未完成 |
| --- | --- | --- |
| D1 | 源、任务、授权、图、投影、模板、模式、配置和执行器版本随行绑定 | 更复杂任务与变换契约 |
| D2 | 实际工具RPC原文、独立接收正文、回执、离线重评分 | 提供方原文捕获尚未接入，不能执行正式模型pilot |
| D3 | ID定向/匹配随机成本，持久化查询预留与跨种子20次上限 | 本次定向为冻结依赖优先静态算法，无实际自适应模型搜索；不声称完整研究攻击已验收 |
| D4 | 按计划分母导出指标、覆盖、暴露、缺失界和统计输入缺口 | 完整正式网格未执行，C3阈值/C6尚未定稿 |

新代码入口：

- [图与candidate ID](../development_graph_v2.py)
- [任务绑定、工具RPC、归档、重评分及端点](../development_execution_v2.py)
- [开发查询成本账本](../development_queries_v2.py)
- [限定工程运行器](../run_development_v2.py)
- [新增测试](../test_development_v2.py)

## 验收结果

21项新增测试通过，覆盖五模式实际执行与回执、模式/配置篡改、原文缺失/篡改、
派发前归档失败、偏离率差、未知偏离、不同任务集合、完整与缺失统计网格、
查询失败/中断/重启/并发写入/上限、candidate ID及匹配成本。
最后一次测试套件包含20次真实本机工具探测、8次送达；测试与研究预算分别记录。
首次在无socket权限的沙箱中本机集成项失败，未当作防御成功；取得本机网络能力后通过。

[16行独立工程批次](run-001/report.json)覆盖2个已知作者家族、E0与SP=1、无防御与precision。
实际本机送达14次，运行时阻断2次，16行原文归档均可重评分，预定N=10抽样一致。
该批次为工程验收，不是新独立材料或正式984行pilot。
本工作包新增模型调用0、费用0；正式材料仍0/60，正式pilot仍0，统计仍未定稿。

## 复核与重建

只读重评分不需要模型、凭据或网络：

```sh
python docs/research/source-trust/convergence/run_development_v2.py verify \
  --root docs/research/source-trust/convergence/development-v2/run-001
```

测试需允许127.0.0.1本机socket，不访问模型提供方：

```sh
python -m unittest discover -s docs/research/source-trust/convergence -p 'test_development_v2.py' -v
```

如需新建工程批次，目录必须尚不存在，已开始批次不能重试覆盖：

```sh
python docs/research/source-trust/convergence/run_development_v2.py prepare --root /tmp/agentshield-dev-v2-new
python docs/research/source-trust/convergence/run_development_v2.py run --root /tmp/agentshield-dev-v2-new
```

`request.bin`/`response.bin`为本版工具接口实际应用字节，不是模型提供方原文或原始网络包。
当前无模型传输驱动，旧模型原文无法倒补。归档与哈希证明当前工件一致性，不证明外部执行真实性或第三方复现。
缺档行在当前复核中进入缺失、保留计划分母与最坏界，批次完整性不能通过。

偏离率阈值默认为null，输出`UNDETERMINED_D5_THRESHOLD`。测试中的.05只验证分支，
没有把用户建议或测试参数当最终研究阈值。C6覆盖和阈值定稿前不执行统计推断。
