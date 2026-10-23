# DeepSeek 同工作流开发验证

用户已提供DeepSeek访问凭据，并确认本轮费用上限为人民币¥10、最多16次模型请求。
凭据只进入当次进程，不写入配置、源码、命令参数或实验输出。

## 固定条件

复用[Dots开发实验](../dots-tool-study-v1/README.md)的8条计划行、材料、顺序、提示、
工具定义和运行时判定。`run_row`与`summarize`直接导入冻结的Dots模块，未修改其字节。
同样是2种来源×2类任务×2策略，仅正确标签E0，2个作者合成家族共享1个模板。
正式pilot、确认性实验和新独立材料计数均为0。

本轮适配采用`deepseek-flash`、`https://api.deepseek.com/chat/completions`及Bearer认证，
显式设置`thinking.type=disabled`。官方当前将该模型名映射到DeepSeek-V4.1-Flash-1017，
这仍是可变服务别名，不是可锁定的权重快照。保留256输出token/请求、非流式、
首次`tool_choice=auto`、回传时`none`；不新增采样参数，提供方默认采样行为可能不同。

依据2026-10-23查阅的[官方价格表](https://api-docs.deepseek.com/zh-cn/quick_start/pricing/)
和[Chat Completions接口](https://api-docs.deepseek.com/zh-cn/api/create-chat-completion/)。
Dots的`chat_template_kwargs`不发送给DeepSeek。若出现非空思考内容或模型标识不符，
记录失败并停止后续请求，不静默丢弃后继续对话。

## ¥10费用限制

按公开高峰、缓存未命中价格保守计数：输入¥2/百万token，输出¥8/百万token；
不扣除缓存优惠，也不按当前空闲时段折半。记录的是基于提供方用量的保守估算，
不是已查询的实际账单。

每次请求前预留¥2.099200：用1,048,576个输入token作为公开1M上下文限制的保守上界，
加256个输出token。不把请求字节数当成token数，也不根据模型文本推算用量。
已计费用加该预留超过¥10时，不再发请求。有效用量返回后按实际报告token结算预留；
失败或用量未知则保留预留并停止全轮，不能把它记成零费用。

此上界依赖提供方遵守文档中的上下文、输出限制和价格；不是提供方账户级硬限额。
响应超过预留token界时保留观测并停止，账本会反映预算假设失效。
最多16请求，累计报告token达16,000后停止新请求，30秒网络超时，无自动重试或扩样。
本轮不会额外调用搜索、余额、模型列表或连通性接口。

## 验证与记录

执行前8项测试通过；其中本机执行器集成共9次工具执行、7次合成送达，提供方由测试替代。
这些测试不是DeepSeek模型结果。实际运行目录包含独占开始记录、代码/输入/预算计划、
逐事件摘要链、逐行结果与只读复核。原始模型文本及提供方错误正文不持久保存。

```sh
python docs/research/source-trust/convergence/deepseek_tool_study.py prepare \
  --output docs/research/source-trust/convergence/deepseek-tool-study-v1/run-001
python docs/research/source-trust/convergence/deepseek_tool_study.py run --live \
  --output docs/research/source-trust/convergence/deepseek-tool-study-v1/run-001
python docs/research/source-trust/convergence/deepseek_tool_study.py check \
  --output docs/research/source-trust/convergence/deepseek-tool-study-v1/run-001
```

运行凭据变量为`DEEPSEEK_API_KEY`。默认不执行真实调用，已开始的目录不得重新运行。
两个提供方结果分别报告；同一模板的第二个模型不构成独立材料、第三方复跑或
模型能力变化的因果证据，H1–H5与原正式预算保持不变。

本轮已完成8条轨迹、16次真实请求，详见[结果与两模型对照](REPORT.md)。
