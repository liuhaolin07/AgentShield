# Dots 连通性与工具请求格式诊断

来源：[Dots 官方 Chat Completions 文档](https://dots.ai/platform/docs#chat-completions)，
2026-10-22 核对。官方示例的模型是 `dots3-note-prev`，请求地址是
`https://note3-prev-api.askdiandian.com/v1/chat/completions`，认证头是 `api-key`。
文档支持 `tools` / `tool_choice`；深度思考默认开启，本诊断显式关闭。
这是文档兼容配置，不代表已验证账户权限、模型可用性或服务端行为。

冻结的 `model/dots_client.py` 已有上述基本配置。本次新增
[`dots_diagnostic.py`](../dots_diagnostic.py) 作为独立入口，不修改历史客户端、
PR #5 文件、PR #6 协议或已执行演练的代码摘要。

## 范围与完成标准

仅发送一段公开合成提示及一个 `echo_public_marker` 工具定义。
不会读取候选材料、外部保留集或任意用户文件，不执行模型生成的工具调用。
工具选择由 `auto` 控制：没有选择工具只表示本次未观察到预期请求，不能断言模型不支持工具。

- 单次执行最多一次请求，最多 128 个输出 token，关闭流式和深度思考，无自动重试。
- 固定 HTTPS 端点和模型；拒绝 HTTP 重定向；请求体上限 4 KiB、响应读取上限 64 KiB、网络超时 30 秒。
- 密钥只从指定环境变量读取；不写入文件、命令参数或日志。报告仅保留固定状态、计数及摘要，不保存响应正文、工具参数、错误文本或认证头。
- 请求前独占创建并刷写报告；已有报告不得覆盖。崩溃时留下未完成记录，不能据此推断提供方是否收到请求，也不能自动再次发送。
- 响应、模型名是否匹配、工具请求格式、用量是否有效分别记录。缺失或不一致的用量保持未知，不能当成零成本。
- 费用未核验，报告 `estimated_cost_usd=null`；请求次数和输出 token 上限不是提供方账单硬上限。

完成连通性诊断需真实响应且结构有效；预期工具名、精确合成参数及 `tool_calls` 停止原因
同时匹配时才通过工具请求格式检查。即使两项均通过，也只证明这次 API 交互。
尚未验证工具结果回传、多轮 Agent 行为、AgentShield 真实模型执行或运行时完整覆盖。
实际模型标识仍以本次返回是否与请求匹配的单独字段为准。

## 使用

从仓库根目录执行。默认模式没有任何 API 调用，即使凭据存在也不调用：

```sh
python docs/research/source-trust/convergence/dots_diagnostic.py \
  --output /tmp/agentshield-dots-offline.json
```

真实调用前，通过当前执行环境的 Secret 配置注入 `AGENTSHIELD_API_KEY`。
不要在聊天、源码、命令参数或 Git 中粘贴密钥；已公开的凭据应撤销并更换。
用户提供有效凭据并明确一次调用额度后，使用全新的报告路径：

```sh
python docs/research/source-trust/convergence/dots_diagnostic.py \
  --live --max-calls 1 --output /tmp/agentshield-dots-live-001.json
```

可用 `--credential-env` 指定其他环境变量名。脚本不接受密钥正文、任意 URL、
任意提示或材料路径。默认离线模式退出 0 仅表示检查完成；真实模式只有
`status=OBSERVED` 退出 0，工具格式是否通过仍需看报告独立字段。

## 本次证据

[`offline-unrun.json`](offline-unrun.json) 是默认关闭模式的实际输出，
`dispatch_attempts=0`、`model_availability=UNVERIFIED`。
13 项离线测试使用替代传输及人工响应，真实 API 调用数为零。
这些测试不证明远程服务可达或模型能力。

2026-10-23（Asia/Shanghai）另完成[一次真实诊断](live-001.json)：HTTP 200，
返回模型匹配，预期工具请求格式通过。提供方报告输入222、输出48、合计270 tokens，
无重试、无工具执行。该观察仅证明此次请求成功，费用仍未核验；
详情及后续边界见[真实诊断记录](LIVE_RESULT.md)。上述离线报告保留原样。

H1–H5、54,720 行 E0/E1、3,600 行 E3 和单列 984 行 pilot 预算保持不变；
本诊断不占用或完成正式研究行，不生成 ASR/TCR/FPR，不关闭证据门禁。
