# AgentShield 执行出口与 PUBLIC 授权审查

审查基线：`cb13965b3814d4302fce5d7d720031979b3bbf75`，2026-10-12。
本轮仅新增文件，保留 R3 提交的全部 409 个文件、既有 R4 材料和研究协议。
这是作者代码审查与离线工程加固，不是独立设计评审或新的防御实验。
PR #7 的预注册、pilot、保留集、真人真值与外部配对执行状态继续保持暂停。

## 1. 审查结论与实际落地

1. 错误 `PUBLIC` 外泄是可信来源声明的语义错误，不能通过更换 HMAC 或增加同样的污点传播修复。
2. 支持的 Agent 执行入口在实际发送前调用了中间件或 runtime 判定；底层客户端、传输函数和批准工具回调仍属于可信调用方边界，不能声称拦截任意 Python 或所有进程出口。
3. 旧 Dots 客户端的默认 urllib 路径允许重定向，响应成功路径使用无参数 `read()`。初始 URL 的中间件判定不能授权后续重定向目标。
4. 新增可选 [BoundedDotsClient](../../model/bounded_dots_client.py)：默认禁止实机请求、HTTPS 端点固定、禁止自动重定向和环境代理、请求/响应字节上限，以及不包含服务端正文的错误码。

旧 CLI、旧 DotsClient、研究 runtime、来源注册表、阈值与既有实验均未切换到新适配器。
新增适配器通过已有的 `client=` 注入点接入，属于候选工程变更；没有新版本安全率或性能成绩。
该变化只加固采用这个适配器的传输路径，未修复显式错误 `PUBLIC` 声明。

## 2. 执行链与信任边界

| 路径 | 发送前判定 | 实际执行 | 边界/结论 |
|---|---|---|---|
| `agent.agent.agent` | `check_tool_call` 检查文件和 HTTP | `read_file`、`send_http` | 确定性演示；默认发送为打印模拟 |
| `agent.llm_agent._model_call` | `check_tool_call("model", ...)` | `client.send_payload(payload)` | 客户端由可信调用方注入；直接使用客户端不经过此判定 |
| `agent.llm_agent._execute_tool_call` | `check_tool_call` | `read_file`、`send_http` | 模型只能调用列出的有限工具 |
| `PrecisionAgent.run` / `ResearchAgent.run` | `approve_model_payload` | `client.send_payload` | 先检查组装后的模型请求与依赖；不是模型语义推断保证 |
| `PrecisionRuntime.send` | `_sink_value`、`decide_source`，再到 `GuardedRuntime._check` | `GuardedRuntime.send` → `send_http` | 完整性、来源不确定性、内容/污点和访问策略是不同判定 |
| `AgentPort.dispatch` | 有限 schema、句柄校验、runtime 判定 | runtime 的读取、变换、发送 | 不提供任意代码执行；同进程对象访问不属于隔离保证 |
| `tools.http_tool.send_http` | 调用方负责判定 | 打印模拟或 `LocalHTTPTarget.send` | 此函数本身不强制中间件授权 |
| `LocalHTTPTarget.send` | 独立传输限制 | 固定 127.0.0.1 的 socket/HTTP | 环回限制是实验传输边界，不能计为 AgentShield 防御成功 |
| `DotsClient.send_payload` | 调用方负责判定 | 默认 `urlopen` | 旧默认重定向与无界成功响应保留为历史实现缺口 |
| `ResearchChatClient.send_payload` | live flag、请求上限；调用方负责中间件 | 无重定向 opener、有限响应读取 | 已有研究客户端；没有因此获得真实模型运行证据 |
| `BoundedDotsClient.send_payload`（新增） | 默认 live 关闭、端点/字节检查；调用方负责中间件 | 无代理、无重定向 opener、有限响应读取 | 离线覆盖 urllib 实际重定向处理链；可选接入，不替换冻结默认 |
| `call_approved_tool` / `tool_output` | 注册白名单或可信 producer | Python 回调 | 只负责在回调返回后登记来源；回调自身的 I/O 必须单独审查 |

`observe` 回调、日志写入、stdout、文件导出、动态加载、子进程与第三方工具内部 I/O 不因上述表格获得统一出口保证。
本表是人工源代码审查，不是全程序控制流证明。

## 3. PUBLIC 错标的精确原因

- [SourceRegistry.classify](../../security/source_classification.py) 按类别和 reference 匹配可信计划；计划定义状态与布局。
- [PrecisionRuntime._ingress](../../security/precision_runtime.py) 按该计划给真实读取内容创建来源标签。
- [PrecisionAuthority](../../security/precision_integrity.py) 将值、来源、计划状态、转换与规则绑定到当前会话完整性证据。它验证已签发对象是否一致。
- `decide_source` 处理活跃依赖中的 `UNKNOWN` / `MISSING` / `CONFLICT`；明确的 `PUBLIC` 不属于不确定项。
- [effective_registry](../../security/source_trust_policy.py) 的 conservative 策略只提高 MIXED 源的未列出部分默认敏感性，保留明确 PUBLIC 覆盖。

因此，错误的整个 PUBLIC 计划、错误公开字段/元素，以及 reference 不变而内容已改变的声明复用，需要独立的授权/语义审计。
会话句柄已经绑定读取后的实际内容；缺失的是该内容版本与外部公开授权证据之间的绑定。
“内容 HMAC 正确”与“内容确实允许公开”须分别描述，不能删掉误标失败来提高成绩。

后续修复方案与验收契约见 [PUBLIC_AUTHORIZATION_DESIGN.md](PUBLIC_AUTHORIZATION_DESIGN.md)。

## 4. 传输加固的验证方式

```bash
python -m unittest discover -s test -p 'test_bounded_dots_client.py' -v
python -m ci.validate_source_trust_feasibility
```

新增测试通过伪 HTTPS handler 在 urllib 的真实 HTTP 状态/重定向处理层返回脚本响应，测试中禁止 socket 和 create_connection。
旧适配器负对照确实产生第二个请求，且继承伪造测试 api-key；新适配器对 301/302/303/307/308 的同源、跨源及 HTTPS→HTTP 跳转均只产生一个请求。
新增适配器测试没有真实网络发送、API 调用或模型推理；本轮不获取新保留集材料、不启动新保留集评估，也不入组新攻击数据。
这是离线实现回归证据，不能用于计算 ASR、TCR、FPR 或论文功效。

2026-10-12 本地实际验证（Python 3.12.14）：新增适配器 19 项测试通过，完整套件 404 项通过、0 失败；既有独立解析门禁确认 409 个 R3 文件未变且 readiness 仍为 BLOCKED；7 个本地文档链接可解析。原始本地单测输出位于 Git 忽略的 `logs/bounded-dots/full-unittest.txt`，GitHub 工作流另行记录各 Python 版本的新增离线控制与冻结门禁，不将本地完整套件数量冒充远程执行数量。

## 5. 使用条件与限制

`BoundedDotsClient` 与 `DotsClient` 共用 `build_payload` 接口，可由可信宿主传入 `run_llm_agent_result(client=...)` 或模型 Agent。
默认 `allow_live=False`；现阶段不能据这份文档打开暂停实验。
未来获准的执行还须由宿主完成初始端点策略、精确请求的中间件检查、任务预算和来源授权。

请求上限 256 KiB，响应读取上限 1 MiB，有限 socket 操作超时为 `(0, 60]` 秒；这些值只约束新适配器，不改变研究协议预算。
错误正文不读取，避免将服务端回显的凭据或用户数据写入公共异常。
环境 HTTP(S) 代理关闭，因此依赖环境代理的部署需要另行设计可信代理接入；OS/VPN 路由不受此参数控制。
DNS/IP 固定、地址重绑定、TLS 系统信任库、总壁钟截止时间、完整内存/CPU 上限和同进程恶意 Python 都不属于新增保证。
响应校验覆盖 JSON 重复键、非有限数和首条 message envelope；工具参数和动作权限仍由既有 Agent/runtime 校验。
