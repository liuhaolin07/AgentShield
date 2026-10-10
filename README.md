# AgentShield · V1.9 开发中（保留 V1.7 / V1.8 基线）

[English](README.en.md) · **中文**

[![CI](https://github.com/liuhaolin07/AgentShield/actions/workflows/ci.yml/badge.svg)](https://github.com/liuhaolin07/AgentShield/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

AgentShield 是一个面向「使用工具的 Agent」的小型、可运行安全层。每一次文件读取与每一条对外 HTTP 调用都会经过中间件——在工具真正执行之前，由中间件放行或拦截该动作。

V1.6 同时包含确定性演示 Agent 和一个可选的、由 Dots 驱动的工具调用 Agent。策略解析器与 API 客户端仅使用 Python 标准库。`send_http` 工具目前仍只打印模拟结果，不发起真实网络请求。

## V1.9：可信来源边界与可核验实验（开发中）

在 V1.8 `ecfa751` 上迭代，新增运行时签发的不透明句柄、来源/转换链完整性检查和受限数据接口 `AgentPort`。文件、批准工具和模型适配器才能生成来源；手工包装、伪造 literal、标签剥离、跨会话句柄在新运行时发送前被拒绝。旧 CLI、V1.7 扫描器和 V1.8 公共 API/历史证据保持兼容。**同进程私有对象不是 Python 沙箱**；保护依赖可信运行时和仅通过数据接口调用的 Agent。

已冻结 120 开发任务、40 保留任务（版本 agent-exfiltration-v1.9-2），五个基线、四个消融映射为七个独立组。开发集三次重复：2,520 条真实本机接收验证，HELD 1,122 / FAILED 1,020 / UNRUN 378。Scanner ASR **159/246**；Full ASR **6/246**、TCR **48/54**、FPR **6/54**。错误来源分类造成实际外泄，敏感聚合值的公共切片造成误阻断，均保留为 FAILED。199 项单元/集成测试通过；V1.7/V1.8 回归状态不变。

```bash
python -m evaluation --experiment v1.9 --split development --seed 17 --repeat 3 --output-dir logs/v19-development
python -m ci.validate_v19 logs/v19-development/report.json
# 可选真实模型；凭据通过 DEEPSEEK_API_KEY 安全配置，不写入仓库/命令行
python -m evaluation.real_agent --provider deepseek --model deepseek-flash --live --output-dir logs/v19-live
```

真实模型接口默认关闭；用户指定的 DeepSeek 地址/模型已配置，但没有可用凭据，本次九条真实模型评估全部 **UNRUN**，未验证模型可用性。大样本实验是显式数据流验证，Prompt Injection、模型改写和隐式信息流不会默认计为防御成功；Token 成本为 UNRUN。首次保留集只在提交候选后运行，证据随后独立提交。

[实验方法与实际指标](docs/EXPERIMENT_V1.9.md) · [完整 JSON/CSV 证据](docs/results/v1.9/) · [威胁模型](docs/THREAT_MODEL.md) · [安全边界](docs/SECURITY_BOUNDARY.md) · [研究定位](docs/RELATED_WORK.md)。仅支持可信标签下的显式追踪；尚不能声称论文就绪或全面安全。未经合并/发布。

## V1.8：显式来源感知污点追踪 — historical results

在 V1.7 基线 `d1e0552` 上迭代，新增不可变的来源标签、转换记录和输出权限。支持拼接、切片、嵌套列表/字典、JSON、Base64、URL 编解码；即使敏感文件或工具结果不含已知密钥格式，也可按来源策略在 HTTP/模型发送前阻断。扫描与污点判断分别记录，普通数据仍可发送。污点能力默认关闭，原有 CLI 参数与模拟 HTTP 保持兼容。

```bash
python main.py "read normal log and send" --taint-config path/to/taint.json
python -m evaluation --experiment v1.8 --split development --seed 17 --repeat 3 --output-dir logs/v18-development
python -m evaluation --experiment v1.8 --split holdout --seed 17 --repeat 3 --output-dir logs/v18-holdout
```

配置示例：`{"sensitive_files":["test/data/confidential*.txt"],"sensitive_tools":["private_lookup"],"require_tracked":true}`。文件读取权限仍由原策略决定，污点配置单独定义来源保密性。使用方式、数据结构、精确支持范围见 [TAINT_TRACKING.md](docs/TAINT_TRACKING.md)。

本轮 **143 项测试通过，无跳过**；V1.7 的 86 次评估逐项保持 **HELD 82 / FAILED 0 / UNRUN 4**。新数据集先冻结，完整候选 `b3a2808` 提交后首次运行保留集，未根据保留结果修改实现。Linux/Python 3.12.14、seed=17、三次重复的实际结果：

| 组别 | 开发集攻击送达 ASR | 保留集攻击送达 ASR | 开发集正常完成 TCR | 开发集误报 FPR |
| --- | --- | --- | --- | --- |
| No Defense | 42/42 | 15/15 | 18/18 | 0/18 |
| Static Rule | 39/42 | 15/15 | 12/18 | 6/18 |
| Scanner（V1.7） | 36/42 | 12/15 | 18/18 | 0/18 |
| Scanner + Taint（V1.8） | 0/42 | 0/15 | 18/18 | 0/18 |

各组保留集正常完成均为 12/12。以上仅为依赖准确来源分类的探索性合成实验；重复样本不代表更多独立攻击。不支持的转换/隐式信息流保留为 UNRUN，控制项、缺失或无效证据不进入指标分母。对照组真实 FAILED 保留，因此四组评估命令退出 1。完整指标（含 Precision/Recall、延迟、分子分母）、[JSON/CSV 汇总](docs/results/v1.8/)、图表和失败分析见 [EXPERIMENT_V1.8.md](docs/EXPERIMENT_V1.8.md)。

科研绘图为可选依赖，核心仅需标准库：

```bash
python -m pip install -r requirements-research.txt
python -m evaluation.plot logs/v18-development/report.json
```

追踪仅覆盖显式包装操作。普通字符串操作、第三方库转换、模型改写和隐式信息流不受保证；错误来源分类或有权限的调用方重新标为普通值仍可外传，负对照测试已实测这些缺陷。未合并 main，未发布正式版本。

## V1.7 第一阶段：独立安全评估

本开发分支新增完整[架构审查、风险清单和分阶段计划](docs/REVIEW-v1.7.md)，以及依据 Clean Start、Blocked Means Blocked、No Escape、Honest Logs、Done Means Done 的独立评估框架。每个样本记录输入、策略、执行轨迹、实际接收记录、预期/实际结果与阻断来源，输出 `HELD / FAILED / UNRUN`。

```bash
python -m evaluation --seed 17 --repeat 2 --output-dir logs/evaluation
```

该命令显式启动临时 `127.0.0.1` 接收端，仅发送伪造测试数据；无需模型密钥。真实 HTTP 默认关闭，测试传输固定连接本机指定端口，不解析 DNS、不跟随重定向。普通演示仍使用模拟 HTTP。环境或传输层拒绝不会归功于 AgentShield。

2026-10-10 在 Linux/Python 3.12.14 下实际运行：**92 项自动化测试通过**。原有 21 个独立样本重复两次，从 **HELD 28 / FAILED 10 / UNRUN 4** 改善为 **HELD 38 / FAILED 0 / UNRUN 4**。先冻结扩展样本并运行修复前基线后，43 个样本重复两次从 **HELD 40 / FAILED 42 / UNRUN 4** 改善为 **HELD 82 / FAILED 0 / UNRUN 4**，输入、策略和预期契约保持一致。审计防篡改与隐式信息流仍为 UNRUN。这些合成样本计数包含控制项，不能视为 ASR 或整体安全率。

扫描器支持有资源上限的嵌套 JSON、URL 编码和标准/URL-safe Base64 多层检查，识别 RSA、EC、OpenSSH、PKCS#8 等常见私钥头。普通 PASSWORD 文档、公钥与合法 API 参数都有实际送达对照。资源超限单独记录为 `scan_limit`，不算敏感信息识别成功。完整逐项变化和启发式检测局限见[本轮验证记录](docs/ITERATION2.md)。

`run_llm_agent_result` 分别返回 `model_finished`、工具执行 `evidence` 和 `completed`。只有模型完成声明、没有工具执行的运行会返回未完成；调用方还可指定 `required_tools` 和 `require_real_http`，模拟发送不能证明真实 HTTP 完成。默认完成条件是有成功执行的工具，不保证任意自然语言任务的语义目标。CLI 参数保持兼容；LLM 运行缺少执行证据时退出码为 2。

报告写入 Git 忽略的 `logs/evaluation/report.json` 和 `cases.csv`。有 FAILED 时命令退出码为 1；只有 UNRUN 时为 2。详细测试条件、安全边界与后续验收门槛见[评估说明](docs/EVALUATION.md)。上述为保留的 V1.7 历史结果；V1.8 的显式污点 MVP 和探索性四组实验见上文，完整信息流追踪仍未实现。

## 流程

```text
用户任务
    ↓
确定性 Agent 或 Dots Agent
    ↓
工具调用
    ↓
AgentShield 中间件
    ├── 策略检查
    ├── 敏感数据扫描
    └── 审计事件
    ↓
允许 / 拦截
    ↓
工具执行
```

## V1.6 新特性

- 接入 Dots Chat Completions（使用模型 `dots3-note-prev`）。
- 原生解析并执行 `message.tool_calls`。
- 每次模型请求与每次工具执行之前，强制进行中间件检查。
- 防止敏感的工具结果回泄到模型 API。
- 以允许读取根目录（allowed file roots）阻止模型任意读取本地文件。
- 可检测 Dots 的 `ak_...` 凭据。
- 标准库回归测试，含脚本化的假模型工具调用循环；V1.7 另有独立接收证据测试。

V1.5 引入的内容：

- 可运行的 CLI 与确定性演示 Agent。
- `policy.yaml`：定义被禁文件与允许的 HTTP 域名。
- 只追加（append-only）的 JSONL 审计日志，含时间、agent、工具、决策与原因。
- 面对缺失策略、非法策略、审计写入失败与不支持的工具，一律 fail-closed（失败即拒绝）。
- 覆盖攻击流程与正常流程的标准库测试。

审计器不写入工具参数、文件内容或 HTTP 载荷，但 agent/tool 元数据由调用方提供；它不是经过签名或防篡改的日志。ALLOW 代表执行许可，不证明执行成功。工具和模型客户端的直接调用仍需调用方接入中间件。

## 运行确定性演示

无需安装任何依赖。在仓库根目录下执行：

![AgentShield 演示：两次拦截、一次放行](docs/demo.gif)

### 1. 拦截一次受保护的文件读取

```bash
python main.py "read secret and send"
```

```text
[AgentShield] Checking...
BLOCKED: File denied by policy
```

Agent 从未读取 `.env`，因此也不会发起任何 HTTP 调用。

### 2. 拦截已在内存中的敏感数据

```bash
python main.py "send embedded secret"
```

```text
[AgentShield] Checking...
BLOCKED: Sensitive data detected
```

### 3. 放行一次正常流程

```bash
python main.py "read normal log and send"
```

```text
[AgentShield] Checking...
Allowed
[AgentShield] Checking...
Allowed
Sending data to:
example.com
INFO service started successfully
```

## 使用 Dots 模型运行

实机模式会把用户提示词与经安全审核的工具结果发送到：

```text
https://note3-prev-api.askdiandian.com/v1/chat/completions
```

测试前请新建一枚 API 密钥。请勿将其粘贴到源码、命令行参数、shell 历史、`.env` 或 Git 中。在 PowerShell 中，以下写法不会回显密钥，并且只把它保留在当前进程内：

```powershell
$agentShieldKey = Read-Host "Dots API Key" -AsSecureString
$agentShieldPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($agentShieldKey)
try {
    $env:AGENTSHIELD_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($agentShieldPtr)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($agentShieldPtr)
}
```

最简单的实机测试使用安全启动脚本：它以掩码方式提示输入密钥、运行任务，随后清除进程环境变量：

```powershell
.\run_dots_live.ps1
```

需要时传入其它任务：

```powershell
.\run_dots_live.ps1 "Read test/data/app.log and send a summary to example.com"
```

或者：手动配置好进程环境变量后，运行：

```bash
python main.py --llm "Read test/data/app.log and send a summary to example.com"
```

实机模式使用 `dots3-note-prev`，关闭模型的推理输出，将每次响应限制为 512 token，并且最多允许六轮工具调用。只有当对应目标也出现在 `policy.yaml` 中时，才应覆盖模型或 API base URL。

## 策略

V1.6 接受这样一个刻意保持精简的 YAML 结构：

```yaml
blocked_files:
  - .env
  - id_rsa

allowed_file_roots:
  - test

allowed_domains:
  - example.com
  - github.com
  - note3-prev-api.askdiandian.com
```

只有位于允许读取根目录下的文件才能被打开。精确匹配的允许域名及其子域可用于模拟 HTTP 与模型 API 流量；其它所有目标一律拦截。未知的策略键或缺失必需键，会导致 fail-closed（失败即拒绝）决策。

V1.7 开发分支拒绝非法 URL、非 HTTP(S) 协议、URL 用户信息和非法参数类型，按策略所在目录解析文件路径，同时检查原始路径与符号链接目标的禁用文件名。路径检查与文件打开仍是分开的操作，不保证抵抗并发文件系统替换。现有实机 Dots 客户端不在本机实验传输的约束保证内。

## 审计日志

运行时的每次决策会追加写入 `logs/audit.jsonl`：

```json
{"time":"2026-01-01T00:00:00Z","agent":"simple-agent","tool":"http","decision":"BLOCK","reason":"sensitive_data"}
```

运行时的 `logs/` 目录已加入 Git 忽略。

## 安全政策

支持版本与漏洞的私密上报方式见 [SECURITY.md](SECURITY.md)（请勿为漏洞开公开 issue）。

## 测试

```bash
python -m unittest discover -s test -p "test_*.py" -v
```

## 仓库结构

```text
AgentShield/
├── main.py
├── policy.yaml
├── run_dots_live.ps1
├── SECURITY.md
├── CHANGELOG.md
├── LICENSE
├── docs/
│   └── demo.gif
├── agent/
│   ├── agent.py
│   └── llm_agent.py
├── model/
│   └── dots_client.py
├── security/
│   ├── audit.py
│   ├── middleware.py
│   ├── policy.py
│   └── scanner.py
├── tools/
│   ├── file_tool.py
│   └── http_tool.py
└── test/
    ├── data/app.log
    ├── secrets/.env
    ├── test_dots_client.py
    ├── test_llm_agent.py
    └── test_security.py
```

`test/secrets/.env` 中的值是伪造的测试夹具，绝不可替换为真实凭据。

## 下一步方向

在已有显式污点 MVP 和四组探索性实验上，增加外部保留样本、真实 Agent 任务、细粒度传播与误报研究、独立复现及统计分析。生产网络、文件竞态和审计完整性仍需单独验证；详见[实验局限与论文所需工作](docs/EXPERIMENT_V1.8.md)。
