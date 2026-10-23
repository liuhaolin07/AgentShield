# D1 执行环境契约

正式 pilot 执行平台固定为 **Linux、CPython 3.12**，本机接收器使用 IPv4 loopback。
这项平台约束不改变 C2/D6 材料要求、H1–H5 或任何预算；pilot 仍未启动。

执行与安全归档要求：

- `os.O_NOFOLLOW`、`os.O_DIRECTORY`、`os.O_NONBLOCK` 均存在且非零，`os.open` 支持 `dir_fd`。
- 来源/证据的安全读取通过目录描述符逐组件打开，目录及末端文件均使用 `O_NOFOLLOW`，并检查普通文件类型；拒绝符号链接和特殊文件。
- 新归档使用 `O_CREAT|O_EXCL|O_NOFOLLOW` 和文件 fsync；最后组件不可为已有文件或链接。
  写入父目录和查询账本父目录由可信执行器管理，本契约不覆盖主机被攻破或不可信进程改名这些父目录的情形。
- 查询预算账本额外要求 `fcntl.flock`；单写者锁和派发前持久预留保持原义。

`platform_contract.py` 在任何这些安全 I/O 之前进行能力检测。
缺少任一所需能力时返回/抛出定义好的 `PLATFORM_UNSUPPORTED`，不将缺失 flag 当作 0 后继续执行。
工具执行和捕获入口的 CLI 以 JSON 状态和退出码 2 拒绝；查询账本 API 抛出 `PlatformUnsupported(OSError)`。
重评分返回未知端点，原因标为 `PLATFORM_UNSUPPORTED`，不获得防御成功分数。

Windows 是只读元数据检查和平台拒绝验证的平台，**不支持正式执行或安全归档**。
CI 在 Windows 上执行全部测试发现；依赖 POSIX 安全 I/O 的测试显式 skip，数量出现在日志中，
不能将这些 skip 写成 Windows 执行测试通过。独立的平台拒绝测试在 Windows 上照常执行，
验证原文写入、读取、查询账本、捕获和执行均在产生文件/调用前被拒绝。

复核依赖字节摘要时，工作区需要保持 Git 原始 LF 字节。CI 在 checkout 前设置
`git config --global core.autocrlf false`；提交树证据校验直接读取 Git blob，避免路径根和换行转换影响。
测试子进程统一使用 `sys.executable`；不依赖 PATH 中的 `python`。

平台修复改变了部分执行源码，新增运行计划绑定新的源码和 `platform_contract.py` 摘要。
旧归档保持原字节，在其原提交复核：v2 使用 `3ebce7de93781fb5e3c742529c8a6f5be882f2ed`，
v3 使用 `c57563d7a34c3bf6cdd2f5b48b85a5031143596c`。
当前源码不冒充旧归档测量过的源码版本，CI 在 Linux 的独立 worktree 中复核两者。
