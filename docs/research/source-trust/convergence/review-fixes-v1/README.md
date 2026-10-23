# PR #9：F1–F5 修复与复验入口

用户本轮未签审核通过。修复完成后将 PR 转 Ready 供再次复验；研究批准状态不因此改变。
正式 pilot 继续阻塞，材料接收和正式执行均为 0。

| 项 | 修复 | 复验方式 |
| --- | --- | --- |
| F1 | 新增按研究路径触发、无 base 分支过滤的 `Convergence review checks` workflow | PR 页面查看 Ubuntu/Windows、Python 3.12 两个 job；完整日志上传 artifact |
| F2 | 检测 POSIX flag、dir_fd 与 fcntl；能力缺失明确 `PLATFORM_UNSUPPORTED`，派发前拒绝 | `test_platform_contract.py`；Windows 的 POSIX 项标 skip，拒绝路径照常验证；见 [D1 环境契约](D1_ENVIRONMENT.md) |
| F3 | CLI 测试改用 `sys.executable` | 新测试以空 PATH 启动当前解释器并核验 init/check 的状态和不可覆盖行为 |
| F4 | startup 快照新增 `provider_capture_verified=false`、证据引用与显式条件；派发资格按条件计算 | `pilot_readiness.py`；即使其他条件全 true，provider 为 false、缺失、非布尔或缺证据引用均不可派发 |
| F5 | 区分 base commit 和 verified tree；新增提交树校验及显式 superseded 注册表 | [快照索引](snapshot-index.json)、[新提交绑定快照](verification.json)、`evidence_snapshots.py` |

完整收敛套件在本地 Linux 初次修复后运行 212 项，0 failures、0 errors。
Windows 原生结果以本 PR 的 CI job 为准；本地模拟能力缺失不替代 Windows CI。
第一次 CI 的 Ubuntu job 通过；Windows 发现 3 个旧 Dots 测试未在删除临时目录前关闭日志句柄。
这些测试已改为作用域内关闭日志，原失败运行保留；最终结论取后续 CI 的实际结果。
历史 v2 的 21 项、v3 的 24 项记录仍是相应原版本上的作者本地证据；新 CI 会执行修复后的完整套件，
不把历史记录事后改为独立复现或正式 pilot。

## F5 的证据处理

扩大审计覆盖全部 18 份含 `files_sha256` 的历史 verification 快照，在公开 convergence 历史中：

- `verification.json` 的 138 项、`development-v2/verification.json` 的 84 项、
  `model-capture-v3/verification.json` 的 112 项，均可在索引指定的实际提交全部复核。
- 包括 `reviewed-package-verification.json` 在内的 15 份早期快照没有任何完整匹配的公开提交，
  在索引中明确标为 `SUPERSEDED_UNREPRODUCIBLE`，**不作为通过证据**。
- 旧快照中的 `reference_commit=b631d1c…` 实际表示研究设计 base，不能再解释为已验证文件树。
  索引分别提供 `base_commit`、`verified_tree_commit` 和相对路径根；无法重建的条目 verified tree 为 null。
- 旧快照和 `review-record.json` 的原字节保留，避免改写既有评审引用。
  新索引是更正与替代记录，不通过重新计算旧哈希假装重建了当时的测量状态。
- 新快照的 `reference_commit` 与 `verified_tree_commit` 都指向已存在的完整提交；
  所列路径均相对仓库根，在该提交可读取并逐项核对摘要。

新增 CI 文件超出原“仅文档目录变更”范围。原 PR #6 的检查器保持原字节，
新增 `verify_convergence_design.py` 保留 39 项检查，范围检查仅额外允许
`.github/workflows/convergence.yml`；其余冻结、预算、假设和文档检查不放宽。

## 命令

```sh
python -m unittest discover -s docs/research/source-trust/convergence -p 'test_*.py' -v
python docs/research/source-trust/convergence/verify_convergence_design.py
python docs/research/source-trust/convergence/evidence_snapshots.py
python docs/research/source-trust/convergence/pilot_readiness.py \
  docs/research/source-trust/convergence/pilot-startup-v1/startup-check.json
```

最后一条预期输出 `provider_capture_verified=false`、`dispatchable=false` 并返回 2。
所有命令均无真实模型调用。单元测试包含已有作者夹具的本机工具执行，与正式 pilot 分开记账。
