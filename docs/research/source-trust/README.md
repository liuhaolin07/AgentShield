# Source annotation trust: draft research agenda R1

[四页研究设计 PDF](RESEARCH_DESIGN.pdf) · [Markdown 源稿](RESEARCH_DESIGN.md) ·
[详细协议草案/评审问题处置](PROTOCOL_DRAFT.md) · [文献矩阵](LITERATURE_MATRIX.md) ·
[原文核查记录](references-verified.json) · [机器参数](protocol-draft.json)

**PR #6 保持 Draft。本稿尚未注册、尚未定稿，不可据此启动正式实验。**
本分支仅含研究文档与只读文档校验脚本；没有新增防御、数据集、安全实验或运行时依赖。
PR #5 冻结于 `5c2b86c0f381b89f55f6f5d41a5d9180a82240fb`，
[frozen-pr5.json](frozen-pr5.json) 保存全部 255 已跟踪文件哈希，包括代码、测试、CI、原始 JSON/CSV。
V1.10 原有 212 文件是另一历史口径。没有改动或回填历史结果。

R1 修正旧草案的四项关键问题：APPA 改为实际核查的 v2，并补 AgentFlow、Prudentia、
结构化 MCP 标签及移动应用声明一致性研究；E0 仅一次，E0/E1 预算改为 **54,720**；
H5 要同时满足 ASR 改善、逐点 TCR 非劣与绝对完成率下限；随机干预报告命中暴露，
同家族攻击/正常任务及策略共享同一腐化图。正式主推断仅用外部保留集。
5 点效应/非劣界、80% 最低完成率等均为待评审提议，不是根据历史效果选出的已冻结要求。

12 开发家族、984 行 pilot 也是 **PLANNED/UNRUN**，尚未实现/执行。
H4 的结构机制未选择；新数据、保留作者材料、功效/区间覆盖验证、生成器、外部机制适配
及正式注册均未完成。待办门禁在机器参数中逐项列出。文档算术和假想区间规则通过不代表安全实验通过。
真实模型、AgentDojo、外部机制和第三方复跑仍缺执行证据，不能把旧 36 项 UNRUN 当防御效果。

当前引用的 8 篇 PDF 已实际下载核查指定段落；两篇 USENIX 工作通过网页工具读取原文，
本机下载 403、哈希为空的情况如实记录。APPA v1 的历史版本核查也保留。
文献矩阵说明已有能力与待核对工件，未复现外部防御，未证明新颖性，也未声称穷尽综述。
论文全文保留在忽略的本地日志，没有重新分发。

[verification.json](verification.json) 是本次文档/冻结证据核查记录。
286 项单元测试通过、四个 CI 作业成功属于 PR #5 的历史证据；本轮未重新运行完整单元测试，
没有新 CI 工作流运行，不冒充新回归。历史 252 行独立证据仅重新校验，未重新执行。
未合并、未发布、未开始 V2.0。

## Check the documents without running experiments

```sh
python docs/research/source-trust/verify_design.py
```

[verify_design.py](verify_design.py) 只读：校验 255 文件冻结、改动路径、预算、H1–H5 参数、
共同判据、文献口径及本地链接；假想区间只验证全拒绝不能通过提议的 H5。
它不导入防御代码、不启动 Agent/HTTP/模型、不产生实验结果。

## Render the four-page overview

仅渲染需要 Pandoc、XeLaTeX 和 Noto Serif CJK 字体；不属于 AgentShield 运行时依赖。
详细协议与文献矩阵是附录，不算进四页概述，也不冒充已定稿注册书。

```sh
mkdir -p logs/research-design/render
python - <<'PY'
from pathlib import Path
import subprocess
root = Path('docs/research/source-trust')
print_source = Path('logs/research-design/render/RESEARCH_DESIGN-print.md')
print_source.write_text((root/'RESEARCH_DESIGN.md').read_text().replace('<!-- PAGEBREAK -->', r'\newpage'))
subprocess.run([
    'pandoc', str(print_source), '--pdf-engine=xelatex',
    '-V', 'mainfont=Noto Serif CJK SC', '-V', 'monofont=DejaVu Sans Mono',
    '-V', 'fontsize=10pt', '-V', 'papersize=a4', '-V', 'geometry:margin=18mm',
    '-H', str(root/'pdf-header.tex'), '-o', str(root/'RESEARCH_DESIGN.pdf'),
], check=True)
PY
```

This branch preserves PR #5's 255-file baseline and historical results. R1 is an
**unregistered draft**, not a ready confirmatory protocol. It corrects the E0/E1
budget to 54,720, updates the primary-source literature, proposes falsifiable
hypotheses and a joint security/utility success rule, and separates random
exposure from robustness after exposure. Attack/benign pairs share corruption
graphs; primary inference uses an external holdout only. All thresholds require
pre-holdout justification and review; the 984-row development pilot, external
mechanisms and real-agent evaluations remain planned/unrun. The read-only checker
verifies document arithmetic and hypothetical inequalities, not defense efficacy.
