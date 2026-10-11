# Source annotation trust: research design only

[四页研究设计 PDF](RESEARCH_DESIGN.pdf) ·
[可审阅的 Markdown 源文档](RESEARCH_DESIGN.md) ·
[原始文献核查记录](references-verified.json)

本分支只新增文档，不新增防御、数据集或实验结果。PR #5 分支冻结在
`5c2b86c0f381b89f55f6f5d41a5d9180a82240fb`；`frozen-pr5.json` 保存其全部
255 个已跟踪文件的 SHA-256，包括全部历史代码、CI 和原始实验结果。
两到四页要求按实际导出的 PDF 页数验证；本稿为四页。

研究主线是错误或过时来源声明下的安全—可用性边界。候选 Schema/授权机制
尚未选择，更没有实施。正确声明、随机错标、针对性错标、Schema 演变的
实验参数都是拟议预算，状态 PLANNED/UNRUN；没有生成未经测量的曲线。
真实模型与外部基准保留独立验证线，不能把旧 UNRUN 或材料下载计为效果证据。

已实际下载并核查指定版本的 CaMeL、FIDES、APPA、FlowSeal 和 AgentDojo
论文的相关段落，并检查固定提交的 CaMeL 官方策略/能力源码。
`references-verified.json` 记录 URL、版本、原文哈希、PDF 页码、章节和核查范围。
OpenAlex 只用于发现近邻，标题/结论以原始 PDF 为准；APPA 的索引标题与 v1
PDF 不一致，已留档。检索不是穷尽综述，也没有复现这些防御系统。
没有重新分发下载的完整论文；原文保存在忽略的本地研究日志中。

冻结与 PDF/引用核查的实际结果保存在 `verification.json`。
这次文档工作未重新运行完整单元测试；286 项通过与四个 CI 作业成功是冻结
PR #5 的历史证据，不冒充本次新回归。未合并、未发布、未开始 V2.0。

## Render the PDF

文档导出使用 Pandoc、XeLaTeX 和 Noto Serif CJK 字体。它们仅用于渲染文档，
没有加入 AgentShield 运行时依赖。PDF 嵌入字体，四部分各从新页开始。

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

## Verify frozen history

```sh
python - <<'PY'
from pathlib import Path
import hashlib, json
freeze = json.loads(Path('docs/research/source-trust/frozen-pr5.json').read_text())
for name, digest in freeze['tracked_files_sha256'].items():
    if hashlib.sha256(Path(name).read_bytes()).hexdigest() != digest:
        raise SystemExit('Changed frozen PR #5 file: '+name)
print('Frozen PR #5 files verified:', len(freeze['tracked_files_sha256']))
PY
```

The research draft separates authenticated annotations from semantically correct
classification. It proposes paired, cluster-aware experiments on annotation
noise, schema drift and targeted PUBLIC errors, with review cost and missingness
reported explicitly. It claims neither a new deployed mechanism nor verified
novelty. The four-page design is the reviewable input to choosing a minimal next
prototype; all new experiments remain planned and unrun.
