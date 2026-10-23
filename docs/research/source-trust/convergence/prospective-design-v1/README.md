# 有限登记来源框：前瞻性设计绑定候选

状态：**工程元数据检查器，不是研究注册，不是正式执行入口**。用户已选择来源框内推断；真实来源框、采样随机性、谱系审计和执行器契约尚未交付，`proposal.json` 对这些输入保持 null。旧采样声明、旧账本、D5 v2 的失败结果和 C1–C7 原文均不修改。

## 已选范围与未完成的定义

- 总体限定到事前登记、版本固定的来源框，不是所有现实任务。开发/保留框事前分开，模板/派生谱系不得跨框复用。
- 每个模板簇包含 file/tool 两个家族；每框无放回等概率抽取30簇，即原预算的60家族。使用外部提供的随机字节流和拒绝采样；成员/文件排序不改变抽签。条件于随机位独立均匀，每个簇的纳入概率为 `30 / 框内簇数`。此程序不能证明随机源真实、均匀、未挑种子或首次抽签。
- 固定原条件网格与17项 recipes：家族等权，五个注入种子是固定设计，不外推未注册种子。H3的目标按框内事前合格家族定义，家族内合格种子等权；不能将随机样本合格数当固定总体分母。
- 目标涉及冻结执行体制下的潜在二元端点均值。**响应随机性、无跨簇干扰、图生成总体尚待定义和审查**。现有注入器在选入家族的跨家族叶池上分配固定预算；更换样本可能改变图和H3合格集合。没有证明潜在结果/合格集合可在抽样前固定，因此当前还不是完整、可冻结的统计 estimand。不得据此直接套有限总体修正、旧 bootstrap 或 HT 置信区间。
- 用户已选择下一版采用**完整模板簇内事前固定排名和预算**，另起图算子v3；旧算子与旧证据保留。该修订尚未实现或冻结，各簇预算向下取整之和也不能冒充旧全局预算。整个框预固定图/联合抽样边际目标两条路线不作为当前方向。执行器与真实来源框未交付时，仍不选择区间方法。

## 实现边界

`design_binding.py` 接收**仅元数据**的设计包：引用文档保存为 UTF-8 原文，按原字节SHA-256绑定；承诺摘要覆盖全部成员、抽签、计划和执行器声明，不包含摘要字段自身。CLI只从指定git提交读普通blob，不跟随文件系统符号链接，不打开来源载荷、保留答案或执行器，不直接发起外网请求。未对Git partial clone的隐式取对象做负控验收，不声称任意Git配置下的强离线保证。

`randomness.origin_evidence_ref` 与 `audit.review_record_ref` 仅要求值为字符串且 `value.strip()` 非空；null、对象、列表、空串和纯空白均拒绝。原有工程引用字符串仍合法，不要求digest或URI，不读取所引用的证据，也不递归扫描字符串内的 `outcomes`。该语法检查不证明证据真实性、事前时序或独立性，不增加任何研究许可。

三个旧依赖仅从程序所属可信仓库（`HERE.parents[4]`）的固定基线 `d2f2f02d8066bcad7902200aebe978015f5266d7` 读取：`docs/research/source-trust/protocol-draft.json`、`convergence/candidate-materials-v1/manifest.json`、`convergence/candidate-materials-v1/authoring-spec.json`（后两项相对 `docs/research/source-trust/`）。内部白名单及共享普通Git blob读取器拒绝symlink/submodule，逐项校验固定SHA-256，无工作树/磁盘回退；外部测试包可在不含该基线的独立仓库，依赖仍从程序仓库读取。报告的 `dependency_git_commit` / `dependency_sha256` 明示基线和三项字节摘要。公开包读取白名单不扩大到这些旧依赖或payload。`configuration_sha256` 必须是三模式摘要对象，列表等非法输入由CLI结构化拒绝（`INVALID_DESIGN_METADATA`、exit 1），不泄漏traceback。

完整元数据路径会检查：

1. 框成员/谱系唯一、每簇file/tool配对、每家族两任务及五项执行前H3掩码；已知作者夹具的ID、来源字节、谱系或配方不能借改名接收。未知派生关系仍必须人工审计，哈希不能证明独立性。
2. 抽签可重放，两个split各30簇；原81配置齐全、每split 29,160行主条件预算不变，不增加控制或模型重复。
3. 每条行元数据绑定设计承诺、计划、来源、任务、图、defense_mode/configuration和executor摘要。修改字段后重算行摘要仍不能掩盖与设计不一致。
4. 事后声明拒绝；重复JSON键、非有限数、额外结果字段、缺配置、预算膨胀和git符号链接blob拒绝。

`DESIGN_METADATA_VALID_NOT_AUTHORIZED`只表示结构和引用一致。独立真实性、时序、簇独立性、材料接收、区间选择、覆盖、功效与实验许可均不会因此变成true。git祖先关系也不能证明作者在提交前未见结果。本检查器**尚未接入一个可用的正式provider执行器**；它不替代既有pilot阻断门，也没有新开运行通道。

当前旧开发账本仍缺68配置、每家族95端点和5掩码；本轮只拒绝不完整的未来计划，不伪造缺失观测来消除旧缺口。D4、D5均未关闭。

## 复跑

仓库根目录，Python 3.12；先 `env -u PYTHONPATH`，再使用隔离模式。新目录测试不加 `__init__.py`，不改变原212项发现口径。

```bash
python -I -X utf8 -m unittest discover -s docs/research/source-trust/convergence/prospective-design-v1/tests -p 'test_*.py' -v
python -I -X utf8 docs/research/source-trust/convergence/prospective-design-v1/design_binding.py --commit HEAD
python -I -X utf8 docs/research/source-trust/convergence/prospective-design-v1/design_binding.py --commit HEAD --packet docs/research/source-trust/convergence/ledger-input-validation-v1/run-001/sampling-contract.json
```

CLI退出码：0＝仅元数据一致、仍不授权；2＝缺实际输入/事后声明被拒绝；1＝输入无效或工程失败。当前两个CLI命令都必须退出2，分别报告 `PENDING_REAL_DESIGN_INPUTS` 和 `REJECTED_POST_OUTCOME_DESIGN`。

`tests/engineering_fixture.py`只生成带明确 `ENGINEERING_FIXTURE_ONLY` 标记的哈希和元数据，不生成研究任务、真实模型响应或正式材料。它不是来源框，也不是 pilot 接收材料。
