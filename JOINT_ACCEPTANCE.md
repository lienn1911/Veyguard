# SOC-Triage 联合验收 — 2026-10-24

后续修订：最新网站、时间范围一致性修复与报告验收见 [FINAL_ACCEPTANCE.md](FINAL_ACCEPTANCE.md)。下文的真实 AI 运行是历史结果；新一轮发现两个已保存提议的时间范围解释不受证据支持，现已拦截。用户授权后，修订后的真实 Codex 调查与隔离审核到记录的流程已通过，完整十条审计事件链可复核；不能把模拟审核说成正式分析员判断或把流程通过说成 AI 准确率。

本轮在原有未提交改动上继续修复，没有重置分支、迁移旧审批或替用户执行生产审批。进入本轮时的已跟踪文件差异保存在本地 `data/joint-acceptance-20261024/pre-existing.patch`。

## 六轮结果

| 轮次 | 验收结果 | 证据与边界 |
| --- | --- | --- |
| 展示范围 | 通过 | 当前 9 个案件、158 条告警仅含 PortScan、DoS、BruteForce；Benign 仅参与离线评分。旧 DDoS 防护测试保留，不是第四个展示规则。 |
| 安全规则 | 通过软件验证 | 受保护案件的 Likely Benign 需要人工确认；AI 没有关闭、降级或改证据工具。显式安全拒绝现在会阻断提议；已保存报告也不能绕过关闭理由及精确布尔确认。 |
| 检测与分组 | 可复现，性能有限 | 开发集完整复算及外部 CIDDS 冻结测试均完成；案件分组可从当前告警完整重建。不能据告警案件估计所有真实案件的召回率。 |
| 时间线 / ATT&CK | 通过关联验证 | 当前 1,106 个事件均对应本案告警或样本，顺序与源位置可核对，重建结果一致。并未逐包验证原始 PCAP。 |
| AI / 审批 / 审计 | 通过隔离验证 | 五个现有案件及五个外部诊断分组真实只读调查完成；引用校验、未审批状态及审计链可验证。测试中的人工角色是模拟，不是实际分析员的判断质量。 |
| 独立评估 | 已运行并保留不佳结果 | 外部检测低召回；外部 AI 五例全部弃权为 Needs Review。另有 21 项独立构造的安全契约场景全部通过。三种评估不得混为一个准确率。 |

## 本轮修复

- `services/tools.py`、`services/triage.py`：保留每条工具消息 8,000 字符上限，改为完整 JSON 和明确的省略标记；告警支持 `offset` 续取。校验器只把实际返回的证据记为已取回，省略记录不进入引用白名单。超大单条结果返回错误，禁止硬截断 JSON。
- `services/safety.py`、`services/guardrail_bridge.py`、`services/triage.py`：保留安全模块的显式拒绝，格式异常的返回按拒绝处理，避免只读取确认标记而忽略拒绝。
- `services/api.py`：备注、建议审批和任务完成的审核人必须等于当前登录者；案件分配审计记录实际操作者，而非把被分配人当作操作者。已有 record、AI decision、resolve 身份校验保留。
- `services/providers/mock_provider.py`：离线模拟识别 BruteForce 规则，按单分钟计数描述，不把长案件总量说成一分钟，也不声称已经证实登录失败。模拟输出不进入真实 AI 成绩。
- 前端时间线、流量明细、概览及报告区分原始数据时钟和真正带时区的审计时间；修复报告将字符串形式 AI limitations 当数组渲染的问题。
- 新增与扩展证据分页、身份伪造、安全拒绝、人工关闭回归测试，以及联合检查、安全评估、外部 AI 诊断准备脚本。

## 检测成绩

单位均为“源文件 / 有序来源与目标 / 日历分钟分组”，不是单条 flow，也不是案件数。

开发集 CIC-IDS2017：356,103 个分组，TP 156、FP 2、FN 73；召回率 68.12%。正常分组误报率为 2/355,863，即约 **0.000562%**，不是零。完整复算的计数、错误行、混淆矩阵与正式开发报告一致；运行环境 Python 版本不同被如实记录。

外部 CIDDS-001：5,942,316 个计分分组，排除 4,260 个歧义或范围外分组。按冻结代码重跑后，结果与原外部报告完全一致。

| 类型 | TP | FP | FN | 召回率 |
| --- | ---: | ---: | ---: | ---: |
| PortScan | 48 | 0 | 40,617 | 0.118% |
| DoS | 56 | 0 | 80 | 41.176% |
| BruteForce | 2 | 0 | 555 | 0.359% |

零观察误报伴随极少正向预测，不表示跨域性能优秀。没有用外部结果回调本次冻结阈值。

结果文件：[开发复算](evaluation/detection-joint-20261024.json)、[外部复算](evaluation/cidds-joint-20261024.json)、[外部协议](evaluation/CIDDS_HOLDOUT.md)、[分组开发报告](evaluation/grouping-development-20261023.json)。

## AI 与安全评估

开发冒烟五例：真实 Codex 调查 5/5 正常结束，2 个 Likely Attack、3 个 Needs Review；证据校验失败 0，审计链均通过。输入曾用于开发，不能称独立 AI 准确率。见 [运行结果](evaluation/live-joint-acceptance-20261024.json)。

外部 AI 诊断五例：使用 CIDDS 原始标签，在模型运行前冻结案例、提示词指纹及取样规则。选择每种目标攻击在 week 1 CSV 中首次出现的分组键，以及两个最早出现的不同正常分组键；完整分组必须标签纯净，否则停止，不按模型结果替换。原始标签只在评分清单中，模型只看到流量与冻结规则的输出。未命中规则的分组仅进入隔离诊断队列，不加入产品队列，也不算检测器成功检出。

五例全部正常结束、全部 Needs Review。攻击被叫作良性 **0/3**、正常被叫作攻击 **0/2**、弃权 **5/5**。这说明证据不足时保持待审，不能解释为 100% 准确或有实际攻击识别能力。见 [冻结清单](evaluation/cidds-ai-diagnostic-20261024/manifest.json) 与 [真实运行结果](evaluation/cidds-ai-diagnostic-20261024/results.json)。

限制：这是五个有目的选取的外部分组，和检测测试共用 CIDDS 来源；标签来源是数据集，只有自动一致性复核，没有人工专家裁决。没有大样本、双人复核、置信区间或可推广性保证。Codex CLI 使用用户配置的 `default`，未固定底层模型版本；代码与数据可核对，但模型答案不保证逐字复现。不能用本次诊断替代正式的大规模独立 AI 基准。

[安全场景](evaluation/safety-joint-acceptance-20261024.json) 21/21 通过，覆盖三种当前类型及旧 DDoS 的良性提议确认、跨案件证据、关闭、降级和未知工具。它是合成契约评估，不是线上漏防率。254 项测试全部通过，0 失败、0 跳过，见 [测试摘要](evaluation/joint-tests-20261024.json)。追加式审计防更新、防删除及哈希链检查由隔离回归测试验证；不能抵御拥有本地数据库管理员权限的人替换整个存储。

## 重跑

```powershell
python -m pytest tests services evaluation -q
node node_modules/vite/bin/vite.js build
python -m evaluation.check_joint_contracts -o data/joint-contracts.json
python -m evaluation.evaluate_safety -o data/safety-evaluation.json
python -m services.evaluate_detection path/to/GeneratedLabelledFlows.zip -o data/detection-rerun.json
python -m services.evaluate_grouping src/real-alerts.json -o data/grouping-rerun.json
python -m services.evaluate_cidds_holdout data/holdout/CIDDS-001.zip --manifest evaluation/cidds_holdout_manifest.json -o data/cidds-rerun.json
python -m evaluation.run_live --manifest evaluation/cidds-ai-diagnostic-20261024/manifest.json --alerts evaluation/cidds-ai-diagnostic-20261024/alerts.json --timelines evaluation/cidds-ai-diagnostic-20261024/timelines.json --output data/cidds-ai-new-run.json
```

安装 `requirements.txt` 和 `requirements-eval.txt`。大型外部适配器另需 DuckDB；本机位于 `data/tools`，可用 `PYTHONPATH` 指向它。不要覆盖已有 AI 评估输出；每次使用新输出路径。所有真实 AI 调查都使用独立状态与审计目录，不会替用户审批线上案件。Windows 沙箱会阻止某些 socket 初始化；本轮在获准的普通用户环境运行隔离测试，临时目录固定在工作区，未将环境挂起误报为接口缺陷。

前端构建通过；仍有既有 >500 kB bundle 提示及 Starlette TestClient 的 httpx 弃用提示。历史 Isolation Forest 基准不是当前检测器，本轮未重训，不合并进三类检测成绩。

本地 API 已按现有脚本重启以载入修复，未登录 session 查询返回 200 / authenticated=false，未登录案件查询返回 401；见 [运行检查](evaluation/local-api-acceptance-20261024.json)。重启会退出原登录会话，但保留案件与审计文件。本轮未提交、推送或发布。

## ATT&CK 与比赛依据

[比赛官方](https://hackai.my/tracks/cyber-defence) 要求可工作的端到端防御流程、工具选择、证据和置信度、实际影响操作前的人工审批、过程记录及限制；SOC triage 方向要求告警分组、案件时间线及下一步建议，没有强制 Home 待办或每次只读查看都审批。本轮为完成六轮安全验收，保留现有审批数据契约，没有将此前讨论的简化流程直接混入安全修复。

MITRE 官方：[T1046](https://attack.mitre.org/techniques/T1046/) 涉及服务发现与端口扫描，可作有依据的可能映射；[T1110](https://attack.mitre.org/techniques/T1110/) 涉及凭证猜测，单靠连接数不充分；[T1498](https://attack.mitre.org/techniques/T1498/) 涉及可用性耗尽，流量数本身不证实服务中断。当前 DoS、BruteForce 不强行映射；允许 Unmapped。规则提示和 AI 建议均不等于已确认攻击。
