# dsh-privacy-watchdog

> 会话级「隐私 & Token 滥用」看门狗：在模型的每个动作**执行之前**拦截、按本地规则裁决，
> 违规则暂停整个对话并把决定权交还给用户。纯 Python、零第三方依赖、当前为沙盒 demo。

## 核心理念

模型「说了什么/声称在想什么」不可信；但它的动作（联网、读文件、写文件、调工具）
**必须经过本地执行才能生效**。看门狗只盯动作，不猜动机：

```
模型提议动作 Action ──> WatchdogMonitor ──> 检测器 ×3
                                            ├─ EgressDetector        未授权外发 / 载荷含密钥
                                            ├─ SensitiveAccessDetector  触碰受保护路径
                                            └─ ScopeDetector         与用户请求无关（启发式）
                       阻断级发现(≥high) ──> PauseGate 暂停 ──> 用户裁决
                                              ├─ allow    放行这一次，继续监视
                                              ├─ rollback 销毁该动作（暂存写入从未落盘）
                                              └─ cancel   撤回并中止本回合剩余动作
                       快照 ──> snapshots/*.md（证据已脱敏）──> issue-preview.md ──> GitHub 社区
```

文件写入走 **暂存区**（`staging.py`）：用户放行才 commit 到真实目录，
rollback/cancel = 销毁暂存，磁盘上从未出现过。这是「撤回」真实成立的原因。

## 快速开始（纯沙盒，无真实网络）

```bash
python3 -m unittest discover -s tests        # 32 个单元测试
python3 integration/sidecar/test_sidecar.py  # sidecar 协议 6 项测试
cd integration/dsh-watchdog-plugin && npm test  # JS 壳 14 项测试（含真 sidecar e2e）
node integration/smoke-test-plugin/inprocess-probe.mjs  # 进程内驱动真实 DSH 工具运行时（无需 LLM）
python3 demo/run_demo.py --scenario a                        # 正常场景：无暂停
python3 demo/run_demo.py --scenario b --decision rollback    # 偷 .env + 外传密钥：两次暂停→撤回
python3 demo/run_demo.py --scenario c --decision cancel      # 跑题私活：警告+暂停→取消中止
python3 demo/run_demo.py --scenario b --interactive          # 逐次人工裁决
python3 demo/run_demo.py --scenario b --decision rollback --preview   # 生成 issue-preview.md
```

自定义规则：复制 `policy.example.json`，改 `allowed_hosts`（域名白名单）、
`protected_paths`（受保护文件）、`trusted_read_hosts`（可信只读域：GET 只警告不暂停）、
`allowed_paths`（豁免路径）、`max_pauses_per_turn`（每回合暂停预算，超限自动取消）、
`severity_threshold`（暂停阈值，默认 high）。

## 能力边界（诚实版）

| 状态 | 能力 |
|---|---|
| WORKS-NOW | 预执行拦截、三级裁决（放行/撤回/取消）、暂存式文件写入与真实撤回、异常定位到 turn/动作/目标、脱敏快照 md、离线 issue 预览、误报一键加白（写 policy + 审计日志）、每回合暂停预算自动取消、敏感读取后同回合外发升级（污点标记）、可信只读域降噪、sidecar 崩溃自动重启（退避）+ 协议版本握手、看门狗自身状态防改写（policy-tamper） |
| NEEDS-KEY | 真实上传 GitHub Issue：需要 `gh auth login` 或具备 repo 权限的 `GITHUB_TOKEN`。两者都没有时程序会拒绝并给出步骤，绝不假装成功 |
| NOT-POSSIBLE | ① **在客户端检测「API 供应商是否把你的数据拿去训练」**——数据离开本机后在服务商侧不可观测，只能靠合同/隐私设置（如 opt-out training）约束，任何声称能本地检测的插件都是虚假宣传；② 读取模型服务端私有 token 用量；③ 撤回**已放行执行**的外部副作用（放行后请求已发出，无法撤回） |

## 已知漏洞与待完善

1. **ScopeDetector 是关键词启发式**：必然有误报/漏报。拉丁文取 ≥4 字母词、中文取字符
   二元组做重叠判断，仍属最便宜的相似度信号；建议后续接语义相似度或让用户在 policy 里
   显式声明「本次任务意图」。误报可用「放行 + 一键加白」工作流（已实现，带审计）。
2. **shell-egress 的域名正则会把文件名当域名**：`curl ... README.md` 这类命令里的
   `README.md` 也会被抽成"主机名"而触发暂停。方向偏保守（暂停交人裁决，不漏放），
   但会产生噪音，误报时放行即可。
3. **evidence 中的模型备注可能撒谎**（demo 场景 b 里模型假装在读 README）：快照已同时
   记录动作与备注供对比，「备注仅供参考」。
4. **放行后的网络请求无法撤回**：UI 文案写清 allow = 一次性放行且不可逆。
5. **policy.json 是信任根**：模型侧无法改写（runtime 保护 + policy-tamper critical），
   白名单变更均落审计日志（`snapshots/policy-audit.log`）；但仍可诱导**用户**手动改白名单，
   请定期查看审计日志。
6. **快照上传前的隐私复查是人工的**：已默认脱敏（目标/证据/规则说明/时间线全部过 redact），
   但仍建议上传前用 `--preview` 做最终人工预览。
7. **检测盲区**：模型的输出文本（model_message）不做内容审查；解释器内联网络调用
   （`python -c`、`node -e`）与内容混淆绕过 shell 检测——彻底解法是本地代理镜像
   所有出站流量，见 THREAT-MODEL.md，可作为 v2。

## 与 DeepSeek Harness 的集成路线

- **钩子 API 已在真机核实**（详见 `integration/README.md` 的对照表）：
  `ctx.on('tools/pre-execute')` 瀑布 + `PreToolDecision(allow/deny/ask)` + `ctx.userQuestions.ask()`。
- 集成壳已实现：`integration/dsh-watchdog-plugin`（cordis 插件，JS 薄壳，零路径配置）+
  `integration/sidecar/watchdog_sidecar.py`（Python 长驻评审进程，复用本包核心）。
  JS 只翻译工具调用与向人提问；检测、策略、快照全部留在 Python。
- 全链路已在沙盒验证（真 Python sidecar + 真 JS bridge）；集成缝线（钩子注册、
  ToolExecution 形状、deny 落地、ask 无 UI 行为）已用 smoke 探针在真实运行时验证。
  完整 LLM 回合验证待 DeepSeek 账户余额可用后执行。
- 当前 DSH 0.1.1-rc.2 的发布包未随附「读取当前用户 prompt」的公开 session 钩子，
  跑题检测暂用静态 `taskScope` 配置；确认 session 钩子后可一行接入。

## GitHub 开源

- LICENSE（MIT）+ `SECURITY.md`（私有漏洞报告）+ `THREAT-MODEL.md`（威胁模型）+ CI + 误报 Issue 模板已就位
- 用 GitHub **Discussions** 做社区分享区（比 issue 更适合快照贴图），Issue 模板收误报
- 明确免责声明：本工具是「尽力检测」不是安全保证

## 目录结构

```
watchdog/            核心包（policy/actions/detectors/gate/staging/snapshot/monitor/redact/github_report）
demo/mock_model.py   剧本化的模拟模型（正常/外传/跑题 三种剧本）
demo/run_demo.py     端到端演示入口
tests/               32 个单元测试
policy.example.json  规则模板
integration/         DSH 集成壳（JS 插件 + Python sidecar）+ smoke 探针
THREAT-MODEL.md      威胁模型：防什么、不防什么、为什么
```
