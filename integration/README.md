# dsh-watchdog 集成壳

> 本目录属于 [dsh-privacy-watchdog](https://github.com/wilberforce1900/dsh-privacy-watchdog)
> （DSH 插件集成部分）。项目理念、快速开始与威胁模型见
> [主 README](https://github.com/wilberforce1900/dsh-privacy-watchdog#readme) 与
> [THREAT-MODEL.md](https://github.com/wilberforce1900/dsh-privacy-watchdog/blob/main/THREAT-MODEL.md)。

把 `watchdog/`（Python 检测核心）接入真实 DeepSeek Harness 的薄壳层。
已依据 **本机 @deepseek-ai/dsh 0.1.1-rc.2 发布包核实**的公开 API 设计：

| 已核实的缝线 | 出处 | 用途 |
|---|---|---|
| `tools/pre-execute` 瀑布事件，签名 `(exec, next) => PreToolDecision` | `@deepseek-ai/dsh-tools/lib/types/index.d.ts` L38 | 每个工具调用执行前拦截；`allow`/`deny{reason}`/`ask` |
| `PreToolDecision = allow \| deny{reason} \| ask{reason?}` | 同上 L418 | deny = 撤回/取消的落地形态 |
| `ctx.userQuestions.ask({questions})` → `answers[].selected[]` | `@deepseek-ai/dsh-user-questions/lib/types/index.d.ts` L62 | 承载「放行/撤回/取消」三选一，`detail` 字段展示发现 |
| `ApprovalOutcome: allowed-once \| rejected \| cancelled \| unavailable`（fail closed） | `@deepseek-ai/dsh-user-approval/lib/types/types.d.ts` L23 | 语义对齐：无回答=取消 |
| `ToolExecutionInput`: `callId/name/arguments/agent/signal/rootCallId` | `@deepseek-ai/dsh-tools` | 翻译成 watchdog Action 的原料 |
| 插件以 cordis patch 行挂载：`- insert: - id: … name: …` | `@deepseek-ai/dsh-base/cordis.patch.yml` | 安装方式 |

## 架构

```
DSH ToolRuntime
  └─ tools/pre-execute 瀑布
       └─ dsh-watchdog (JS 薄壳, src/index.js)
            ① translate.js:  ToolExecution → Action (kind/tool/target/payload)
            ② bridge.js:     spawn python3 sidecar, JSON-lines 往返
            ③ sidecar:       policy + 检测器 + 暂停状态 + 快照md (全部在 Python)
            ④ 有阻断级发现 → ctx.userQuestions.ask 三选一（这个 await 就是"暂停对话"）
            ⑤ 决策映射：放行→next()；撤回/取消→deny{reason 含位置与快照路径}
```

Python 承担全部智能（复用根目录 `watchdog/` 包），JS 只做翻译与提问，
所以未来换 harness 或钩子名，只改壳不改脑。

## 安装（真实 DSH 上，供参考——本次未在本机执行）

```sh
# 1. 把插件装进某个 profile
dsh plugin --profile web add /path/to/dsh-privacy-watchdog/integration/dsh-watchdog-plugin

# 2. 在该 profile 的 cordis.patch.yml 加一条 patch 行
#    （模板见 cordis.patch.yml，把三个绝对路径改成你的检出位置）
```

`config` 字段（全部有默认值，可零配置安装）：`pythonBin`（Windows 默认 python）/
`sidecarEntry`（默认取本检出内的 sidecar）/ `policyFile`（默认本检出的 policy.example.json）/
`snapshotsDir`（默认本检出的 snapshots/）/ `locale`（提问文案 zh|en）/ `taskScope`（静态任务范围
描述，喂给启发式跑题检测）/ `onSidecarError: deny|allow`（默认 fail closed）/
`askTimeoutMs`（超时无回答 → 取消，fail closed）/ `offerAllowlist`（放行时追问加白，默认开）/
`maxRestarts` + `restartBaseDelay`（sidecar 自愈预算）/ `previewLimit`。

## 已验证 vs 待真机验证（诚实清单）

| 状态 | 项 |
|---|---|
| 已验证（本沙盒） | sidecar 协议 6 测试（含白名单持久化/审计、policy-tamper 自保护）、JS 壳决策逻辑 13 测试（含「python3 缺失 → fail closed」「协议不匹配 → 拒绝自愈」「崩溃 → 退避自愈」「放行 + 加白追问」「offerAllowlist:false 关闭追问」）、**真 Python sidecar + 真 JS bridge 全链路 e2e**（撤回→放行→shell curl 外传→取消→锁回合→新回合恢复→快照落盘），共 14 项 Node 测试 + 38 项 Python 测试 |
| 已验证（真机，2026-09-15） | ① 注册写法是 **`ctx.on('tools/pre-execute', …)`**（context 级事件；`ctx.tools.on` 会让启动直接崩溃 `ctx.tools.on is not a function`，插件本体已照此修复）；② `inject: ['tools','userQuestions']` 服务名解析正确；③ headless 无 UI provider 时 `ask()` **立即拒绝** `UserQuestionError: no user-questions provider is registered`（不挂死）→ fail-closed cancel 成立；④ ToolExecution 实测形状：`rootCallId` 由运行时自动解析（根调用 = 自己的 callId）、`token` 注册表分配、`signal` 为真实 AbortSignal、`arguments` 透传；⑤ deny 端到端：拦截 `{kind:'deny',reason}` 的 reason 原样成为工具错误结果（撤回/取消的落地形态）。验证工具：`smoke-test-plugin/`（真机 profile 探针 + `inprocess-probe.mjs` 进程内驱动真实 ToolRuntime，无需 LLM） |
| 待真机验证 | ① 完整 LLM 回合（模型产生工具调用 → 瀑布触发 → 暂停 UI 三选一）——smoke 探针真机运行时 DeepSeek 账户返回 429 余额不足，待充值后重跑 `dsh --profile watchdog-smoke "…"`；② web profile 的 UI 对 select 问题/`detail` 长文的渲染 |
| 已知局限 | `taskScope` 是静态配置；要拿「当前用户 prompt」做动态跑题检测，需要等确认 session 钩子后加一行取词逻辑 |

## smoke-test-plugin 用法

```sh
# 1) 进程内驱动真实 ToolRuntime（不需要 LLM，也不消耗余额）：
node integration/smoke-test-plugin/inprocess-probe.mjs

# 2) 真机 profile 探针（需要 DeepSeek 余额）：
dsh plugin --profile watchdog-smoke add link:$PWD/integration/smoke-test-plugin
dsh plugin --profile watchdog-smoke add @deepseek-ai/dsh-headless@0.1.1-rc.2
WATCHDOG_SMOKE_PROBE_ASK=1 dsh --profile watchdog-smoke "运行 ls 并告诉我有几个条目"
cat /tmp/dsh-watchdog-smoke.log   # 探针日志
```

## 撤回/取消的真实语义

- 拦截发生在 `pre-execute`：被撤回的动作**从未执行**，不存在需要回滚的副作用；
- `deny` 的 reason 会写给模型（含位置与快照路径），模型能看到「人为什么说不」；
- 「取消本回合」锁住同一 `rootCallId` 的后续动作（sidecar 端按回合拒绝），
  新回合（新 rootCallId）自动恢复干净状态。
- 铁律：**fail closed** —— sidecar 崩溃、提问超时、无提问 UI，一律按取消处理。
