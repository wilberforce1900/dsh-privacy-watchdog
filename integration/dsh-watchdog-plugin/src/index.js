/**
 * dsh-watchdog — cordis plugin shell.
 *
 * Hooks the `tools/pre-execute` waterfall (verified against the real harness,
 * see integration/README.md): every tool call is translated and sent to the
 * Python sidecar. Clean calls pass through; blocking findings pause the
 * conversation (the await below IS the pause) and the human answers through
 * ctx.userQuestions with three options: allow-once / rollback / cancel.
 * All state that needs judgement (policy, detectors, snapshots) lives in the
 * Python sidecar; this shell only translates tool calls and talks to the human.
 */
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { Sidecar } from './bridge.js'
import { translateAction } from './translate.js'

const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')

export const name = 'dsh-watchdog'
export const inject = ['tools', 'userQuestions']

/** Human-facing strings. Answers are matched by label prefix because the
 * dsh-user-questions API returns selected option LABELS (no ids/values). */
const UI = {
  zh: {
    header: (sev) => `Watchdog 已暂停 · ${sev}`,
    question: (loc) => `检测到可疑动作：${loc}。请选择处置方式：`,
    evidence: '证据',
    options: [
      { label: '放行一次', description: '允许这一个动作并继续监视后续动作' },
      { label: '撤回该动作', description: '拦截该动作，本回合继续' },
      { label: '取消本回合', description: '拦截该动作并中止本回合的剩余动作' },
    ],
    match: { allow: '放行', rollback: '撤回' },
    allowlistHeader: '误报处理',
    allowlistQuestion: '确认误报？可以把这个对象永久加入白名单（写入 policy 并留审计记录）：',
    allowHostPrefix: '把 host 加入白名单:',
    allowPathPrefix: '豁免该路径:',
    allowlistSkip: '不加白，仅放行这一次',
  },
  en: {
    header: (sev) => `Watchdog paused · ${sev}`,
    question: (loc) => `Suspicious action: ${loc}. Choose how to proceed:`,
    evidence: 'Evidence',
    options: [
      { label: 'Allow once', description: 'Release this single action and keep watching' },
      { label: 'Roll back', description: 'Block this action, continue the turn' },
      { label: 'Cancel turn', description: 'Block this action and abort the rest of the turn' },
    ],
    match: { allow: 'Allow', rollback: 'Roll back' },
    allowlistHeader: 'False positive?',
    allowlistQuestion: 'Whitelist this object permanently (written to policy with an audit record):',
    allowHostPrefix: 'Allowlist host:',
    allowPathPrefix: 'Exempt path:',
    allowlistSkip: 'No whitelist — allow this one time only',
  },
}

export function apply(ctx, config = {}) {
  // Zero-path defaults: the bundled sidecar and policy live in this checkout
  // next to the plugin — no absolute paths to hand-edit at install time.
  // Explicit config always wins.
  const cfg = {
    pythonBin: config.pythonBin ?? (process.platform === 'win32' ? 'python' : 'python3'),
    sidecarEntry: config.sidecarEntry ?? join(PLUGIN_ROOT, '..', 'sidecar', 'watchdog_sidecar.py'),
    policyFile: config.policyFile ?? join(PLUGIN_ROOT, '..', '..', 'policy.example.json'),
    snapshotsDir: config.snapshotsDir ?? join(PLUGIN_ROOT, '..', '..', 'snapshots'),
    taskScope: config.taskScope ?? '',
    locale: config.locale ?? 'zh',
    onSidecarError: config.onSidecarError ?? 'deny',
    askTimeoutMs: config.askTimeoutMs ?? 300000,
    previewLimit: config.previewLimit ?? 400,
    maxRestarts: config.maxRestarts ?? 3,
    restartBaseDelay: config.restartBaseDelay ?? 500,
    offerAllowlist: config.offerAllowlist ?? true,
  }
  const log = config.log ?? ((...a) => console.error(...a))
  const sidecar = config.sidecar ?? new Sidecar(cfg, log)
  if (!config.sidecar) {
    // Startup health check: fail loudly at boot (with remediation hints)
    // instead of quietly denying every tool call later.
    sidecar.start()
      .then(() => sidecar.waitHello(15000))
      .then((hello) => log(`[watchdog] sidecar ready (protocol ${hello.protocol}, policy: ${hello.policy})`))
      .catch((err) => {
        log(`[watchdog] ⚠️ sidecar 未能启动: ${err.message}`)
        log('[watchdog] 在 sidecar 恢复前，所有工具调用将 fail closed（拒绝执行）。')
        log('[watchdog] 请检查 pythonBin / sidecarEntry / policyFile 配置（见 integration/README.md）。')
      })
  }
  ctx.on?.('dispose', () => sidecar.shutdown())

  // Verified on the real harness (smoke probe, inprocess-probe.mjs): the
  // pre/post-execute waterfalls are CONTEXT events — dsh-tools calls
  // ctx.waterfall(…). Registering on the service (ctx.tools.on) crashes the
  // boot with "ctx.tools.on is not a function".
  ctx.on('tools/pre-execute', async (exec, next) => {
    const action = translateAction(exec, cfg.previewLimit)

    let resp
    try {
      resp = await sidecar.review(action, {
        rootCallId: String(exec?.rootCallId ?? exec?.callId ?? 'root'),
      })
    } catch (err) {
      if (cfg.onSidecarError === 'allow') return next()
      return { kind: 'deny',
               reason: `watchdog sidecar unavailable (${err.message}); failing closed` }
    }

    if (resp.verdict === 'clean') return next()
    if (resp.verdict === 'denied') {
      return { kind: 'deny', reason: resp.reason || 'watchdog: denied' }
    }

    // Paused: flag the findings and let the human decide.
    const decision = await askHuman(ctx, cfg, resp, exec)

    // False-positive workflow: on allow, offer to make the exemption permanent.
    let policyUpdate
    if (decision === 'allow' && cfg.offerAllowlist !== false) {
      policyUpdate = await askAllowlist(ctx, cfg, resp)
    }

    const resolution = await sidecar.resolve(resp.ref, decision, policyUpdate).catch(() => null)
    const snapshotNote = resolution?.snapshot ? ` 快照: ${resolution.snapshot}` : ''

    if (decision === 'allow') {
      if (resolution?.policyChange) log(`[watchdog] policy updated: ${resolution.policyChange}`)
      return next()
    }
    return {
      kind: 'deny',
      reason: decision === 'rollback'
        ? `watchdog: 用户检视后撤回了该动作（${resp.location}）。不要重试此调用。${snapshotNote}`
        : `watchdog: 用户检视后取消了本回合（${resp.location}）。请停止当前工作。${snapshotNote}`,
    }
  })
}

async function askHuman(ctx, cfg, resp, exec) {
  const ui = UI[cfg.locale] ?? UI.zh
  const findingsText = resp.findings
    .map((f) => `• [${f.rule_id} / ${f.severity}] ${f.message}\n  ${ui.evidence}: ${f.evidence}`)
    .join('\n')
    .slice(0, 4000)
  const question = {
    id: 'watchdog-pause',
    header: ui.header(resp.worst_severity),
    question: ui.question(resp.location),
    detail: findingsText,
    options: ui.options,
  }
  try {
    if (!ctx.userQuestions?.ask) return 'cancel'          // no UI: fail closed
    const answer = await raceWithTimeout(
      ctx.userQuestions.ask({ questions: [question], signal: exec?.signal }),
      cfg.askTimeoutMs,
    )
    const selected = answer?.answers?.find((a) => a.id === 'watchdog-pause')
      ?.selected?.[0] ?? ''
    if (selected.startsWith(ui.match.allow)) return 'allow'
    if (selected.startsWith(ui.match.rollback)) return 'rollback'
    return 'cancel'                                        // unknown label: fail closed
  } catch {
    return 'cancel'                                        // error/timeout: fail closed
  }
}

/** Follow-up question after an allow: offer the sidecar's allowlist candidates
 * (the flagged host / protected path). Returns a policyUpdate or undefined.
 * Matching is by exact label because the API returns selected labels. */
async function askAllowlist(ctx, cfg, resp) {
  const candidates = resp?.allowlist ?? {}
  const hosts = candidates.hosts ?? []
  const paths = candidates.paths ?? []
  if (!hosts.length && !paths.length) return undefined
  const locale = UI[cfg.locale] ?? UI.zh
  const options = [
    ...hosts.map((h) => ({ label: `${locale.allowHostPrefix} ${h}`, host: h })),
    ...paths.map((p) => ({ label: `${locale.allowPathPrefix} ${p}`, path: p })),
    { label: locale.allowlistSkip },
  ]
  try {
    const answer = await raceWithTimeout(
      ctx.userQuestions.ask({
        questions: [{
          id: 'watchdog-allowlist',
          header: locale.allowlistHeader,
          question: locale.allowlistQuestion,
          options,
        }],
      }),
      cfg.askTimeoutMs,
    )
    const selected = answer?.answers?.find((a) => a.id === 'watchdog-allowlist')
      ?.selected?.[0] ?? ''
    const hit = options.find((o) => o.label === selected)
    if (hit?.host) return { allowHost: hit.host }
    if (hit?.path) return { allowPath: hit.path }
    return undefined                                    // skipped or unknown: no change
  } catch {
    return undefined                                    // error/timeout: no change (the allow stands)
  }
}

function raceWithTimeout(promise, ms) {
  let timer
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('ask timeout')), ms)
    }),
  ]).finally(() => clearTimeout(timer))
}
