/**
 * dsh-watchdog-smoke — real-harness probe for the three unverified seams the
 * watchdog integration depends on:
 *   ① `ctx.tools.on('tools/pre-execute', …)` registers and fires;
 *   ② the ToolExecution shape (callId / rootCallId / signal / arguments);
 *   ③ `inject: ['tools','userQuestions']` service names resolve, and what
 *      `ctx.userQuestions.ask()` does where no UI provider exists (headless).
 * It never blocks: every call passes through with `next()`.
 * Set WATCHDOG_SMOKE_PROBE_ASK=1 to fire one 5s-timeout ask() probe.
 */
import { appendFileSync } from 'node:fs'

const LOG = process.env.WATCHDOG_SMOKE_LOG || '/tmp/dsh-watchdog-smoke.log'

function log(line) {
  try { appendFileSync(LOG, `${new Date().toISOString()} ${line}\n`) } catch {}
  console.error(`[smoke] ${line}`)
}

export const name = 'dsh-watchdog-smoke'
export const inject = ['tools', 'userQuestions']

export function apply(ctx, config = {}) {
  log(`applied: ctx.tools=${typeof ctx.tools} ctx.userQuestions=${typeof ctx.userQuestions} ask=${typeof ctx.userQuestions?.ask}`)

  let seen = 0
  // Verified on real harness: the pre/post-execute waterfalls are CONTEXT
  // events (dsh-tools calls ctx.waterfall(…)), registered via ctx.on — NOT
  // ctx.tools.on (a Service instance has no .on; that crashed the boot).
  ctx.on('tools/pre-execute', async (exec, next) => {
    seen++
    const args = JSON.stringify(exec?.arguments) ?? 'undefined'
    log(`pre-execute #${seen}: name=${exec?.name} callId=${exec?.callId} rootCallId=${exec?.rootCallId} ` +
        `signal=${exec?.signal?.constructor?.name ?? typeof exec?.signal} aborted=${exec?.signal?.aborted} ` +
        `agent=${exec?.agent ? 'yes' : 'no'} args=${args.slice(0, 200)}`)
    return next()
  })
  log(`registered tools/pre-execute listener`)

  if (config.probeAsk || process.env.WATCHDOG_SMOKE_PROBE_ASK) {
    void (async () => {
      try {
        const answer = await Promise.race([
          ctx.userQuestions.ask({ questions: [{
            id: 'smoke-probe',
            question: 'smoke probe: this should never be answerable in headless mode',
          }] }),
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error('probe timeout (5s): ask() never settled')), 5000)),
        ])
        log(`ask probe RESOLVED: ${JSON.stringify(answer)?.slice(0, 200)}`)
      } catch (err) {
        log(`ask probe rejected: ${err?.name ?? 'Error'}: ${err?.message}`)
      }
    })()
  }
}
