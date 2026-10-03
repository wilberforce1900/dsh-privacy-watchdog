/**
 * In-process probe: boot the REAL dsh-tools ToolRuntime in a bare cordis
 * Context (no LLM, no network), register a trivial tool, and execute it —
 * verifying that a `ctx.on('tools/pre-execute', …)` listener fires and
 * inspecting the ToolExecution shape the watchdog would translate.
 * Run: node integration/smoke-test-plugin/inprocess-probe.mjs
 */
import { pathToFileURL } from 'node:url'
import { join } from 'node:path'
import { homedir } from 'node:os'

// Resolve the @deepseek-ai packages from the local DSH profile store
// (~/.dsh/profiles/node_modules) without hard-coding any absolute path.
const DSH_PKGS = process.env.DSH_PROFILE_ROOT
  ?? join(homedir(), '.dsh', 'profiles', 'node_modules')
const pkg = (name, file = 'lib/index.js') =>
  import(pathToFileURL(join(DSH_PKGS, name, file)).href)

const { Context } = await pkg('@deepseek-ai/cordis')
const dshToolsMod = await pkg('@deepseek-ai/dsh-tools')
const dshTools = dshToolsMod.default
const defineTool = dshToolsMod.defineTool
const dshSystemPrompt = (await pkg('@deepseek-ai/dsh-system-prompt')).default

const log = (...a) => console.log('[probe]', ...a)

const ctx = new Context()
await ctx.plugin(dshSystemPrompt)   // ToolRuntime declares static inject=['systemPrompt']
await ctx.plugin(dshTools)

const seen = []
ctx.on('tools/pre-execute', async (exec, next) => {
  seen.push({
    name: exec?.name,
    callId: exec?.callId,
    rootCallId: exec?.rootCallId,
    token: exec?.token ? 'present' : 'missing',
    signal: exec?.signal?.constructor?.name ?? String(exec?.signal),
    signalAborted: exec?.signal?.aborted,
    agent: exec?.agent ? 'present' : 'absent',
    arguments: exec?.arguments,
  })
  // Verify deny works end-to-end on the second call.
  if (exec?.arguments?.which === 'deny-me') {
    return { kind: 'deny', reason: 'smoke probe denies this call' }
  }
  return next()
})

ctx.tools.register(defineTool({
  name: 'smoke_echo',
  description: 'echo probe tool for the watchdog smoke test',
  parameters: { which: { type: 'string', required: true, description: 'which variant' } },
  output: { schema: { type: 'object', additionalProperties: false, properties: { echoed: { type: 'string' } } } },
  async execute(args) { return { echoed: String(args?.which ?? 'hello') } },
}))

const controller = new AbortController()
const r1 = await ctx.tools.execute({
  callId: 'probe-call-1', name: 'smoke_echo',
  arguments: { which: 'allow-me' }, signal: controller.signal,
})
log('allow-me result kind:', JSON.stringify(r1).slice(0, 160))

const r2 = await ctx.tools.execute({
  callId: 'probe-call-2', rootCallId: 'probe-root-1', name: 'smoke_echo',
  arguments: { which: 'deny-me' }, signal: controller.signal,
})
log('deny-me result kind:', JSON.stringify(r2).slice(0, 200))

log(`pre-execute fired ${seen.length} time(s); shapes:`)
for (const s of seen) log('  ', JSON.stringify(s))
await ctx.dispose?.()
process.exit(0)
