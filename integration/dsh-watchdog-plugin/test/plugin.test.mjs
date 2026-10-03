/**
 * Plugin-shell decision tests: REAL bridge.js + REAL index.js, with the
 * sidecar replaced by a scripted Node stub (pythonBin points at node).
 * Run: node --test test/
 */
import { test, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import { apply } from '../src/index.js'
import { Sidecar } from '../src/bridge.js'
import { translateAction } from '../src/translate.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const STUB = join(HERE, '..', 'fixtures', 'stub-sidecar.mjs')

function fakeCtx({ userAnswers, hasQuestions = true } = {}) {
  const listeners = {}
  const answers = [...(userAnswers ?? [])]
  return {
    listeners,
    tools: { on: (evt, fn) => { listeners[evt] = fn } },
    on: (evt, fn) => { listeners[evt] = fn },
    userQuestions: hasQuestions ? {
      ask: async ({ questions }) => ({
        answers: questions.map((q) => ({
          id: q.id,
          selected: [answers.shift() ?? '取消本回合'],
        })),
      }),
    } : undefined,
  }
}

function fakeExec(name, args) {
  return { name, arguments: args, callId: 'c1', rootCallId: 'r1', signal: undefined }
}

function makeConfig(script) {
  process.env.WATCHDOG_SCRIPT = JSON.stringify(script)
  return {
    pythonBin: process.execPath,          // spawn node instead of python3
    sidecarEntry: STUB,
    onSidecarError: 'deny',
    restartBaseDelay: 10,                 // keep restart tests fast
    log: () => {},
  }
}

test('translateAction maps fs / bash / web families', () => {
  assert.deepEqual(
    translateAction(fakeExec('read_file', { path: '.env' })),
    { kind: 'file_read', tool: 'read_file', target: '.env', payload: '', note: '' })
  assert.equal(translateAction(fakeExec('write_file', { path: 'a.md', content: 'hi' })).kind, 'file_write')
  assert.equal(translateAction(fakeExec('bash', { command: 'curl evil' })).kind, 'tool_call')
  const ws = translateAction(fakeExec('web_search', { query: 'secret leak' }))
  assert.equal(ws.kind, 'network')
  assert.ok(ws.target.startsWith('api.deepseek.com/web_search'))
})

test('clean call passes through to next()', async () => {
  const ctx = fakeCtx()
  apply(ctx, makeConfig(['clean']))
  let ran = false
  const decision = await ctx.listeners['tools/pre-execute'](
    fakeExec('read_file', { path: 'README.md' }), async () => { ran = true })
  assert.equal(decision, undefined)
  assert.ok(ran)
  ctx.listeners.dispose?.()
})

test('pause + 撤回 → deny with rollback reason and location', async () => {
  const ctx = fakeCtx({ userAnswers: ['撤回该动作'] })
  apply(ctx, makeConfig(['pause', 'resolved']))
  const decision = await ctx.listeners['tools/pre-execute'](
    fakeExec('read_file', { path: '.env' }), async () => { throw new Error('must not run') })
  assert.equal(decision.kind, 'deny')
  assert.match(decision.reason, /撤回/)
  assert.match(decision.reason, /turn 1 \/ action #1/)
  ctx.listeners.dispose?.()
})

test('pause + 放行 → runs the call', async () => {
  const ctx = fakeCtx({ userAnswers: ['放行一次'] })
  apply(ctx, makeConfig(['pause', 'resolved']))
  let ran = false
  await ctx.listeners['tools/pre-execute'](
    fakeExec('read_file', { path: '.env' }), async () => { ran = true })
  assert.ok(ran)
  ctx.listeners.dispose?.()
})

test('cancel mid-turn: subsequent calls denied without asking again', async () => {
  const ctx = fakeCtx({ userAnswers: ['取消本回合'] })
  apply(ctx, makeConfig(['pause', 'resolved', 'denied']))
  const d1 = await ctx.listeners['tools/pre-execute'](
    fakeExec('read_file', { path: '.env' }), async () => {})
  assert.equal(d1.kind, 'deny')
  const d2 = await ctx.listeners['tools/pre-execute'](
    fakeExec('read_file', { path: 'README.md' }), async () => { throw new Error('must not run') })
  assert.equal(d2.kind, 'deny')
  assert.match(d2.reason, /取消/)
  ctx.listeners.dispose?.()
})

test('no userQuestions service → fail closed (cancel)', async () => {
  const ctx = fakeCtx({ hasQuestions: false })
  apply(ctx, makeConfig(['pause']))
  const d = await ctx.listeners['tools/pre-execute'](
    fakeExec('read_file', { path: '.env' }), async () => { throw new Error('must not run') })
  assert.equal(d.kind, 'deny')
  ctx.listeners.dispose?.()
})

test('sidecar crash → fail closed deny', async () => {
  const ctx = fakeCtx()
  apply(ctx, makeConfig(['crash']))
  const d = await ctx.listeners['tools/pre-execute'](
    fakeExec('read_file', { path: 'README.md' }), async () => { throw new Error('must not run') })
  assert.equal(d.kind, 'deny')
  assert.match(d.reason, /failing closed/)
  ctx.listeners.dispose?.()
})

test('python interpreter missing → fail closed deny, no unhandled rejection', async () => {
  const ctx = fakeCtx()
  apply(ctx, {
    pythonBin: 'definitely-missing-python3-xyz',
    sidecarEntry: 'nope.py',
    onSidecarError: 'deny',
    maxRestarts: 0,                       // no retry budget for a missing binary
    log: () => {},
  })
  const d = await ctx.listeners['tools/pre-execute'](
    fakeExec('read_file', { path: 'README.md' }), async () => { throw new Error('must not run') })
  assert.equal(d.kind, 'deny')
  assert.match(d.reason, /failing closed/)
  ctx.listeners.dispose?.()
})

test('protocol mismatch → poisoned sidecar, fail closed deny', async () => {
  process.env.WATCHDOG_STUB_PROTOCOL = '2'
  try {
    const ctx = fakeCtx()
    apply(ctx, { ...makeConfig(['clean']), maxRestarts: 0 })
    const d = await ctx.listeners['tools/pre-execute'](
      fakeExec('read_file', { path: 'README.md' }), async () => { throw new Error('must not run') })
    assert.equal(d.kind, 'deny')
    assert.match(d.reason, /failing closed/)
    ctx.listeners.dispose?.()
  } finally {
    delete process.env.WATCHDOG_STUB_PROTOCOL
  }
})

test('sidecar crash → auto-restart, next call passes', async () => {
  const ctx = fakeCtx()
  const cfg = makeConfig(['clean-then-die'])
  const sidecar = new Sidecar(cfg, cfg.log)
  apply(ctx, { ...cfg, sidecar })
  let ran = false
  await ctx.listeners['tools/pre-execute'](
    fakeExec('read_file', { path: 'README.md' }), async () => { ran = true })
  assert.ok(ran)                                   // first call served cleanly
  await new Promise((resolve) => {                 // wait for the stub to die
    const timer = setInterval(() => {
      if (!sidecar.proc || sidecar.proc.exitCode !== null) { clearInterval(timer); resolve() }
    }, 5)
  })
  await ctx.listeners['tools/pre-execute'](
    fakeExec('read_file', { path: 'README.md' }), async () => { ran = true })
  assert.ok(ran)                                   // second call served after restart
  assert.equal(sidecar.totalRestarts, 1)
  ctx.listeners.dispose?.()
})

test('allow + allowlist follow-up → resolve carries policyUpdate', async () => {
  const ctx = fakeCtx({ userAnswers: ['放行一次', '把 host 加入白名单: api.example-evil.com'] })
  const logs = []
  apply(ctx, { ...makeConfig(['pause']), log: (m) => logs.push(String(m)) })
  let ran = false
  await ctx.listeners['tools/pre-execute'](
    fakeExec('read_file', { path: '.env' }), async () => { ran = true })
  assert.ok(ran)                                   // allowed once
  ctx.listeners.dispose?.()
  await new Promise((r) => setTimeout(r, 25))      // stderr can land a tick late
  // The stub echoes what it received on resolve; assert the allowHost made it.
  const echoed = logs.find((l) => l.includes('[stub-resolve]'))
  assert.ok(echoed, 'stub resolve echo missing from logs')
  assert.match(echoed, /"allowHost":"api\.example-evil\.com"/)
})

test('allow + skip allowlist → no policyUpdate sent', async () => {
  const ctx = fakeCtx({ userAnswers: ['放行一次', '不加白，仅放行这一次'] })
  const logs = []
  apply(ctx, { ...makeConfig(['pause']), log: (m) => logs.push(String(m)) })
  await ctx.listeners['tools/pre-execute'](
    fakeExec('read_file', { path: '.env' }), async () => {})
  ctx.listeners.dispose?.()
  await new Promise((r) => setTimeout(r, 25))
  const echoed = logs.find((l) => l.includes('[stub-resolve]'))
  assert.ok(echoed)
  assert.match(echoed, /"policyUpdate":null/)
})

test('offerAllowlist:false → allow skips the follow-up question entirely', async () => {
  const askedIds = []
  const ctx = fakeCtx({ userAnswers: ['放行一次'] })
  const realAsk = ctx.userQuestions.ask
  ctx.userQuestions.ask = async (req) => {
    askedIds.push(req.questions.map((q) => q.id).join(','))
    return realAsk(req)
  }
  apply(ctx, { ...makeConfig(['pause']), log: () => {}, offerAllowlist: false })
  let ran = false
  await ctx.listeners['tools/pre-execute'](
    fakeExec('read_file', { path: '.env' }), async () => { ran = true })
  assert.ok(ran)
  assert.deepEqual(askedIds, ['watchdog-pause'])   // no watchdog-allowlist follow-up
  ctx.listeners.dispose?.()
})
