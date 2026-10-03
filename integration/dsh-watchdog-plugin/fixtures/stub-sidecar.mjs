/** Scripted Node stub of the Python sidecar protocol for shell tests. */
import readline from 'node:readline'

const script = JSON.parse(process.env.WATCHDOG_SCRIPT || '[]')
const protocol = Number(process.env.WATCHDOG_STUB_PROTOCOL || 1)
let step = 0

const send = (obj) => process.stdout.write(JSON.stringify(obj) + '\n')
send({ ok: true, verdict: 'hello', protocol })

const rl = readline.createInterface({ input: process.stdin })
rl.on('line', (line) => {
  if (!line.trim()) return
  const req = JSON.parse(line)

  if (req.op === 'shutdown') {
    send({ id: req.id, ok: true, bye: true })
    process.exit(0)
  }
  if (req.op === 'resolve') {
    process.stderr.write(`[stub-resolve] ${JSON.stringify({ policyUpdate: req.policyUpdate ?? null })}\n`)
    return send({ id: req.id, ok: true, aborted: req.decision === 'cancel',
                  snapshot: '/tmp/snap-stub.md',
                  policyChange: req.policyUpdate
                    ? `${Object.keys(req.policyUpdate)[0]}=${Object.values(req.policyUpdate)[0]}`
                    : null })
  }
  if (req.op !== 'review') return

  const action = script[Math.min(step++, script.length - 1)]
  if (action === 'crash') {
    process.stderr.write('stub crash requested\n')
    process.exit(9)
  }
  if (action === 'clean') return send({ id: req.id, ok: true, verdict: 'clean' })
  if (action === 'clean-then-die') {
    // Respond once, then die immediately after the response is flushed —
    // used to exercise the auto-restart path.
    process.stdout.write(JSON.stringify({ id: req.id, ok: true, verdict: 'clean' }) + '\n',
                         () => process.exit(9))
    return
  }
  if (action === 'denied') {
    return send({ id: req.id, ok: true, verdict: 'denied',
                  reason: 'watchdog: 本回合已被用户取消，该动作未执行' })
  }
  // default: pause
  send({
    id: req.id, ok: true, verdict: 'pause', ref: `p${step}`,
    location: 'turn 1 / action #1 / file_read:read_file -> .env',
    worst_severity: 'high',
    findings: [{ rule_id: 'sensitive-file-access', severity: 'high',
                 message: 'file_read targets protected path .env', evidence: '...' }],
    allowlist: { hosts: ['api.example-evil.com'], paths: ['.env'] },
  })
})
