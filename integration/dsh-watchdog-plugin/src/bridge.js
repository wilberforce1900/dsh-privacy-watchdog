/** JSON-lines sidecar client: spawn python3 watchdog_sidecar.py, one request at a time.
 *
 * Resilience contract (fail closed, then self-heal):
 *  - protocol handshake: the sidecar's hello must carry the expected protocol
 *    version, otherwise the sidecar is treated as poisoned (no restarts);
 *  - spawn failures and crashes fail every in-flight request immediately;
 *  - unexpected deaths are retried with exponential backoff up to
 *    `maxRestarts`; a healthy hello resets the crash budget;
 *  - a request arriving while the sidecar is down triggers an on-demand start.
 */
import { spawn } from 'node:child_process'
import { once } from 'node:events'
import readline from 'node:readline'

export class Sidecar {
  constructor(config, log = () => {}) {
    this.config = config
    this.log = log
    this.protocolVersion = 1
    this.maxRestarts = config.maxRestarts ?? 3
    this.restartBaseDelay = config.restartBaseDelay ?? 500
    this.restarts = 0          // consecutive crashes since last healthy hello
    this.totalRestarts = 0     // restarts ever performed (observable)
    this.stopping = false
    this.poisoned = null       // permanent error: never restart
    this.proc = null
    this.pending = new Map()
    this.hello = null
    this.dead = null
    this.helloWaiters = []
    this.seq = 0
  }

  async start() {
    if (this.proc && this.proc.exitCode === null) return   // already running
    this.stopping = false
    this.hello = null
    this.proc = spawn(this.config.pythonBin || 'python3',
                      [this.config.sidecarEntry], {
      env: {
        ...process.env,
        WATCHDOG_POLICY: this.config.policyFile || '',
        WATCHDOG_SNAPSHOTS: this.config.snapshotsDir || '',
        WATCHDOG_TASK_SCOPE: this.config.taskScope || '',
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    })
    this.proc.stdin.on('error', () => {})   // writes racing an exit must not crash the host
    this.started = once(this.proc, 'spawn').then(() => {})
    this.started.catch(() => {})   // rejection surfaces through request()/start(); never unhandled
    this.proc.stderr.on('data', (d) => this.log(`[watchdog-sidecar] ${String(d).trim()}`))
    this.proc.on('error', (err) => this._onDeath(err))
    this.proc.on('exit', (code, signal) =>
      this._onDeath(new Error(`sidecar exited (code=${code} signal=${signal})`)))
    const rl = readline.createInterface({ input: this.proc.stdout })
    rl.on('line', (line) => this._onLine(line))
    await once(this.proc, 'spawn')
  }

  _onLine(line) {
    let msg
    try { msg = JSON.parse(line) } catch { return }
    if (msg.verdict === 'hello') {
      if (msg.protocol !== this.protocolVersion) {
        this.poisoned = new Error(
          `sidecar protocol mismatch: expected ${this.protocolVersion}, got ${msg.protocol} ` +
          `(watchdog plugin and watchdog_sidecar.py versions are out of sync)`)
        this.log(`[watchdog-sidecar] ${this.poisoned.message}`)
        this.proc?.kill('SIGKILL')
        this._rejectHelloWaiters(this.poisoned)
        return
      }
      this.hello = msg
      this.restarts = 0
      this._resolveHelloWaiters(msg)
      return
    }
    const p = this.pending.get(msg.id)
    if (!p) return
    this.pending.delete(msg.id)
    if (msg.ok) p.resolve(msg)
    else p.reject(new Error(msg.error || 'sidecar error'))
  }

  _onDeath(err) {
    for (const p of this.pending.values()) p.reject(err)
    this.pending.clear()
    this._rejectHelloWaiters(err)
    if (this.stopping || this.poisoned) {
      this.dead = this.poisoned ?? err
      return
    }
    if (this.restarts < this.maxRestarts) {
      this.restarts++
      this.totalRestarts++
      const delay = this.restartBaseDelay * 2 ** (this.restarts - 1)
      this.log(`[watchdog-sidecar] ${err.message}; restarting ` +
               `(${this.restarts}/${this.maxRestarts}) in ${delay}ms`)
      this.proc = null
      setTimeout(() => {
        if (this.stopping) return
        this.start().catch((e) => {
          this.dead = e
          this.log(`[watchdog-sidecar] restart failed: ${e.message}`)
        })
      }, delay)
    } else {
      this.dead = err
    }
  }

  /** Resolves with the sidecar's hello, or rejects on death/timeout. */
  waitHello(timeoutMs = 15000) {
    if (this.hello) return Promise.resolve(this.hello)
    if (this.dead) return Promise.reject(this.dead)
    return new Promise((resolve, reject) => {
      const entry = { resolve, reject, cleanup: () => clearTimeout(timer) }
      const timer = setTimeout(() => {
        this.helloWaiters = this.helloWaiters.filter((e) => e !== entry)
        reject(new Error(`no sidecar hello within ${timeoutMs}ms ` +
                         `(pythonBin/sidecarEntry correct? policy parseable?)`))
      }, timeoutMs)
      this.helloWaiters.push(entry)
    })
  }

  _resolveHelloWaiters(msg) {
    for (const e of this.helloWaiters) { e.cleanup(); e.resolve(msg) }
    this.helloWaiters = []
  }

  _rejectHelloWaiters(err) {
    for (const e of this.helloWaiters) { e.cleanup(); e.reject(err) }
    this.helloWaiters = []
  }

  async request(obj, timeoutMs = 60000) {
    if (this.dead) throw this.dead
    if (this.stopping) throw new Error('sidecar is shutting down')
    if (!this.proc || this.proc.exitCode !== null) await this.start()
    await this.started
    if (this.dead) throw this.dead            // died while booting
    return new Promise((resolve, reject) => {
      const id = ++this.seq
      const timer = setTimeout(() => {
        this.pending.delete(id)
        reject(new Error(`sidecar timeout on op=${obj.op}`))
      }, timeoutMs)
      this.pending.set(id, {
        resolve: (v) => { clearTimeout(timer); resolve(v) },
        reject: (e) => { clearTimeout(timer); reject(e) },
      })
      this.proc.stdin.write(JSON.stringify({ id, ...obj }) + '\n')
    })
  }

  review(action, context) { return this.request({ op: 'review', action, context }) }
  resolve(ref, decision, policyUpdate) {
    return this.request({ op: 'resolve', ref, decision, ...(policyUpdate ? { policyUpdate } : {}) })
  }

  shutdown() {
    this.stopping = true
    if (!this.proc || this.proc.exitCode !== null) return
    try { this.proc.stdin.write(JSON.stringify({ id: ++this.seq, op: 'shutdown' }) + '\n') } catch {}
    const killTimer = setTimeout(() => this.proc?.kill('SIGKILL'), 2000)
    this.proc.once('exit', () => clearTimeout(killTimer))
  }
}
