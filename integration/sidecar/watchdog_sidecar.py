#!/usr/bin/env python3
"""Watchdog sidecar: long-lived JSON-lines reviewer process.

The DSH plugin shell (Node) spawns this with python3 and speaks one JSON object
per line on stdin/stdout. Protocol:

  -> {"id":1,"op":"review","action":{kind,tool,target,payload,note},
      "context":{"rootCallId":"c1","userPrompt":"..."}}
  <- {"id":1,"ok":true,"verdict":"clean"}
     | {"id":1,"ok":true,"verdict":"pause","ref":"p1","location":"...",
        "findings":[{rule_id,severity,message,evidence}]}
     | {"id":1,"ok":true,"verdict":"denied","reason":"turn already cancelled"}

  -> {"id":2,"op":"resolve","ref":"p1","decision":"allow|rollback|cancel"}
  <- {"id":2,"ok":true,"aborted":false,"snapshot":"/path/snap-....md"|null}

  -> {"id":3,"op":"shutdown"}
  <- process exits

State (policy, detectors, pause gate, snapshots) lives here, in Python; the
Node shell only translates tool calls and talks to the human.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]      # dsh-privacy-watchdog/
sys.path.insert(0, str(ROOT))

from watchdog import (Action, PauseGate, Policy, SnapshotStore,  # noqa: E402
                      WatchdogMonitor)
from watchdog.actions import SEVERITY_ORDER, severity_at_least  # noqa: E402

PROTOCOL_VERSION = 1
MAX_MONITORS = 256      # long-lived process: cap per-turn state, evict oldest


class Sidecar:
    def __init__(self, policy: Policy, snapshots_dir: Path, default_prompt: str = "",
                 policy_path: str | None = None):
        self.policy = policy
        self.snapshots = SnapshotStore(snapshots_dir)
        self.policy_path = policy_path
        self.default_prompt = default_prompt
        self.monitors: dict[str, WatchdogMonitor] = {}
        self.cancelled_roots: set[str] = set()
        self.pending: dict[str, tuple[str, Action, list]] = {}  # ref -> (root, action, findings)
        self._ref_seq = 0
        self._turn_of: dict[str, int] = {}
        self._turn_seq = 0
        self._idx: dict[str, int] = {}

    def _evict_oldest_monitor(self) -> None:
        if len(self.monitors) < MAX_MONITORS:
            return
        for old in self.monitors:
            if old not in self.cancelled_roots:
                break
        else:
            # Everything tracked is cancelled; drop the oldest entry anyway.
            old = next(iter(self.monitors))
            self.cancelled_roots.discard(old)
        self.monitors.pop(old, None)
        self._turn_of.pop(old, None)
        self._idx.pop(old, None)

    def _monitor_for(self, root: str, user_prompt: str) -> WatchdogMonitor:
        if root not in self.monitors:
            self._evict_oldest_monitor()
            gate = PauseGate(self.policy, responder=None)
            prompt = user_prompt or self.default_prompt
            self.monitors[root] = WatchdogMonitor(
                self.policy, gate, self.snapshots, user_prompt=prompt,
                environment="dsh integration shell (sandboxed by harness)")
            self._turn_seq += 1
            self._turn_of[root] = self._turn_seq
            self._idx[root] = 0
        return self.monitors[root]

    def review(self, req: dict) -> dict:
        ctx = req.get("context") or {}
        root = str(ctx.get("rootCallId") or "root")
        raw = req.get("action") or {}
        if root in self.cancelled_roots:
            return {"ok": True, "verdict": "denied",
                    "reason": "watchdog: 本回合已被用户取消，该动作未执行"}
        monitor = self._monitor_for(root, str(ctx.get("userPrompt") or ""))
        self._idx[root] = self._idx.get(root, 0) + 1
        action = Action(
            turn_id=self._turn_of[root],
            index=self._idx[root],
            kind=str(raw.get("kind") or "tool_call"),
            tool=str(raw.get("tool") or "unknown"),
            target=str(raw.get("target") or ""),
            payload=str(raw.get("payload") or "")[: self.policy.max_payload_preview],
            note=str(raw.get("note") or ""),
        )
        findings: list = []
        for det in monitor.detectors:
            findings.extend(det.check(action))

        blocking = [f for f in findings
                    if severity_at_least(f.severity, self.policy.severity_threshold)]
        if not blocking:
            monitor.timeline.append(f"ALLOW {action.location}")
            return {"ok": True, "verdict": "clean"}

        # Pause: hand the decision to the human; the shell asks via userQuestions.
        self._ref_seq += 1
        ref = f"p{self._ref_seq}"
        self.pending[ref] = (root, action, blocking)
        monitor.state = "PAUSED"
        # False-positive workflow: offer what the human may permanently exempt
        # when allowing this action. Content-based findings offer nothing.
        allowlist = {
            "hosts": sorted({f.allow_host for f in blocking if f.allow_host})[:2],
            "paths": sorted({f.allow_path for f in blocking if f.allow_path})[:2],
        }
        return {
            "ok": True, "verdict": "pause", "ref": ref,
            "location": action.location,
            "worst_severity": max((f.severity for f in blocking),
                                  key=lambda s: SEVERITY_ORDER.get(s, 0)),
            "findings": [{"rule_id": f.rule_id, "severity": f.severity,
                          "message": f.message, "evidence": f.evidence}
                         for f in blocking],
            "allowlist": allowlist,
        }

    def resolve(self, req: dict) -> dict:
        ref = str(req.get("ref") or "")
        decision = str(req.get("decision") or "cancel")
        if decision not in ("allow", "rollback", "cancel"):
            decision = "cancel"
        entry = self.pending.pop(ref, None)
        if entry is None:
            return {"ok": False, "error": f"unknown or already-resolved ref {ref!r}"}

        root, action, findings = entry
        monitor = self.monitors[root]
        import datetime
        detail = {"allow": "user released this action once",
                  "rollback": "user rolled the pending action back",
                  "cancel": "user cancelled; rest of the turn is aborted"}[decision]

        # False-positive workflow: apply a human-approved allowlist update,
        # persist it to the policy file, and leave an audit trail.
        policy_change = None
        update = req.get("policyUpdate") or {}
        if decision == "allow" and isinstance(update, dict):
            host = str(update.get("allowHost") or "").strip().lower()
            path = str(update.get("allowPath") or "").strip()
            if host:
                policy_change = self._allowlist_change(
                    "allow_host", host, lambda h: h not in self.policy.allowed_hosts,
                    lambda h: self.policy.allowed_hosts.add(h),
                    "allowed_hosts", ["allowed_hosts", sorted(self.policy.allowed_hosts)])
            elif path:
                policy_change = self._allowlist_change(
                    "allow_path", path, lambda p: p.lower() not in self.policy.allowed_paths,
                    lambda p: self.policy.allowed_paths.append(p.lower()),
                    "allowed_paths", ["allowed_paths", self.policy.allowed_paths])

        sid = f"snap-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}-{self._ref_seq}"
        path = monitor.snapshots.save(sid, action, findings, decision, detail,
                                      context={"timeline": monitor.timeline,
                                               "environment": monitor.environment})
        if decision == "cancel":
            self.cancelled_roots.add(root)
        return {"ok": True, "aborted": decision == "cancel", "snapshot": str(path),
                "policyChange": policy_change}

    def _allowlist_change(self, kind, value, is_new, apply_in_memory, json_key, json_value):
        """Persist one human-approved allowlist change: memory + policy file + audit log."""
        import datetime
        if is_new(value):
            apply_in_memory(value)
            if self.policy_path and Path(self.policy_path).exists():
                try:
                    data = json.loads(Path(self.policy_path).read_text(encoding="utf-8"))
                    data[json_key] = json_value[1]
                    tmp = Path(self.policy_path).with_suffix(".tmp")
                    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                                   encoding="utf-8")
                    tmp.replace(self.policy_path)
                except (OSError, json.JSONDecodeError) as e:
                    return f"{kind}={value} (in-memory only; policy file write failed: {e})"
            stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                with open(self.snapshots.directory / "policy-audit.log", "a",
                          encoding="utf-8") as fh:
                    fh.write(json.dumps({"time": stamp, "change": f"{kind}={value}"},
                                        ensure_ascii=False) + "\n")
            except OSError:
                pass
            return f"{kind}={value}"
        return f"{kind}={value} (already present)"


def main() -> int:
    policy_path = os.environ.get("WATCHDOG_POLICY") or str(ROOT / "policy.example.json")
    snapshots_dir = Path(os.environ.get("WATCHDOG_SNAPSHOTS") or (ROOT / "snapshots"))
    default_prompt = os.environ.get("WATCHDOG_TASK_SCOPE") or ""
    policy = Policy.load(policy_path)
    # Self-protection: the model must never be able to rewrite its own
    # guardrails. Touching the policy file or the snapshots dir is always
    # critical (rule policy-tamper), regardless of user protected_paths.
    policy.runtime_protected = [str(Path(policy_path).resolve()), str(snapshots_dir.resolve())]

    sidecar = Sidecar(policy, snapshots_dir, default_prompt=default_prompt,
                      policy_path=policy_path)
    out = sys.stdout

    def send(obj: dict) -> None:
        out.write(json.dumps(obj, ensure_ascii=False) + "\n")
        out.flush()

    send({"ok": True, "verdict": "hello", "protocol": PROTOCOL_VERSION,
          "policy": policy_path, "snapshots": str(snapshots_dir)})

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as e:
            send({"ok": False, "error": f"bad json: {e}"})
            continue
        op = req.get("op")
        try:
            if op == "review":
                send({"id": req.get("id"), **sidecar.review(req)})
            elif op == "resolve":
                send({"id": req.get("id"), **sidecar.resolve(req)})
            elif op == "shutdown":
                send({"id": req.get("id"), "ok": True, "bye": True})
                return 0
            else:
                send({"id": req.get("id"), "ok": False, "error": f"unknown op {op!r}"})
        except Exception as e:  # noqa: BLE001 — never crash the protocol loop
            send({"id": req.get("id"), "ok": False, "error": f"{type(e).__name__}: {e}"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
