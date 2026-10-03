"""WatchdogMonitor: the bridge a real harness plugin would call.

A future DSH plugin (Node side) would spawn this as a subprocess/HTTP sidecar
and forward every proposed tool call / network request here BEFORE executing
it; the returned Outcome decides whether the harness proceeds. The current
DSH 0.1.1-rc.2 bundle exposes no confirmed public hook API, so this side is
host-agnostic on purpose.
"""
from __future__ import annotations

import datetime as _dt
import itertools

from .actions import Action, Finding, severity_at_least
from .detectors import build_detectors
from .gate import PauseGate, Outcome
from .policy import Policy
from .snapshot import SnapshotStore


class WatchdogMonitor:
    def __init__(self, policy: Policy, gate: PauseGate, snapshots: SnapshotStore,
                 user_prompt: str = "", environment: str = "demo/sandbox"):
        self.policy = policy
        self.gate = gate
        self.snapshots = snapshots
        self.detectors = build_detectors(policy, user_prompt)
        self.environment = environment
        self.timeline: list[str] = []
        self._ids = itertools.count(1)
        self.warnings: list[Finding] = []
        self.sensitive_context = False    # a protected-path read was allowed this turn

    def observe(self, action: Action) -> Outcome:
        findings: list[Finding] = []
        for det in self.detectors:
            findings.extend(det.check(action))

        # Taint tracking (turn level): once the user allowed a protected-path
        # read, its content is plausibly in the model context — treat any
        # egress attempt afterwards as a potential exfiltration of it.
        if self.sensitive_context:
            for f in findings:
                if f.rule_id in ("unauthorized-egress", "shell-egress") and f.severity == "high":
                    f.severity = "critical"
                    f.message += (" Sensitive file content was released into the model "
                                  "context earlier this turn; egress risk escalated.")

        out = self.gate.review(action, findings)
        stamp = _dt.datetime.now().strftime("%H:%M:%S")

        if out.executed:
            self.timeline.append(f"{stamp} ALLOW  {action.location}")
        else:
            sid = f"snap-{_dt.datetime.now().strftime('%Y%m%d-%H%M%S')}-{next(self._ids)}"
            path = self.snapshots.save(sid, action, findings or out.findings,
                                       out.decision, out.detail,
                                       context={"timeline": self.timeline,
                                                "environment": self.environment})
            self.timeline.append(
                f"{stamp} {out.decision.upper()}  {action.location} -> {path.name}")
            out.snapshot_path = str(path)  # type: ignore[attr-defined]

        # "Warnings" are strictly the below-threshold findings; blocking ones
        # were surfaced to the user (paused or allowed-once), never silent.
        below = [f for f in findings
                 if not severity_at_least(f.severity, self.policy.severity_threshold)]
        self.warnings.extend(below)
        if (out.decision == "allow_once" and out.action.kind == "file_read"
                and self.policy.path_protected(out.action.target)):
            self.sensitive_context = True
        return out
