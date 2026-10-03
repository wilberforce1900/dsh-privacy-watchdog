"""PauseGate: when blocking findings exist, freeze the conversation here and
ask the human for one of three decisions:

  allow     -> release exactly this one action, keep watching
  rollback  -> destroy the pending action (staged writes never hit disk)
  cancel    -> rollback this action AND abort the rest of the turn

Default when no responder answers: cancel (fail closed).
"""
from __future__ import annotations

from .actions import Action, Finding, severity_at_least

Responder = callable  # (Action, list[Finding]) -> "allow" | "rollback" | "cancel"


class Outcome:
    def __init__(self, action: Action, findings: list[Finding],
                 decision: str, executed: bool, detail: str = ""):
        self.action = action
        self.findings = findings
        self.decision = decision          # allow | allow_once | rollback | cancel | abort
        self.executed = executed
        self.detail = detail

    @property
    def blocked(self) -> bool:
        return not self.executed


class PauseGate:
    def __init__(self, policy, responder: Responder | None = None):
        self.policy = policy
        self.responder = responder
        self.state = "OPEN"               # OPEN | PAUSED
        self.aborted = False
        self.pause_count = 0
        self.history: list[Outcome] = []

    def review(self, action: Action, findings: list[Finding]) -> Outcome:
        threshold = self.policy.severity_threshold
        blocking = [f for f in findings if severity_at_least(f.severity, threshold)]
        if not blocking and not self.aborted:
            out = Outcome(action, findings, "allow", True)
            self.history.append(out)
            return out

        self.state = "PAUSED"
        self.pause_count += 1

        # Alarm-fatigue brake: once the per-turn budget is spent, further
        # blocking findings auto-cancel without asking again — a model cycling
        # through hosts to pressure the user into "just allow it" is cut off.
        if self.pause_count > self.policy.max_pauses_per_turn:
            self.aborted = True
            out = Outcome(action, blocking, "cancel", False,
                          f"auto-cancelled: {self.pause_count} pauses this turn exceeded "
                          f"max_pauses_per_turn={self.policy.max_pauses_per_turn}")
            self.history.append(out)
            return out

        cmd = "cancel"
        if self.responder and not self.aborted:
            cmd = self.responder(action, blocking) or "cancel"
        cmd = cmd if cmd in ("allow", "rollback", "cancel") else "cancel"

        if cmd == "allow":
            out = Outcome(action, blocking, "allow_once", True,
                          "user inspected findings and released this action")
        elif cmd == "rollback":
            out = Outcome(action, blocking, "rollback", False,
                          "user rolled the pending action back")
        else:
            self.aborted = True
            out = Outcome(action, blocking, "cancel", False,
                          "user cancelled; rest of the turn is aborted")
        self.state = "OPEN" if not self.aborted else "PAUSED"
        self.history.append(out)
        return out
