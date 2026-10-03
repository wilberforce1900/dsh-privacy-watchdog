"""Action model: every observable step a model/agent wants to take, before it runs."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Action:
    """One observable, pre-execution step proposed by the model.

    kind: network | tool_call | file_read | file_write | model_message
    target: URL / file path / command name
    payload: short preview of what would be sent/written
    """
    turn_id: int
    index: int
    kind: str
    tool: str
    target: str
    payload: str = ""
    origin: str = "model"          # model | user | system
    note: str = ""

    @property
    def location(self) -> str:
        return f"turn {self.turn_id} / action #{self.index} / {self.kind}:{self.tool} -> {self.target}"


@dataclass
class Finding:
    rule_id: str
    severity: str                  # low | medium | high | critical
    message: str
    action: Action
    evidence: str = ""
    # Allowlist candidate for the false-positive workflow: what the human may
    # permanently exempt when allowing this action. Empty = no candidate
    # (content-based findings like egress-contains-secret offer none).
    allow_host: str = ""
    allow_path: str = ""

    @property
    def location(self) -> str:
        return self.action.location


SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def severity_at_least(sev: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(sev, 0) >= SEVERITY_ORDER.get(threshold, 2)
