"""dsh-privacy-watchdog: pre-execution privacy & scope watchdog for AI agents.

Core idea: intercept every observable action BEFORE it runs, judge it against
local rules, and pause the whole conversation when rules are violated.
"""
from .actions import Action, Finding
from .policy import Policy
from .gate import PauseGate, Outcome
from .snapshot import SnapshotStore
from .monitor import WatchdogMonitor
from .staging import StagedFilesystem

__version__ = "0.1.0-demo"

__all__ = [
    "Action", "Finding", "Policy", "PauseGate", "Outcome",
    "SnapshotStore", "WatchdogMonitor", "StagedFilesystem",
]
