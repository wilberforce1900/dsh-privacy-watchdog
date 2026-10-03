"""Policy: what this deployment considers allowed / protected.

Loaded from JSON so each user can tune rules locally (the "local rule" the
watchdog enforces). See policy.example.json.

`runtime_protected` is NOT part of the JSON: the harness integration sets it
at startup to protect the watchdog's own state (policy file, snapshots dir) —
a model must never be able to rewrite its own guardrails.
"""
from __future__ import annotations

import json
from pathlib import Path

DEFAULTS = {
    "allowed_hosts": [
        "api.deepseek.com",
    ],
    "protected_paths": [
        ".env",
        ".ssh/",
        "id_rsa",
        ".gitconfig",
        ".netrc",
        "credentials",
    ],
    # Second tier: hosts we still judge but tolerate for read-only GETs
    # (medium warning instead of a pause). Common development infrastructure.
    "trusted_read_hosts": [
        "pypi.org",
        "files.pythonhosted.org",
        "registry.npmjs.org",
        "github.com",
        "raw.githubusercontent.com",
        "objects.githubusercontent.com",
        "docs.python.org",
    ],
    "scope_exempt_tools": ["model_message"],
    # Paths explicitly exempted from protected_paths via the false-positive
    # workflow (or by hand). Substring match, case-insensitive.
    "allowed_paths": [],
    "severity_threshold": "high",   # pause when any finding >= this severity
    "max_payload_preview": 400,
    # Ask-the-human budget per turn; further pauses auto-cancel (alarm-fatigue
    # guard and retry-pressure brake).
    "max_pauses_per_turn": 3,
}


class Policy:
    def __init__(self, data: dict | None = None):
        merged = dict(DEFAULTS)
        merged.update(data or {})
        self.allowed_hosts = {h.lower() for h in merged["allowed_hosts"]}
        self.protected_paths = [p.lower() for p in merged["protected_paths"]]
        self.trusted_read_hosts = [h.lower() for h in merged["trusted_read_hosts"]]
        self.scope_exempt_tools = set(merged["scope_exempt_tools"])
        self.allowed_paths = [p.lower() for p in merged["allowed_paths"]]
        self.severity_threshold = merged["severity_threshold"]
        self.max_payload_preview = int(merged["max_payload_preview"])
        self.max_pauses_per_turn = int(merged["max_pauses_per_turn"])
        self.runtime_protected: list[str] = []

    @classmethod
    def load(cls, path: str | Path | None) -> "Policy":
        if path is None:
            return cls()
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"policy file not found: {p}")
        return cls(json.loads(p.read_text(encoding="utf-8")))

    def host_allowed(self, host: str) -> bool:
        return host.lower() in self.allowed_hosts

    def host_trusted_read(self, host: str) -> bool:
        low = (host or "").lower()
        return any(low == t or low.endswith("." + t) for t in self.trusted_read_hosts)

    def protected_kind(self, path: str) -> str | None:
        """'runtime' (watchdog's own state) | 'user' (protected_paths) | None."""
        low = (path or "").lower()
        if any(mark.lower() in low for mark in self.runtime_protected):
            return "runtime"
        if any(exempt in low for exempt in self.allowed_paths):
            return None
        if any(mark in low for mark in self.protected_paths):
            return "user"
        return None

    def path_protected(self, path: str) -> bool:
        return self.protected_kind(path) is not None
