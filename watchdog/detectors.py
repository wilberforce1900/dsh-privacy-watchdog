"""Detectors: pure functions from Action -> list[Finding].

Design rule: we only judge OBSERVABLE actions (network targets, file paths,
tool calls), never the model's self-reported reasoning — a model can lie
about its intent, but its actions have to actually run somewhere.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from .actions import Action, Finding
from .redact import redact

_STOPWORDS = {
    "this", "that", "with", "from", "have", "has", "the", "and", "for",
    "please", "about", "into", "your", "you", "our", "are", "was", "were",
    "will", "would", "could", "should", "what", "when", "where", "which",
    "http", "https", "www", "com", "file", "files", "make", "made", "using",
}


def _host_of(target: str) -> str:
    try:
        if "://" not in target:
            target = "http://" + target
        return (urlparse(target).hostname or "").lower()
    except ValueError:
        return ""


def _words(text: str) -> set[str]:
    """Latin words (>=4 letters) + Chinese character bigrams.

    Plain English word extraction silently disables the scope check for
    Chinese prompts (no 4+ letter tokens), so CJK runs are split into
    overlapping 2-grams — the cheapest usable similarity signal for Chinese.
    """
    low = (text or "").lower()
    words = {w for w in re.findall(r"[a-zA-Z]{4,}", low) if w not in _STOPWORDS}
    for run in _CJK_RUN_RE.findall(low):
        words.update(run[i:i + 2] for i in range(len(run) - 1))
    return words


_SHELL_NET_RE = re.compile(
    r"\b(curl|wget|nc|ncat|netcat|scp|rsync|sftp|ftp|telnet|ssh|git\s+push)\b")
_URL_HOST_RE = re.compile(r"(?:https?://|ftp://)?([A-Za-z0-9._\-]+\.[A-Za-z]{2,})(?:[/:?#]\S*)?")
_CJK_RUN_RE = re.compile(r"[\u4e00-\u9fff]+")


class EgressDetector:
    """Rule 1: is the model sending data to a host the user never allowed?

    Covers both direct network actions and shell commands that reach the
    network (curl/wget/nc/ssh/...), which are the same exfiltration in
    a different costume.
    """
    rule_prefix = "egress"

    def __init__(self, policy):
        self.policy = policy

    def check(self, a: Action) -> list[Finding]:
        findings: list[Finding] = []
        if a.kind == "network":
            findings.extend(self._egress_findings(a, _host_of(a.target)))
        elif a.kind == "tool_call" and _SHELL_NET_RE.search(a.target or ""):
            hosts = {h.lower() for h in _URL_HOST_RE.findall(a.target or "")}
            allowlisted = [h for h in hosts if self.policy.host_allowed(h)]
            flagged = hosts - set(allowlisted) - {"localhost", "127.0.0.1"}
            if flagged:
                findings.append(Finding(
                    rule_id="shell-egress",
                    severity="high",
                    message=f"Shell command reaches non-allowlisted host(s): "
                            f"{', '.join(sorted(flagged))}.",
                    action=a,
                    evidence=redact(a.target[:self.policy.max_payload_preview]),
                    allow_host=sorted(flagged)[0] if len(flagged) == 1 else "",
                ))
        if findings or a.kind == "network":
            blob = f"{a.target} {a.payload}"
            if any(m in blob for m in ("sk-", "BEGIN PRIVATE KEY", "ghp_", "password=",
                                       "token=", "AKIA", "authorization:")):
                findings.append(Finding(
                    rule_id="egress-contains-secret",
                    severity="critical",
                    message="Outbound payload looks like it contains a credential/secret.",
                    action=a,
                    evidence=redact(a.payload[:self.policy.max_payload_preview] or a.target),
                ))
        return findings

    def _egress_findings(self, a: Action, host: str) -> list[Finding]:
        if self.policy.host_allowed(host):
            return []
        # Read-only GETs to common development infrastructure still get
        # flagged, but at warning severity — pausing on every `pip`/`npm`
        # fetch trains users to approve blindly (alarm fatigue).
        read_only_get = (not a.payload.strip()
                         and a.tool.lower().replace("-", "_") in ("http_get", "get", "web_fetch", "fetch"))
        if read_only_get and self.policy.host_trusted_read(host):
            return [Finding(
                rule_id="trusted-egress-read",
                allow_host=host,
                severity="medium",
                message=f"Read-only request to non-allowlisted but trusted-read host '{host}' "
                        f"(warning only; add to allowed_hosts to silence).",
                action=a,
                evidence=redact(f"{a.tool} {a.target} payload={a.payload[:self.policy.max_payload_preview]}"),
            )]
        return [Finding(
            rule_id="unauthorized-egress",
            allow_host=host,
            severity="high",
            message=f"Network request to non-allowlisted host '{host}' "
                    f"(user never approved this destination).",
            action=a,
            evidence=redact(f"{a.tool} {a.target} payload={a.payload[:self.policy.max_payload_preview]}"),
        )]


class SensitiveAccessDetector:
    """Rule 2: is the model touching files the local rules mark as protected?

    Two protection tiers: 'user' paths pause (high); 'runtime' paths are the
    watchdog's own state (policy file, snapshots) — touching them is a
    self-tampering attempt and is always critical.
    """

    rule_prefix = "sensitive"

    def __init__(self, policy):
        self.policy = policy

    def check(self, a: Action) -> list[Finding]:
        if a.kind not in ("file_read", "file_write"):
            return []
        kind = self.policy.protected_kind(a.target)
        if kind == "runtime":
            return [Finding(
                rule_id="policy-tamper",
                severity="critical",
                message=f"{a.kind} targets the watchdog's own state '{a.target}' "
                        f"(policy/snapshots must never be rewritten by the model).",
                action=a,
                evidence=redact(f"{a.kind}:{a.tool} -> {a.target} :: {a.payload[:self.policy.max_payload_preview]}"),
            )]
        if kind == "user":
            return [Finding(
                rule_id="sensitive-file-access",
                severity="high",
                message=f"{a.kind} targets protected path '{a.target}' "
                        f"(matched local protected_paths rules).",
                action=a,
                allow_path=a.target,
                evidence=redact(f"{a.kind}:{a.tool} -> {a.target} :: {a.payload[:self.policy.max_payload_preview]}"),
            )]
        return []


class ScopeDetector:
    """Rule 3 (heuristic!): is the action even related to the user's prompt?

    Transparent keyword-overlap heuristic — expect false positives, tune with
    scope_exempt_tools / richer intent matching later. Deliberately 'medium'
    so it warns without pausing by default.
    """
    rule_prefix = "scope"

    def __init__(self, policy, user_prompt: str = ""):
        self.policy = policy
        self.prompt_words = _words(user_prompt)

    def check(self, a: Action) -> list[Finding]:
        if a.kind in self.policy.scope_exempt_tools or a.kind == "model_message":
            return []
        action_words = _words(f"{a.target} {a.note} {a.tool}")
        if self.prompt_words and action_words and not (action_words & self.prompt_words):
            overlap = ", ".join(sorted(action_words)[:6])
            return [Finding(
                rule_id="scope-creep",
                severity="medium",
                message="Action shares no keyword with the user's request "
                        "(heuristic; may be a false positive).",
                action=a,
                evidence=redact(f"action words: {overlap}"),
            )]
        return []


def build_detectors(policy, user_prompt: str):
    return [
        EgressDetector(policy),
        SensitiveAccessDetector(policy),
        ScopeDetector(policy, user_prompt=user_prompt),
    ]
