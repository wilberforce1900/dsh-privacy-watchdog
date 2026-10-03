# Security Policy

## Reporting a vulnerability

This project is a security tool — please do NOT report vulnerabilities in it
through public GitHub issues.

Use GitHub's **private vulnerability reporting**
(Security → Report a vulnerability) on this repository. Include:

- the component affected (`watchdog/` core, Python sidecar, JS shell, demo)
- a minimal reproduction (a scripted action list is ideal — see `demo/mock_model.py`)
- your assessment of severity and exploitability

You will get an acknowledgment within 7 days and a fix timeline within 30 days
for confirmed issues. We credit reporters in the release notes by default;
say so explicitly if you prefer to remain anonymous.

## Scope

In scope: anything that lets a watched model bypass, disable, or deceive the
watchdog (detector bypasses, staging escapes, redaction bypasses, protocol
spoofing, fail-open conversions), and any way snapshots could leak unredacted
secrets.

Out of scope: the documented limitations in `THREAT-MODEL.md` (they are known,
stated, and by design). Reading it first makes your report stronger — if you
find a practical bypass of something we declared impossible, we definitely
want to hear that too.

## Design stance

The watchdog is **best-effort detection**, not a security boundary. It fails
closed where it can, but it runs on the same machine as the model it watches
and trusts the local `policy.json` as its root of trust. Treat it as a seatbelt,
not a vault.
