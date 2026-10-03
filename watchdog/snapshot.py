"""Snapshot: persist one anomaly as a local Markdown file (evidence redacted)."""
from __future__ import annotations

import datetime as _dt
from pathlib import Path

from .actions import Action, Finding, SEVERITY_ORDER
from .redact import redact


def _worst_severity(findings: list[Finding]) -> str:
    return max((f.severity for f in findings),
               key=lambda s: SEVERITY_ORDER.get(s, 0), default="unknown")


def snapshot_markdown(snapshot_id: str, action: Action, findings: list[Finding],
                      decision: str, detail: str, context: dict | None = None) -> str:
    now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ctx = context or {}
    lines = [
        f"# Watchdog 异常快照 · {snapshot_id}",
        "",
        f"- **时间**: {now}",
        f"- **严重级别**: {_worst_severity(findings).upper()}",
        f"- **最终处置**: `{decision}` — {detail}",
        f"- **运行环境**: {ctx.get('environment', 'demo/sandbox（未发送真实网络请求）')}",
        "",
        "## 检测到的行为发生在哪里",
        "",
        f"- **位置**: turn `{action.turn_id}` · action `#{action.index}`",
        f"- **类型/工具**: `{action.kind}` via `{action.tool}`",
        f"- **目标**: `{redact(action.target)}`",
        f"- **来源**: {action.origin}" + (f" · 备注: {redact(action.note)}" if action.note else ""),
        "",
        "## 触发的规则",
        "",
        "| 规则 | 级别 | 说明 |",
        "|---|---|---|",
    ]
    for f in findings:
        lines.append(f"| `{f.rule_id}` | {f.severity} | {redact(f.message)} |")
    lines += ["", "## 证据（已脱敏）", "", "```text"]
    for f in findings:
        lines.append(f"[{f.rule_id}] {f.evidence}")
    lines += ["```", "", "## 时间线", ""]
    for item in ctx.get("timeline", []):
        lines.append(f"- {redact(item)}")
    lines += [
        "",
        "## 后续你可以做什么",
        "",
        "1. 本地检视本文件；2. 如确认是误报，调整 `policy.json` 的 allowlist；",
        "3. 如确认是真问题，可用本仓库的 `watchdog/github_report.py` 生成 GitHub issue",
        "   内容并（可选）上传（demo 入口：`run_demo.py --preview` / `--upload-repo`）。",
        "",
        "> 本快照由 dsh-privacy-watchdog 自动生成，证据字段均经过 redact 处理。",
    ]
    return "\n".join(lines)


class SnapshotStore:
    def __init__(self, directory: str | Path):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.files: list[Path] = []

    def save(self, snapshot_id: str, action: Action, findings: list[Finding],
             decision: str, detail: str, context: dict | None = None) -> Path:
        md = snapshot_markdown(snapshot_id, action, findings, decision, detail, context)
        path = self.directory / f"{snapshot_id}.md"
        path.write_text(md, encoding="utf-8")
        self.files.append(path)
        return path
