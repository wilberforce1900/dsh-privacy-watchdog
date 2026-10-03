"""GitHub community report.

WORKS-NOW  : build_issue() — generates title/body from a snapshot (dry-run by default)
NEEDS-KEY  : upload() — real upload needs either `gh` CLI (authenticated) or
             a GITHUB_TOKEN env var with repo access. Without it we refuse and
             print exact setup steps instead of pretending it worked.
"""
from __future__ import annotations

import json
import os
import shutil
import urllib.request
from pathlib import Path


class NeedsAuth(RuntimeError):
    pass


def build_issue(snapshot_path: str | Path) -> tuple[str, str]:
    src = Path(snapshot_path).read_text(encoding="utf-8")
    first = next((l for l in src.splitlines() if l.startswith("# ")), "# watchdog anomaly")
    title = "[watchdog] " + first.lstrip("# ").strip()
    body = (
        "> 由 dsh-privacy-watchdog 自动生成。证据已脱敏；上传前请再自行检查一遍。\n\n"
        + src
        + "\n\n---\n**分享者补充说明**（可编辑）：\n\n"
    )
    return title, body


def write_preview(snapshot_path: str | Path, out_dir: str | Path) -> Path:
    title, body = build_issue(snapshot_path)
    p = Path(out_dir) / "issue-preview.md"
    p.write_text(f"<!-- title: {title} -->\n\n{body}", encoding="utf-8")
    return p


def upload(snapshot_path: str | Path, repo: str) -> str:
    """Try to create an issue. Prefers gh CLI, falls back to REST + GITHUB_TOKEN."""
    title, body = build_issue(snapshot_path)

    gh = shutil.which("gh")
    if gh:
        import subprocess
        proc = subprocess.run(
            [gh, "issue", "create", "--repo", repo, "--title", title, "--body", body],
            capture_output=True, text=True,
        )
        if proc.returncode == 0:
            return proc.stdout.strip()
        raise NeedsAuth(
            f"gh CLI 已安装但创建失败（未登录或无权限）：{proc.stderr.strip()}\n"
            f"修复：运行 `gh auth login` 后重试。"
        )

    token = os.environ.get("GITHUB_TOKEN")
    if token:
        url = f"https://api.github.com/repos/{repo}/issues"
        data = json.dumps({"title": title, "body": body}).encode()
        req = urllib.request.Request(url, data=data, method="POST", headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        })
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read()).get("html_url", "created")

    raise NeedsAuth(
        "本机既没有 gh CLI，也没有 GITHUB_TOKEN —— 无法真实上传（这是权限问题，不是 bug）。\n"
        "两种开启方式（任选其一）：\n"
        "  1) 安装并登录 gh CLI：`gh auth login`\n"
        "  2) 导出具有该 repo Issue 权限的 GITHUB_TOKEN 环境变量\n"
        "在那之前，可先用 `report.py --preview` 生成的 issue-preview.md 手动粘贴到社区。"
    )
