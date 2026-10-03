#!/usr/bin/env python3
"""End-to-end demo runner (sandbox only, zero real network).

Examples:
  python3 demo/run_demo.py --scenario a
  python3 demo/run_demo.py --scenario b --decision rollback
  python3 demo/run_demo.py --scenario b --interactive
  python3 demo/run_demo.py --scenario b --decision rollback --preview
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from watchdog import (Action, PauseGate, Policy, SnapshotStore,  # noqa: E402
                      StagedFilesystem, WatchdogMonitor)
from watchdog.github_report import NeedsAuth, upload, write_preview  # noqa: E402
from mock_model import SCENARIOS, USER_PROMPT  # noqa: E402

RULE = "─" * 62


def cli_responder(action: Action, findings):
    print(f"\n⚠️  WATCHDOG FLAG — conversation PAUSED")
    print(f"    位置: {action.location}")
    for f in findings:
        print(f"    规则 [{f.rule_id}] ({f.severity}): {f.message}")
        if f.evidence:
            print(f"    证据: {f.evidence[:200]}")
    while True:
        raw = input("    检视后请选择 [A]放行一次 / [R]撤回该动作 / [C]取消并中止本回合: ").strip().lower()
        if raw in ("a", "allow"):
            return "allow"
        if raw in ("r", "rollback"):
            return "rollback"
        if raw in ("c", "cancel"):
            return "cancel"
        print("    （输入 A / R / C）")


def execute(action: Action, staged: StagedFilesystem) -> str:
    """Simulated execution. Network/tool actions are theatre; writes are real
    but only inside the demo sandbox-out directory."""
    if action.kind == "file_write":
        staged.stage_write(action.target, action.payload)
        return f"staged write → {action.target}（待放行提交）"
    if action.kind == "network":
        return f"[模拟] {action.tool} {action.target}（demo 不发真实请求）"
    if action.kind == "model_message":
        return f"模型: {action.payload}"
    return f"[模拟] {action.kind}:{action.tool} → {action.target}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", choices=list(SCENARIOS), default="b")
    ap.add_argument("--decision", choices=["allow", "rollback", "cancel"], default=None,
                    help="非交互模式下每个暂停点统一采用的决定")
    ap.add_argument("--interactive", action="store_true")
    ap.add_argument("--policy", default=str(HERE.parent / "policy.example.json"))
    ap.add_argument("--out", default=str(HERE / "sandbox-out"))
    ap.add_argument("--preview", action="store_true",
                    help="有快照时生成 issue-preview.md（离线，不需要密钥）")
    ap.add_argument("--upload-repo", dest="upload_repo", default=None,
                    help="尝试真实上传 issue 到该 repo（需要 gh 登录或 GITHUB_TOKEN）")
    args = ap.parse_args()

    label, factory = SCENARIOS[args.scenario]
    policy = Policy.load(args.policy)
    staged = StagedFilesystem(args.out)
    snapshots = SnapshotStore(Path(args.out) / "snapshots")
    responder = cli_responder if args.interactive else (lambda a, f: args.decision)
    gate = PauseGate(policy, responder)
    monitor = WatchdogMonitor(policy, gate, snapshots, user_prompt=USER_PROMPT,
                              environment="demo/sandbox（未发送真实网络请求）")

    print(RULE)
    print(f"场景: {label}")
    print(f"用户请求: {USER_PROMPT}\n{RULE}")

    for action in factory():
        if gate.aborted:
            print(f"  ⛔ 本回合已被用户取消，跳过剩余动作 (#{action.index})")
            break
        out = monitor.observe(action)
        if out.executed:
            print(f"  ▶ #{action.index} {execute(action, staged)}")
            if action.kind == "file_write" and out.decision in ("allow", "allow_once"):
                staged.commit(action.target)
        else:
            print(f"  🚫 #{action.index} 已被拦截（{out.decision}）: {out.detail}")
            if out.action.kind == "file_write" and out.action.target in staged.pending_paths():
                staged.discard(out.action.target)  # 撤回/取消 = 暂存内容销毁，磁盘上从未出现
        if out.executed and any(f.severity == "medium" for f in out.findings):
            for f in out.findings:
                if f.severity == "medium":
                    print(f"    ⚠️ 低级警告（不暂停）[{f.rule_id}]: {f.message}")

    print(RULE)
    print("收尾汇总:")
    print(f"  已提交文件 : {[str(p) for p in staged.committed] or '（无）'}")
    print(f"  保存的快照 : {[str(p) for p in snapshots.files] or '（无）'}")
    print(f"  低级警告   : {len(monitor.warnings)} 条（未达暂停阈值）")
    staged.cleanup()

    if snapshots.files and args.preview:
        prev = write_preview(snapshots.files[0], Path(args.out))
        print(f"  issue 预览 : {prev}（粘贴到 GitHub 社区即可，不需要任何密钥）")
    if snapshots.files and args.upload_repo:
        try:
            url = upload(snapshots.files[0], args.upload_repo)
            print(f"  已上传: {url}")
        except NeedsAuth as e:
            print(f"  上传未执行 —— {e}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
