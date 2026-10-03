"""Staged filesystem: file writes land in a staging area and only commit to
the real workspace after the user allows them. This is what makes
"rollback / cancel" real instead of cosmetic — a blocked write simply never
touches the disk.
"""
from __future__ import annotations

import hashlib
import shutil
import tempfile
from pathlib import Path


class StagedFilesystem:
    def __init__(self, real_root: str | Path):
        self.real_root = Path(real_root).resolve()
        self._staging = Path(tempfile.mkdtemp(prefix="watchdog-stage-"))
        self._staged: dict[str, Path] = {}     # relative path -> staged file
        self.committed: list[str] = []

    def stage_write(self, rel_path: str, content: str) -> str:
        rel_path = str(rel_path)
        dest = self._staging / "payload"
        dest.mkdir(parents=True, exist_ok=True)
        # Key the temp file by a hash of the full relative path so two staged
        # writes that share a basename (docs/a.md vs src/a.md) never collide.
        key = hashlib.sha256(rel_path.encode("utf-8")).hexdigest()[:16]
        tmp = dest / f"{key}-{Path(rel_path).name}"
        tmp.write_text(content, encoding="utf-8")
        self._staged[rel_path] = tmp
        return rel_path

    def commit(self, rel_path: str) -> Path:
        """User allowed it: move staged content into the real workspace."""
        tmp = self._staged[rel_path]
        real = (self.real_root / rel_path).resolve()
        if not real.is_relative_to(self.real_root):
            raise ValueError(f"refusing to commit outside the workspace root: {rel_path!r}")
        real.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(tmp), str(real))
        del self._staged[rel_path]
        self.committed.append(rel_path)
        return real

    def discard(self, rel_path: str) -> bool:
        """User rolled back / cancelled: staged content is destroyed."""
        return self._staged.pop(rel_path, None) is not None

    def pending_paths(self) -> list[str]:
        return list(self._staged)

    def cleanup(self) -> None:
        shutil.rmtree(self._staging, ignore_errors=True)
