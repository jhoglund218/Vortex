#!/usr/bin/env python3
"""Hash helpers for Flatpak pnpm generated-sources synchronization."""

import hashlib
from pathlib import Path
from typing import List, Optional, Tuple

from _flatpak_env import repo_root


def compute_pnpm_sources_hash(lockfile: Path) -> Tuple[str, List[Path]]:
    root = repo_root()
    if not lockfile.is_absolute():
        lockfile = root / lockfile

    if not lockfile.exists():
        raise FileNotFoundError(f"pnpm lockfile not found: {lockfile}")

    contents = lockfile.read_bytes()
    relative = lockfile.relative_to(root).as_posix()

    digest = hashlib.sha256()
    digest.update(b"flatpak-generated-pnpm-sources-hash-v1\n")
    digest.update(f"path:{relative}\n".encode("utf-8"))
    digest.update(f"size:{len(contents)}\n".encode("utf-8"))
    digest.update(contents)
    digest.update(b"\n")

    return digest.hexdigest(), [lockfile]


def read_stored_hash(hash_file: Path) -> Optional[str]:
    if not hash_file.exists():
        return None
    value = hash_file.read_text(encoding="utf-8").strip()
    return value or None


def write_stored_hash(hash_file: Path, value: str) -> None:
    hash_file.parent.mkdir(parents=True, exist_ok=True)
    hash_file.write_text(f"{value}\n", encoding="utf-8")
