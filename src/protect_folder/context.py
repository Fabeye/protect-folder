"""Injectable environment: lets the same code run for real (root) and under test."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from . import mounts as mnt
from .constants import Layout
from .hostops import HostOps, RealHostOps


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _confirm(prompt: str) -> bool:
    if not sys.stdin.isatty():
        return False
    try:
        return input(f"{prompt} [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


@dataclass
class Context:
    layout: Layout = field(default_factory=Layout)
    host: HostOps = field(default_factory=RealHostOps)
    euid: Callable[[], int] = os.geteuid
    read_mounts: Callable[[], list[mnt.MountEntry]] = mnt.read_mounts
    now: Callable[[], str] = _now
    confirm: Callable[[str], bool] = _confirm
    # Home directories treated as unprotectable; None = discover from the passwd database.
    homes: set[str] | None = None
    # Verify the installed code tree on launch. Tests that run from a source checkout turn this off.
    check_installed_code: bool = True
    # Real-world actor uid for audit: SUDO_UID when run through sudo.
    actor_uid: Callable[[], int] = lambda: int(os.environ.get("SUDO_UID", os.geteuid()))


def default_context() -> Context:
    return Context()
