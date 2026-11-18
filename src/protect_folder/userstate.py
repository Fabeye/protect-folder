"""Per-user (unprivileged, NOT tamper-proof) state: verification cache, hook log, session records."""

from __future__ import annotations

import os
from pathlib import Path


def state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return Path(base) / "protect-folder"
