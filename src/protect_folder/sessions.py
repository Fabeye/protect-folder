"""Running protected sessions started by `protect-folder run` (per-user, best-effort, NOT tamper-proof).

Each launch records the per-directory policy digest it was started under. `list`/`status` compare running
sessions against the CURRENT registry, so a session that predates a policy change is reported as
"restart pending" instead of being shown as fully protected. Agents started outside `protect-folder run`
are unknown to this mechanism (and unprotected by it)."""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from . import layers as layers_mod
from .userstate import state_dir


def _dir() -> Path:
    return state_dir() / "sessions"


def target_digest(t: Any) -> str:
    raw = json.dumps([t.canonical_path, t.st_dev, t.st_ino, [int(t.layers[k]) for k in layers_mod.LAYERS]])
    return hashlib.sha256(raw.encode("utf-8", "surrogateescape")).hexdigest()[:12]


def _starttime(pid: int) -> int | None:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
        return int(raw.rsplit(")", 1)[1].split()[19])        # field 22: starttime in clock ticks
    except (OSError, ValueError, IndexError):
        return None


def register(reg: Any, agent: str) -> None:
    pid = os.getpid()
    rec = {"pid": pid, "starttime": _starttime(pid), "agent": agent, "policy_revision": reg.policy_revision,
           "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "targets": {t.id: target_digest(t) for t in reg.targets}}
    try:
        d = _dir()
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = d / f".{pid}.tmp"
        tmp.write_text(json.dumps(rec, sort_keys=True))
        os.replace(tmp, d / f"{pid}.json")
    except OSError:
        pass


def unregister() -> None:
    try:
        (_dir() / f"{os.getpid()}.json").unlink()
    except OSError:
        pass


def running() -> list[dict[str, Any]]:
    """Live sessions only; records of dead processes (or recycled pids) are pruned."""
    out: list[dict[str, Any]] = []
    try:
        files = sorted(_dir().glob("*.json"))
    except OSError:
        return out
    for f in files:
        try:
            rec = json.loads(f.read_text())
            pid = int(rec["pid"])
        except (OSError, ValueError, KeyError, TypeError):
            continue
        if _starttime(pid) is None or _starttime(pid) != rec.get("starttime"):
            try:
                f.unlink()
            except OSError:
                pass
            continue
        out.append(rec)
    return out


def pending_restarts(reg: Any) -> dict[str, Any]:
    """{"sessions": [...stale sessions...], "by_target": {target_id: [pids]}, "removed": [...]}"""
    current = {t.id: target_digest(t) for t in reg.targets}
    sessions, by_target = [], {}
    for rec in running():
        stale = False
        for tid, dig in current.items():
            if rec.get("targets", {}).get(tid) != dig:
                by_target.setdefault(tid, []).append(rec["pid"])
                stale = True
        if any(tid not in current for tid in rec.get("targets", {})):
            stale = True                         # a directory it was started with has since been removed
        if stale:
            sessions.append({"pid": rec["pid"], "agent": rec.get("agent"), "started_at": rec.get("started_at")})
    return {"sessions": sessions, "by_target": by_target, "running": len(running())}
