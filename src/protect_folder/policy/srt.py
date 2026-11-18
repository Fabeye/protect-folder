"""Compile the registry into an SRT settings document, and self-check it before use."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ..context import Context
from ..errors import ProtectError
from ..paths import is_within
from ..registry import Target
from ..runtime import Runtime

WEAKENING_FLAGS = ("enableWeakerNestedSandbox", "allowNestedUserNamespaces",
                   "enableWeakerNetworkIsolation")


def literal(path: str) -> dict[str, Any]:
    """SRT's literal-path syntax: never treated as a glob, even with *, ?, [ in the name."""
    return {"path": path, "literal": True}


def compile_settings(ctx: Context, targets: list[Target], *, workspace: str, extra_write: list[str],
                     allowed_domains: list[str], rt: Runtime,
                     extra_deny_paths: list[str] | None = None) -> dict[str, Any]:
    lo = ctx.layout
    deny = [literal(p) for p in sorted({t.canonical_path for t in targets})
            + sorted(extra_deny_paths or [])]
    allow_write: list[str] = []
    for p in [workspace, *extra_write]:
        if p not in allow_write:
            allow_write.append(p)
    trusted = [str(p) for p in lo.trusted_paths()]
    settings: dict[str, Any] = {
        "network": {"allowedDomains": list(allowed_domains), "deniedDomains": [],
                    "allowLocalBinding": False, "allowAllUnixSockets": False},
        "filesystem": {
            "denyRead": deny,
            "allowRead": [],                              # nothing may re-open a protected path
            "allowWrite": allow_write,
            "denyWrite": deny + [literal(p) for p in trusted],
        },
        "enableWeakerNestedSandbox": False,
        "allowNestedUserNamespaces": False,
        "enableWeakerNetworkIsolation": False,
        "bwrapPath": rt.bwrap,
        "socatPath": rt.socat,
        "ripgrep": {"command": rt.rg},
    }
    validate_settings(settings, [t.canonical_path for t in targets])
    return settings


def _entry_path(e: Any) -> str:
    return e["path"] if isinstance(e, dict) else e


def validate_settings(settings: dict[str, Any], target_paths: list[str]) -> None:
    """Independent self-check of the compiled policy. Raises PREFLIGHT_FAILED on any weakness."""
    def fail(msg: str) -> None:
        raise ProtectError("PREFLIGHT_FAILED", f"compiled SRT policy rejected: {msg}")

    fs = settings.get("filesystem", {})
    net = settings.get("network", {})
    for flag in WEAKENING_FLAGS:
        if settings.get(flag):
            fail(f"{flag} must be false")
    if net.get("allowAllUnixSockets") or net.get("allowLocalBinding"):
        fail("unix-socket/local-binding relaxations must be off")
    if fs.get("allowRead"):
        fail("allowRead must be empty (it overrides denyRead)")
    if fs.get("disabled"):
        fail("filesystem restrictions must not be disabled")
    for d in net.get("allowedDomains", []):
        if d.strip("*.") == "" or d in ("*", "*.*"):
            fail(f"allow-all network entry {d!r}")
    deny_read = {_entry_path(e) for e in fs.get("denyRead", []) if isinstance(e, dict) and e.get("literal")}
    deny_write = {_entry_path(e) for e in fs.get("denyWrite", []) if isinstance(e, dict) and e.get("literal")}
    for tp in target_paths:
        if tp not in deny_read:
            fail(f"{tp!r} missing from denyRead (as a literal entry)")
        if tp not in deny_write:
            fail(f"{tp!r} missing from denyWrite (as a literal entry)")
        for w in fs.get("allowWrite", []):
            wp = _entry_path(w)
            if wp == "/" or is_within(wp, tp):
                fail(f"allowWrite {wp!r} is, or lies inside, protected {tp!r}")


def find_workspace(cwd: str, homes: set[str]) -> str:
    """Git toplevel if cwd is inside a repository, otherwise cwd itself."""
    cwd = os.path.realpath(cwd)
    cur = cwd
    while True:
        if os.path.lexists(os.path.join(cur, ".git")):
            ws = cur
            break
        parent = os.path.dirname(cur)
        if parent == cur or parent in homes:
            ws = cwd
            break
        cur = parent
    return ws


def check_workspace(ws: str, targets: list[Target], homes: set[str]) -> None:
    if ws == "/" or any(ws == h or is_within(h, ws) for h in homes):
        raise ProtectError("PREFLIGHT_FAILED",
                           f"refusing to make {ws!r} writable: it is / or contains a home directory",
                           hint="cd into a specific project directory before 'protect-folder run'.")
    for t in targets:
        if is_within(ws, t.canonical_path):
            raise ProtectError("PREFLIGHT_FAILED",
                               f"the working directory {ws!r} is inside protected {t.canonical_path!r}",
                               hint="Run the agent from a different project directory.")


def write_private_settings(settings: dict[str, Any], runtime_dir: str | None = None) -> str:
    """Write the settings to a 0600 file outside any sandbox-writable location."""
    import json
    import tempfile
    base = runtime_dir if runtime_dir and os.path.isdir(runtime_dir) else None
    fd, path = tempfile.mkstemp(prefix="pf-srt-", suffix=".json", dir=base)
    with os.fdopen(fd, "w") as fh:
        json.dump(settings, fh, sort_keys=True)
    os.chmod(path, 0o600)
    return path
