"""`verify --admin`: checks that need root to read root-only state. Read-only; never launches an agent
(administrative commands must not run agents as root) and never changes permissions."""

from __future__ import annotations

import os
import stat
from typing import Any

from .. import admin as admin_mod, paths, registry, runtime as runtime_mod, snapshots
from ..adapters.base import FAIL, PASS, UNVERIFIED
from ..context import Context
from ..errors import ProtectError
from ..transactions import pending_journals, read_marker


def _chk(name: str, status: str, detail: str) -> dict[str, str]:
    return {"name": name, "status": status, "detail": detail}


def _mode(path: os.PathLike | str) -> tuple[int, int]:
    st = os.stat(path)
    return st.st_uid, stat.S_IMODE(st.st_mode)


def run_admin_verify(ctx: Context) -> dict[str, Any]:
    if ctx.euid() != 0:
        raise ProtectError("NOT_ROOT", "'verify --admin' reads root-only state and needs administrator privileges",
                           hint="Run: sudo protect-folder verify --admin   (it never launches an agent)")
    lo = ctx.layout
    out: list[dict[str, str]] = []

    for label, p, want in (("state_dir_private", lo.state_dir, 0o700), ("snapshots_file_private", lo.snapshots_file, 0o600)):
        if not p.exists():
            out.append(_chk(label, UNVERIFIED if label == "snapshots_file_private" else FAIL, f"{p} does not exist"))
            continue
        uid, mode = _mode(p)
        ok = uid == lo.trusted_uid and mode == want
        out.append(_chk(label, PASS if ok else FAIL, f"{p}: owner {uid} mode {mode:04o} (want {lo.trusted_uid} {want:04o})"))

    marker = read_marker(ctx)
    out.append(_chk("no_interrupted_operation", FAIL if marker is not None else PASS,
                    f"RECOVERY_REQUIRED marker present: {marker}" if marker is not None else "no marker"))
    js = list(pending_journals(ctx))
    out.append(_chk("no_unfinished_journals", FAIL if js else PASS, f"{len(js)} unfinished journal(s)" if js else "none"))

    try:
        issues = admin_mod.consistency_issues(ctx)
        out.append(_chk("registry_snapshot_l4_consistent", PASS if not issues else FAIL,
                        "consistent" if not issues else "; ".join(issues)))
    except ProtectError as exc:
        out.append(_chk("registry_snapshot_l4_consistent", FAIL, f"{exc.code}: {exc.message}"))

    # would `remove` be safe right now? (identity of every snapshotted object, without restoring anything)
    try:
        reg = registry.load(lo)
        snaps = snapshots.load(lo)
        table = ctx.read_mounts()
        for t in reg.sorted_targets():
            s = snaps.get(t.id)
            if s is None:
                continue
            ident = paths.check_identity(t.canonical_path, s.st_dev, s.st_ino, s.mount_point, s.filesystem_type,
                                         t.mount_source, t.fs_uuid, mounts=table)
            out.append(_chk(f"restore_identity:{t.id}", PASS if ident.status == "OK" else FAIL,
                            "a restore would target the same object that was snapshotted" if ident.status == "OK"
                            else f"a restore would be REFUSED: {ident.detail}"))
    except ProtectError as exc:
        out.append(_chk("restore_identity", FAIL, f"{exc.code}: {exc.message}"))

    for label, root in (("installed_code_trusted", lo.lib_dir),):
        if not root.exists():
            out.append(_chk(label, FAIL, f"{root} missing"))
            continue
        try:
            n = runtime_mod.check_tree(root, lo.trusted_uid)
            out.append(_chk(label, PASS, f"{n} entries under {root}: trusted owner, none group/world writable"))
        except ProtectError as exc:
            out.append(_chk(label, FAIL, exc.message))
    try:
        rt = runtime_mod.check_runtime(ctx, full_hash=True)
        out.append(_chk("runtime_hashes", PASS, f"srt {rt.srt_version}: every vendored file matches its recorded hash"))
    except ProtectError as exc:
        out.append(_chk("runtime_hashes", FAIL, f"{exc.code}: {exc.message}"))

    status = FAIL if any(c["status"] == FAIL for c in out) else (UNVERIFIED if any(c["status"] == UNVERIFIED for c in out) else PASS)
    return {"admin": True, "summary": status, "checks": out}
