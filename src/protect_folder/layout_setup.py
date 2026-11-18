"""Create/verify the root-owned directory skeleton (spec section 5)."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .context import Context
from .errors import ProtectError


def _ensure(path: Path, mode: int, uid: int, gid: int) -> None:
    if path.is_symlink():
        raise ProtectError("TAMPERED", f"{path} is a symbolic link")
    if not path.exists():
        path.mkdir(parents=True, exist_ok=True)
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode):
        raise ProtectError("TAMPERED", f"{path} exists but is not a directory")
    if st.st_uid != uid or st.st_gid != gid:
        os.chown(path, uid, gid)
    if (st.st_mode & 0o7777) != mode:
        os.chmod(path, mode)


def ensure_layout(ctx: Context) -> None:
    lo = ctx.layout
    uid, gid = lo.trusted_uid, lo.trusted_gid
    _ensure(lo.etc_dir, 0o755, uid, gid)
    _ensure(lo.generated_dir, 0o755, uid, gid)
    _ensure(lo.state_dir, 0o700, uid, gid)
    _ensure(lo.journal_dir, 0o700, uid, gid)
    _ensure(lo.log_dir, 0o755, uid, gid)


def initialize_state(ctx: Context) -> None:
    """Write an empty registry and its generated policy if none exist (fresh install)."""
    from . import jsonio, registry
    lo = ctx.layout
    ensure_layout(ctx)
    if not lo.targets_file.exists():
        registry.save(lo, registry.Registry())
    reg = registry.load(lo)
    if not lo.srt_targets_file.exists():
        jsonio.atomic_write_json(lo.srt_targets_file, registry.generated_srt_targets(reg), 0o644,
                                 lo.trusted_uid, lo.trusted_gid)
