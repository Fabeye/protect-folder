"""Journalled, compensating transactions for privileged administration.

add/remove touch several independent things (host permissions, snapshots, registry,
generated policy). That cannot be atomic. Instead every mutation is preceded by a durable
*undo record* (write-ahead). If anything fails, or the process dies, the undo records are
replayed in reverse; each metadata undo first re-verifies the directory's identity and
refuses to touch a different object. If rollback cannot be proven complete, the world-readable
marker file is left in place with state RECOVERY_REQUIRED and every launch refuses.
"""

from __future__ import annotations

import base64
import fcntl
import os
import secrets
import signal
from pathlib import Path
from typing import Any, Iterator

from . import jsonio
from .context import Context
from .errors import ProtectError
from .paths import open_dir_nofollow


# ------------------------------------------------------------------------------------------
# lock
# ------------------------------------------------------------------------------------------
class AdminLock:
    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.fd = -1

    def __enter__(self) -> "AdminLock":
        self.ctx.layout.state_dir.mkdir(parents=True, exist_ok=True)
        self.fd = os.open(self.ctx.layout.lock_file, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.fd)
            self.fd = -1
            raise ProtectError("LOCKED", "another protect-folder administrative operation is running")
        return self

    def __exit__(self, *exc: Any) -> None:
        if self.fd >= 0:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
            self.fd = -1


# ------------------------------------------------------------------------------------------
# marker (world-readable so the unprivileged launcher/status can see it)
# ------------------------------------------------------------------------------------------
def read_marker(ctx: Context) -> dict[str, Any] | None:
    try:
        return jsonio.read_json(ctx.layout.marker_file)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return {"state": "RECOVERY_REQUIRED", "reason": "unreadable marker"}


def write_marker(ctx: Context, state: str, txid: str | None, op: str | None, reason: str = "") -> None:
    jsonio.atomic_write_json(ctx.layout.marker_file,
                             {"state": state, "txid": txid, "op": op, "reason": reason},
                             0o644, ctx.layout.trusted_uid, ctx.layout.trusted_gid)


def clear_marker(ctx: Context) -> None:
    try:
        os.unlink(ctx.layout.marker_file)
    except FileNotFoundError:
        pass
    jsonio.fsync_dir(ctx.layout.etc_dir)


def refuse_if_pending(ctx: Context) -> None:
    m = read_marker(ctx)
    if m is not None:
        raise ProtectError(
            "RECOVERY_REQUIRED",
            f"a previous administrative operation did not finish (state={m.get('state')}, "
            f"op={m.get('op')}, tx={m.get('txid')})",
            hint="Run 'sudo protect-folder recover'.")


# ------------------------------------------------------------------------------------------
# undo execution
# ------------------------------------------------------------------------------------------
def undo_file_record(path: Path) -> dict[str, Any]:
    try:
        content = base64.b64encode(path.read_bytes()).decode("ascii")
        st = path.stat()
        return {"kind": "restore_file", "path": str(path), "content_b64": content,
                "mode": st.st_mode & 0o7777}
    except FileNotFoundError:
        return {"kind": "restore_file", "path": str(path), "content_b64": None, "mode": 0o644}


def undo_meta_record(canonical: str, st_dev: int, st_ino: int, meta: Any, acl: Any) -> dict[str, Any]:
    return {"kind": "restore_meta", "path": canonical, "st_dev": st_dev, "st_ino": st_ino,
            "uid": meta.uid, "gid": meta.gid, "mode": meta.mode,
            "acl_text": acl.text, "acl_extended": acl.extended}


def apply_meta(ctx: Context, fd: int, uid: int, gid: int, mode: int,
               acl_text: str, acl_extended: bool) -> None:
    """Set ownership/mode/ACL on an open fd and verify the result. Not recursive."""
    host = ctx.host
    cur_acl = host.get_acl(fd)
    if acl_extended:
        host.set_acl(fd, acl_text)
    elif cur_acl.extended:
        host.clear_acl(fd)
    host.chown(fd, uid, gid)
    host.chmod(fd, mode)
    got = host.stat(fd)
    if (got.uid, got.gid, got.mode) != (uid, gid, mode):
        raise ProtectError("APPLY_FAILED",
                           f"after applying, stat shows {got.uid}:{got.gid} {got.mode:o}, "
                           f"expected {uid}:{gid} {mode:o} (filesystem may not honour it)")
    if acl_extended and host.get_acl(fd).text != acl_text:
        raise ProtectError("APPLY_FAILED", "ACL does not match after restore")


def run_undo(ctx: Context, ops: list[dict[str, Any]]) -> list[str]:
    """Replay undo records in reverse. Returns a list of failure descriptions (empty = proven)."""
    failures: list[str] = []
    for op in reversed(ops):
        try:
            if op["kind"] == "restore_file":
                p = Path(op["path"])
                if op["content_b64"] is None:
                    try:
                        os.unlink(p)
                    except FileNotFoundError:
                        pass
                else:
                    jsonio.atomic_write(p, base64.b64decode(op["content_b64"]), op["mode"],
                                        ctx.layout.trusted_uid, ctx.layout.trusted_gid)
            elif op["kind"] == "restore_meta":
                fd = open_dir_nofollow(op["path"])
                try:
                    st = os.fstat(fd)
                    if st.st_ino != op["st_ino"] or st.st_dev != op["st_dev"]:
                        raise ProtectError("IDENTITY_MISMATCH",
                                           f"{op['path']!r} is no longer the directory that was modified")
                    apply_meta(ctx, fd, op["uid"], op["gid"], op["mode"],
                               op["acl_text"], op["acl_extended"])
                finally:
                    os.close(fd)
            else:
                failures.append(f"unknown undo kind {op.get('kind')!r}")
        except ProtectError as exc:
            if op["kind"] == "restore_meta" and exc.code == "PATH_NOT_FOUND":
                failures.append(f"{op['path']!r}: directory is gone; nothing to restore")
            else:
                failures.append(f"{op.get('path')!r}: {exc.code}: {exc.message}")
        except Exception as exc:  # noqa: BLE001 - must keep going; reported below
            failures.append(f"{op.get('path')!r}: {type(exc).__name__}: {exc}")
    return failures


# ------------------------------------------------------------------------------------------
# transaction
# ------------------------------------------------------------------------------------------
class Transaction:
    def __init__(self, ctx: Context, op: str, target_id: str | None):
        self.ctx = ctx
        self.op = op
        self.target_id = target_id
        self.txid = secrets.token_hex(8)
        self.path = ctx.layout.journal_dir / f"{self.txid}.json"
        self.doc: dict[str, Any] = {"schema": 1, "txid": self.txid, "op": op,
                                    "target_id": target_id, "state": "started",
                                    "started_at": ctx.now(), "undo": []}
        self._old_handlers: dict[int, Any] = {}

    # -- journal persistence -----------------------------------------------------------------
    def _flush(self) -> None:
        jsonio.atomic_write_json(self.path, self.doc, 0o600,
                                 self.ctx.layout.trusted_uid, self.ctx.layout.trusted_gid)

    def begin(self) -> None:
        self.ctx.layout.journal_dir.mkdir(parents=True, exist_ok=True)
        # marker first: a crash at any later point is discoverable from an unprivileged account
        write_marker(self.ctx, "IN_PROGRESS", self.txid, self.op)
        self._flush()
        for sig in (signal.SIGTERM, signal.SIGHUP):
            self._old_handlers[sig] = signal.signal(sig, self._on_signal)

    @staticmethod
    def _on_signal(signum: int, frame: Any) -> None:
        raise KeyboardInterrupt(f"signal {signum}")

    def _restore_signals(self) -> None:
        for sig, h in self._old_handlers.items():
            signal.signal(sig, h)
        self._old_handlers.clear()

    def record_undo(self, record: dict[str, Any]) -> None:
        """Durably log how to reverse the step *before* performing it."""
        self.doc["undo"].append(record)
        self._flush()

    def undo_file(self, path: Path) -> None:
        self.record_undo(undo_file_record(path))

    def commit(self) -> None:
        self.doc["state"] = "committed"
        self._flush()
        os.unlink(self.path)
        clear_marker(self.ctx)
        self._restore_signals()

    def rollback(self, cause: BaseException) -> bool:
        """Compensate. Returns True if rollback is proven complete."""
        self._restore_signals()
        self.doc["state"] = "rolling_back"
        self.doc["error"] = f"{type(cause).__name__}: {cause}"
        self._flush()
        failures = run_undo(self.ctx, self.doc["undo"])
        if not failures:
            os.unlink(self.path)
            clear_marker(self.ctx)
            return True
        self.doc["state"] = "recovery_required"
        self.doc["failures"] = failures
        self._flush()
        write_marker(self.ctx, "RECOVERY_REQUIRED", self.txid, self.op,
                     "; ".join(failures)[:500])
        return False


def pending_journals(ctx: Context) -> Iterator[tuple[Path, dict[str, Any]]]:
    d = ctx.layout.journal_dir
    if not d.exists():
        return
    for p in sorted(d.glob("*.json")):
        try:
            yield p, jsonio.read_json(p)
        except (OSError, ValueError):
            yield p, {"state": "corrupt", "undo": [], "txid": p.stem}
