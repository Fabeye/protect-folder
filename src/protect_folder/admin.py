"""Privileged administrative operations: add, remove, recover."""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from . import audit, jsonio, layers as layers_mod, mounts as mnt, paths, registry, snapshots
from .constants import PROTECTED_GID, PROTECTED_MODE, PROTECTED_UID
from .context import Context
from .errors import ProtectError
from .layout_setup import ensure_layout
from .registry import Registry, Target, target_id
from .snapshots import Snapshot
from .transactions import (AdminLock, Transaction, apply_meta, clear_marker, pending_journals,
                           read_marker, refuse_if_pending, run_undo, undo_meta_record, write_marker)

RESTART_WARNING = ("Already-running AI sessions keep their old sandbox mount namespace and are NOT "
                   "protected by this change. Restart them with 'protect-folder run -- ...'.")
SUDO_WARNING = ("This is not a privilege boundary against your own account: anything running as "
                "your Unix user that can use sudo (or an already-authorised sudo session) can still "
                "undo it. Run 'sudo -K' now to drop cached sudo credentials.")
USABILITY_WARNING = ("The directory is now root:root 0700: your own programs, editors and file "
                     "managers also lose access until it is removed.")
PARENT_WARNING = ("Only the directory itself is locked. If its parent directory is writable by the "
                  "agent, the entry can still be renamed or replaced (L3 pins it inside the sandbox; "
                  "L4 alone does not).")


@dataclass
class Outcome:
    ok: bool
    reason_code: str
    message: str
    data: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def _require_root(ctx: Context, op: str) -> None:
    if ctx.euid() != 0:
        raise ProtectError("NOT_ROOT", f"'{op}' needs administrator privileges",
                           hint=f"Run: sudo protect-folder {op} ...")


def _confirm(ctx: Context, yes: bool, prompt: str) -> None:
    if yes:
        return
    if not ctx.confirm(prompt):
        raise ProtectError("CONFIRMATION_REQUIRED", "not confirmed (pass --yes to proceed non-interactively)")


def _confirm_layers(ctx: Context, yes: bool, accept_no_fs: bool, layers: dict[str, bool], path: str,
                    prompt: str) -> None:
    """The normal confirmation, plus a SEPARATE explicit one when both filesystem-enforcement layers
    (SRT and Linux permissions) are off. `--yes` alone never satisfies the latter."""
    if not layers["sandbox_runtime"] and not layers["linux_permissions"]:
        if not accept_no_fs and not ctx.confirm(
                f"BOTH SRT and Linux permissions are disabled for {path!r}: no independent filesystem-level "
                "enforcement will remain (only bypassable agent rules and hook). Proceed anyway?"):
            raise ProtectError(
                "CONFIRMATION_REQUIRED",
                "refusing to disable both filesystem-enforcement layers without explicit confirmation",
                hint="Re-run with --accept-no-fs-enforcement if you really want this, or keep at least "
                     "one of SRT / Linux permissions enabled.")
    _confirm(ctx, yes, prompt)


def _effective_layers(reg: Registry, t: Target, layers: dict[str, bool]) -> dict[str, bool]:
    """Layers that really apply to `t`: its own settings OR those a protected ancestor enforces."""
    probe = replace(t, layers=dict(layers))
    eff = layers_mod.effective([x for x in reg.targets if x.id != t.id] + [probe], probe)
    return {k: eff[k]["enabled"] for k in layers_mod.LAYERS}


def _effective_notes(reg: Registry, t: Target, layers: dict[str, bool]) -> list[str]:
    """Explain layers a child cannot opt out of because a protected ancestor enforces them."""
    probe = replace(t, layers=dict(layers))
    others = [x for x in reg.targets if x.id != t.id]
    eff = layers_mod.effective(others + [probe], probe)
    return [f"{layers_mod.LABEL[k]} is OFF here but still ENFORCED because protected parent "
            f"{eff[k]['inherited_from']!r} enables it" for k in layers_mod.LAYERS
            if not layers[k] and eff[k]["enabled"]]


def _no_layers(layers: dict[str, bool]) -> None:
    if not any(layers.values()):
        raise ProtectError("NO_LAYERS_ENABLED", "at least one protection layer must stay enabled",
                           hint="To stop protecting a directory use 'sudo protect-folder remove'.")


def write_generated(ctx: Context, reg: Registry) -> None:
    jsonio.atomic_write_json(ctx.layout.srt_targets_file, registry.generated_srt_targets(reg), 0o644,
                             ctx.layout.trusted_uid, ctx.layout.trusted_gid)


def _run_tx(ctx: Context, tx: Transaction, steps) -> None:
    tx.begin()
    try:
        steps()
        tx.commit()
    except BaseException as exc:
        proven = tx.rollback(exc)
        if not proven:
            raise ProtectError(
                "RECOVERY_REQUIRED",
                f"operation failed ({exc}) and rollback could not be proven complete",
                hint="Run 'sudo protect-folder recover' and read its output.") from exc
        raise


# ------------------------------------------------------------------------------------------
def add(ctx: Context, path_arg: str, *, dry_run: bool = False, yes: bool = False,
        follow_symlinks: bool = False, layers: dict[str, bool] | None = None,
        accept_no_fs_enforcement: bool = False) -> Outcome:
    """`layers` lists only the layers to CHANGE from the default (all four ON)."""
    want = {**layers_mod.default_layers(), **(layers or {})}
    _no_layers(want)
    if not dry_run:
        _require_root(ctx, "add")
    lo = ctx.layout
    if not dry_run:
        ensure_layout(ctx)
        refuse_if_pending(ctx)
    lock = AdminLock(ctx) if not dry_run else None
    if lock:
        lock.__enter__()
    try:
        reg = registry.load(lo)
        mounts = ctx.read_mounts()
        res = paths.resolve_target(path_arg, lo, follow_symlinks=follow_symlinks,
                                   existing_paths=reg.paths(), mounts=mounts, homes=ctx.homes)
        try:
            warnings = list(res.warnings)
            existing = reg.find_identity(res.st_dev, res.st_ino)
            if existing is not None:
                return Outcome(True, "ALREADY_PROTECTED",
                               f"{existing.canonical_path} is already protected (no changes made)",
                               {"target": existing.to_dict()},
                               warnings + ["its layer selection was NOT changed; use "
                                           "'protect-folder set-layers' to change layers"])
            same_path = reg.find_path(res.canonical_path)
            if same_path is not None:
                raise ProtectError(
                    "IDENTITY_MISMATCH",
                    f"{res.canonical_path!r} is registered, but the directory there is a different "
                    "object than the one that was protected",
                    hint="Refusing to protect a newly appearing directory at an old path. "
                         "Run 'sudo protect-folder remove --forget " + res.canonical_path + "' "
                         "after confirming the original is gone.")
            if res.mount is None:
                raise ProtectError("UNSUPPORTED_FILESYSTEM", "cannot determine the filesystem type")
            mnt.require_posix_filesystem(res.mount.fstype)

            linux = want["linux_permissions"]
            meta = ctx.host.stat(res.fd)
            acl = ctx.host.get_acl(res.fd) if linux else None
            if linux and acl.extended and not ctx.host.has_acl_tools():
                raise ProtectError("UNEXPECTED_ACL", "directory has an extended ACL and setfacl is unavailable",
                                   hint="Install the 'acl' package.")
            if linux and acl.extended:
                warnings.append("an extended ACL exists; it is snapshotted and will be cleared while "
                                "protected, then restored exactly on remove")

            tid = target_id(res.st_dev, res.st_ino, res.canonical_path)
            plan = {
                "action": "add", "id": tid, "canonical_path": res.canonical_path,
                "input_path": path_arg, "filesystem_type": res.mount.fstype,
                "mount_point": res.mount.mount_point, "layers": dict(want),
                "current": {"uid": meta.uid, "gid": meta.gid, "mode": f"{meta.mode:04o}"},
                "will_apply": ({"uid": PROTECTED_UID, "gid": PROTECTED_GID, "mode": f"{PROTECTED_MODE:04o}",
                                "recursive": False} if linux else
                               "nothing: linux_permissions is disabled, ownership/mode/ACL stay as they are"),
                "acl_extended": bool(acl.extended) if acl else None,
            }
            warnings.append(RESTART_WARNING)
            warnings.append(SUDO_WARNING)
            if linux:
                warnings += [USABILITY_WARNING, PARENT_WARNING]
            candidate = Target(
                id=tid, input_path=path_arg, canonical_path=res.canonical_path,
                st_dev=res.st_dev, st_ino=res.st_ino, filesystem_type=res.mount.fstype,
                mount_point=res.mount.mount_point, created_at=ctx.now(),
                mount_source=res.mount.source, fs_uuid=mnt.fs_uuid(res.mount.source), layers=dict(want))
            eff_want = _effective_layers(reg, candidate, want)
            warnings += layers_mod.layer_warnings(eff_want)
            warnings += _effective_notes(reg, candidate, want)
            if dry_run:
                return Outcome(True, "OK", f"dry run: would protect {res.canonical_path}",
                               {"plan": plan, "dry_run": True}, warnings)
            _confirm_layers(ctx, yes, accept_no_fs_enforcement, eff_want, res.canonical_path,
                            f"Lock {res.canonical_path!r} to root:root 0700?" if linux else
                            f"Register {res.canonical_path!r} (layers: "
                            + ", ".join(k for k in layers_mod.LAYERS if want[k]) + ")?")

            target = candidate
            snap = (Snapshot(target_id=tid, canonical_path=res.canonical_path, st_dev=res.st_dev,
                             st_ino=res.st_ino, mount_point=res.mount.mount_point,
                             filesystem_type=res.mount.fstype, uid=meta.uid, gid=meta.gid,
                             mode=meta.mode, acl_text=acl.text, acl_extended=acl.extended,
                             taken_at=ctx.now()) if linux else None)
            tx = Transaction(ctx, "add", tid)

            def steps() -> None:
                if linux:
                    # 1. snapshot (root-only) -- before anything is changed
                    snaps = snapshots.load(lo)
                    tx.undo_file(lo.snapshots_file)
                    snaps[tid] = snap
                    snapshots.save(lo, snaps)
                    # 2. L4 on the directory itself (never recursive), verified by stat
                    tx.record_undo(undo_meta_record(res.canonical_path, res.st_dev, res.st_ino, meta, acl))
                    apply_meta(ctx, res.fd, PROTECTED_UID, PROTECTED_GID, PROTECTED_MODE, "", False)
                # 3. registry -- a success record exists only once L4 (if enabled) is verified
                tx.undo_file(lo.targets_file)
                tx.undo_file(lo.targets_prev_file)
                new = Registry(list(reg.targets), reg.revision + 1)
                new.add(target)
                registry.save(lo, new)
                # 4. generated policy artifacts
                tx.undo_file(lo.srt_targets_file)
                write_generated(ctx, new)
                plan["policy_revision"] = new.policy_revision
                plan["revision"] = new.revision

            _run_tx(ctx, tx, steps)
            audit.log_admin(ctx, "add", "success", "OK", tid, revision=plan["revision"],
                            policy_revision=plan["policy_revision"], layers=dict(want))
            return Outcome(True, "OK", f"protected {res.canonical_path}",
                           {"target": target.to_dict(), "plan": plan, "restart_required": True}, warnings)
        finally:
            res.close()
    except ProtectError as exc:
        if not dry_run:
            audit.log_admin(ctx, "add", "failure", exc.code)
        raise
    finally:
        if lock:
            lock.__exit__()


# ------------------------------------------------------------------------------------------
def set_layers(ctx: Context, path_arg: str, changes: dict[str, bool], *, dry_run: bool = False,
               yes: bool = False, accept_no_fs_enforcement: bool = False) -> Outcome:
    """Change which layers are enabled for ONE registered directory. Only the layers named in
    `changes` are touched; nothing is enabled or disabled implicitly."""
    if not changes:
        raise ProtectError("USAGE", "no layer change requested",
                           hint="e.g. 'sudo protect-folder set-layers PATH --no-linux' or '--all'")
    if not dry_run:
        _require_root(ctx, "set-layers")
        ensure_layout(ctx)
        refuse_if_pending(ctx)
    lo = ctx.layout
    lock = AdminLock(ctx) if not dry_run else None
    if lock:
        lock.__enter__()
    try:
        reg = registry.load(lo)
        t = _find_for_removal(reg, path_arg)
        old = dict(t.layers)
        new_layers = {**old, **changes}
        changed = [k for k in layers_mod.LAYERS if old[k] != new_layers[k]]
        if not changed:
            return Outcome(True, "OK", f"{t.canonical_path}: layers already as requested (no changes made)",
                           {"target": t.to_dict(), "changed": []}, [])
        _no_layers(new_layers)
        lin_off = "linux_permissions" in changed and not new_layers["linux_permissions"]
        lin_on = "linux_permissions" in changed and new_layers["linux_permissions"]
        warnings: list[str] = []
        ident = paths.check_identity(t.canonical_path, t.st_dev, t.st_ino, t.mount_point,
                                     t.filesystem_type, t.mount_source, t.fs_uuid, mounts=ctx.read_mounts())
        warnings += ident.warnings
        snaps = snapshots.load(lo) if (not dry_run or ctx.euid() == 0) else {}
        snap = snaps.get(t.id)
        plan = {"action": "set-layers", "id": t.id, "canonical_path": t.canonical_path, "before": old,
                "after": dict(new_layers), "changed": changed, "identity": ident.status,
                "linux": ("restore original ownership/mode/ACL from the snapshot" if lin_off else
                          "capture the current state and apply root:root 0700" if lin_on else "unchanged")}
        if (lin_off or lin_on) and ident.status != "OK":
            raise ProtectError(
                ident.reason if ident.reason in ("MOUNT_MISSING", "IDENTITY_MISMATCH", "STALE")
                else "IDENTITY_MISMATCH",
                f"cannot change Linux permissions of {t.canonical_path!r}: {ident.detail}",
                details={"identity": ident.status},
                hint="The directory is not the object that was registered, so permissions are NOT touched. "
                     + _manual_recovery(t, snap) + " To drop the stale registration: "
                     "sudo protect-folder remove --forget -- <path>")
        if lin_off:
            if snap is None:
                raise ProtectError("TAMPERED", f"no permission snapshot for {t.id}; refusing to guess "
                                   "original permissions", hint=_manual_recovery(t, None))
            if snap.st_ino != t.st_ino or snap.st_dev != t.st_dev:
                raise ProtectError("TAMPERED", "snapshot identity does not match the registry entry")
        eff_new = _effective_layers(reg, t, new_layers)
        warnings += _effective_notes(reg, t, new_layers)
        warnings += layers_mod.layer_warnings(eff_new)
        restart = any(k != "linux_permissions" for k in changed)
        if restart:
            warnings.append(RESTART_WARNING)
        if lin_on:
            warnings += [USABILITY_WARNING, PARENT_WARNING]
        if lin_off:
            warnings.append("Linux permissions were restored: processes outside the sandbox can use this "
                            "directory again. Already-open handles are unaffected by either direction.")
        if dry_run:
            return Outcome(True, "OK", f"dry run: would change layers of {t.canonical_path}: "
                           + ", ".join(f"{k}={'on' if new_layers[k] else 'off'}" for k in changed),
                           {"plan": plan, "dry_run": True}, warnings)
        _confirm_layers(ctx, yes, accept_no_fs_enforcement, eff_new, t.canonical_path,
                        f"Change layers of {t.canonical_path!r}: "
                        + ", ".join(f"{layers_mod.LABEL[k]} -> {'ON' if new_layers[k] else 'OFF'}" for k in changed) + "?")

        tx = Transaction(ctx, "set-layers", t.id)
        fd = paths.open_dir_nofollow(t.canonical_path) if (lin_off or lin_on) else None
        try:
            if fd is not None:
                st = os.fstat(fd)
                if st.st_ino != t.st_ino or st.st_dev != t.st_dev:     # re-check on the open handle
                    raise ProtectError("IDENTITY_MISMATCH", "directory changed while preparing the change")

            def steps() -> None:
                if lin_off:
                    cur_meta, cur_acl = ctx.host.stat(fd), ctx.host.get_acl(fd)
                    tx.record_undo(undo_meta_record(t.canonical_path, t.st_dev, t.st_ino, cur_meta, cur_acl))
                    apply_meta(ctx, fd, snap.uid, snap.gid, snap.mode, snap.acl_text, snap.acl_extended)
                    tx.undo_file(lo.snapshots_file)
                    s = snapshots.load(lo)
                    s.pop(t.id, None)
                    snapshots.save(lo, s)
                elif lin_on:
                    meta, acl = ctx.host.stat(fd), ctx.host.get_acl(fd)
                    locked = (meta.uid, meta.gid, meta.mode) == (PROTECTED_UID, PROTECTED_GID, PROTECTED_MODE)
                    valid = (snap is not None and snap.st_ino == t.st_ino and snap.st_dev == t.st_dev)
                    if valid and locked:
                        plan["snapshot"] = "reused (directory is still locked; original state is in the snapshot)"
                    else:
                        if locked:
                            raise ProtectError(
                                "ERROR", f"{t.canonical_path!r} is already root:root 0700 and no valid "
                                "original-state snapshot exists, so its original permissions are unknown",
                                hint="Set the ownership/mode you want it to have when unprotected "
                                     "(chown/chmod by hand), then run set-layers again.")
                        if acl.extended and not ctx.host.has_acl_tools():
                            raise ProtectError("UNEXPECTED_ACL", "directory has an extended ACL and setfacl "
                                               "is unavailable", hint="Install the 'acl' package.")
                        plan["snapshot"] = ("replaced stale snapshot with the current state" if snap is not None
                                            else "captured the current state")
                        tx.undo_file(lo.snapshots_file)
                        s = snapshots.load(lo)
                        s[t.id] = Snapshot(target_id=t.id, canonical_path=t.canonical_path, st_dev=t.st_dev,
                                           st_ino=t.st_ino, mount_point=t.mount_point,
                                           filesystem_type=t.filesystem_type, uid=meta.uid, gid=meta.gid,
                                           mode=meta.mode, acl_text=acl.text, acl_extended=acl.extended,
                                           taken_at=ctx.now())
                        snapshots.save(lo, s)
                    tx.record_undo(undo_meta_record(t.canonical_path, t.st_dev, t.st_ino, meta, acl))
                    apply_meta(ctx, fd, PROTECTED_UID, PROTECTED_GID, PROTECTED_MODE, "", False)
                tx.undo_file(lo.targets_file)
                tx.undo_file(lo.targets_prev_file)
                new = Registry([replace(x, layers=dict(new_layers)) if x.id == t.id else x for x in reg.targets],
                               reg.revision + 1)
                registry.save(lo, new)
                tx.undo_file(lo.srt_targets_file)
                write_generated(ctx, new)
                plan["policy_revision"], plan["revision"] = new.policy_revision, new.revision

            _run_tx(ctx, tx, steps)
        finally:
            if fd is not None:
                os.close(fd)
        audit.log_admin(ctx, "set-layers", "success", "OK", t.id, revision=plan["revision"],
                        policy_revision=plan["policy_revision"], layers=dict(new_layers))
        return Outcome(True, "OK", f"updated layers of {t.canonical_path}",
                       {"target": replace(t, layers=dict(new_layers)).to_dict(), "plan": plan,
                        "changed": changed, "restart_required": restart}, warnings)
    except ProtectError as exc:
        if not dry_run:
            audit.log_admin(ctx, "set-layers", "failure", exc.code)
        raise
    finally:
        if lock:
            lock.__exit__()


# ------------------------------------------------------------------------------------------
def _find_for_removal(reg: Registry, arg: str) -> Target:
    t = reg.find_id(arg)
    if t:
        return t
    if len(arg) >= 6 and all(c in "0123456789abcdef" for c in arg):          # unique id prefix (as printed by list)
        hits = [x for x in reg.targets if x.id.startswith(arg)]
        if len(hits) == 1:
            return hits[0]
        if len(hits) > 1:
            raise ProtectError("NOT_PROTECTED", f"id prefix {arg!r} is ambiguous", hint="Use more characters.")
    absolute = os.path.abspath(os.path.expanduser(arg))
    for cand in (absolute, os.path.realpath(absolute)):
        t = reg.find_path(cand)
        if t:
            return t
    for t in reg.targets:
        if t.input_path == arg or os.path.abspath(t.input_path) == absolute:
            return t
    raise ProtectError("NOT_PROTECTED", f"{arg!r} is not a registered protected directory",
                       hint="See 'protect-folder list'.")


def _manual_recovery(t: Target, snap: Snapshot | None) -> str:
    orig = (f"uid={snap.uid} gid={snap.gid} mode={snap.mode:04o}" if snap
            else "(snapshot unavailable)")
    return (f"Manual recovery: verify with 'ls -di' that {t.canonical_path!r} is inode {t.st_ino} "
            f"on the original disk, then as root restore only that directory (not recursively): "
            f"chown {snap.uid if snap else '<uid>'}:{snap.gid if snap else '<gid>'} <dir> && "
            f"chmod {snap.mode:04o} <dir>  [original: {orig}]." if snap else
            "Manual recovery: the original metadata snapshot is unavailable; inspect the directory "
            "and set ownership/mode by hand.")


def remove(ctx: Context, path_arg: str, *, dry_run: bool = False, yes: bool = False,
           forget: bool = False) -> Outcome:
    if not dry_run:
        _require_root(ctx, "remove")
        ensure_layout(ctx)
        refuse_if_pending(ctx)
    lo = ctx.layout
    lock = AdminLock(ctx) if not dry_run else None
    if lock:
        lock.__enter__()
    try:
        reg = registry.load(lo)
        t = _find_for_removal(reg, path_arg)
        snaps = snapshots.load(lo) if (not dry_run or ctx.euid() == 0) else {}
        snap = snaps.get(t.id)
        warnings: list[str] = []

        ident = paths.check_identity(t.canonical_path, t.st_dev, t.st_ino, t.mount_point,
                                     t.filesystem_type, t.mount_source, t.fs_uuid,
                                     mounts=ctx.read_mounts())
        warnings += ident.warnings
        plan = {"action": "remove", "id": t.id, "canonical_path": t.canonical_path,
                "forget_only": forget, "identity": ident.status,
                "will_restore": ({"uid": snap.uid, "gid": snap.gid, "mode": f"{snap.mode:04o}",
                                  "acl_extended": snap.acl_extended} if snap else None)}

        if forget:
            if dry_run:
                return Outcome(True, "OK", f"dry run: would forget {t.canonical_path} "
                               "without touching the filesystem", {"plan": plan, "dry_run": True}, warnings)
            _confirm(ctx, yes, f"Forget {t.canonical_path!r} WITHOUT restoring its permissions?")
            tx = Transaction(ctx, "forget", t.id)

            def forget_steps() -> None:
                tx.undo_file(lo.snapshots_file)
                s = snapshots.load(lo)
                s.pop(t.id, None)
                snapshots.save(lo, s)
                tx.undo_file(lo.targets_file)
                tx.undo_file(lo.targets_prev_file)
                new = Registry([x for x in reg.targets if x.id != t.id], reg.revision + 1)
                registry.save(lo, new)
                tx.undo_file(lo.srt_targets_file)
                write_generated(ctx, new)

            _run_tx(ctx, tx, forget_steps)
            audit.log_admin(ctx, "forget", "success", "OK", t.id)
            warnings.append("Permissions were NOT restored. If the directory still exists it may "
                            "remain root:root 0700. " + _manual_recovery(t, snap))
            return Outcome(True, "OK", f"forgot {t.canonical_path}", {"plan": plan}, warnings)

        needs_restore = t.layers["linux_permissions"] or snap is not None
        if not needs_restore:
            # Linux permissions were never applied (or were already restored): there is no filesystem state
            # to put back, so the registration alone is dropped. The directory is not touched.
            plan["will_restore"] = None
            if dry_run:
                return Outcome(True, "OK", f"dry run: would unregister {t.canonical_path} "
                               "(Linux permissions were off; the directory is not touched)",
                               {"plan": plan, "dry_run": True}, warnings)
            _confirm(ctx, yes, f"Stop protecting {t.canonical_path!r}? (its permissions are not touched)")
            tx = Transaction(ctx, "remove", t.id)

            def unreg_steps() -> None:
                tx.undo_file(lo.targets_file)
                tx.undo_file(lo.targets_prev_file)
                new = Registry([x for x in reg.targets if x.id != t.id], reg.revision + 1)
                registry.save(lo, new)
                tx.undo_file(lo.srt_targets_file)
                write_generated(ctx, new)

            _run_tx(ctx, tx, unreg_steps)
            audit.log_admin(ctx, "remove", "success", "OK", t.id)
            warnings.append(RESTART_WARNING)
            return Outcome(True, "OK", f"unprotected {t.canonical_path} (permissions were not changed by "
                           "protect-folder, so none were restored)", {"plan": plan}, warnings)
        if ident.status != "OK":
            raise ProtectError(
                ident.reason if ident.reason in ("MOUNT_MISSING", "IDENTITY_MISMATCH", "STALE")
                else "IDENTITY_MISMATCH",
                f"cannot restore {t.canonical_path!r}: {ident.detail}",
                details={"identity": ident.status},
                hint=_manual_recovery(t, snap) + " To drop the stale registration without touching "
                     "the filesystem: sudo protect-folder remove --forget -- <path>")
        if snap is None:
            raise ProtectError("TAMPERED", f"no permission snapshot for {t.id}; refusing to guess "
                               "original permissions", hint=_manual_recovery(t, None))
        if snap.st_ino != t.st_ino or snap.st_dev != t.st_dev:
            raise ProtectError("TAMPERED", "snapshot identity does not match the registry entry")

        if dry_run:
            return Outcome(True, "OK", f"dry run: would restore {t.canonical_path}",
                           {"plan": plan, "dry_run": True}, warnings)
        _confirm(ctx, yes, f"Restore original permissions of {t.canonical_path!r} and unprotect it?")

        fd = paths.open_dir_nofollow(t.canonical_path)
        try:
            st = os.fstat(fd)
            if st.st_ino != snap.st_ino or st.st_dev != t.st_dev:  # re-check on the open handle
                raise ProtectError("IDENTITY_MISMATCH", "directory changed while preparing to restore")
            cur_meta = ctx.host.stat(fd)
            cur_acl = ctx.host.get_acl(fd)
            tx = Transaction(ctx, "remove", t.id)

            def steps() -> None:
                tx.record_undo(undo_meta_record(t.canonical_path, t.st_dev, t.st_ino, cur_meta, cur_acl))
                apply_meta(ctx, fd, snap.uid, snap.gid, snap.mode, snap.acl_text, snap.acl_extended)
                tx.undo_file(lo.targets_file)
                tx.undo_file(lo.targets_prev_file)
                new = Registry([x for x in reg.targets if x.id != t.id], reg.revision + 1)
                registry.save(lo, new)
                tx.undo_file(lo.snapshots_file)
                s = snapshots.load(lo)
                s.pop(t.id, None)
                snapshots.save(lo, s)
                tx.undo_file(lo.srt_targets_file)
                write_generated(ctx, new)

            _run_tx(ctx, tx, steps)
        finally:
            os.close(fd)
        audit.log_admin(ctx, "remove", "success", "OK", t.id)
        warnings.append(RESTART_WARNING)
        return Outcome(True, "OK", f"unprotected {t.canonical_path}; original ownership/mode/ACL restored",
                       {"plan": plan}, warnings)
    except ProtectError as exc:
        if not dry_run:
            audit.log_admin(ctx, "remove", "failure", exc.code)
        raise
    finally:
        if lock:
            lock.__exit__()


# ------------------------------------------------------------------------------------------
def consistency_issues(ctx: Context) -> list[str]:
    """Registry/snapshot/L4 consistency, independent of journals. Empty list = consistent."""
    issues: list[str] = []
    reg = registry.load(ctx.layout, require_trusted=False)
    snaps = snapshots.load(ctx.layout)
    ids = {t.id for t in reg.targets}
    for t in reg.targets:
        linux = t.layers["linux_permissions"]
        if linux and t.id not in snaps:
            issues.append(f"{t.canonical_path}: registered but has no permission snapshot")
        if not linux and t.id in snaps:
            issues.append(f"{t.canonical_path}: Linux permissions are off but a snapshot exists "
                          "(permissions may still be locked)")
        if not linux:
            continue
        try:
            fd = paths.open_dir_nofollow(t.canonical_path)
        except (ProtectError, OSError):
            continue  # absent/unmounted: reported by status, not an inconsistency
        try:
            m = ctx.host.stat(fd)
            if (m.uid, m.gid, m.mode) != (PROTECTED_UID, PROTECTED_GID, PROTECTED_MODE):
                issues.append(f"{t.canonical_path}: registered but L4 is not applied "
                              f"({m.uid}:{m.gid} {m.mode:04o})")
        finally:
            os.close(fd)
    for sid, s in snaps.items():
        if sid not in ids:
            issues.append(f"{s.canonical_path}: has a snapshot but is not registered (may be locked "
                          f"root:root 0700 without protection record)")
    return issues


def recover(ctx: Context, *, dry_run: bool = False, yes: bool = False) -> Outcome:
    _require_root(ctx, "recover") if not dry_run else None
    lo = ctx.layout
    ensure_layout(ctx) if not dry_run else None
    lock = AdminLock(ctx) if not dry_run else None
    if lock:
        lock.__enter__()
    try:
        marker = read_marker(ctx)
        journals = list(pending_journals(ctx))
        if marker is None and not journals:
            return Outcome(True, "OK", "nothing to recover", {"journals": 0, "marker": None})
        plan = {"marker": marker, "journals": [
            {"txid": j.get("txid"), "op": j.get("op"), "state": j.get("state"),
             "undo_steps": len(j.get("undo", []))} for _, j in journals]}
        if dry_run:
            return Outcome(True, "OK", "dry run: would roll back the journals listed",
                           {"plan": plan, "dry_run": True})
        _confirm(ctx, yes, "Roll back interrupted operation(s) to the pre-operation state?")
        failures: list[str] = []
        for p, j in journals:
            if j.get("state") == "committed":
                p.unlink()
                continue
            f = run_undo(ctx, j.get("undo", []))
            if f:
                failures += f
                j["state"] = "recovery_required"
                j["failures"] = f
                jsonio.atomic_write_json(p, j, 0o600, lo.trusted_uid, lo.trusted_gid)
            else:
                p.unlink()
        if failures:
            write_marker(ctx, "RECOVERY_REQUIRED", None, "recover", "; ".join(failures)[:500])
            audit.log_admin(ctx, "recover", "failure", "RECOVERY_REQUIRED", detail=failures[:5])
            raise ProtectError("RECOVERY_REQUIRED", "automatic rollback could not be proven for some steps",
                               details={"failures": failures},
                               hint="Resolve manually (see failures), e.g. restore the directory's "
                                    "ownership/mode by hand, then 'sudo protect-folder remove --forget'.")
        reg = registry.load(lo, require_trusted=False)
        issues = consistency_issues(ctx)
        if issues:
            write_marker(ctx, "RECOVERY_REQUIRED", None, "recover", "; ".join(issues)[:500])
            audit.log_admin(ctx, "recover", "failure", "RECOVERY_REQUIRED", detail=issues[:5])
            raise ProtectError("RECOVERY_REQUIRED", "state is still inconsistent after rollback",
                               details={"issues": issues},
                               hint="Fix each listed item (remove --forget for stale entries, or restore "
                                    "permissions by hand), then run recover again.")
        write_generated(ctx, reg)
        clear_marker(ctx)
        audit.log_admin(ctx, "recover", "success", "OK")
        return Outcome(True, "OK", "recovered: previous operation rolled back; state is consistent",
                       {"plan": plan})
    finally:
        if lock:
            lock.__exit__()
