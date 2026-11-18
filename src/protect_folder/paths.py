"""Safe path resolution, no-follow identity checks and forbidden-target rules."""

from __future__ import annotations

import errno
import os
import pwd
import stat
from dataclasses import dataclass, field
from pathlib import Path

from . import mounts as mnt
from .constants import Layout
from .errors import ProtectError

O_PATH = getattr(os, "O_PATH", 0o10000000)
_DIR_FLAGS = O_PATH | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC

# Never protectable, nor anything inside them.
SYSTEM_TREES = ("/proc", "/sys", "/dev", "/run", "/boot", "/usr", "/bin", "/sbin",
                "/lib", "/lib32", "/lib64", "/libx32", "/snap", "/etc", "/root")
# Never protectable themselves (their children may be).
SYSTEM_EXACT = ("/", "/home", "/mnt", "/media", "/opt", "/var", "/srv", "/tmp", "/var/tmp",
                "/var/lib", "/var/log", "/usr/local")


def is_within(path: str, base: str) -> bool:
    """True if `path` equals or lies beneath `base` (string-wise, both absolute and normalised)."""
    if base == "/":
        return True
    return path == base or path.startswith(base.rstrip("/") + "/")


def home_directories() -> set[str]:
    homes = set()
    for ent in pwd.getpwall():
        if ent.pw_dir and ent.pw_dir not in ("/", "/nonexistent") and os.path.isabs(ent.pw_dir):
            homes.add(os.path.realpath(ent.pw_dir))
    env_home = os.environ.get("HOME")
    if env_home and os.path.isabs(env_home):
        homes.add(os.path.realpath(env_home))
    return homes


def open_dir_nofollow(canonical: str) -> int:
    """Open `canonical` as an O_PATH fd, refusing symlinks in *every* component.

    O_PATH on the final component needs only search permission on its parents, so this works
    for a root-locked 0700 directory as an ordinary user.
    """
    if not os.path.isabs(canonical):
        raise ValueError("canonical path must be absolute")
    parts = [p for p in canonical.split("/") if p]
    cur = os.open("/", _DIR_FLAGS)
    try:
        for part in parts:
            try:
                nxt = os.open(part, _DIR_FLAGS, dir_fd=cur)
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    # Distinguish a symlink from a non-directory for a precise message.
                    try:
                        st = os.stat(part, dir_fd=cur, follow_symlinks=False)
                        if stat.S_ISLNK(st.st_mode):
                            raise ProtectError(
                                "IDENTITY_MISMATCH",
                                f"a component of {canonical!r} is now a symbolic link ({part!r})",
                            ) from exc
                    except OSError:
                        pass
                    raise ProtectError("NOT_A_DIRECTORY", f"{canonical!r} is not a directory "
                                       f"(component {part!r})") from exc
                if exc.errno == errno.ENOENT:
                    raise ProtectError("PATH_NOT_FOUND", f"{canonical!r} does not exist") from exc
                raise
            os.close(cur)
            cur = nxt
        return cur
    except BaseException:
        os.close(cur)
        raise


@dataclass
class Resolved:
    input_path: str
    canonical_path: str
    fd: int
    st_dev: int
    st_ino: int
    mount: mnt.MountEntry | None
    warnings: list[str] = field(default_factory=list)

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def check_forbidden(canonical: str, layout: Layout, homes: set[str] | None = None) -> None:
    for tree in SYSTEM_TREES:
        if is_within(canonical, tree):
            raise ProtectError("FORBIDDEN_PATH", f"{canonical!r} is inside the system tree {tree}",
                               hint="System directories cannot be protected safely.")
    if canonical in SYSTEM_EXACT:
        raise ProtectError("FORBIDDEN_PATH", f"{canonical!r} is a system/base directory",
                           hint="Protect a specific subdirectory instead.")
    for home in (homes if homes is not None else home_directories()):
        if canonical == home:
            raise ProtectError("FORBIDDEN_PATH", f"{canonical!r} is a user's entire home directory",
                               hint="Protect a specific subdirectory of it instead.")
        if is_within(home, canonical):
            raise ProtectError("FORBIDDEN_PATH",
                               f"{canonical!r} contains the home directory {home!r}")
    for trusted in layout.trusted_paths():
        t = os.path.realpath(trusted)
        if is_within(canonical, t) or is_within(t, canonical):
            raise ProtectError("OVERLAPS_TRUSTED",
                               f"{canonical!r} overlaps protect-folder's own path {t!r}")


def nesting_warnings(canonical: str, existing: list[str]) -> list[str]:
    """Nested protected directories are allowed: the effective protection of a child is the union of its
    own layers and those of every protected ancestor (a child can never opt out of what a parent enforces)."""
    out: list[str] = []
    for other in existing:
        if canonical == other:
            continue
        if is_within(canonical, other):
            out.append(f"{canonical!r} is inside already-protected {other!r}: layers enabled on the parent "
                       "also apply here and cannot be disabled for this child")
        elif is_within(other, canonical):
            out.append(f"already-protected {other!r} is inside {canonical!r}: layers enabled here will also "
                       "apply to it")
    return out


def resolve_target(arg: str, layout: Layout, *, follow_symlinks: bool = False,
                   existing_paths: list[str] | None = None, cwd: str | None = None,
                   mounts: list[mnt.MountEntry] | None = None,
                   homes: set[str] | None = None) -> Resolved:
    """Validate an operator-supplied path and return an open no-follow handle on it.

    The caller owns the returned fd (Resolved.close()). Identity is taken from the fd, not
    from the path string, so later operations act on exactly the inspected object.
    """
    if arg == "" or "\x00" in arg:
        raise ProtectError("PATH_NOT_FOUND", "empty or invalid path")
    base = cwd or os.getcwd()
    absolute = os.path.abspath(os.path.join(base, os.path.expanduser(arg)))
    try:
        canonical = os.path.realpath(absolute, strict=True)
    except FileNotFoundError as exc:
        raise ProtectError("PATH_NOT_FOUND", f"{absolute!r} does not exist (or is a dangling link)",
                           hint="Mount the disk / create the directory first.") from exc
    except OSError as exc:
        raise ProtectError("PATH_NOT_FOUND", f"cannot resolve {absolute!r}: {exc.strerror}") from exc

    warnings: list[str] = []
    if canonical != absolute:
        if not follow_symlinks:
            raise ProtectError(
                "SYMLINK_TARGET",
                f"{absolute!r} resolves through a symbolic link to {canonical!r}",
                details={"resolves_to": canonical},
                hint="Re-run with the real path, or pass --follow-symlinks to protect the link "
                     "destination. The original spelling is recorded as metadata.",
            )
        warnings.append(f"input path resolves via a symlink; protecting {canonical!r}")

    check_forbidden(canonical, layout, homes)
    if existing_paths:
        warnings += nesting_warnings(canonical, existing_paths)

    fd = open_dir_nofollow(canonical)
    try:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode):
            raise ProtectError("NOT_A_DIRECTORY", f"{canonical!r} is not a directory")
        table = mounts if mounts is not None else mnt.read_mounts()
        if mnt.is_mount_point(canonical, table):
            raise ProtectError(
                "FORBIDDEN_PATH", f"{canonical!r} is a mount point",
                hint="Protecting a mount root would follow the mount, not the data; protect a "
                     "directory inside the filesystem instead.")
        entry = mnt.mount_for(canonical, st.st_dev, table)
        if entry is None:
            warnings.append("could not determine the mount for this path")
        else:
            nested = mnt.nested_mounts(canonical, table)
            if nested:
                warnings.append("mount points exist below the target: "
                                + ", ".join(m.mount_point for m in nested))
            if entry.root != "/":
                warnings.append(f"target is on a bind mount of {entry.root!r}")
            aliases = mnt.alias_mounts(entry, table)
            if aliases:
                warnings.append("the same filesystem is mounted at other paths "
                                + ", ".join(m.mount_point for m in aliases)
                                + "; path-based SRT rules do not cover those spellings (L4 does)")
        return Resolved(arg, canonical, fd, st.st_dev, st.st_ino, entry, warnings)
    except BaseException:
        os.close(fd)
        raise


@dataclass
class Identity:
    status: str          # OK | MISSING | MOUNT_MISSING | MISMATCH
    detail: str = ""
    warnings: list[str] = field(default_factory=list)
    reason: str = "OK"


def check_identity(canonical: str, st_dev: int, st_ino: int, mount_point: str | None,
                   fs_type: str | None, mount_source: str | None, uuid: str | None,
                   mounts: list[mnt.MountEntry] | None = None) -> Identity:
    """Compare the object currently at `canonical` with a registered identity (no side effects)."""
    table = mounts if mounts is not None else mnt.read_mounts()
    try:
        fd = open_dir_nofollow(canonical)
    except ProtectError as exc:
        if exc.code == "PATH_NOT_FOUND":
            if mount_point and not mnt.is_mount_point(mount_point, table) and mount_point != "/":
                return Identity("MOUNT_MISSING", f"mount point {mount_point!r} is not mounted",
                                reason="MOUNT_MISSING")
            return Identity("MISSING", f"{canonical!r} no longer exists", reason="STALE")
        return Identity("MISMATCH", exc.message, reason=exc.code if exc.code != "NOT_A_DIRECTORY"
                        else "IDENTITY_MISMATCH")
    except PermissionError as exc:
        return Identity("MISMATCH", f"cannot traverse to {canonical!r}: {exc.strerror}",
                        reason="STALE")
    try:
        st = os.fstat(fd)
    finally:
        os.close(fd)
    warnings: list[str] = []
    if st.st_ino != st_ino:
        return Identity("MISMATCH", "a different directory now exists at this path "
                        "(inode differs)", reason="IDENTITY_MISMATCH")
    entry = mnt.mount_for(canonical, st.st_dev, table)
    if st.st_dev != st_dev:
        # Device numbers are reassigned across reboots/replugs; accept only with a matching UUID.
        cur_uuid = mnt.fs_uuid(entry.source) if entry else None
        if uuid and cur_uuid and uuid == cur_uuid:
            warnings.append("device number changed since registration (filesystem UUID matches)")
        else:
            return Identity("MISMATCH", "device differs from the registered one and the "
                            "filesystem UUID could not confirm it is the same disk",
                            reason="IDENTITY_MISMATCH")
    if entry is not None:
        if mount_point and entry.mount_point != mount_point:
            return Identity("MISMATCH", f"mount point changed ({mount_point!r} -> "
                            f"{entry.mount_point!r})", reason="IDENTITY_MISMATCH")
        if fs_type and entry.fstype != fs_type:
            return Identity("MISMATCH", f"filesystem type changed ({fs_type} -> {entry.fstype})",
                            reason="IDENTITY_MISMATCH")
    return Identity("OK", warnings=warnings)
