"""Mount table parsing and filesystem semantics checks."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from .errors import ProtectError

# Filesystems whose chown/chmod/ACL semantics are POSIX and honoured by the kernel.
POSIX_FILESYSTEMS = frozenset({
    "ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "jfs", "reiserfs", "zfs",
    "bcachefs", "tmpfs",
})


@dataclass(frozen=True)
class MountEntry:
    mount_id: int
    parent_id: int
    major: int
    minor: int
    root: str
    mount_point: str
    options: str
    fstype: str
    source: str

    @property
    def dev(self) -> int:
        return os.makedev(self.major, self.minor)


def _unescape(field: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), field)


def parse_mountinfo(text: str) -> list[MountEntry]:
    entries = []
    for line in text.splitlines():
        if not line.strip():
            continue
        left, sep, right = line.partition(" - ")
        if not sep:
            continue
        a = left.split(" ")
        b = right.split(" ")
        if len(a) < 6 or len(b) < 2:
            continue
        major, _, minor = a[2].partition(":")
        entries.append(MountEntry(
            mount_id=int(a[0]), parent_id=int(a[1]), major=int(major), minor=int(minor),
            root=_unescape(a[3]), mount_point=_unescape(a[4]), options=a[5],
            fstype=b[0], source=_unescape(b[1]),
        ))
    return entries


def read_mounts(path: str = "/proc/self/mountinfo") -> list[MountEntry]:
    with open(path, "rb") as fh:
        return parse_mountinfo(fh.read().decode("utf-8", "surrogateescape"))


def _within(path: str, base: str) -> bool:
    return base == "/" or path == base or path.startswith(base.rstrip("/") + "/")


def mount_for(path: str, st_dev: int | None, mounts: list[MountEntry]) -> MountEntry | None:
    """The mount holding `path`: longest mount point prefix, preferring a matching device."""
    best = None
    for m in mounts:
        if not _within(path, m.mount_point):
            continue
        if st_dev is not None and m.dev != st_dev:
            continue
        # later entries shadow earlier ones with the same mount point
        if best is None or len(m.mount_point) >= len(best.mount_point):
            best = m
    return best


def is_mount_point(path: str, mounts: list[MountEntry]) -> bool:
    return any(m.mount_point == path for m in mounts)


def nested_mounts(path: str, mounts: list[MountEntry]) -> list[MountEntry]:
    return [m for m in mounts if m.mount_point != path and _within(m.mount_point, path)]


def alias_mounts(entry: MountEntry, mounts: list[MountEntry]) -> list[MountEntry]:
    """Other mounts of the same filesystem instance (bind mounts): the same inode is reachable
    under other path spellings, which path-based SRT rules do not cover."""
    return [m for m in mounts
            if m.mount_id != entry.mount_id and m.dev == entry.dev and m.fstype == entry.fstype]


def fs_uuid(source: str, by_uuid_dir: str = "/dev/disk/by-uuid") -> str | None:
    """Best-effort filesystem UUID for a block-device source; None when unknown."""
    if not source.startswith("/dev/"):
        return None
    try:
        real = os.path.realpath(source)
        for name in os.listdir(by_uuid_dir):
            if os.path.realpath(os.path.join(by_uuid_dir, name)) == real:
                return name
    except OSError:
        return None
    return None


def require_posix_filesystem(fstype: str) -> None:
    if fstype not in POSIX_FILESYSTEMS:
        raise ProtectError(
            "UNSUPPORTED_FILESYSTEM",
            f"filesystem type {fstype!r} is not known to honour POSIX ownership/mode semantics",
            details={"filesystem_type": fstype},
            hint="Only " + ", ".join(sorted(POSIX_FILESYSTEMS)) + " are supported for L4. "
                 "Move the data to a supported filesystem; protect-folder will not record a "
                 "partial registration.",
        )
