"""Host metadata operations on an already-open directory fd.

All changes go through /proc/self/fd/N so they act on the exact inode that was validated,
never on whatever a path string resolves to later. Nothing here is recursive.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass

from .errors import ProtectError


@dataclass(frozen=True)
class MetaState:
    uid: int
    gid: int
    mode: int  # permission + setuid/setgid/sticky bits only


@dataclass(frozen=True)
class AclState:
    text: str          # `getfacl -c -p -n -E` output (access + default entries)
    extended: bool     # anything beyond the base user/group/other entries


def acl_is_extended(text: str) -> bool:
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("default:"):
            return True
        kind, _, rest = line.partition(":")
        qualifier = rest.partition(":")[0]
        if kind in ("user", "group") and qualifier:
            return True
        if kind == "mask":
            return True
    return False


class HostOps:
    """Interface; see RealHostOps."""

    def stat(self, fd: int) -> MetaState: ...
    def chown(self, fd: int, uid: int, gid: int) -> None: ...
    def chmod(self, fd: int, mode: int) -> None: ...
    def get_acl(self, fd: int) -> AclState: ...
    def clear_acl(self, fd: int) -> None: ...
    def set_acl(self, fd: int, text: str) -> None: ...
    def has_acl_tools(self) -> bool: ...


class RealHostOps(HostOps):
    @staticmethod
    def _p(fd: int) -> str:
        return f"/proc/self/fd/{fd}"

    def stat(self, fd: int) -> MetaState:
        st = os.fstat(fd)
        return MetaState(st.st_uid, st.st_gid, st.st_mode & 0o7777)

    def chown(self, fd: int, uid: int, gid: int) -> None:
        os.chown(self._p(fd), uid, gid)

    def chmod(self, fd: int, mode: int) -> None:
        os.chmod(self._p(fd), mode)

    def has_acl_tools(self) -> bool:
        return shutil.which("getfacl") is not None and shutil.which("setfacl") is not None

    def _run(self, argv: list[str], fd: int) -> str:
        proc = subprocess.run(argv, capture_output=True, text=True, pass_fds=(fd,), timeout=30)
        if proc.returncode != 0:
            raise ProtectError("APPLY_FAILED", f"{argv[0]} failed: {proc.stderr.strip()}")
        return proc.stdout

    def get_acl(self, fd: int) -> AclState:
        if not shutil.which("getfacl"):
            # Without getfacl we can only say "no extended ACL" if the kernel exposes none.
            try:
                names = os.listxattr(self._p(fd))
            except OSError:
                names = []
            if any(n.startswith("system.posix_acl") for n in names):
                raise ProtectError("UNEXPECTED_ACL", "directory has ACLs but getfacl is not installed",
                                   hint="Install the 'acl' package.")
            return AclState("", False)
        text = self._run(["getfacl", "-c", "-p", "-n", "-E", self._p(fd)], fd)
        return AclState(text, acl_is_extended(text))

    def clear_acl(self, fd: int) -> None:
        self._run(["setfacl", "-b", self._p(fd)], fd)

    def set_acl(self, fd: int, text: str) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".acl", delete=True) as fh:
            fh.write(text)
            fh.flush()
            self._run(["setfacl", "-b", self._p(fd)], fd)
            self._run(["setfacl", "-M", fh.name, self._p(fd)], fd)
