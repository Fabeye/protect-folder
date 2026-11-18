"""Test doubles. FakeHostOps keeps ownership/mode/ACL in memory so privileged logic runs unprivileged."""

from __future__ import annotations

import os

from protect_folder.hostops import AclState, HostOps, MetaState, acl_is_extended


class FakeHostOps(HostOps):
    def __init__(self) -> None:
        self.meta: dict[tuple[int, int], MetaState] = {}
        self.acls: dict[tuple[int, int], AclState] = {}
        self.calls: list[tuple[str, tuple[int, int]]] = []
        self.fail_on: dict[str, int] = {}   # op name -> fail on the Nth call (1-based)
        self._counts: dict[str, int] = {}

    @staticmethod
    def key(fd: int) -> tuple[int, int]:
        st = os.fstat(fd)
        return (st.st_dev, st.st_ino)

    def _tick(self, op: str, fd: int) -> tuple[int, int]:
        k = self.key(fd)
        self.calls.append((op, k))
        self._counts[op] = self._counts.get(op, 0) + 1
        if self.fail_on.get(op) == self._counts[op]:
            raise OSError(5, f"injected failure in {op}")
        return k

    def stat(self, fd: int) -> MetaState:
        k = self.key(fd)
        if k in self.meta:
            return self.meta[k]
        st = os.fstat(fd)
        return MetaState(st.st_uid, st.st_gid, st.st_mode & 0o7777)

    def chown(self, fd: int, uid: int, gid: int) -> None:
        k = self._tick("chown", fd)
        self.meta[k] = MetaState(uid, gid, self.stat(fd).mode)

    def chmod(self, fd: int, mode: int) -> None:
        k = self._tick("chmod", fd)
        cur = self.stat(fd)
        self.meta[k] = MetaState(cur.uid, cur.gid, mode)

    def has_acl_tools(self) -> bool:
        return True

    def get_acl(self, fd: int) -> AclState:
        return self.acls.get(self.key(fd), AclState("user::rwx\ngroup::r-x\nother::r-x\n", False))

    def clear_acl(self, fd: int) -> None:
        k = self._tick("clear_acl", fd)
        self.acls[k] = AclState("user::rwx\ngroup::---\nother::---\n", False)

    def set_acl(self, fd: int, text: str) -> None:
        k = self._tick("set_acl", fd)
        self.acls[k] = AclState(text, acl_is_extended(text))

    def set_initial_acl(self, path: str, text: str) -> None:
        st = os.stat(path)
        self.acls[(st.st_dev, st.st_ino)] = AclState(text, acl_is_extended(text))

    def touched_inodes(self) -> set[int]:
        return {k[1] for _, k in self.calls}
