"""Atomic, deterministic JSON file IO."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def dumps_stable(obj: Any) -> bytes:
    """Deterministic encoding. ensure_ascii keeps non-UTF-8 filenames (surrogate escapes) lossless."""
    return (json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path: Path, data: bytes, mode: int = 0o644,
                 uid: int | None = None, gid: int | None = None) -> None:
    """Write via a same-directory temp file, fsync, rename, fsync the directory."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        try:
            os.fchmod(fd, mode)
            if uid is not None:
                os.fchown(fd, uid, gid if gid is not None else -1)
            view = memoryview(data)
            while view:
                n = os.write(fd, view)
                view = view[n:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    fsync_dir(path.parent)


def atomic_write_json(path: Path, obj: Any, mode: int = 0o644,
                      uid: int | None = None, gid: int | None = None) -> None:
    atomic_write(path, dumps_stable(obj), mode, uid, gid)


def read_json(path: Path) -> Any:
    with open(path, "rb") as fh:
        return json.loads(fh.read().decode("utf-8"))
