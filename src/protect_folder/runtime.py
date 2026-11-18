"""The trusted SRT runtime: a root-owned copy of node + sandbox-runtime, verified on every launch."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path

from .context import Context
from .errors import ProtectError
from .registry import check_trusted_chain, check_trusted_file

TESTED_SRT_VERSIONS = frozenset({"0.0.83"})
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
MANIFEST = "MANIFEST.json"


@dataclass(frozen=True)
class Runtime:
    node: Path
    srt_cli: Path
    srt_version: str
    bwrap: str
    socat: str
    rg: str


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def system_binary(name: str, trusted_uid: int) -> str:
    """Absolute path of a system helper, resolved on a fixed root-owned PATH (never the caller's)."""
    found = shutil.which(name, path=SAFE_PATH)
    if not found:
        raise ProtectError("SRT_UNAVAILABLE", f"required helper {name!r} not found in {SAFE_PATH}",
                           hint="apt install bubblewrap socat ripgrep")
    real = os.path.realpath(found)
    check_trusted_chain(Path(real), trusted_uid)
    return real


def check_tree(root: Path, trusted_uid: int) -> int:
    """Every entry owned by a trusted uid, nothing group/world writable, symlinks only inside root.
    Returns the number of entries checked."""
    n = 0
    root_real = os.path.realpath(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            p = os.path.join(dirpath, name)
            st = os.lstat(p)
            n += 1
            if st.st_uid not in (trusted_uid, 0):
                raise ProtectError("TAMPERED", f"{p} is owned by uid {st.st_uid}")
            if stat.S_ISLNK(st.st_mode):
                tgt = os.path.realpath(p)
                if tgt != root_real and not tgt.startswith(root_real + os.sep):
                    raise ProtectError("TAMPERED", f"{p} is a symlink pointing outside the runtime")
            elif st.st_mode & 0o022:
                raise ProtectError("TAMPERED", f"{p} is group/world writable")
    return n


def load_manifest(ctx: Context) -> dict:
    mf = ctx.layout.runtime_dir / MANIFEST
    check_trusted_file(mf, ctx.layout.trusted_uid)
    try:
        return json.loads(mf.read_text())
    except (OSError, ValueError) as exc:
        raise ProtectError("TAMPERED", f"cannot parse {mf}: {exc}") from exc


def check_runtime(ctx: Context, *, full_hash: bool = False) -> Runtime:
    """Fail closed (SRT_UNAVAILABLE / TAMPERED) unless the vendored runtime is intact and tested."""
    lo = ctx.layout
    rt = lo.runtime_dir
    if not (rt / MANIFEST).exists():
        raise ProtectError("SRT_UNAVAILABLE", f"trusted SRT runtime not installed at {rt}",
                           hint="Run 'sudo protect-folder install'. An srt on PATH is user-writable "
                                "and is deliberately not used.")
    check_trusted_chain(rt, lo.trusted_uid)
    manifest = load_manifest(ctx)
    version = manifest.get("srt_version")
    if version not in TESTED_SRT_VERSIONS:
        raise ProtectError("SRT_UNAVAILABLE", f"SRT version {version!r} is not a tested version "
                           f"({', '.join(sorted(TESTED_SRT_VERSIONS))})")
    check_tree(rt, lo.trusted_uid)
    node = rt / "node"
    cli = rt / "srt" / "dist" / "cli.js"
    for p in (node, cli):
        if not p.is_file():
            raise ProtectError("SRT_UNAVAILABLE", f"{p} is missing")
    pkg_version = json.loads((rt / "srt" / "package.json").read_text()).get("version")
    if pkg_version != version:
        raise ProtectError("TAMPERED", "runtime package.json version differs from the manifest")
    hashes = manifest.get("sha256", {})
    to_check = hashes if full_hash else {k: v for k, v in hashes.items() if k in ("node", "srt/dist/cli.js")}
    if not {"node", "srt/dist/cli.js"} <= set(hashes):
        raise ProtectError("TAMPERED", "manifest lacks hashes for the entry points")
    for rel, want in to_check.items():
        got = sha256_file(rt / rel)
        if got != want:
            raise ProtectError("TAMPERED", f"{rel} does not match the installed hash")
    tu = lo.trusted_uid
    return Runtime(node, cli, version, system_binary("bwrap", tu), system_binary("socat", tu),
                   system_binary("rg", tu))


def srt_argv(rt: Runtime, settings_file: str, command: list[str]) -> list[str]:
    return [str(rt.node), str(rt.srt_cli), "--settings", settings_file, "--", *command]
