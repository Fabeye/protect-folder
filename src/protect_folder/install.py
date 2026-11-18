"""Installation of the root-owned code and SRT runtime. Nothing is downloaded."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from . import jsonio
from .constants import VERSION
from .context import Context
from .errors import ProtectError
from .layout_setup import initialize_state
from .policy.config import DEFAULT_POLICY
from .runtime import MANIFEST, TESTED_SRT_VERSIONS, sha256_file


SRT_PACKAGE_NAME = "@anthropic-ai/sandbox-runtime"


def _valid_srt_package(pkg: Path) -> str | None:
    """Return None when `pkg` is the real sandbox-runtime package, else the reason it is not."""
    try:
        meta = json.loads((pkg / "package.json").read_text())
    except (OSError, ValueError):
        return f"{pkg} has no readable package.json"
    if meta.get("name") != SRT_PACKAGE_NAME:
        return f"{pkg} is package {meta.get('name')!r}, not {SRT_PACKAGE_NAME}"
    if not (pkg / "dist" / "cli.js").is_file():
        return f"{pkg} has no dist/cli.js"
    return None


def _user_homes() -> list[Path]:
    """Homes to look in. Under sudo root's PATH and HOME are not the operator's, so search the invoking user."""
    import pwd
    homes: list[Path] = []
    for name in (os.environ.get("SUDO_USER"),):
        if name and name != "root":
            try:
                homes.append(Path(pwd.getpwnam(name).pw_dir))
            except KeyError:
                pass
    h = os.environ.get("HOME")
    if h and os.geteuid() != 0:
        homes.append(Path(h))
    return list(dict.fromkeys(homes))


def _discover() -> list[tuple[Path, Path | None]]:
    """(srt package, node next to it or None), most specific first. Never trusts a bare `srt` on PATH."""
    out: list[tuple[Path, Path | None]] = []
    roots: list[Path] = []
    for home in _user_homes():
        nvm = home / ".nvm" / "versions" / "node"
        if nvm.is_dir():
            roots += sorted(nvm.iterdir(), reverse=True)
        roots += [home / ".npm-global", home / ".local", home / ".volta"]
    roots += [Path("/usr/local"), Path("/usr")]
    for r in roots:
        pkg = r / "lib" / "node_modules" / "@anthropic-ai" / "sandbox-runtime"
        if pkg.is_dir():
            node = r / "bin" / "node"
            out.append((pkg, node if node.is_file() else None))
    srt = shutil.which("srt")
    if srt:
        pkg = Path(os.path.realpath(srt)).parent.parent
        out.append((pkg, None))
    return out


def find_node_and_srt(node: str | os.PathLike | None = None,
                      srt_package: str | os.PathLike | None = None) -> tuple[Path, Path]:
    """Locate node and @anthropic-ai/sandbox-runtime to vendor from. Explicit arguments win (and are validated);
    otherwise the invoking user's installs are searched. A package that is not the real sandbox-runtime, or an
    untested version, is skipped, never vendored."""
    hint = ("npm install -g @anthropic-ai/sandbox-runtime@0.0.83 as your user, or pass "
            "--srt-package DIR_OF_THE_PACKAGE and --node PATH_TO_NODE")
    problems: list[str] = []
    cands: list[tuple[Path, Path | None]]
    if srt_package is not None:
        cands = [(Path(srt_package), None)]
    else:
        cands = _discover()
    for pkg, near_node in cands:
        why = _valid_srt_package(pkg)
        if why is None:
            ver = json.loads((pkg / "package.json").read_text()).get("version")
            if ver not in TESTED_SRT_VERSIONS:
                why = f"{pkg} is version {ver}; tested: {sorted(TESTED_SRT_VERSIONS)}"
        if why is not None:
            problems.append(why)
            if srt_package is not None:
                raise ProtectError("SRT_UNAVAILABLE", why, hint=hint)
            continue
        n = Path(node) if node is not None else near_node
        if n is None:
            w = shutil.which("node")
            n = Path(w) if w else None
        if n is None or not os.access(n, os.X_OK):
            raise ProtectError("SRT_UNAVAILABLE", f"no usable node executable for {pkg}", hint=hint)
        return Path(os.path.realpath(n)), Path(os.path.realpath(pkg))
    raise ProtectError("SRT_UNAVAILABLE", "could not find the sandbox-runtime package to vendor",
                       details={"skipped": problems}, hint=hint)


def _lock_down(root: Path, uid: int, gid: int) -> None:
    """Make every entry trusted-owned, world-readable, never group/world-writable."""
    def fix(p: str) -> None:
        if os.path.islink(p):
            os.lchown(p, uid, gid)
            return
        os.chown(p, uid, gid)
        mode = os.lstat(p).st_mode & 0o7777
        new = (mode | 0o444) & ~0o022
        if os.path.isdir(p) or mode & 0o111:
            new |= 0o111
        os.chmod(p, new & ~0o7000)       # also drop setuid/setgid/sticky

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            fix(os.path.join(dirpath, name))
    fix(str(root))


def vendor_runtime(ctx: Context, node_src: Path, srt_pkg_src: Path) -> dict:
    lo = ctx.layout
    pkg = json.loads((srt_pkg_src / "package.json").read_text())
    version = pkg.get("version")
    if version not in TESTED_SRT_VERSIONS:
        raise ProtectError("SRT_UNAVAILABLE", f"refusing to vendor untested sandbox-runtime {version!r}; "
                           f"tested: {sorted(TESTED_SRT_VERSIONS)}")
    dest = lo.runtime_dir
    tmp = dest.with_name(dest.name + ".new")
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    shutil.copy2(node_src, tmp / "node")
    shutil.copytree(srt_pkg_src, tmp / "srt", symlinks=True)
    _lock_down(tmp, lo.trusted_uid, lo.trusted_gid)
    node_ver = subprocess.run([str(tmp / "node"), "--version"], capture_output=True, text=True).stdout.strip()
    hashes = {"node": sha256_file(tmp / "node")}
    for p in sorted((tmp / "srt").rglob("*")):
        if p.is_file() and not p.is_symlink():
            hashes[str(p.relative_to(tmp))] = sha256_file(p)
    manifest = {"schema_version": 1, "installed_by": VERSION, "node_version": node_ver,
                "srt_version": version, "sha256": hashes}
    jsonio.atomic_write_json(tmp / MANIFEST, manifest, 0o644, lo.trusted_uid, lo.trusted_gid)
    if dest.exists():
        shutil.rmtree(dest)
    os.rename(tmp, dest)
    return manifest


def install(ctx: Context, *, dry_run: bool = False, source_dir: Path | None = None,
            vendor: bool = True, node: str | None = None, srt_package: str | None = None) -> dict:
    """Create the layout, default policy and runtime. Idempotent. Needs root unless dry_run."""
    lo = ctx.layout
    steps = [f"create {lo.etc_dir} (0755), {lo.state_dir} (0700), {lo.log_dir} (0755)",
             f"write an empty registry and generated policy if absent",
             f"write default {lo.policy_file} if absent"]
    if vendor:
        steps.append(f"vendor root-owned node + sandbox-runtime into {lo.runtime_dir}")
    if source_dir is not None:
        steps.append(f"copy protect_folder package into {lo.lib_dir} and write {lo.bin_path}")
    if dry_run:
        return {"dry_run": True, "steps": steps}
    if ctx.euid() != 0:
        raise ProtectError("NOT_ROOT", "'install' needs administrator privileges",
                           hint="Run: sudo protect-folder install")
    initialize_state(ctx)
    if not lo.policy_file.exists():
        jsonio.atomic_write_json(lo.policy_file, DEFAULT_POLICY, 0o644, lo.trusted_uid, lo.trusted_gid)
    result: dict = {"steps": steps}
    if source_dir is not None:
        install_code(ctx, source_dir)
    if vendor:
        node_bin, pkg = find_node_and_srt(node, srt_package)
        lo.lib_dir.mkdir(parents=True, exist_ok=True)
        os.chown(lo.lib_dir, lo.trusted_uid, lo.trusted_gid)
        os.chmod(lo.lib_dir, 0o755)
        result["manifest"] = {k: v for k, v in vendor_runtime(ctx, node_bin, pkg).items() if k != "sha256"}
    return result


SHIM = """#!/bin/sh
# protect-folder launcher (root-owned). -I: ignore PYTHON* env and user site; -S: no site hooks.
exec /usr/bin/python3 -I -S -c 'import sys; sys.path.insert(0, "{lib}"); from protect_folder.cli import main; sys.exit(main())' "$@"
"""


def install_code(ctx: Context, source_dir: Path) -> None:
    lo = ctx.layout
    pkg_src = source_dir / "protect_folder"
    if not pkg_src.is_dir():
        raise ProtectError("NOT_INSTALLED", f"{pkg_src} not found")
    lo.lib_dir.mkdir(parents=True, exist_ok=True)
    dest = lo.lib_dir / "protect_folder"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(pkg_src, dest, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for root in (lo.lib_dir,):
        for dirpath, dirnames, filenames in os.walk(root):
            if Path(dirpath) == lo.runtime_dir:
                dirnames.clear()
                continue
            for name in dirnames + filenames:
                p = os.path.join(dirpath, name)
                os.chown(p, lo.trusted_uid, lo.trusted_gid)
                os.chmod(p, 0o755 if os.path.isdir(p) else 0o644)
    os.chown(lo.lib_dir, lo.trusted_uid, lo.trusted_gid)
    os.chmod(lo.lib_dir, 0o755)
    lo.bin_path.parent.mkdir(parents=True, exist_ok=True)
    jsonio.atomic_write(lo.bin_path, SHIM.format(lib=lo.lib_dir).encode(), 0o755,
                        lo.trusted_uid, lo.trusted_gid)
