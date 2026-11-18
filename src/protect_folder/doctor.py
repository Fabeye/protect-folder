"""Environment/dependency/integrity diagnostics."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from typing import Any

from . import registry
from .context import Context
from .errors import ProtectError
from .transactions import pending_journals, read_marker

PASS, WARN, FAIL, INFO = "PASS", "WARN", "FAIL", "INFO"
AGENT_COMMANDS = ("claude", "opencode", "codex")


def _version(cmd: list[str]) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout.strip()
        return out.splitlines()[0] if out else "(no output)"
    except (OSError, subprocess.SubprocessError):
        return "(unavailable)"


def _check(name: str, status: str, detail: str) -> dict[str, str]:
    return {"name": name, "status": status, "detail": detail}


PRIVILEGED_GROUPS = {"docker": "can start a root container with the host filesystem mounted",
                     "lxd": "can start a privileged container with the host filesystem mounted",
                     "lxc": "can start a privileged container with the host filesystem mounted",
                     "disk": "has raw read/write access to block devices",
                     "sudo": "may run any command as root after a password prompt",
                     "admin": "may run any command as root after a password prompt",
                     "wheel": "may run any command as root after a password prompt"}


def _privilege_checks(ctx: Context) -> list[dict[str, str]]:
    """Same-UID escalation paths that the launcher cannot close. WARN only, never a claim of protection."""
    import grp
    out: list[dict[str, str]] = []
    try:
        names = {grp.getgrgid(g).gr_name for g in os.getgroups()}
    except (KeyError, OSError):
        names = set()
    risky = sorted(n for n in names if n in PRIVILEGED_GROUPS)
    for n in risky:
        hard = n in ("docker", "lxd", "lxc", "disk")
        out.append(_check(f"group:{n}", WARN if hard else INFO,
                          f"this user is in '{n}': {PRIVILEGED_GROUPS[n]}. "
                          + ("An agent that reaches that mechanism bypasses L4 entirely; SRT blocks the Docker/LXD "
                             "sockets only if they are not allowlisted." if hard else
                             "A same-UID agent could use a cached sudo credential; run 'sudo -K'.")))
    if not risky:
        out.append(_check("privileged-groups", PASS, "not a member of docker/lxd/disk/sudo-style groups"))
    for sock in ("/var/run/docker.sock", "/run/docker.sock", "/var/lib/lxd/unix.socket", "/var/snap/lxd/common/lxd/unix.socket"):
        if os.path.exists(sock) and os.access(sock, os.W_OK):
            out.append(_check(f"socket:{sock}", WARN,
                              "a privileged service socket is writable by this user (outside SRT it is a root-equivalent path)"))
    return out


def _agent_hazard_checks() -> list[dict[str, str]]:
    """Agent processes that already run OUTSIDE the launcher (and so outside L3) on this machine."""
    out: list[dict[str, str]] = []
    try:
        procs = subprocess.run(["ps", "-eo", "pid=,args="], capture_output=True, text=True, timeout=10).stdout.splitlines()
    except (OSError, subprocess.SubprocessError):
        return out
    me = str(os.getpid())
    svc = [p for p in procs if "opencode" in p and "serve --service" in p and not p.lstrip().startswith(me)]
    if svc:
        out.append(_check("opencode-background-service", WARN,
                          "an OpenCode background service is running; sessions that attach to it are NOT confined "
                          "(protect-folder always starts --standalone and refuses --server/service)"))
    ext = [p for p in procs if "/codex" in p and ("openai.chatgpt" in p or "app-server" in p)]
    if ext:
        out.append(_check("codex-outside-launcher", WARN,
                          f"{len(ext)} Codex process(es) (e.g. an IDE extension) run outside protect-folder and are "
                          "not confined; only agents started with 'protect-folder run' are"))
    return out


def run(ctx: Context) -> dict[str, Any]:
    checks: list[dict[str, str]] = []
    lo = ctx.layout
    ok_py = sys.version_info >= (3, 10)
    checks.append(_check("python", PASS if ok_py else FAIL, platform.python_version()))
    checks.append(_check("platform", PASS if sys.platform == "linux" else FAIL, platform.platform()))
    checks.append(_check("euid", INFO, f"{ctx.euid()} ({'root' if ctx.euid() == 0 else 'unprivileged'})"))

    for tool, why in (("bwrap", "SRT sandbox (bubblewrap)"), ("socat", "SRT proxy bridge"),
                      ("rg", "SRT deny-path scan (ripgrep)"), ("getfacl", "ACL snapshot"),
                      ("setfacl", "ACL restore")):
        p = shutil.which(tool)
        checks.append(_check(tool, PASS if p else FAIL, f"{p} - {why}" if p else
                             f"missing ({why}); apt install bubblewrap socat ripgrep acl"))

    # trusted runtime
    node, srt_dir = lo.runtime_dir / "node", lo.runtime_dir / "srt"
    if node.exists() and srt_dir.exists():
        checks.append(_check("srt-runtime", PASS, f"root-owned runtime at {lo.runtime_dir}"))
    else:
        path_srt = shutil.which("srt")
        checks.append(_check(
            "srt-runtime", FAIL,
            f"trusted runtime missing at {lo.runtime_dir}; 'run' will refuse. "
            + (f"An srt on PATH ({path_srt}) is NOT trusted (user-writable)." if path_srt else
               "Run 'sudo protect-folder install'.")))

    # trusted file ownership
    for label, p in (("etc_dir", lo.etc_dir), ("registry", lo.targets_file), ("lib_dir", lo.lib_dir)):
        if not p.exists():
            checks.append(_check(f"trust:{label}", WARN if label != "etc_dir" else FAIL,
                                 f"{p} does not exist (not installed?)"))
            continue
        try:
            registry.check_trusted_file(p, lo.trusted_uid)
            checks.append(_check(f"trust:{label}", PASS, f"{p} owned by trusted uid, not writable by others"))
        except ProtectError as exc:
            checks.append(_check(f"trust:{label}", FAIL, exc.message))

    marker = read_marker(ctx)
    if marker is not None:
        checks.append(_check("recovery", FAIL, f"interrupted operation: {marker}. Run 'sudo protect-folder recover'"))
    else:
        checks.append(_check("recovery", PASS, "no interrupted administrative operation"))
    try:
        js = list(pending_journals(ctx))
        if js:
            checks.append(_check("journals", FAIL, f"{len(js)} unfinished journal(s)"))
    except PermissionError:
        checks.append(_check("journals", INFO, "state dir is root-only (run doctor with sudo to inspect journals)"))

    # sudo credential cache: same-uid agents could reuse it
    if ctx.euid() != 0 and shutil.which("sudo"):
        r = subprocess.run(["sudo", "-n", "-v"], capture_output=True, text=True)
        if r.returncode == 0:
            checks.append(_check("sudo-cache", WARN,
                                 "cached sudo credentials are active in this terminal; run 'sudo -K'"))
        else:
            checks.append(_check("sudo-cache", PASS, "no cached sudo credentials"))

    checks.extend(_privilege_checks(ctx))
    checks.extend(_agent_hazard_checks())

    for agent in AGENT_COMMANDS:
        p = shutil.which(agent)
        checks.append(_check(f"agent:{agent}", INFO if p else INFO,
                             f"{p} ({_version([agent, '--version'])})" if p else "not installed"))

    summary = "FAIL" if any(c["status"] == FAIL for c in checks) else (
        "WARN" if any(c["status"] == WARN for c in checks) else "PASS")
    return {"summary": summary, "checks": checks}
