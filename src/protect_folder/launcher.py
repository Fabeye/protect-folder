"""Spawn the agent inside SRT: argv arrays only, no shell, signals and exit status preserved."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from typing import Any

from . import sessions
from .context import Context
from .preflight import Preflight, run_preflight
from .runtime import srt_argv

SI_USER = 0   # siginfo code for kill(2)/sigqueue; terminal-generated signals use SI_KERNEL (0x80)
_FORWARD = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT, signal.SIGUSR1, signal.SIGUSR2)


def _unblock() -> None:
    signal.pthread_sigmask(signal.SIG_SETMASK, [])


def spawn_and_wait(argv: list[str], env: dict[str, str], cwd: str) -> int:
    """Run argv in our foreground process group and wait for it.

    The child stays in our process group, so the terminal delivers Ctrl-C/Ctrl-Z/SIGWINCH to it
    directly. A signal that reaches *us* via kill(2) (SI_USER) is forwarded to the child; one the
    terminal generated is not, so the child never sees a doubled Ctrl-C.
    """
    watch = set(_FORWARD) | {signal.SIGCHLD}
    old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, watch)
    try:
        proc = subprocess.Popen(argv, env=env, cwd=cwd, close_fds=True, preexec_fn=_unblock)
    except BaseException:
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        raise
    # SIGCHLD is ignored by default, so a blocked one is never delivered to sigtimedwait unless
    # a handler exists. Install a no-op handler.
    prev_chld = signal.signal(signal.SIGCHLD, lambda *_: None)
    try:
        while True:
            rc = proc.poll()
            if rc is not None:
                break
            info = signal.sigtimedwait(watch, 0.2)
            if info is not None and info.si_signo != signal.SIGCHLD and info.si_code == SI_USER:
                try:
                    proc.send_signal(info.si_signo)
                except ProcessLookupError:
                    pass
    finally:
        signal.signal(signal.SIGCHLD, prev_chld)
        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
    if rc < 0:
        sig = -rc
        if sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
            # die the same way, so shells and parents see the real cause
            signal.signal(sig, signal.SIG_DFL)
            os.kill(os.getpid(), sig)
        return 128 + sig
    return rc


def relay_script() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "sandbox_relay.py")


def wrap_relays(relays: list[tuple[str, str]], argv: list[str]) -> list[str]:
    """Run the agent under the in-sandbox relay when the network profile declares one."""
    if not relays:
        return argv
    cmd = ["/usr/bin/python3", "-I", "-S", relay_script()]
    for listen, upstream in relays:
        cmd += ["--relay", f"{listen}={upstream}"]
    return [*cmd, "--", *argv]


def format_banner(report: dict[str, Any]) -> str:
    lay = report["layers"]

    def s(k: str) -> str:
        return {"NOT_APPLICABLE": "n/a", "DISABLED": "off"}.get(lay[k], lay[k])
    return (f"protect-folder: agent={report['agent']} profile={report['profile']} "
            f"L1={s('native_permissions')} L2={s('pre_execution_hook')} L3={s('srt')} "
            f"L4={s('linux_permissions')} VERIFIED_LAYERS: {report['verified_layers']} "
            f"targets={report['target_count']}")


def run(ctx: Context, argv: list[str], *, profile: str | None = None, require_layers: int | None = None,
        cwd: str | None = None, quiet: bool = False, json_report: bool = False) -> int:
    cwd = cwd or os.getcwd()
    pre: Preflight = run_preflight(ctx, argv, cwd=cwd, profile=profile, require_layers=require_layers)
    try:
        report = pre.report()
        if json_report:
            print(json.dumps({"schema": "protect-folder/1", "command": "run", "report": report},
                             sort_keys=True), file=sys.stderr)
        elif not quiet:
            print(format_banner(report), file=sys.stderr)
            for w in report["warnings"]:
                print(f"protect-folder: warning: {w}", file=sys.stderr)
        full = srt_argv(pre.rt, pre.settings_path, wrap_relays(pre.relays, pre.prepared.argv))
        sessions.register(pre.reg, pre.adapter.name)           # lets list/status flag "restart pending"
        try:
            child_env = dict(pre.prepared.env)
            child_env["PWD"] = cwd              # some agents (OpenCode) trust $PWD over the real cwd
            return spawn_and_wait(full, child_env, cwd)
        finally:
            sessions.unregister()
    finally:
        for f in [pre.settings_path, *pre.prepared.cleanup]:
            try:
                os.unlink(f)
            except OSError:
                pass
