"""Adversarial matrix for the L2 pre-execution hook, through the REAL hook script (the same entry point Claude
Code and the OpenCode plugin call). L2 is best-effort by design: whatever it cannot decide it reports as
INCOMPLETE and the OS layers (L3/L4) are the guarantee. This file pins down both halves:
  * DETECTED:   commands the hook must block;
  * OPAQUE:     commands it cannot resolve statically; strict mode must block them, and SRT must still hide the
                directory when they run (defence in depth is verified, not assumed)."""

import os
import shlex

import pytest

from protect_folder import admin
from protect_folder.adapters.claude_verify import run_hook

MARK = "HOOKBYPASS-MARKER-2718"


@pytest.fixture
def world(env, tmp_path):
    env.install()
    p = env.mkdir("Forbidden folder")
    (p / "secret.txt").write_text(MARK)
    assert admin.add(env.ctx, str(p), yes=True).ok
    env.is_root = False
    env.p = p
    env.proj = tmp_path / "proj"
    env.proj.mkdir()
    (env.proj / "ok.txt").write_text("fine")
    return env


def verdict(e, cmd, tool="Bash"):
    ti = {"command": cmd} if tool in ("Bash", "shell") else {"file_path": cmd}
    rc, err = run_hook(e.ctx, {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": ti, "cwd": str(e.proj)}, [])
    return rc, err


def Q(p):
    return shlex.quote(str(p))


DETECTED = [
    "cat {P}/secret.txt",
    "cat \"{P}/secret.txt\"",
    "cat {P}/./secret.txt",
    "cat {P}/../{N}/secret.txt",
    "cat {P}/sub/../secret.txt",
    "ls {P}",
    "cd {P} && cat secret.txt",
    "pushd {P} >/dev/null; cat secret.txt",
    "find {P} -type f",
    "rg {MARK} {P}",
    "grep -r {MARK} {P}",
    "head -c 20 {P}/secret.txt | base64",
    "bash -c 'cat {PS}/secret.txt'",
    "sh -c \"cat {PS}/secret.txt\"",
    "eval \"cat {PS}/secret.txt\"",
    "D={P}; cat \"$D/secret.txt\"",
    "export D={P} && cat $D/secret.txt",
    "cat $(echo {P})/secret.txt",
    "cat `echo {P}`/secret.txt",
    "cp -r {P} /tmp/x",
    "tar cf /tmp/x.tar {P}",
    "ln -s {P} link && cat link/secret.txt",
    "cat < {P}/secret.txt",
    "xargs cat <<< {P}/secret.txt",
    "python3 -c \"print(open('{PR}/secret.txt').read())\"",
    "python3 -c \"import pathlib;print(pathlib.Path('{PR}').joinpath('secret.txt').read_text())\"",
    "python3 -c \"print(open('{PR}'+'/secret.txt').read())\"",
    "python3 -c \"d='{PR}';print(open(d+'/secret.txt').read())\"",
    "node -e \"console.log(require('fs').readFileSync('{PR}/secret.txt','utf8'))\"",
    "perl -e 'print `cat {PR}/secret.txt`'",
    "ruby -e \"puts File.read('{PR}/secret.txt')\"",
    "sudo cat {P}/secret.txt",
    "sudo ls",
    "sudo -n true",
    "env sudo id",
    "command sudo id",
    "\\sudo id",
    "su -c id",
    "doas id",
    "pkexec id",
    "echo hi; sudo id",
    "true && su root",
]

SAFE = ["ls -la", "git status", "python3 -c 'print(1+1)'", "cat ok.txt", "echo hello > out.txt",
        "grep -r TODO .", "npm test", "python3 -m pytest -q", "sed -n 1,5p ok.txt", "curl --version"]


@pytest.mark.parametrize("tmpl", DETECTED)
def test_detected_forms_are_blocked(world, tmpl):
    e = world
    cmd = tmpl.format(P=Q(e.p), PS=str(e.p).replace(" ", "\\ "), PR=str(e.p), N=Q(e.p.name), MARK=MARK)
    rc, err = verdict(e, cmd)
    assert rc == 2, f"NOT blocked: {cmd!r}"
    assert MARK not in err and "secret" not in err.replace("secret.txt", "")     # the message never echoes content


def test_script_files_are_followed(world):
    e = world
    (e.proj / "evil.py").write_text(f"print(open({str(e.p / 'secret.txt')!r}).read())\n")
    (e.proj / "evil.sh").write_text(f"#!/bin/sh\ncat {Q(e.p)}/secret.txt\n")
    (e.proj / "ind.py").write_text("import evil\n")
    for cmd in ("python3 evil.py", "sh evil.sh", "bash ./evil.sh", "python3 ind.py", "chmod +x evil.sh && ./evil.sh"):
        assert verdict(e, cmd)[0] == 2, cmd


def test_file_tools_are_checked_too(world):
    e = world
    assert verdict(e, str(e.p / "secret.txt"), tool="Read")[0] == 2
    assert verdict(e, str(e.p), tool="Glob")[0] == 2
    assert verdict(e, str(e.proj / "ok.txt"), tool="Read")[0] == 0


@pytest.mark.parametrize("cmd", SAFE)
def test_ordinary_development_commands_are_not_blocked(world, cmd):
    assert verdict(world, cmd)[0] == 0, cmd


OPAQUE = [
    "python3 -c \"exec(__import__('base64').b64decode('{B64}'))\"",
    "bash -c \"$(echo {B64} | base64 -d)\"",
]


def _b64(e):
    import base64
    return base64.b64encode(f"print(open({str(e.p / 'secret.txt')!r}).read())".encode()).decode()


@pytest.mark.parametrize("tmpl", OPAQUE)
def test_opaque_forms_are_reported_incomplete_and_strict_mode_blocks_them(world, tmpl):
    """The hook cannot resolve these statically. It must not claim 'safe' in strict mode; in balanced mode the
    decision is deferred to L3/L4 (verified below against a real sandbox)."""
    import json
    e = world
    pol = e.layout.policy_file
    from protect_folder import jsonio
    from protect_folder.policy.config import DEFAULT_POLICY
    doc = dict(DEFAULT_POLICY, inspection_mode="strict")
    jsonio.atomic_write(pol, json.dumps(doc).encode(), 0o644, e.layout.trusted_uid, e.layout.trusted_gid)
    cmd = tmpl.format(B64=_b64(e))
    assert verdict(e, cmd)[0] == 2, f"strict mode let an opaque command through: {cmd!r}"


def test_a_path_built_at_runtime_from_the_environment_is_not_seen_by_the_hook(world):
    """HONEST LIMIT, pinned so it cannot silently change: a path assembled from the process environment at
    runtime is invisible to static inspection. Only L3/L4 stop it (proved in test_sandbox_escapes.py)."""
    e = world
    rc, _ = verdict(e, "python3 -c \"import os;print(open(os.environ['PF_X']+'/secret.txt').read())\"")
    assert rc == 0


def test_malformed_and_hostile_inputs_fail_closed(world):
    e = world
    for raw in (b"", b"{", b"null", b"[]", b'{"tool_name": 5}', b"\x00\xff", b"{" * 5000, b'{"tool_name":"Bash","tool_input":"x"}'):
        rc, _ = run_hook(e.ctx, None, [], raw=raw)
        assert rc == 2, raw[:20]


def test_huge_inputs_do_not_hang_or_allow(world):
    import time
    e = world
    t0 = time.time()
    rc, _ = verdict(e, "echo " + "A" * 3_000_000)
    assert time.time() - t0 < 20
    assert rc in (0, 2)
