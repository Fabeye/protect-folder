"""Adversarial regression tests: attempts, from INSIDE a real SRT sandbox, to reach or alter what must stay
protected. Every test asserts on what actually happened on the host. Temporary fixtures only; L4 is simulated
(FakeHostOps), real root locking is in tests/integration/test_privileged_l4.py."""

import hashlib
import os
import shlex
import socket
import threading

import pytest

from protect_folder import admin, launcher

pytestmark = pytest.mark.srt
MARK = "ESCAPE-SYNTH-MARKER-31337"


@pytest.fixture
def world(senv):
    e = senv
    e.targets = []
    for rel in (("Forbidden folder",), ("disk two", "credentials"), ("Ünï disk", "private data")):
        d = e.mkdir(*rel)
        (d / "secret.txt").write_text(MARK)
        (d / "sub").mkdir()
        (d / "sub" / "deep.txt").write_text(MARK)
        e.targets.append(d)
    e.ws = e.tmp / "project"
    e.ws.mkdir()
    e.install()
    for d in e.targets:
        assert admin.add(e.ctx, str(d), yes=True).ok
    e.is_root = False
    return e


def sh(e, script, capfd, env=None):
    """Runs `script` in the sandbox. {u} expands to a fresh /tmp prefix so no run can see another run's
    leftovers (the sandbox's /tmp is the real /tmp); it is removed afterwards."""
    import glob
    import shutil
    import uuid
    u = "/tmp/pf-" + uuid.uuid4().hex[:10]
    try:
        return _sh(e, script.replace("{u}", u), capfd, env)
    finally:
        for p in glob.glob(u + "*"):
            if os.path.islink(p) or os.path.isfile(p):
                os.unlink(p)
            else:
                shutil.rmtree(p, ignore_errors=True)


def _sh(e, script, capfd, env=None):
    if env:
        old = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
    try:
        code = launcher.run(e.ctx, ["sh", "-c", script], cwd=str(e.ws), quiet=True)
    finally:
        if env:
            for k, v in old.items():
                os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
    c = capfd.readouterr()
    return code, c.out + c.err


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


@pytest.mark.parametrize("name,script", [
    ("find-fixture-area", "find {data} /tmp -name secret.txt -o -name deep.txt 2>/dev/null"),
    ("find-by-content", "find {data} -type f -exec cat {{}} + 2>/dev/null"),
    ("grep-recursive", "grep -rI {mark} {data} 2>/dev/null"),
    ("tar", "tar cf - {t0} 2>/dev/null | tar xOf - 2>/dev/null"),
    ("cp-a-then-read", "cp -a {t0} {u}-copy 2>/dev/null; cat {u}-copy/secret.txt 2>/dev/null"),
    ("proc-self-root", "cat /proc/self/root{t0}/secret.txt 2>/dev/null"),
    ("proc-1-root", "cat /proc/1/root{t1}/secret.txt 2>/dev/null"),
    ("symlink-alias", "ln -s {t2} {u}-link 2>/dev/null; cat {u}-link/secret.txt 2>/dev/null"),
    ("dotdot-spelling", "cat {t0}/../{n0}/secret.txt 2>/dev/null"),
    ("hardlink", "ln {t0}/secret.txt {u}-hard 2>/dev/null; cat {u}-hard 2>/dev/null"),
    ("python-walk", "python3 -I -c \"import os;[print(open(os.path.join(r,f)).read()) for r,_,fs in os.walk('{datar}') for f in fs]\" 2>/dev/null"),
    ("userns-bind-mount", "unshare -Urm sh -c 'mount --bind {t0} /tmp 2>/dev/null; cat {t0}/secret.txt 2>/dev/null' 2>/dev/null"),
    ("chdir-then-relative", "cd {t0} 2>/dev/null && cat secret.txt 2>/dev/null"),
])
def test_no_route_returns_the_marker(world, capfd, name, script):
    e = world
    q = lambda p: shlex.quote(str(p))
    cmd = script.format(data=q(e.data), datar=str(e.data), mark=MARK, t0=q(e.targets[0]), t1=q(e.targets[1]),
                        t2=q(e.targets[2]), n0=q(e.targets[0].name), u="{u}")
    code, out = sh(e, cmd, capfd)
    assert MARK not in out, f"{name} leaked the marker"


def test_host_permissions_and_contents_cannot_be_changed_from_inside(world, capfd):
    e = world
    t = e.targets[0]
    before = (os.stat(t).st_mode, sha(t / "secret.txt"), sorted(os.listdir(t)))
    sh(e, f"chmod -R 777 '{t}' 2>/dev/null; echo hacked > '{t}/secret.txt' 2>/dev/null; touch '{t}/new' 2>/dev/null; "
          f"rm -rf '{t}/sub' 2>/dev/null; mv '{t}' '{t}.moved' 2>/dev/null", capfd)
    assert (os.stat(t).st_mode, sha(t / "secret.txt"), sorted(os.listdir(t))) == before
    assert not (t.parent / (t.name + ".moved")).exists()


def test_trusted_configuration_cannot_be_modified_from_inside(world, capfd):
    e = world
    lo = e.layout
    files = [lo.targets_file, lo.srt_targets_file, lo.policy_file]
    before = {str(f): sha(f) for f in files if f.exists()}
    cmds = "; ".join(f"echo x >> '{f}' 2>/dev/null; rm -f '{f}' 2>/dev/null; mv '{f}' '{f}.bak' 2>/dev/null" for f in files)
    cmds += f"; echo x > '{lo.lib_dir}/pwn.py' 2>/dev/null; echo x > '{lo.etc_dir}/pwn' 2>/dev/null"
    sh(e, cmds, capfd)
    assert {str(f): sha(f) for f in files if f.exists()} == before
    assert not (lo.lib_dir / "pwn.py").exists() and not (lo.etc_dir / "pwn").exists()


def test_dangerous_environment_is_dropped_before_launch(world, capfd):
    e = world
    code, out = sh(e, "env", capfd, env={"LD_PRELOAD": "/tmp/evil.so", "PYTHONPATH": "/tmp/evil",
                                          "NODE_OPTIONS": "--require=/tmp/evil.js", "SUDO_ASKPASS": "/tmp/askpass",
                                          "LD_LIBRARY_PATH": "/tmp/evil"})
    for k in ("LD_PRELOAD=", "PYTHONPATH=", "NODE_OPTIONS=", "SUDO_ASKPASS=", "LD_LIBRARY_PATH="):
        assert k not in out, k


def test_no_privilege_escalation_inside(world, capfd):
    e = world
    code, out = sh(e, "id -u; sudo -n true 2>&1; echo sudo-rc=$?; su -c id 2>&1 </dev/null; echo su-rc=$?", capfd)
    assert out.splitlines()[0] == str(os.getuid())
    assert "sudo-rc=0" not in out and "uid=0" not in out


def test_host_unix_sockets_are_unreachable_from_inside(world, capfd, tmp_path):
    """A privileged service would be reached through a unix socket; the sandbox must not allow it."""
    e = world
    path = "/tmp/pf-sock-%d" % os.getpid()
    if os.path.exists(path):
        os.unlink(path)
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(path)
    srv.listen(1)
    hit = []

    def accept():
        try:
            c, _ = srv.accept()
            hit.append(1)
            c.sendall(b"PRIVILEGED-SERVICE-REPLY")
        except OSError:
            pass
    threading.Thread(target=accept, daemon=True).start()
    try:
        code, out = sh(e, "python3 -I -c \"import socket;s=socket.socket(socket.AF_UNIX);s.settimeout(5);"
                          f"s.connect('{path}');print(s.recv(100).decode())\" 2>&1", capfd)
        assert "PRIVILEGED-SERVICE-REPLY" not in out and not hit
    finally:
        srv.close()
        os.unlink(path)


def test_network_is_closed_by_default_profile(world, capfd):
    e = world
    code, out = sh(e, "python3 -I -c \"import socket;socket.create_connection(('1.1.1.1',443),timeout=4);print('CONNECTED')\" 2>&1; "
                      "python3 -I -c \"import socket;socket.create_connection(('127.0.0.1',22),timeout=4);print('CONNECTED')\" 2>&1", capfd)
    assert "CONNECTED" not in out


@pytest.mark.parametrize("name,script", [
    ("find-by-content", "find {c} -type f -exec cat {{}} + 2>/dev/null"),
    ("grep-recursive", "grep -rI {mark} {c} 2>/dev/null"),
    ("tar", "tar cf - {c} 2>/dev/null | tar xOf - 2>/dev/null"),
    ("cp-a-then-read", "cp -a {c} {u}-copy-c 2>/dev/null; cat {u}-copy-c/secret.txt 2>/dev/null"),
    ("proc-self-root", "cat /proc/self/root{c}/secret.txt 2>/dev/null"),
    ("symlink-alias", "ln -s {c} {u}-link-c 2>/dev/null; cat {u}-link-c/secret.txt 2>/dev/null"),
    ("dotdot-spelling", "cat {c}/../{cn}/secret.txt 2>/dev/null"),
    ("python-walk", "python3 -I -c \"import os;[print(open(os.path.join(r,f)).read()) for r,_,fs in os.walk('{cr}') for f in fs]\" 2>/dev/null"),
    ("chdir-then-relative", "cd {c} 2>/dev/null && cat secret.txt 2>/dev/null"),
])
def test_negative_control_same_commands_do_leak_from_an_unprotected_directory(world, capfd, name, script):
    """Without this, 'the marker was not returned' could just mean the command line was broken."""
    e = world
    c = e.mkdir("unprotected control")
    (c / "secret.txt").write_text(MARK)
    q = lambda p: shlex.quote(str(p))
    code, out = sh(e, script.format(c=q(c), cr=str(c), cn=q(c.name), mark=MARK, u="{u}"), capfd)
    assert MARK in out, f"control {name} did not even work on an unprotected directory; the matching test proves nothing"


def test_what_the_hook_cannot_see_is_still_blocked_by_the_sandbox(world, capfd):
    """Defence in depth, verified: constructions the L2 hook cannot resolve statically (see
    test_hook_bypass.py) still cannot read a protected directory once they run inside SRT."""
    import base64
    e = world
    t = e.targets[0]
    payload = base64.b64encode(f"print(open({str(t / 'secret.txt')!r}).read())".encode()).decode()
    scripts = [
        f"python3 -c \"exec(__import__('base64').b64decode('{payload}'))\" 2>/dev/null",
        f"bash -c \"$(echo {payload} | base64 -d | python3 -I -)\" 2>/dev/null",
        "python3 -I -c \"import os;print(open(os.environ['PF_X']+'/secret.txt').read())\" 2>/dev/null",
    ]
    for script in scripts:
        code, out = sh(e, script, capfd, env={"PF_X": str(t)})
        assert MARK not in out, script
    # and the same opaque construction DOES work on an unprotected directory (the control)
    c = e.mkdir("unprotected control 2")
    (c / "secret.txt").write_text(MARK)
    code, out = sh(e, "python3 -I -c \"import os;print(open(os.environ['PF_X']+'/secret.txt').read())\" 2>&1", capfd,
                   env={"PF_X": str(c)})
    assert MARK in out
