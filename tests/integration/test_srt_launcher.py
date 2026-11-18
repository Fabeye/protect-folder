"""Real SRT + bubblewrap. Uses only temporary fixtures; L4 is simulated by FakeHostOps (see
tests/integration/test_privileged_l4.py for real root locking)."""

import json
import os
import pty
import select
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from protect_folder import admin, launcher, registry
from protect_folder.errors import ProtectError
from protect_folder.preflight import run_preflight

pytestmark = pytest.mark.srt
MARK = "LAUNCH-SYNTHETIC-MARKER-77"


@pytest.fixture
def world(senv):
    """Three independent protected targets + a git-less project workspace."""
    e = senv
    targets = []
    for rel in (("Forbidden folder",), ("disk two", "credentials"), ("Ünï disk", "private data")):
        d = e.mkdir(*rel)
        (d / "secret.txt").write_text(MARK)
        (d / "sub").mkdir()
        (d / "sub" / "deep.txt").write_text(MARK)
        targets.append(d)
    ws = e.tmp / "project"
    ws.mkdir()
    (ws / "README.md").write_text("hello")
    e.install()
    for d in targets:
        assert admin.add(e.ctx, str(d), yes=True).ok
    e.targets, e.ws = targets, ws
    e.is_root = False            # from here on we are the ordinary user, as 'run' requires
    return e


def go(e, argv, capfd, **kw):
    kw.setdefault("quiet", True)
    code = launcher.run(e.ctx, argv, cwd=str(e.ws), **kw)
    out = capfd.readouterr()
    return code, out.out, out.err


def test_ordinary_development_still_works(world, capfd):
    e = world
    code, out, err = go(e, ["sh", "-c", "echo edited > notes.txt && python3 -I -c 'print(6*7)' && git --version"], capfd)
    assert code == 0, err
    assert "42" in out and "git version" in out
    assert (e.ws / "notes.txt").read_text() == "edited\n"          # the project really was edited on the host


def test_every_target_is_unreadable_by_every_route(world, capfd):
    e = world
    for d in e.targets:
        for argv in (
            ["cat", f"{d}/secret.txt"],
            ["python3", "-I", "-c", "import sys;print(open(sys.argv[1]).read())", f"{d}/secret.txt"],
            ["python3", "-I", "-c", "import os,sys;print(os.listdir(sys.argv[1]))", str(d)],
            ["sh", "-c", f"cat '{d}'/sub/deep.txt"],
            ["cat", f"{d}/../{d.name}/secret.txt"],
            ["cat", f"/proc/self/root{d}/secret.txt"],
        ):
            code, out, err = go(e, argv, capfd)
            assert MARK not in out + err, argv
        code, out, err = go(e, ["python3", "-I", "-c", "import os,sys;print(os.listdir(sys.argv[1]))", str(d)], capfd)
        assert out.strip() == "[]"                                  # masked as an empty directory


def test_symlink_routes_do_not_expose_content(world, capfd):
    e = world
    d = e.targets[0]
    os.symlink(d, e.ws / "pre_alias")
    code, out, err = go(e, ["sh", "-c", f"cat pre_alias/secret.txt; ln -s '{d}' made_alias; cat made_alias/secret.txt"], capfd)
    assert MARK not in out + err


def test_write_into_target_never_reaches_host_and_rename_fails(world, capfd):
    e = world
    d = e.targets[1]
    code, out, err = go(e, ["sh", "-c", f"echo pwned > '{d}/new.txt'; mv '{d}' '{d}.moved'; echo rc=$?"], capfd)
    assert not (d / "new.txt").exists() and d.exists() and not Path(str(d) + ".moved").exists()


def test_target_inside_workspace_is_masked_and_pinned(world, capfd):
    e = world
    inner = e.ws / "credentials"
    inner.mkdir()
    (inner / "k.txt").write_text(MARK)
    e.is_root = True
    assert admin.add(e.ctx, str(inner), yes=True).ok
    e.is_root = False
    code, out, err = go(e, ["sh", "-c", "cat credentials/k.txt; mv credentials credentials.x; echo rc=$?; rm -rf credentials; ls"], capfd)
    assert MARK not in out + err
    assert (inner / "k.txt").read_text() == MARK                    # still intact on the host


def test_argv_fidelity_and_exit_status(world, capfd):
    e = world
    weird = ["a  b", "$HOME", "*", "it's", "--flag", "", "ü日本", "`id`", "; echo injected"]
    code, out, err = go(e, ["python3", "-I", "-c", "import sys, json; print(json.dumps(sys.argv[1:]))", *weird], capfd)
    assert json.loads(out.strip().splitlines()[-1]) == weird
    for want in (0, 1, 37, 255):
        code, *_ = go(e, ["sh", "-c", f"exit {want}"], capfd)
        assert code == want
    code, out, err = go(e, ["sh", "-c", "echo to-out; echo to-err >&2"], capfd)
    assert "to-out" in out and "to-err" in err and "to-err" not in out


def test_working_directory_is_preserved(world, capfd):
    e = world
    sub = e.ws / "sub dir"
    sub.mkdir()
    code = launcher.run(e.ctx, ["pwd"], cwd=str(sub), quiet=True)
    assert capfd.readouterr().out.strip() == str(sub)


def test_stdin_is_forwarded(world, capfd, monkeypatch, tmp_path):
    e = world
    p = tmp_path / "in.txt"
    p.write_text("line-from-stdin\n")
    fd = os.open(p, os.O_RDONLY)
    saved = os.dup(0)
    os.dup2(fd, 0)
    try:
        code, out, err = go(e, ["cat"], capfd)
    finally:
        os.dup2(saved, 0)
    assert "line-from-stdin" in out


def test_banner_reports_only_what_is_established(world, capfd):
    e = world
    code, out, err = go(e, ["true"], capfd, quiet=False)
    assert "L1=n/a" in err and "L2=n/a" in err and "L3=PASS" in err and "L4=PASS" in err
    assert "VERIFIED_LAYERS: 2/4" in err and "targets=3" in err
    code, out, err = go(e, ["true"], capfd, quiet=False, json_report=True)
    rep = json.loads(err.strip().splitlines()[-1])["report"]
    assert rep["layers"]["native_permissions"] == "NOT_APPLICABLE" and rep["verified_layers"] == "2/4"


# ---- refusals (fail closed) ----------------------------------------------------------------
def refuses(e, code, **kw):
    with pytest.raises(ProtectError) as ex:
        run_preflight(e.ctx, ["true"], cwd=str(e.ws), **kw)
    assert ex.value.code == code, ex.value.message
    return ex.value


def test_refuses_as_root(world):
    world.is_root = True
    refuses(world, "IS_ROOT")


def test_refuses_when_a_target_disappears_or_is_replaced(world):
    e = world
    d = e.targets[0]
    os.rename(d, str(d) + ".gone")
    refuses(e, "STALE")
    os.mkdir(d)                                       # new object at the old string path
    refuses(e, "IDENTITY_MISMATCH")


def test_refuses_when_removable_disk_absent(world):
    e = world
    reg = registry.load(e.layout)
    reg.targets[0].mount_point = "/media/nobody/absent-disk"
    registry.save(e.layout, reg)
    os.rename(Path(reg.targets[0].canonical_path), reg.targets[0].canonical_path + ".away")
    refuses(e, "MOUNT_MISSING")


def test_refuses_when_l4_not_effective(world):
    world.host.meta.clear()
    err = refuses(world, "PREFLIGHT_FAILED")
    assert "L4 is not effective" in err.message


def test_refuses_tampered_registry_and_generated_policy(world):
    e = world
    os.chmod(e.layout.targets_file, 0o666)
    refuses(e, "TAMPERED")
    os.chmod(e.layout.targets_file, 0o644)
    gen = e.layout.srt_targets_file
    doc = json.loads(gen.read_text())
    doc["denyRead"] = doc["denyRead"][:1]
    gen.write_text(json.dumps(doc))
    refuses(e, "TAMPERED")


def test_refuses_registry_edited_by_hand(world):
    e = world
    doc = json.loads(e.layout.targets_file.read_text())
    doc["targets"] = doc["targets"][:1]                # attacker drops two targets from the policy
    e.layout.targets_file.write_text(json.dumps(doc))
    refuses(e, "TAMPERED")


def test_refuses_without_trusted_srt_or_with_tampered_runtime(world, srt_runtime_dir):
    e = world
    import dataclasses
    from protect_folder.context import Context
    bad = dataclasses.replace(e.layout, runtime_override=e.tmp / "no-runtime")
    ctx = Context(layout=bad, host=e.host, euid=lambda: 1000, homes=set(), check_installed_code=False)
    with pytest.raises(ProtectError) as ex:
        run_preflight(ctx, ["true"], cwd=str(e.ws))
    assert ex.value.code == "SRT_UNAVAILABLE"


def test_refuses_pending_recovery(world):
    from protect_folder import transactions
    transactions.write_marker(world.ctx, "IN_PROGRESS", "t", "add")
    refuses(world, "RECOVERY_REQUIRED")


def test_refuses_cwd_inside_target_or_home_root(world):
    e = world
    with pytest.raises(ProtectError) as ex:
        run_preflight(e.ctx, ["true"], cwd=str(e.targets[0] / "sub"))
    assert ex.value.code == "PREFLIGHT_FAILED"
    e.ctx.homes = {str(e.ws)}
    refuses(e, "PREFLIGHT_FAILED")


def test_layer_requirements(world):
    refuses(world, "LAYERS_INSUFFICIENT", require_layers=4)         # generic adapter cannot give 4/4
    refuses(world, "USAGE", require_layers=1)
    refuses(world, "PREFLIGHT_FAILED", profile="no-such-profile")


# ---- signals / process lifecycle -------------------------------------------------------------
HELPER = ("import sys; from protect_folder.launcher import spawn_and_wait; import os; "
          "sys.exit(spawn_and_wait(sys.argv[1:], dict(os.environ), '/'))")


def helper(*argv):
    root = Path(__file__).resolve().parents[2]
    env = dict(os.environ, PYTHONPATH=str(root / "src"))
    return subprocess.Popen([sys.executable, "-I", "-c", HELPER.replace("import sys;", "import sys; sys.path.insert(0, %r);" % str(root / "src")), *argv],
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def test_kill_signal_is_forwarded_and_exit_status_preserved():
    p = helper("sh", "-c", "trap 'exit 42' TERM; echo ready; while :; do sleep 0.05; done")
    assert p.stdout.readline().strip() == "ready"
    p.send_signal(signal.SIGTERM)
    assert p.wait(timeout=10) == 42


def test_child_killed_by_signal_kills_launcher_the_same_way():
    p = helper("sh", "-c", "echo ready; kill -TERM $$")
    assert p.stdout.readline().strip() == "ready"
    assert p.wait(timeout=10) == -signal.SIGTERM


def test_sigint_via_kill_reaches_child_once():
    p = helper("sh", "-c", "n=0; trap 'n=$((n+1)); echo got-int-$n' INT; echo ready; i=0; while [ $i -lt 60 ]; do sleep 0.05; i=$((i+1)); done; echo done-$n")
    assert p.stdout.readline().strip() == "ready"
    p.send_signal(signal.SIGINT)
    out = p.communicate(timeout=20)[0]
    assert "got-int-1" in out and "got-int-2" not in out


def test_no_orphans_when_launcher_is_terminated(world):
    e = world
    from protect_folder.runtime import srt_argv
    tag = str(31000 + os.getpid() % 900)           # unique argument so pgrep cannot match anything else
    pre = run_preflight(e.ctx, ["sleep", tag], cwd=str(e.ws))
    try:
        p = helper(*srt_argv(pre.rt, pre.settings_path, pre.prepared.argv))
        deadline = time.time() + 15
        while time.time() < deadline and subprocess.run(["pgrep", "-f", f"^sleep {tag}$"], capture_output=True).returncode != 0:
            time.sleep(0.1)
        assert subprocess.run(["pgrep", "-f", f"^sleep {tag}$"], capture_output=True).returncode == 0, "sandboxed sleep never started"
        p.send_signal(signal.SIGTERM)                 # kill(2) -> forwarded to srt
        p.wait(timeout=15)
        deadline = time.time() + 10
        while time.time() < deadline and subprocess.run(["pgrep", "-f", f"^sleep {tag}$"], capture_output=True).returncode == 0:
            time.sleep(0.2)
        left = subprocess.run(["pgrep", "-af", f"^sleep {tag}$"], capture_output=True, text=True).stdout
        assert left == "", f"orphaned sandboxed process survived: {left}"
    finally:
        subprocess.run(["pkill", "-f", f"^sleep {tag}$"])
        os.unlink(pre.settings_path)


def test_tty_is_preserved_inside_sandbox(world):
    """A real pty: stdin/stdout must be a tty inside the sandbox and the window size must arrive."""
    e = world
    import fcntl, struct, termios
    from protect_folder.runtime import srt_argv
    pre = run_preflight(e.ctx, ["sh", "-c", "[ -t 0 ] && [ -t 1 ] && echo TTY-OK; stty size"], cwd=str(e.ws))
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 33, 101, 0, 0))
    buf = b""
    try:
        proc = subprocess.Popen(srt_argv(pre.rt, pre.settings_path, pre.prepared.argv), stdin=slave,
                                stdout=slave, stderr=slave, cwd=str(e.ws), env=pre.prepared.env,
                                start_new_session=True, close_fds=True)
        os.close(slave)
        deadline = time.time() + 20
        while time.time() < deadline:
            r, _, _ = select.select([master], [], [], 0.5)
            if r:
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
            elif proc.poll() is not None:
                break
        proc.wait(timeout=10)
    finally:
        os.unlink(pre.settings_path)
        os.close(master)
    text = buf.decode(errors="replace")
    assert "TTY-OK" in text, text
    assert "33 101" in text, text


def test_negative_control_marker_is_readable_when_nothing_is_protected(senv, capfd):
    """Proves the leak assertions above are capable of failing: with no registered targets the
    very same read DOES return the marker."""
    e = senv
    d = e.mkdir("unprotected")
    (d / "secret.txt").write_text(MARK)
    ws = e.tmp / "project"
    ws.mkdir()
    e.install()
    e.is_root = False
    code = launcher.run(e.ctx, ["cat", f"{d}/secret.txt"], cwd=str(ws), quiet=True)
    out = capfd.readouterr()
    assert code == 0 and MARK in out.out
