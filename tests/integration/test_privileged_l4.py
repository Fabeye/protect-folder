"""Real chown/chmod/ACL behaviour. Opt-in: sudo env PF_PRIVILEGED_TESTS=1 python3 -m pytest -m privileged tests/integration

Uses only temporary fixtures; never touches real user directories.
"""

from __future__ import annotations

import os
import pwd
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from protect_folder import admin, registry, snapshots
from protect_folder.constants import Layout
from protect_folder.context import Context
from protect_folder.errors import ProtectError
from protect_folder.hostops import RealHostOps

pytestmark = pytest.mark.privileged

MARKER = "REAL-L4-SYNTHETIC-MARKER-42"


def _agent_ids() -> tuple[int, int]:
    uid = int(os.environ.get("SUDO_UID", "0"))
    if uid == 0:
        pytest.skip("run via sudo from an ordinary account so there is an unprivileged user to test with")
    return uid, int(os.environ.get("SUDO_GID", str(uid)))


def as_user(code: str, *args: str, cwd: str = "/") -> subprocess.CompletedProcess:
    uid, gid = _agent_ids()
    return subprocess.run(
        ["setpriv", f"--reuid={uid}", f"--regid={gid}", "--clear-groups", "python3", "-I", "-c", code, *args],
        capture_output=True, text=True, cwd=cwd)


@pytest.fixture
def sandbox():
    uid, gid = _agent_ids()
    base = Path(tempfile.mkdtemp(prefix="pf-priv-", dir="/var/tmp"))
    os.chown(base, uid, gid)
    os.chmod(base, 0o755)
    # trusted layout owned by root in a root-only parent so the unprivileged user can read but not write it
    sysdir = Path(tempfile.mkdtemp(prefix="pf-sys-", dir="/var/tmp"))
    os.chmod(sysdir, 0o755)
    layout = Layout(bin_path=sysdir / "bin", lib_dir=sysdir / "lib", etc_dir=sysdir / "etc",
                    state_dir=sysdir / "var", log_dir=sysdir / "log", trusted_uid=0, trusted_gid=0)
    ctx = Context(layout=layout, host=RealHostOps(), homes=set(), confirm=lambda p: True)
    projects = base / "projects"
    projects.mkdir()
    os.chown(projects, uid, gid)
    try:
        yield ctx, base, projects, uid, gid
    finally:
        for d in base.rglob("*"):
            pass
        shutil.rmtree(base, ignore_errors=True)
        shutil.rmtree(sysdir, ignore_errors=True)


def make_target(projects: Path, uid: int, gid: int, name: str = "Forbidden folder") -> Path:
    d = projects / name
    d.mkdir()
    os.chown(d, uid, gid)
    os.chmod(d, 0o750)
    f = d / "secret.txt"
    f.write_text(MARKER)
    os.chown(f, uid, gid)
    return d


def test_add_denies_unprivileged_access_then_remove_restores(sandbox):
    ctx, base, projects, uid, gid = sandbox
    d = make_target(projects, uid, gid)
    child = d / "sub"
    child.mkdir()
    os.chown(child, uid, gid)

    before = as_user("import sys; print(open(sys.argv[1]).read())", str(d / "secret.txt"))
    assert before.returncode == 0 and MARKER in before.stdout        # control: readable before

    assert admin.add(ctx, str(d), yes=True).ok
    st = d.stat()
    assert (st.st_uid, st.st_gid, st.st_mode & 0o7777) == (0, 0, 0o700)

    r = as_user("import sys; print(open(sys.argv[1]).read())", str(d / "secret.txt"))
    assert r.returncode != 0 and MARKER not in r.stdout + r.stderr
    assert "Permission denied" in r.stderr                            # real EACCES from the kernel (L4)
    r = as_user("import os,sys; print(os.listdir(sys.argv[1]))", str(d))
    assert r.returncode != 0 and "Permission denied" in r.stderr

    # not recursive: children keep their original owner
    assert child.stat().st_uid == uid and (d / "secret.txt").stat().st_uid == uid

    # registry/state are not writable by the unprivileged user, and snapshots are unreadable
    w = as_user("import sys; open(sys.argv[1],'a').write('x')", str(ctx.layout.targets_file))
    assert w.returncode != 0
    assert as_user("import os,sys; os.listdir(sys.argv[1])", str(ctx.layout.state_dir)).returncode != 0
    assert as_user("import sys; print(len(open(sys.argv[1]).read()))", str(ctx.layout.targets_file)).returncode == 0

    assert admin.remove(ctx, str(d), yes=True).ok
    st = d.stat()
    assert (st.st_uid, st.st_gid, st.st_mode & 0o7777) == (uid, gid, 0o750)
    after = as_user("import sys; print(open(sys.argv[1]).read())", str(d / "secret.txt"))
    assert MARKER in after.stdout


def test_parent_rename_limitation_is_real(sandbox):
    """Documented limitation: L4 locks the directory, not its entry in a user-writable parent."""
    ctx, base, projects, uid, gid = sandbox
    d = make_target(projects, uid, gid)
    admin.add(ctx, str(d), yes=True)
    r = as_user("import os,sys; os.rename(sys.argv[1], sys.argv[2])", str(d), str(projects / "moved"))
    assert r.returncode == 0, "expected the user CAN rename a locked directory inside a writable parent"
    assert (projects / "moved" / "secret.txt").exists()
    # the registry still refers to the old path, so remove must refuse to restore (stale)
    with pytest.raises(ProtectError) as e:
        admin.remove(ctx, str(d), yes=True)
    assert e.value.code in ("STALE", "MOUNT_MISSING", "IDENTITY_MISMATCH")
    os.rename(projects / "moved", d)         # operator puts it back
    assert admin.remove(ctx, str(d), yes=True).ok


def test_replaced_directory_is_never_restored_onto(sandbox):
    ctx, base, projects, uid, gid = sandbox
    d = make_target(projects, uid, gid)
    admin.add(ctx, str(d), yes=True)
    os.rename(d, projects / "old")
    d.mkdir()
    os.chown(d, uid, gid)
    os.chmod(d, 0o755)
    with pytest.raises(ProtectError) as e:
        admin.remove(ctx, str(d), yes=True)
    assert e.value.code == "IDENTITY_MISMATCH"
    assert d.stat().st_mode & 0o7777 == 0o755 and d.stat().st_uid == uid   # untouched
    assert admin.remove(ctx, str(d), forget=True, yes=True).ok


@pytest.mark.skipif(shutil.which("setfacl") is None, reason="setfacl not installed")
def test_extended_acl_round_trip_real(sandbox):
    ctx, base, projects, uid, gid = sandbox
    d = make_target(projects, uid, gid, "acl dir")
    subprocess.run(["setfacl", "-m", "u:nobody:rx", str(d)], check=True)
    subprocess.run(["setfacl", "-d", "-m", "u:nobody:rx", str(d)], check=True)
    before = subprocess.run(["getfacl", "-c", "-p", "-n", "-E", str(d)], capture_output=True, text=True).stdout
    mode_before = d.stat().st_mode & 0o7777
    assert admin.add(ctx, str(d), yes=True).ok
    mid = subprocess.run(["getfacl", "-c", "-p", "-n", "-E", str(d)], capture_output=True, text=True).stdout
    assert "nobody" not in mid and "65534" not in mid and "default:" not in mid
    assert admin.remove(ctx, str(d), yes=True).ok
    after = subprocess.run(["getfacl", "-c", "-p", "-n", "-E", str(d)], capture_output=True, text=True).stdout
    assert after == before and d.stat().st_mode & 0o7777 == mode_before


def test_multiple_independent_targets_cumulative(sandbox):
    ctx, base, projects, uid, gid = sandbox
    ds = [make_target(projects, uid, gid, n) for n in ("one", "two words", "Ünï")]
    for d in ds:
        assert admin.add(ctx, str(d), yes=True).ok
    assert len(registry.load(ctx.layout).targets) == 3
    assert all((d.stat().st_uid, d.stat().st_mode & 0o7777) == (0, 0o700) for d in ds)
    assert admin.remove(ctx, str(ds[1]), yes=True).ok
    assert (ds[0].stat().st_uid, ds[0].stat().st_mode & 0o7777) == (0, 0o700)
    for d in (ds[0], ds[2]):
        assert admin.remove(ctx, str(d), yes=True).ok
    assert snapshots.load(ctx.layout) == {}


def test_filesystem_without_posix_semantics_refused_when_available(sandbox):
    """Only runs if a vfat/exfat/ntfs mount exists on this machine; otherwise SKIPPED (not PASS)."""
    ctx, base, projects, uid, gid = sandbox
    from protect_folder import mounts as mnt
    bad = [m for m in mnt.read_mounts() if m.fstype in ("vfat", "exfat", "ntfs", "ntfs3", "fuseblk")
           and m.mount_point not in ("/boot/efi",)]
    if not bad:
        pytest.skip("SKIPPED: no non-POSIX filesystem mounted here")
    cand = Path(bad[0].mount_point)
    sub = next((p for p in cand.iterdir() if p.is_dir()), None) if os.access(cand, os.R_OK) else None
    if sub is None:
        pytest.skip("SKIPPED: no usable directory on the non-POSIX mount")
    with pytest.raises(ProtectError) as e:
        admin.add(ctx, str(sub), yes=True)
    assert e.value.code == "UNSUPPORTED_FILESYSTEM"


# ---- per-directory layer selection against the REAL kernel ---------------------------------------------------
def _stat(d: Path):
    st = os.stat(d)
    return st.st_uid, st.st_gid, st.st_mode & 0o7777


def test_no_linux_leaves_real_ownership_mode_and_acl_untouched(sandbox):
    ctx, base, projects, uid, gid = sandbox
    d = make_target(projects, uid, gid)
    subprocess.run(["setfacl", "-m", "u:root:rx", str(d)], check=True)
    acl_before = subprocess.run(["getfacl", "-c", "-p", "-n", "-E", str(d)], capture_output=True, text=True).stdout
    out = admin.add(ctx, str(d), yes=True, layers={"linux_permissions": False})
    assert out.ok
    assert _stat(d) == (uid, gid, 0o750)
    assert subprocess.run(["getfacl", "-c", "-p", "-n", "-E", str(d)], capture_output=True, text=True).stdout == acl_before
    r = as_user("import os,sys; print(os.listdir(sys.argv[1]))", str(d))
    assert r.returncode == 0                       # nothing denies the unprivileged user: there is NO OS-level protection
    assert snapshots.load(ctx.layout) == {}


def test_set_layers_disable_then_enable_linux_with_real_kernel(sandbox):
    ctx, base, projects, uid, gid = sandbox
    d = make_target(projects, uid, gid)
    subprocess.run(["setfacl", "-m", "u:root:rx", str(d)], check=True)
    acl_before = subprocess.run(["getfacl", "-c", "-p", "-n", "-E", str(d)], capture_output=True, text=True).stdout
    assert admin.add(ctx, str(d), yes=True).ok
    assert _stat(d) == (0, 0, 0o700) and as_user("import os,sys; os.listdir(sys.argv[1])", str(d)).returncode != 0
    out = admin.set_layers(ctx, str(d), {"linux_permissions": False}, yes=True)
    assert out.ok and _stat(d) == (uid, gid, 0o750)
    assert subprocess.run(["getfacl", "-c", "-p", "-n", "-E", str(d)], capture_output=True, text=True).stdout == acl_before
    assert as_user("import os,sys; os.listdir(sys.argv[1])", str(d)).returncode == 0
    os.chmod(d, 0o770)                              # the owner changes the mode while unprotected
    assert admin.set_layers(ctx, str(d), {"linux_permissions": True}, yes=True).ok
    assert _stat(d) == (0, 0, 0o700)
    err = as_user("import os,sys; os.listdir(sys.argv[1])", str(d))
    assert err.returncode != 0 and "Permission denied" in err.stderr
    assert admin.remove(ctx, str(d), yes=True).ok
    assert _stat(d) == (uid, gid, 0o770)           # the state captured at re-enable, not the very first one


def test_disable_linux_refuses_on_a_replaced_directory_with_real_inodes(sandbox):
    ctx, base, projects, uid, gid = sandbox
    d = make_target(projects, uid, gid)
    assert admin.add(ctx, str(d), yes=True).ok
    moved = Path(str(d) + ".moved")
    os.rename(d, moved)
    os.mkdir(d)
    os.chmod(d, 0o755)
    os.chown(d, 4242, 4242)
    with pytest.raises(ProtectError):
        admin.set_layers(ctx, str(d), {"linux_permissions": False}, yes=True)
    assert _stat(d) == (4242, 4242, 0o755)         # the impostor was never touched
    assert _stat(moved) == (0, 0, 0o700)           # nor was the real one chmod'ed away


def test_child_of_a_locked_parent_is_unreachable_even_with_its_own_linux_layer_off(sandbox):
    ctx, base, projects, uid, gid = sandbox
    parent = make_target(projects, uid, gid, "outer")
    child = parent / "inner"
    child.mkdir()
    os.chown(child, uid, gid)
    (child / "k.txt").write_text(MARKER)
    assert admin.add(ctx, str(parent), yes=True).ok
    out = admin.add(ctx, str(child), yes=True, layers={"linux_permissions": False})
    assert out.ok
    r = as_user("print(open(__import__('sys').argv[1]).read())", str(child / "k.txt"))
    assert r.returncode != 0 and MARKER not in r.stdout    # blocked by the parent's root:root 0700, not by the child
    assert _stat(child)[:2] == (uid, gid)                 # the child itself was never chowned
    assert admin.remove(ctx, str(child), yes=True).ok     # nothing to restore for the child: it is not touched
    assert admin.remove(ctx, str(parent), yes=True).ok
    assert as_user("print(open(__import__('sys').argv[1]).read())", str(child / "k.txt")).stdout.strip() == MARKER
