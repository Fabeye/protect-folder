import json
import os

import pytest

from protect_folder import admin, audit, registry, snapshots, transactions
from protect_folder.errors import ProtectError
from protect_folder.hostops import MetaState

MARKER = "SYNTHETIC-SECRET-MARKER-9f3a"


def add(env, path, **kw):
    kw.setdefault("yes", True)
    return admin.add(env.ctx, str(path), **kw)


def remove(env, path, **kw):
    kw.setdefault("yes", True)
    return admin.remove(env.ctx, str(path), **kw)


def meta_of(env, path):
    fd = os.open(path, os.O_PATH | os.O_DIRECTORY)
    try:
        return env.host.stat(fd)
    finally:
        os.close(fd)


def test_add_applies_l4_registers_and_generates(env):
    d = env.mkdir("Forbidden folder")
    out = add(env, d)
    assert out.ok and out.reason_code == "OK"
    assert meta_of(env, d) == MetaState(0, 0, 0o700)
    reg = registry.load(env.layout)
    assert reg.paths() == [str(d)] and reg.revision == 1
    gen = json.loads(env.layout.srt_targets_file.read_text())
    assert gen["denyRead"] == [{"path": str(d), "literal": True}] and gen["policy_revision"] == reg.policy_revision
    assert not env.layout.marker_file.exists() and not list(env.layout.journal_dir.glob("*.json"))
    assert any("Already-running" in w for w in out.warnings) and any("sudo -K" in w for w in out.warnings)


def test_requires_root_but_dry_run_does_not(env):
    d = env.mkdir("x")
    env.is_root = False
    with pytest.raises(ProtectError) as e:
        add(env, d)
    assert e.value.code == "NOT_ROOT"
    env.install()
    out = add(env, d, dry_run=True)
    assert out.data["dry_run"] and meta_of(env, d).mode != 0o700


def test_dry_run_changes_nothing(env):
    d = env.mkdir("x")
    env.install()
    before = sorted(p.name for p in env.layout.etc_dir.rglob("*"))
    out = add(env, d, dry_run=True)
    assert out.data["plan"]["will_apply"]["recursive"] is False
    assert env.host.calls == [] and sorted(p.name for p in env.layout.etc_dir.rglob("*")) == before


def test_confirmation_required_without_yes(env):
    d = env.mkdir("x")
    with pytest.raises(ProtectError) as e:
        admin.add(env.ctx, str(d), yes=False)
    assert e.value.code == "CONFIRMATION_REQUIRED" and env.host.calls == []
    env.confirm_answer = True
    assert admin.add(env.ctx, str(d), yes=False).ok


def test_idempotent_and_snapshot_never_overwritten(env):
    d = env.mkdir("x")
    original = meta_of(env, d)
    add(env, d)
    snap1 = snapshots.load(env.layout)[next(iter(snapshots.load(env.layout)))]
    calls = len(env.host.calls)
    again = add(env, d)
    assert again.ok and again.reason_code == "ALREADY_PROTECTED"
    assert len(env.host.calls) == calls                        # no host change at all
    snap2 = list(snapshots.load(env.layout).values())[0]
    assert snap2 == snap1 and (snap2.uid, snap2.gid, snap2.mode) == (original.uid, original.gid, original.mode)
    assert registry.load(env.layout).revision == 1


def test_three_independent_targets_accumulate(env):
    ds = [env.mkdir("Forbidden folder"), env.mkdir("proj two", "credentials"), env.mkdir("Ünï data", "private data")]
    for d in ds:
        add(env, d)
    reg = registry.load(env.layout)
    assert reg.paths() == sorted(str(d) for d in ds) and reg.revision == 3
    assert all(meta_of(env, d) == MetaState(0, 0, 0o700) for d in ds)       # earlier ones still active
    gen = json.loads(env.layout.srt_targets_file.read_text())
    assert [e["path"] for e in gen["denyRead"]] == reg.paths()
    assert len(snapshots.load(env.layout)) == 3


def test_never_recursive(env):
    d = env.mkdir("top")
    child = env.mkdir("top", "child")
    (child / "f.txt").write_text("x")
    add(env, d)
    assert env.host.touched_inodes() == {d.stat().st_ino}
    remove(env, d)
    assert env.host.touched_inodes() == {d.stat().st_ino}


def test_remove_restores_exact_original(env):
    d = env.mkdir("x")
    os.chmod(d, 0o2750)
    add(env, d)
    assert meta_of(env, d).mode == 0o700
    out = remove(env, d)
    assert out.ok
    m = meta_of(env, d)
    assert (m.uid, m.gid, m.mode) == (os.getuid(), os.getgid(), 0o2750)
    assert registry.load(env.layout).targets == [] and snapshots.load(env.layout) == {}
    assert json.loads(env.layout.srt_targets_file.read_text())["denyRead"] == []


def test_remove_other_targets_stay_protected(env):
    a, b = env.mkdir("a"), env.mkdir("b")
    add(env, a)
    add(env, b)
    remove(env, a)
    assert meta_of(env, b) == MetaState(0, 0, 0o700) and registry.load(env.layout).paths() == [str(b)]


def test_remove_accepts_id_and_original_spelling(env):
    d = env.mkdir("x")
    out = add(env, d)
    tid = out.data["target"]["id"]
    assert remove(env, tid).ok
    add(env, d)
    assert remove(env, str(d) + "/").ok


def test_remove_unknown_target(env):
    env.install()
    with pytest.raises(ProtectError) as e:
        remove(env, env.mkdir("never"))
    assert e.value.code == "NOT_PROTECTED"


def test_extended_acl_snapshotted_cleared_and_restored(env):
    d = env.mkdir("acl")
    acl = "user::rwx\nuser:65534:r-x\ngroup::rwx\nmask::r-x\nother::---\ndefault:user::rwx\ndefault:other::r-x\n"
    env.host.set_initial_acl(str(d), acl)
    env.host.calls.clear()
    out = add(env, d)
    assert any("extended ACL" in w for w in out.warnings)
    assert not env.host.get_acl(os.open(d, os.O_PATH)).extended        # cleared while protected
    remove(env, d)
    assert env.host.get_acl(os.open(d, os.O_PATH)).text == acl


# ---- failure / rollback ---------------------------------------------------------------------
def assert_pristine(env, d, original):
    assert meta_of(env, d) == original
    assert registry.load(env.layout).targets == []
    assert snapshots.load(env.layout) == {}
    assert not env.layout.marker_file.exists()
    assert not list(env.layout.journal_dir.glob("*.json"))


@pytest.mark.parametrize("op", ["chown", "chmod"])
def test_host_failure_rolls_back(env, op):
    d = env.mkdir("x")
    original = meta_of(env, d)
    env.host.fail_on[op] = 1
    with pytest.raises(OSError):
        add(env, d)
    assert_pristine(env, d, original)


def test_registry_write_failure_restores_permissions(env, monkeypatch):
    d = env.mkdir("x")
    original = meta_of(env, d)

    def boom(*a, **k):
        raise OSError(28, "disk full")
    monkeypatch.setattr(registry, "save", boom)
    with pytest.raises(OSError):
        add(env, d)
    assert_pristine(env, d, original)


def test_generated_policy_failure_restores_everything(env, monkeypatch):
    d = env.mkdir("x")
    original = meta_of(env, d)
    monkeypatch.setattr(admin, "write_generated", lambda *a: (_ for _ in ()).throw(OSError("nope")))
    with pytest.raises(OSError):
        add(env, d)
    assert_pristine(env, d, original)


def test_failed_add_leaves_earlier_targets_intact(env, monkeypatch):
    a, b = env.mkdir("a"), env.mkdir("b")
    add(env, a)
    env.host.fail_on["chmod"] = env.host._counts.get("chmod", 0) + 1
    with pytest.raises(OSError):
        add(env, b)
    assert registry.load(env.layout).paths() == [str(a)]
    assert meta_of(env, a) == MetaState(0, 0, 0o700) and meta_of(env, b).mode != 0o700


def test_failed_remove_reprotects(env, monkeypatch):
    d = env.mkdir("x")
    add(env, d)
    monkeypatch.setattr(registry, "save", lambda *a, **k: (_ for _ in ()).throw(OSError("fail")))
    with pytest.raises(OSError):
        remove(env, d)
    assert meta_of(env, d) == MetaState(0, 0, 0o700)        # compensation re-applied L4
    assert len(registry.load(env.layout).targets) == 1


def test_unprovable_rollback_leaves_recovery_required(env, monkeypatch):
    d = env.mkdir("x")
    original_registry_save = registry.save

    def swap_then_fail(layout, reg):
        # While L4 is applied, the operator's directory is replaced by a different object.
        os.rename(d, str(d) + ".moved")
        os.mkdir(d)
        raise OSError("fail after swap")
    monkeypatch.setattr(registry, "save", swap_then_fail)
    with pytest.raises(ProtectError) as e:
        add(env, d)
    assert e.value.code == "RECOVERY_REQUIRED"
    monkeypatch.setattr(registry, "save", original_registry_save)
    marker = transactions.read_marker(env.ctx)
    assert marker["state"] == "RECOVERY_REQUIRED"
    # the replacement object must NOT have been touched by the rollback
    assert meta_of(env, d).mode != 0o700 and d.stat().st_ino not in env.host.touched_inodes()
    # everything refuses until recovered
    with pytest.raises(ProtectError) as e:
        add(env, env.mkdir("other"))
    assert e.value.code == "RECOVERY_REQUIRED"
    with pytest.raises(ProtectError) as e:
        remove(env, d)
    assert e.value.code == "RECOVERY_REQUIRED"


def test_crash_mid_operation_is_discoverable_and_recoverable(env, monkeypatch):
    d = env.mkdir("x")
    original = meta_of(env, d)
    # Simulate sudden process death: rollback never runs, journal+marker stay behind.
    monkeypatch.setattr(transactions.Transaction, "rollback", lambda self, cause: False)
    monkeypatch.setattr(registry, "save", lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(BaseException):
        add(env, d)
    monkeypatch.undo()
    assert meta_of(env, d).mode == 0o700                       # half-applied
    assert transactions.read_marker(env.ctx)["state"] == "IN_PROGRESS"   # visible without root
    with pytest.raises(ProtectError) as e:
        add(env, d)
    assert e.value.code == "RECOVERY_REQUIRED"
    out = admin.recover(env.ctx, yes=True)
    assert out.ok
    assert_pristine(env, d, original)
    assert add(env, d).ok                                      # usable again


def test_recover_dry_run_and_noop(env):
    env.install()
    assert admin.recover(env.ctx, yes=True).message == "nothing to recover"


def test_recover_reports_inconsistency(env):
    d = env.mkdir("x")
    add(env, d)
    # a locked-but-unregistered dir: snapshot with no registry entry
    reg = registry.load(env.layout)
    registry.save(env.layout, registry.Registry([], 5))
    transactions.write_marker(env.ctx, "IN_PROGRESS", "t", "add")
    with pytest.raises(ProtectError) as e:
        admin.recover(env.ctx, yes=True)
    assert e.value.code == "RECOVERY_REQUIRED" and e.value.details["issues"]


def test_concurrent_admin_operation_is_rejected(env):
    d = env.mkdir("x")
    env.install()
    with transactions.AdminLock(env.ctx):
        with pytest.raises(ProtectError) as e:
            add(env, d)
    assert e.value.code == "LOCKED"
    assert add(env, d).ok


# ---- identity / staleness -------------------------------------------------------------------
def test_replaced_directory_is_not_adopted_and_not_restored(env):
    d = env.mkdir("x")
    add(env, d)
    old_ino = d.stat().st_ino
    os.rename(d, str(d) + ".old")
    os.mkdir(d)                                   # unexpected new object at the same string path
    assert d.stat().st_ino != old_ino
    before = list(env.host.calls)
    with pytest.raises(ProtectError) as e:
        add(env, d)
    assert e.value.code == "IDENTITY_MISMATCH"
    with pytest.raises(ProtectError) as e:
        remove(env, d)
    assert e.value.code == "IDENTITY_MISMATCH" and "Manual recovery" in (e.value.hint or "")
    assert env.host.calls == before               # nothing was changed on the new directory
    assert len(registry.load(env.layout).targets) == 1


def test_stale_path_remove_fails_safely_then_forget(env):
    d = env.mkdir("x")
    add(env, d)
    os.rename(d, str(d) + ".moved")
    with pytest.raises(ProtectError) as e:
        remove(env, d)
    assert e.value.code in ("STALE", "MOUNT_MISSING")
    out = remove(env, d, forget=True)
    assert out.ok and registry.load(env.layout).targets == []
    assert any("NOT restored" in w for w in out.warnings)


def test_removable_media_absent_reports_mount_missing(env):
    d = env.mkdir("x")
    add(env, d)
    reg = registry.load(env.layout)
    t = reg.targets[0]
    t.mount_point = "/media/user/not-mounted-disk"
    registry.save(env.layout, registry.Registry(reg.targets, reg.revision))
    os.rename(d, str(d) + ".away")
    with pytest.raises(ProtectError) as e:
        remove(env, d)
    assert e.value.code == "MOUNT_MISSING"


def test_unsupported_filesystem_records_nothing(env, monkeypatch):
    from protect_folder import mounts as mnt
    d = env.mkdir("x")
    real = mnt.read_mounts()
    fake = [mnt.MountEntry(m.mount_id, m.parent_id, m.major, m.minor, m.root, m.mount_point, m.options,
                           "exfat", m.source) for m in real]
    env.ctx.read_mounts = lambda: fake
    with pytest.raises(ProtectError) as e:
        add(env, d)
    assert e.value.code == "UNSUPPORTED_FILESYSTEM"
    assert env.host.calls == [] and registry.load(env.layout).targets == []


def test_host_that_ignores_chmod_is_detected(env):
    d = env.mkdir("x")
    original = meta_of(env, d)
    env.host.chmod = lambda fd, mode: env.host._tick("chmod", fd)      # silently does nothing
    with pytest.raises(ProtectError) as e:
        add(env, d)
    assert e.value.code == "APPLY_FAILED"
    assert registry.load(env.layout).targets == []


# ---- audit / secrecy ------------------------------------------------------------------------
def test_audit_log_has_no_contents_and_records_actor(env):
    d = env.mkdir("x")
    (d / "secret.txt").write_text(MARKER)
    add(env, d)
    remove(env, d)
    with pytest.raises(ProtectError):
        remove(env, d)
    recs = audit.read_admin_log(env.ctx)
    assert [(r["op"], r["outcome"]) for r in recs] == [("add", "success"), ("remove", "success"),
                                                      ("remove", "failure")]
    assert recs[-1]["reason_code"] == "NOT_PROTECTED" and recs[0]["actor_uid"] == os.getuid()
    blob = "".join(p.read_text(errors="replace") for p in env.tmp.rglob("*")
                   if p.is_file() and not p.is_relative_to(env.data))
    assert blob and MARKER not in blob     # non-empty: we really scanned logs, registry, snapshots, journals


def test_audit_drops_unlisted_fields(env):
    audit.log_admin(env.ctx, "x", "success", secret_content="hunter2", reason="fine")
    rec = audit.read_admin_log(env.ctx)[0]
    assert "secret_content" not in rec and rec["reason"] == "fine"
