import os
from pathlib import Path

import pytest

from protect_folder import mounts as mnt
from protect_folder import paths
from protect_folder.errors import ProtectError


def resolve(env, arg, **kw):
    kw.setdefault("homes", set())
    return paths.resolve_target(arg, env.layout, **kw)


@pytest.mark.parametrize("name", ["plain", "with space", "Ünïcødé 日本語", "-leading-dash",
                                  "glob*[x]?name", "[WIP] project", "semi;colon $(x) `y`"])
def test_awkward_names_resolve_exactly(env, name):
    d = env.mkdir(name)
    r = resolve(env, str(d))
    try:
        assert r.canonical_path == str(d)
        assert os.fstat(r.fd).st_ino == d.stat().st_ino
    finally:
        r.close()


def test_relative_and_leading_dash_relative(env):
    d = env.mkdir("-dash")
    r = resolve(env, "-dash", cwd=str(env.data))
    assert r.canonical_path == str(d)
    r.close()


def test_missing_and_dangling(env):
    with pytest.raises(ProtectError) as e:
        resolve(env, str(env.data / "nope"))
    assert e.value.code == "PATH_NOT_FOUND"
    (env.data / "dangling").symlink_to(env.data / "gone")
    with pytest.raises(ProtectError) as e:
        resolve(env, str(env.data / "dangling"))
    assert e.value.code == "PATH_NOT_FOUND"


def test_file_is_not_a_directory(env):
    f = env.data / "f.txt"
    f.write_text("x")
    with pytest.raises(ProtectError) as e:
        resolve(env, str(f))
    assert e.value.code == "NOT_A_DIRECTORY"


def test_symlink_alias_refused_unless_flag(env):
    real = env.mkdir("real dir")
    link = env.data / "alias"
    link.symlink_to(real)
    with pytest.raises(ProtectError) as e:
        resolve(env, str(link))
    assert e.value.code == "SYMLINK_TARGET" and e.value.details["resolves_to"] == str(real)
    r = resolve(env, str(link), follow_symlinks=True)
    assert r.canonical_path == str(real) and r.input_path == str(link) and r.warnings
    r.close()


def test_symlink_in_middle_of_path(env):
    real = env.mkdir("real", "sub")
    (env.data / "via").symlink_to(env.data / "real")
    with pytest.raises(ProtectError) as e:
        resolve(env, str(env.data / "via" / "sub"))
    assert e.value.code == "SYMLINK_TARGET"


def test_dotdot_spelling_resolves_to_same_object(env):
    d = env.mkdir("a", "b")
    r = resolve(env, str(env.data / "a" / "b" / ".." / "b"))
    assert r.canonical_path == str(d)
    r.close()


@pytest.mark.parametrize("p", ["/", "/etc", "/etc/ssl", "/usr/lib", "/proc", "/home", "/mnt", "/media",
                               "/var", "/tmp", "/dev/shm", "/root", "/boot"])
def test_forbidden_system_paths(env, p):
    if not os.path.isdir(p):
        pytest.skip(f"{p} absent")
    with pytest.raises(ProtectError) as e:
        resolve(env, p)
    assert e.value.code == "FORBIDDEN_PATH"


def test_entire_home_and_ancestor_of_home_forbidden(env):
    home = env.mkdir("users", "bob")
    with pytest.raises(ProtectError) as e:
        resolve(env, str(home), homes={str(home)})
    assert e.value.code == "FORBIDDEN_PATH"
    with pytest.raises(ProtectError) as e:
        resolve(env, str(home.parent), homes={str(home)})
    assert e.value.code == "FORBIDDEN_PATH"
    sub = home / "secrets"
    sub.mkdir()
    r = resolve(env, str(sub), homes={str(home)})
    r.close()


def test_trusted_paths_overlap_forbidden(env):
    env.layout.etc_dir.mkdir(parents=True)
    for p in (env.layout.etc_dir, env.layout.etc_dir / "generated", env.layout.etc_dir.parent):
        (p).mkdir(exist_ok=True)
        with pytest.raises(ProtectError) as e:
            resolve(env, str(p))
        assert e.value.code == "OVERLAPS_TRUSTED", p


def test_nested_targets_are_allowed_but_warned_about_in_both_directions(env):
    outer = env.mkdir("outer")
    inner = env.mkdir("outer", "inner")
    r = resolve(env, str(inner), existing_paths=[str(outer)])
    assert any("inside already-protected" in w and "cannot be disabled for this child" in w for w in r.warnings)
    r.close()
    r = resolve(env, str(outer), existing_paths=[str(inner)])
    assert any("is inside" in w and "will also apply" in w for w in r.warnings)
    r.close()
    r = resolve(env, str(env.mkdir("outer2")), existing_paths=[str(outer)])  # sibling with shared prefix
    assert not any("inside" in w for w in r.warnings)
    r.close()


def test_mount_point_itself_rejected(env):
    d = env.mkdir("mnt")
    fake = [mnt.MountEntry(1, 0, 8, 1, "/", str(d), "rw", "ext4", "/dev/x")]
    with pytest.raises(ProtectError) as e:
        resolve(env, str(d), mounts=fake)
    assert e.value.code == "FORBIDDEN_PATH"


def test_nested_mount_and_alias_warnings(env):
    d = env.mkdir("disk", "data")
    st = d.stat()
    outer = mnt.MountEntry(1, 0, os.major(st.st_dev), os.minor(st.st_dev), "/", str(env.data / "disk"), "rw", "ext4", "/dev/x")
    alias = mnt.MountEntry(2, 0, os.major(st.st_dev), os.minor(st.st_dev), "/", "/elsewhere", "rw", "ext4", "/dev/x")
    inner = mnt.MountEntry(3, 1, 9, 9, "/", str(d / "sub"), "rw", "tmpfs", "tmpfs")
    r = resolve(env, str(d), mounts=[outer, alias, inner])
    text = " | ".join(r.warnings)
    assert "mount points exist below" in text and "/elsewhere" in text
    r.close()


def test_mountinfo_parser_handles_escapes():
    line = "36 35 98:0 /sub /mnt/my\\040disk rw,noatime shared:1 - ext4 /dev/sdb1 rw"
    (m,) = mnt.parse_mountinfo(line)
    assert m.mount_point == "/mnt/my disk" and m.root == "/sub" and m.fstype == "ext4"
    assert m.dev == os.makedev(98, 0)


@pytest.mark.parametrize("fs", ["vfat", "exfat", "ntfs", "ntfs3", "fuseblk", "fuse.sshfs", "nfs4", "cifs", "weirdfs"])
def test_unsupported_filesystems(fs):
    with pytest.raises(ProtectError) as e:
        mnt.require_posix_filesystem(fs)
    assert e.value.code == "UNSUPPORTED_FILESYSTEM"


@pytest.mark.parametrize("fs", ["ext4", "xfs", "btrfs"])
def test_supported_filesystems(fs):
    mnt.require_posix_filesystem(fs)


# ---- identity ------------------------------------------------------------------------------
def ident(path: Path, **over):
    st = path.stat()
    args = dict(canonical=str(path), st_dev=st.st_dev, st_ino=st.st_ino, mount_point="/", fs_type=None,
                mount_source=None, uuid=None)
    args.update(over)
    return paths.check_identity(**args)


def test_identity_ok(env):
    d = env.mkdir("x")
    assert ident(d).status == "OK"


def test_identity_replaced_directory_same_path(env):
    d = env.mkdir("victim")
    st = d.stat()
    d.rmdir()
    d.mkdir()    # new inode at the same string path (inode may be reused; force a distinct value)
    res = ident(d, st_ino=st.st_ino + 12345)
    assert res.status == "MISMATCH" and res.reason == "IDENTITY_MISMATCH"


def test_identity_renamed_is_missing(env):
    d = env.mkdir("before")
    st = d.stat()
    d.rename(env.data / "after")
    res = paths.check_identity(str(d), st.st_dev, st.st_ino, "/", None, None, None)
    assert res.status == "MISSING" and res.reason == "STALE"


def test_identity_symlink_swapped_in(env):
    d = env.mkdir("t")
    other = env.mkdir("other")
    st = d.stat()
    d.rmdir()
    d.symlink_to(other)
    res = paths.check_identity(str(d), st.st_dev, st.st_ino, "/", None, None, None)
    assert res.status == "MISMATCH"


def test_identity_ancestor_symlink_swapped_in(env):
    d = env.mkdir("parent", "child")
    st = d.stat()
    os.rename(env.data / "parent", env.data / "parent.real")
    (env.data / "parent").symlink_to(env.data / "parent.real")
    res = paths.check_identity(str(d), st.st_dev, st.st_ino, "/", None, None, None)
    assert res.status == "MISMATCH"       # same inode reachable, but the path now goes through a symlink


def test_identity_mount_missing(env):
    d = env.mkdir("gone")
    st = d.stat()
    d.rmdir()
    res = paths.check_identity(str(d), st.st_dev, st.st_ino, "/media/removable", "ext4", "/dev/sdz1", None,
                               mounts=[])
    assert res.status == "MOUNT_MISSING" and res.reason == "MOUNT_MISSING"


def test_identity_device_changed_without_uuid_fails(env):
    d = env.mkdir("dev")
    st = d.stat()
    res = paths.check_identity(str(d), st.st_dev + 1, st.st_ino, "/", None, None, None)
    assert res.status == "MISMATCH"


def test_identity_mount_point_or_fstype_change_detected(env):
    d = env.mkdir("m")
    st = d.stat()
    table = mnt.read_mounts()
    cur = mnt.mount_for(str(d), st.st_dev, table)
    assert paths.check_identity(str(d), st.st_dev, st.st_ino, "/some/other", None, None, None).status == "MISMATCH"
    assert paths.check_identity(str(d), st.st_dev, st.st_ino, cur.mount_point, "vfat", None, None).status == "MISMATCH"


def test_open_nofollow_rejects_symlink_component(env):
    real = env.mkdir("r")
    (env.data / "l").symlink_to(real)
    with pytest.raises(ProtectError):
        paths.open_dir_nofollow(str(env.data / "l"))
