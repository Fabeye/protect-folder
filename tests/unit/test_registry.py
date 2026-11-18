import json
import os
import random

import pytest

from protect_folder import registry
from protect_folder.errors import ProtectError
from protect_folder.registry import Registry, Target, target_id


def mk(i: int, path: str | None = None) -> Target:
    p = path or f"/data/t{i:04d}"
    return Target(id=target_id(1, i, p), input_path=p, canonical_path=p, st_dev=1, st_ino=i,
                  filesystem_type="ext4", mount_point="/data", created_at="2026-01-01T00:00:00Z")


def test_crud_and_sorting():
    r = Registry()
    for i in (3, 1, 2):
        r.add(mk(i))
    assert r.paths() == ["/data/t0001", "/data/t0002", "/data/t0003"]
    assert r.find_identity(1, 2).canonical_path == "/data/t0002"
    removed = r.remove(mk(2).id)
    assert removed.st_ino == 2 and len(r.targets) == 2
    with pytest.raises(ProtectError) as e:
        r.remove("nope")
    assert e.value.code == "NOT_PROTECTED"


def test_duplicate_rejected():
    r = Registry()
    r.add(mk(1))
    with pytest.raises(ProtectError) as e:
        r.add(mk(1))
    assert e.value.code == "ALREADY_PROTECTED"


def test_round_trip_and_policy_revision():
    r = Registry([mk(i) for i in range(5)], revision=7)
    r2 = Registry.from_dict(json.loads(r.to_bytes()))
    assert r2.to_bytes() == r.to_bytes() and r2.revision == 7
    assert r2.policy_revision == r.policy_revision


def test_tamper_detected_via_policy_revision():
    doc = Registry([mk(1), mk(2)]).to_dict()
    doc["targets"][0]["canonical_path"] = "/data/evil"
    with pytest.raises(ProtectError) as e:
        Registry.from_dict(doc)
    assert e.value.code == "TAMPERED"


def test_duplicates_in_file_are_tampering():
    doc = Registry([mk(1)]).to_dict()
    doc["targets"].append(dict(doc["targets"][0]))
    doc.pop("policy_revision")
    with pytest.raises(ProtectError) as e:
        Registry.from_dict(doc)
    assert e.value.code == "TAMPERED"


def test_missing_field_and_relative_path_rejected():
    doc = Registry([mk(1)]).to_dict()
    del doc["targets"][0]["st_ino"]
    doc.pop("policy_revision")
    with pytest.raises(ProtectError):
        Registry.from_dict(doc)
    doc = Registry([mk(1)]).to_dict()
    doc["targets"][0]["canonical_path"] = "relative/path"
    doc.pop("policy_revision")
    with pytest.raises(ProtectError):
        Registry.from_dict(doc)


def test_newer_schema_refused():
    with pytest.raises(ProtectError) as e:
        Registry.from_dict({"schema_version": 99, "targets": []})
    assert e.value.code == "SCHEMA_UNSUPPORTED"


def test_migration_framework(monkeypatch):
    # Pre-release development format ("version" + bare "paths"): exercises the upgrade chain.
    def v0_to_v1(doc):
        t = [{**mk(i, p).to_dict()} for i, p in enumerate(doc["paths"], 1)]
        return {"revision": doc.get("revision", 0), "targets": t}
    monkeypatch.setitem(registry.MIGRATIONS, 0, v0_to_v1)
    r = Registry.from_dict({"paths": ["/data/a b", "/data/ü"], "revision": 3})
    assert r.paths() == ["/data/a b", "/data/ü"] and r.revision == 3


def test_missing_migration_is_an_error():
    with pytest.raises(ProtectError) as e:
        Registry.from_dict({"targets": []})   # schema 0 and no migration registered
    assert e.value.code == "SCHEMA_UNSUPPORTED"


@pytest.mark.parametrize("n", [1, 10, 100, 500])
def test_deterministic_at_scale(n):
    items = [mk(i) for i in range(n)]
    ref = None
    for seed in range(3):
        shuffled = items[:]
        random.Random(seed).shuffle(shuffled)
        r = Registry(shuffled, revision=1)
        raw = r.to_bytes()
        ref = ref or raw
        assert raw == ref
    assert Registry.from_dict(json.loads(ref)).policy_revision == Registry(items, 1).policy_revision


def test_unicode_and_surrogate_paths_survive_serialisation():
    weird = "/data/" + os.fsdecode(b"bad\xff-\xd0\xb4\xd0\xb0")   # invalid UTF-8 + valid Cyrillic
    r = Registry([mk(1, weird), mk(2, "/data/日本語 dir")])
    back = Registry.from_dict(json.loads(r.to_bytes()))
    assert back.paths() == r.paths()


def test_load_save_and_prev_kept(env):
    env.install()
    r = Registry([mk(1)], 1)
    registry.save(env.layout, r)
    registry.save(env.layout, Registry([mk(1), mk(2)], 2))
    assert registry.load(env.layout).revision == 2
    assert json.loads(env.layout.targets_prev_file.read_text())["revision"] == 1


def test_load_refuses_writable_registry(env):
    env.install()
    registry.save(env.layout, Registry([mk(1)], 1))
    registry.load(env.layout)            # sanity: loads fine before tampering
    os.chmod(env.layout.targets_file, 0o666)
    with pytest.raises(ProtectError) as e:
        registry.load(env.layout)
    assert e.value.code == "TAMPERED" and "targets.json" in e.value.message and "writable" in e.value.message


def test_load_refuses_writable_etc_dir(env):
    env.install()
    registry.save(env.layout, Registry([mk(1)], 1))
    os.chmod(env.layout.etc_dir, 0o777)
    with pytest.raises(ProtectError) as e:
        registry.load(env.layout)
    assert e.value.code == "TAMPERED" and "writable" in e.value.message


def test_load_refuses_symlinked_registry(env, tmp_path):
    env.install()
    other = tmp_path / "other.json"
    other.write_bytes(Registry([mk(9)], 1).to_bytes())
    env.layout.targets_file.unlink()
    env.layout.targets_file.symlink_to(other)
    with pytest.raises(ProtectError) as e:
        registry.load(env.layout)
    assert e.value.code == "TAMPERED" and "symbolic link" in e.value.message


def test_not_installed():
    from protect_folder.constants import Layout
    from pathlib import Path
    with pytest.raises(ProtectError) as e:
        registry.load(Layout(etc_dir=Path("/nonexistent-pf-test/etc")))
    assert e.value.code == "NOT_INSTALLED"
