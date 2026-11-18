"""Scale and latency bounds with 500 protected directories. Generous limits (they catch accidental quadratic
behaviour, not micro-regressions). Temporary fixtures only."""

import time

import pytest

from protect_folder import registry, render
from protect_folder.adapters.claude_verify import run_hook
from protect_folder.policy import srt as srt_policy
from protect_folder.registry import Registry, Target, target_id

N = 500


def mk(i):
    p = f"/data/disk{i % 7}/project {i:04d}/Ünï [x]"
    return Target(id=target_id(1, i, p), input_path=p, canonical_path=p, st_dev=1 + i % 7, st_ino=i,
                  filesystem_type="ext4", mount_point=f"/data/disk{i % 7}", created_at="2026-01-01T00:00:00Z")


def timed(fn, *a, **k):
    t0 = time.perf_counter()
    out = fn(*a, **k)
    return out, time.perf_counter() - t0


@pytest.fixture
def big(env):
    env.install()
    reg = Registry([mk(i) for i in range(N)], revision=1)
    registry.save(env.layout, reg)
    return env, reg


def test_registry_roundtrip_with_500_targets(big):
    env, reg = big
    loaded, dt = timed(registry.load, env.layout)
    assert len(loaded.targets) == N and loaded.policy_revision == reg.policy_revision
    assert dt < 2.0, dt
    (_, dt2) = timed(loaded.to_bytes)
    assert dt2 < 1.0, dt2


def test_policy_compilation_with_500_targets(big):
    env, reg = big
    rt = type("RT", (), {"bwrap": "/usr/bin/bwrap", "socat": "/usr/bin/socat", "rg": "/usr/bin/rg"})()
    settings, dt = timed(srt_policy.compile_settings, env.ctx, reg.sorted_targets(), workspace="/work/proj",
                         extra_write=["/tmp"], allowed_domains=[], rt=rt)
    assert len(settings["filesystem"]["denyRead"]) == N and dt < 2.0, dt


def test_hook_latency_with_500_targets_through_the_real_script(big, tmp_path):
    env, reg = big
    proj = tmp_path / "p"
    proj.mkdir()
    ev = lambda cmd: {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": str(proj)}
    rc, dt = timed(run_hook, env.ctx, ev("git status && ls -la"), [])
    assert rc[0] == 0 and dt < 3.0, dt
    # a reference to the LAST target is still found
    rc, dt = timed(run_hook, env.ctx, ev(f"cat '{mk(N - 1).canonical_path}/x'"), [])
    assert rc[0] == 2 and dt < 3.0, dt


def test_list_pipeline_and_table_rendering_with_500_rows(big):
    """The real `list` pipeline: identity checks (all STALE here: the paths do not exist), views, rendering."""
    from protect_folder import status as status_mod
    env, reg = big
    t0 = time.perf_counter()
    l4 = {}
    rows = [status_mod.target_view(env.ctx, reg, t, {}, l4) for t in reg.sorted_targets()]
    lines = render.render_table(rows, cols=100, color=False, homes=[])
    dt = time.perf_counter() - t0
    assert len(rows) == N and len(lines) >= N and dt < 5.0, dt
    narrow = render.render_table(rows, cols=40, color=False, homes=[])
    assert all(render.width(x) <= 40 for x in narrow)


def test_one_megabyte_source_is_bounded_in_time(env, tmp_path):
    from protect_folder.inspect.engine import Inspector, InspectPolicy, ProtectedPath, ScanCache
    pol = InspectPolicy(tuple(ProtectedPath(f"t{i}", mk(i).canonical_path) for i in range(N)), "balanced",
                        1 << 20, 2.0, "r", "/home/u")
    src = tmp_path / "big.py"
    src.write_text("x = 1\n" * (170_000))                   # ~1 MiB of statements
    d, dt = timed(Inspector(pol, ScanCache()).inspect, "Bash", {"command": f"python3 {src}"}, str(tmp_path))
    assert dt < 6.0, dt                                    # 2 s budget + parse overhead; it must not hang
    assert d.verdict in ("ALLOW", "INCOMPLETE_INSPECTION", "DENY")
