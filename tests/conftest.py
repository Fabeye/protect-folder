from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from fakes import FakeHostOps  # noqa: E402
from protect_folder.constants import Layout  # noqa: E402
from protect_folder.context import Context  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


class Env:
    def __init__(self, tmp: Path, runtime_dir: Path | None = None):
        self.tmp = tmp
        self.layout = Layout(
            bin_path=tmp / "sys" / "bin" / "protect-folder", lib_dir=tmp / "sys" / "lib",
            etc_dir=tmp / "sys" / "etc", state_dir=tmp / "sys" / "var", log_dir=tmp / "sys" / "log",
            trusted_uid=os.getuid(), trusted_gid=os.getgid(), runtime_override=runtime_dir)
        self.host = FakeHostOps()
        self.is_root = True
        self.confirm_answer = False
        self.ctx = Context(layout=self.layout, host=self.host, euid=lambda: 0 if self.is_root else os.getuid(),
                           confirm=lambda prompt: self.confirm_answer, homes=set(),
                           now=lambda: "2026-01-01T00:00:00Z", check_installed_code=False)
        self.data = tmp / "data"
        self.data.mkdir()

    def install(self) -> None:
        from protect_folder.layout_setup import initialize_state
        initialize_state(self.ctx)

    def mkdir(self, *parts: str) -> Path:
        p = self.data.joinpath(*parts)
        p.mkdir(parents=True, exist_ok=True)
        return p


@pytest.fixture(autouse=True)
def _hermetic_user_state(tmp_path, monkeypatch):
    """No test may read or write the real per-user state (verify cache, hook log, session records)."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg-state"))


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return Env(tmp_path)


@pytest.fixture(scope="session")
def srt_runtime_dir(tmp_path_factory) -> Path:
    """One real vendored runtime (node + srt) for the whole session, built by the production code."""
    from protect_folder import install as inst
    try:
        node, pkg = inst.find_node_and_srt()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"SKIPPED: node/srt not available: {exc}")
    base = tmp_path_factory.mktemp("rt")
    lo = Layout(lib_dir=base / "lib", trusted_uid=os.getuid(), trusted_gid=os.getgid())
    ctx = Context(layout=lo, host=FakeHostOps(), euid=lambda: 0)
    (base / "lib").mkdir(mode=0o755)
    os.chmod(base / "lib", 0o755)
    inst.vendor_runtime(ctx, node, pkg)
    return lo.runtime_dir


@pytest.fixture
def senv(tmp_path: Path, srt_runtime_dir: Path) -> Env:
    """Env wired to the real SRT runtime; skips (visibly) if the sandbox cannot run here."""
    import shutil, subprocess
    if not (shutil.which("bwrap") and shutil.which("socat") and shutil.which("rg")):
        pytest.skip("SKIPPED: bubblewrap/socat/ripgrep missing")
    e = Env(tmp_path, srt_runtime_dir)
    return e


def pytest_collection_modifyitems(config, items):
    run_priv = os.environ.get("PF_PRIVILEGED_TESTS") == "1" and os.geteuid() == 0
    for item in items:
        if "live_agent" in item.keywords and os.environ.get("PF_LIVE_AGENT_TESTS") != "1":
            item.add_marker(pytest.mark.skip(
                reason="SKIPPED: live agent test (uses model quota; set PF_LIVE_AGENT_TESTS=1)"))
        if "privileged" in item.keywords and not run_priv:
            item.add_marker(pytest.mark.skip(
                reason="SKIPPED: privileged test (needs root and PF_PRIVILEGED_TESTS=1)"))
