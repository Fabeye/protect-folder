"""Fixed locations and schema versions. No environment overrides: tests build a Layout."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

VERSION = "1.0.0"
REGISTRY_SCHEMA_VERSION = 2
SNAPSHOT_SCHEMA_VERSION = 1
JSON_SCHEMA_ID = "protect-folder/1"

PROTECTED_UID = 0
PROTECTED_GID = 0
PROTECTED_MODE = 0o700


@dataclass(frozen=True)
class Layout:
    """Where the trusted installation lives. The defaults follow spec section 5."""

    bin_path: Path = Path("/usr/local/bin/protect-folder")
    lib_dir: Path = Path("/usr/local/lib/protect-folder")
    etc_dir: Path = Path("/etc/protect-folder")
    state_dir: Path = Path("/var/lib/protect-folder")
    log_dir: Path = Path("/var/log/protect-folder")
    # Uid that must own every trusted file. 0 in production; tests use their own uid.
    trusted_uid: int = 0
    trusted_gid: int = 0
    # Tests share one vendored runtime across many temp layouts. Never set in production.
    runtime_override: Path | None = None

    @property
    def targets_file(self) -> Path:
        return self.etc_dir / "targets.json"

    @property
    def targets_prev_file(self) -> Path:
        return self.etc_dir / "targets.json.prev"

    @property
    def policy_file(self) -> Path:
        return self.etc_dir / "policy.json"

    @property
    def generated_dir(self) -> Path:
        return self.etc_dir / "generated"

    @property
    def srt_targets_file(self) -> Path:
        return self.generated_dir / "srt-targets.json"

    @property
    def marker_file(self) -> Path:
        """World-readable flag: a transaction is in flight, crashed, or needs recovery."""
        return self.etc_dir / "RECOVERY_REQUIRED"

    @property
    def snapshots_file(self) -> Path:
        return self.state_dir / "snapshots.json"

    @property
    def journal_dir(self) -> Path:
        return self.state_dir / "transactions"

    @property
    def lock_file(self) -> Path:
        return self.state_dir / "lock"

    @property
    def admin_log(self) -> Path:
        return self.log_dir / "admin.log"

    @property
    def runtime_dir(self) -> Path:
        return self.runtime_override or (self.lib_dir / "runtime")

    def trusted_paths(self) -> list[Path]:
        """Paths a protected target may never equal, contain, or live inside."""
        return [self.bin_path, self.lib_dir, self.etc_dir, self.state_dir, self.log_dir]
