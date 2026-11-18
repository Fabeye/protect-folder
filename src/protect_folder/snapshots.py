"""Root-only snapshots of original ownership/mode/ACL, keyed by target id."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

from . import jsonio
from .constants import SNAPSHOT_SCHEMA_VERSION, Layout
from .errors import ProtectError


@dataclass
class Snapshot:
    target_id: str
    canonical_path: str
    st_dev: int
    st_ino: int
    mount_point: str
    filesystem_type: str
    uid: int
    gid: int
    mode: int
    acl_text: str
    acl_extended: bool
    taken_at: str
    snapshot_version: int = SNAPSHOT_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Snapshot":
        try:
            return cls(**d)
        except TypeError as exc:
            raise ProtectError("TAMPERED", f"malformed snapshot entry: {exc}") from exc


def load(layout: Layout) -> dict[str, Snapshot]:
    if not layout.snapshots_file.exists():
        return {}
    try:
        doc = jsonio.read_json(layout.snapshots_file)
    except (OSError, ValueError) as exc:
        raise ProtectError("TAMPERED", f"cannot parse {layout.snapshots_file}: {exc}") from exc
    if doc.get("schema_version", 0) > SNAPSHOT_SCHEMA_VERSION:
        raise ProtectError("SCHEMA_UNSUPPORTED", "snapshot file is from a newer protect-folder")
    return {k: Snapshot.from_dict(v) for k, v in doc.get("snapshots", {}).items()}


def encode(snaps: dict[str, Snapshot]) -> bytes:
    return jsonio.dumps_stable({"schema_version": SNAPSHOT_SCHEMA_VERSION,
                                "snapshots": {k: v.to_dict() for k, v in sorted(snaps.items())}})


def save(layout: Layout, snaps: dict[str, Snapshot]) -> None:
    jsonio.atomic_write(layout.snapshots_file, encode(snaps), 0o600, layout.trusted_uid, layout.trusted_gid)
