"""The root-owned target registry: schema, validation, migration, deterministic serialisation."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable

from . import jsonio
from .constants import REGISTRY_SCHEMA_VERSION, Layout
from .errors import ProtectError
from . import layers as layers_mod

REQUIRED_FIELDS = ("id", "input_path", "canonical_path", "st_dev", "st_ino", "filesystem_type",
                   "mount_point", "created_at", "status")


def target_id(st_dev: int, st_ino: int, canonical: str) -> str:
    h = hashlib.sha256(f"{st_dev}:{st_ino}:{canonical}".encode("utf-8", "surrogateescape"))
    return h.hexdigest()[:16]


@dataclass
class Target:
    id: str
    input_path: str
    canonical_path: str
    st_dev: int
    st_ino: int
    filesystem_type: str
    mount_point: str
    created_at: str
    status: str = "active"
    mount_source: str = ""
    fs_uuid: str | None = None
    layers: dict[str, bool] = field(default_factory=layers_mod.default_layers)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["layers"] = {k: bool(self.layers[k]) for k in layers_mod.LAYERS}
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Target":
        missing = [k for k in REQUIRED_FIELDS if k not in d]
        if missing:
            raise ProtectError("TAMPERED", f"registry entry is missing fields: {missing}")
        known = {f for f in cls.__dataclass_fields__}
        kw = {k: v for k, v in d.items() if k in known}
        # 'layers' is mandatory from schema 2 on (migration fills it for schema 1): a missing object
        # in a current-schema file is tampering, not "all on".
        kw["layers"] = layers_mod.validate_layers(d.get("layers"))
        t = cls(**kw)
        if not os.path.isabs(t.canonical_path):
            raise ProtectError("TAMPERED", "registry entry has a non-absolute canonical_path")
        if not isinstance(t.st_dev, int) or not isinstance(t.st_ino, int):
            raise ProtectError("TAMPERED", "registry entry has non-integer identity")
        return t


# version -> function upgrading a document from that version to version+1
Migration = Callable[[dict[str, Any]], dict[str, Any]]
MIGRATIONS: dict[int, Migration] = {}


def _migrate_1_to_2(doc: dict[str, Any]) -> dict[str, Any]:
    """Schema 1 had no per-directory layer selection: every target had all four layers."""
    doc = dict(doc)
    doc["targets"] = [dict(t, layers=layers_mod.default_layers()) if isinstance(t, dict) else t
                      for t in doc.get("targets", [])]
    doc.pop("policy_revision", None)        # it hashed the v1 basis; recomputed on load
    return doc


MIGRATIONS[1] = _migrate_1_to_2


def migrate(doc: dict[str, Any]) -> dict[str, Any]:
    version = doc.get("schema_version", 0)
    if not isinstance(version, int) or version > REGISTRY_SCHEMA_VERSION:
        raise ProtectError("SCHEMA_UNSUPPORTED",
                           f"registry schema_version {version!r} is newer than this tool "
                           f"supports ({REGISTRY_SCHEMA_VERSION})",
                           hint="Upgrade protect-folder; it will not guess at newer formats.")
    while version < REGISTRY_SCHEMA_VERSION:
        step = MIGRATIONS.get(version)
        if step is None:
            raise ProtectError("SCHEMA_UNSUPPORTED", f"no migration from schema {version}")
        doc = step(doc)
        version += 1
        doc["schema_version"] = version
    return doc


@dataclass
class Registry:
    targets: list[Target] = field(default_factory=list)
    revision: int = 0

    # ---- queries -------------------------------------------------------------------------
    def sorted_targets(self) -> list[Target]:
        return sorted(self.targets, key=lambda t: t.canonical_path.encode("utf-8", "surrogateescape"))

    def find_identity(self, st_dev: int, st_ino: int) -> Target | None:
        for t in self.targets:
            if t.st_ino == st_ino and t.st_dev == st_dev:
                return t
        return None

    def find_path(self, canonical: str) -> Target | None:
        for t in self.targets:
            if t.canonical_path == canonical:
                return t
        return None

    def find_id(self, tid: str) -> Target | None:
        return next((t for t in self.targets if t.id == tid), None)

    def with_layer(self, layer: str) -> list[Target]:
        """Targets that enable `layer` themselves (inherited coverage needs no entry of its own)."""
        return [t for t in self.sorted_targets() if t.layers[layer]]

    def effective(self, t: Target) -> dict[str, dict[str, Any]]:
        return layers_mod.effective(self.targets, t)

    def paths(self) -> list[str]:
        return [t.canonical_path for t in self.sorted_targets()]

    @property
    def policy_revision(self) -> str:
        basis = [[t.id, t.canonical_path, t.st_dev, t.st_ino, [int(t.layers[k]) for k in layers_mod.LAYERS]]
                 for t in self.sorted_targets()]
        raw = json.dumps(basis, sort_keys=True, ensure_ascii=True).encode("ascii")
        return hashlib.sha256(raw).hexdigest()[:16]

    # ---- mutation ------------------------------------------------------------------------
    def add(self, t: Target) -> None:
        if self.find_id(t.id) or self.find_path(t.canonical_path):
            raise ProtectError("ALREADY_PROTECTED", f"{t.canonical_path!r} is already registered")
        self.targets.append(t)

    def remove(self, tid: str) -> Target:
        t = self.find_id(tid)
        if t is None:
            raise ProtectError("NOT_PROTECTED", f"no registered target with id {tid}")
        self.targets.remove(t)
        return t

    # ---- (de)serialisation -----------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": REGISTRY_SCHEMA_VERSION,
            "revision": self.revision,
            "policy_revision": self.policy_revision,
            "targets": [t.to_dict() for t in self.sorted_targets()],
        }

    def to_bytes(self) -> bytes:
        return jsonio.dumps_stable(self.to_dict())

    @classmethod
    def from_dict(cls, doc: dict[str, Any]) -> "Registry":
        doc = migrate(dict(doc))
        raw = doc.get("targets")
        if not isinstance(raw, list):
            raise ProtectError("TAMPERED", "registry 'targets' is not a list")
        reg = cls([Target.from_dict(d) for d in raw], int(doc.get("revision", 0)))
        ids = [t.id for t in reg.targets]
        paths = [t.canonical_path for t in reg.targets]
        if len(set(ids)) != len(ids) or len(set(paths)) != len(paths):
            raise ProtectError("TAMPERED", "registry contains duplicate targets")
        claimed = doc.get("policy_revision")
        if claimed is not None and claimed != reg.policy_revision:
            raise ProtectError("TAMPERED", "registry policy_revision does not match its contents")
        return reg


def check_trusted_file(path: Path, trusted_uid: int, *, allow_group_read: bool = True) -> None:
    """The file and every ancestor up to / must be owned by the trusted uid (or root) and not
    writable by anyone else. Raises TAMPERED otherwise."""
    try:
        st = os.lstat(path)
    except FileNotFoundError as exc:
        raise ProtectError("NOT_INSTALLED", f"{path} does not exist",
                           hint="Run 'sudo protect-folder install' first.") from exc
    if stat.S_ISLNK(st.st_mode):
        raise ProtectError("TAMPERED", f"{path} is a symbolic link")
    if st.st_uid not in (trusted_uid, 0):
        raise ProtectError("TAMPERED", f"{path} is owned by uid {st.st_uid}, expected {trusted_uid}")
    sticky_dir = stat.S_ISDIR(st.st_mode) and bool(st.st_mode & stat.S_ISVTX)
    if st.st_mode & 0o022 and not sticky_dir:   # e.g. /tmp: root-owned sticky is acceptable
        raise ProtectError("TAMPERED", f"{path} is group/world writable (mode {st.st_mode & 0o7777:o})")


def check_trusted_chain(path: Path, trusted_uid: int, stop_at: Path | None = None) -> None:
    """check_trusted_file for the file and each parent directory below `stop_at` (default: /)."""
    cur = Path(os.path.abspath(path))
    stop = Path(os.path.abspath(stop_at)) if stop_at else Path("/")
    while True:
        check_trusted_file(cur, trusted_uid)
        if cur == stop or cur.parent == cur:
            break
        cur = cur.parent


def load(layout: Layout, *, require_trusted: bool = True) -> Registry:
    """Load the registry. A missing file is an empty registry only if the install dir exists."""
    path = layout.targets_file
    if require_trusted:
        if not layout.etc_dir.exists():
            raise ProtectError("NOT_INSTALLED", f"{layout.etc_dir} does not exist",
                               hint="Run 'sudo protect-folder install' first.")
        check_trusted_file(layout.etc_dir, layout.trusted_uid)
        if path.exists():
            check_trusted_file(path, layout.trusted_uid)
    if not path.exists():
        return Registry()
    try:
        doc = jsonio.read_json(path)
    except (OSError, ValueError) as exc:
        raise ProtectError("TAMPERED", f"cannot parse {path}: {exc}") from exc
    if not isinstance(doc, dict):
        raise ProtectError("TAMPERED", f"{path} is not a JSON object")
    return Registry.from_dict(doc)


def save(layout: Layout, reg: Registry) -> None:
    """Persist, keeping the previous revision as last-known-good."""
    if layout.targets_file.exists():
        try:
            prev = layout.targets_file.read_bytes()
            jsonio.atomic_write(layout.targets_prev_file, prev, 0o644, layout.trusted_uid, layout.trusted_gid)
        except OSError:
            pass
    jsonio.atomic_write(layout.targets_file, reg.to_bytes(), 0o644, layout.trusted_uid, layout.trusted_gid)


def generated_srt_targets(reg: Registry) -> dict[str, Any]:
    """Generated artifact: literal-path deny entries (SRT 'literal' syntax) for every target that enables
    the sandbox_runtime layer (a protected ancestor's entry already covers its descendants).
    The launcher recompiles from targets.json and compares against this file to detect tampering."""
    entries = [{"path": t.canonical_path, "literal": True} for t in reg.with_layer("sandbox_runtime")]
    return {"schema_version": 1, "policy_revision": reg.policy_revision,
            "denyRead": entries, "denyWrite": entries}
