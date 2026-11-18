"""Root-owned policy.json: default/custom profiles, inspection mode, environment handling."""

from __future__ import annotations

from typing import Any

from .. import jsonio
from ..constants import Layout
from ..errors import ProtectError
from ..registry import check_trusted_file

DEFAULT_POLICY: dict[str, Any] = {
    "schema_version": 1,
    "inspection_mode": "balanced",          # balanced | strict
    "default_profile": None,                # None = the adapter's own default
    "profiles": {},                         # custom: {"name": {"allowedDomains": [...]}}
    "inspection": {"max_source_bytes": 1048576, "max_seconds": 2.0},
    "env_drop": ["LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "PYTHONPATH", "PYTHONSTARTUP",
                 "PYTHONINSPECT", "NODE_OPTIONS", "NODE_PATH", "BASH_ENV", "ENV", "SUDO_ASKPASS",
                 "SSH_AUTH_SOCK", "DBUS_SESSION_BUS_ADDRESS", "SUDO_COMMAND", "SUDO_USER",
                 "SUDO_UID", "SUDO_GID"],
    "env_keep": [],
    "extra_write_paths": [],                # additional writable dirs (absolute), e.g. a shared cache
}


def load_policy(layout: Layout) -> dict[str, Any]:
    p = layout.policy_file
    if not p.exists():
        return dict(DEFAULT_POLICY)
    check_trusted_file(p, layout.trusted_uid)
    try:
        doc = jsonio.read_json(p)
    except (OSError, ValueError) as exc:
        raise ProtectError("TAMPERED", f"cannot parse {p}: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("schema_version", 1) != 1:
        raise ProtectError("SCHEMA_UNSUPPORTED", f"{p}: unsupported schema")
    merged = dict(DEFAULT_POLICY)
    merged.update(doc)
    if merged["inspection_mode"] not in ("balanced", "strict"):
        raise ProtectError("TAMPERED", "policy.json: inspection_mode must be balanced or strict")
    return merged
