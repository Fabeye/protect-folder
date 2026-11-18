"""Adapter interface: what a given agent supports, and how to launch it."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Layer status vocabulary (spec section 13)
PASS, FAIL, UNVERIFIED, UNSUPPORTED, STALE, NOT_APPLICABLE, DISABLED = (
    "PASS", "FAIL", "UNVERIFIED", "UNSUPPORTED", "STALE", "NOT_APPLICABLE", "DISABLED")
LAYER_KEYS = ("native_permissions", "pre_execution_hook", "srt", "linux_permissions")


@dataclass
class Prepared:
    """Result of an adapter preparing one protected launch."""
    argv: list[str]
    env: dict[str, str]
    extra_write: list[str] = field(default_factory=list)
    layers: dict[str, str] = field(default_factory=dict)       # L1/L2 status as far as known at launch
    warnings: list[str] = field(default_factory=list)
    cleanup: list[str] = field(default_factory=list)           # temp files to delete afterwards


class Adapter:
    name = "generic"
    default_profile = "offline"
    description = "any executable (no native permissions/hooks)"
    # command basenames this adapter recognises
    commands: tuple[str, ...] = ()

    def matches(self, argv0: str) -> bool:
        return os.path.basename(argv0) in self.commands

    def agent_version(self, env: Any = None) -> str | None:
        """Installed version of the agent (used to expire cached L1/L2 verification). None = unknown."""
        return None

    def state_dirs(self, home: str) -> list[str]:
        """Directories the agent legitimately needs to write (created lazily by the agent)."""
        return []

    def capabilities(self, ctx: Any) -> dict[str, str]:
        """Static capability declaration (what *can* be provided), not a verification result."""
        return {"native_permissions": NOT_APPLICABLE, "pre_execution_hook": NOT_APPLICABLE}

    def prepare(self, ctx: Any, argv: list[str], env: dict[str, str], workspace: str,
                targets: list[Any], policy: dict[str, Any]) -> Prepared:
        """`targets` are ALL registered targets; an adapter must only generate policy for the targets
        that enable the corresponding layer (t.layers[...]) and report DISABLED when none do."""
        return Prepared(argv=list(argv), env=dict(env),
                        layers={"native_permissions": NOT_APPLICABLE, "pre_execution_hook": NOT_APPLICABLE})

    def sandbox_check(self, ctx: Any, rt: Any, settings_path: str, prepared: "Prepared", workspace: str,
                      targets: list[Any]) -> None:
        """Called after the sandbox is known to work and before launch. Raise ProtectError to refuse
        (used to prove that an enabled layer really initialised, e.g. a plugin actually loaded)."""

    def cached_layers(self, ctx: Any, targets: list[Any], env: dict[str, str]) -> dict[str, str]:
        """L1/L2 are PASS at launch only if the last live verify for this exact policy revision AND the
        installed agent version passed; otherwise UNVERIFIED/STALE. Never assumed. DISABLED when no
        directory enables the layer."""
        from ..registry import Registry
        from ..verify import cache
        try:
            rev = Registry(targets=list(targets)).policy_revision
        except Exception:                                    # noqa: BLE001
            rev = ""
        got = cache.lookup(self.name, rev, self.agent_version(env)) or {}
        out = {"native_permissions": got.get("native_permissions", UNVERIFIED),
               "pre_execution_hook": got.get("pre_execution_hook", UNVERIFIED)}
        if targets and not any(t.layers["agent_permissions"] for t in targets):
            out["native_permissions"] = DISABLED
        if targets and not any(t.layers["pre_execution_hook"] for t in targets):
            out["pre_execution_hook"] = DISABLED
        return out

    def preflight_extra(self, ctx: Any, argv: list[str], env: dict[str, str]) -> list[str]:
        """Adapter-specific refusals/warnings (e.g. detached servers). Raise ProtectError to refuse."""
        return []
