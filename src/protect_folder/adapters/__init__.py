"""Adapter registry and command detection."""

from __future__ import annotations

from .base import Adapter
from .generic import GenericAdapter


def all_adapters() -> list[Adapter]:
    adapters: list[Adapter] = []
    try:
        from .claude import ClaudeAdapter
        adapters.append(ClaudeAdapter())
    except ImportError:
        pass
    try:
        from .opencode import OpenCodeAdapter
        adapters.append(OpenCodeAdapter())
    except ImportError:
        pass
    try:
        from .codex import CodexAdapter
        adapters.append(CodexAdapter())
    except ImportError:
        pass
    return adapters


def detect(argv0: str) -> Adapter:
    for a in all_adapters():
        if a.matches(argv0):
            return a
    return GenericAdapter()


def by_name(name: str) -> Adapter:
    for a in [*all_adapters(), GenericAdapter()]:
        if a.name == name:
            return a
    raise KeyError(name)
