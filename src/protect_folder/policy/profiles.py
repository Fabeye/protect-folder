"""Network profiles: named allowlists. There is no implicit allow-all and no fallback to one."""

from __future__ import annotations

from typing import Any

from ..errors import ProtectError

# Host lists are verified empirically per agent (see verify); keep them minimal.
BUILTIN_PROFILES: dict[str, dict[str, Any]] = {
    "offline": {"allowedDomains": [], "description": "no network at all"},
    # Each hosted-agent profile below was derived by running the REAL agent inside SRT and watching which hosts
    # the proxy blocked; telemetry/MCP/analytics hosts they also try are intentionally NOT allowed.
    # A token refresh or API-key login may need more hosts: use a custom profile in policy.json.
    "claude": {"allowedDomains": ["api.anthropic.com"], "description": "Claude Code API only"},
    "opencode-cloud": {"allowedDomains": ["opencode.ai"],
                       "description": "OpenCode hosted (opencode/*) models only; other providers need a custom profile"},
    "codex": {"allowedDomains": ["chatgpt.com"],
              "description": "Codex with ChatGPT login only; API-key use (api.openai.com) needs a custom profile"},
    # Host Ollama. SRT's allowlist honours an explicit IP:port literal, but a client inside the sandbox dials
    # the SANDBOX's loopback (and OpenCode ignores the proxy for discovery), so a fixed in-sandbox relay
    # forwards 127.0.0.1:11434 through the proxy to exactly that literal. Verified with a real inference.
    "opencode-local-ollama": {
        "allowedDomains": ["127.0.0.1:11434"],
        "relays": [{"listen": "127.0.0.1:11434", "upstream": "127.0.0.1:11434"}],
        "description": "OpenCode with the host's Ollama on 127.0.0.1:11434 and nothing else"},
}


def validate_domains(name: str, domains: Any) -> list[str]:
    if not isinstance(domains, list) or not all(isinstance(d, str) and d for d in domains):
        raise ProtectError("PREFLIGHT_FAILED", f"network profile {name!r}: allowedDomains must be a list of strings")
    for d in domains:
        bare = d.rsplit(":", 1)[0] if d.count(":") == 1 else d
        if bare in ("*", "*.*", "**", "") or bare.strip("*.") == "":
            raise ProtectError("PREFLIGHT_FAILED",
                               f"network profile {name!r}: refusing allow-all style entry {d!r}",
                               hint="List explicit hosts (and optionally :port).")
    return sorted(set(domains))


def resolve_profile(name: str, policy: dict[str, Any]) -> list[str]:
    custom = policy.get("profiles", {})
    if name in custom:
        return validate_domains(name, custom[name].get("allowedDomains"))
    if name in BUILTIN_PROFILES:
        return validate_domains(name, BUILTIN_PROFILES[name]["allowedDomains"])
    known = sorted(set(BUILTIN_PROFILES) | set(custom))
    raise ProtectError("PREFLIGHT_FAILED", f"unknown network profile {name!r}",
                       hint="known profiles: " + ", ".join(known))


def resolve_relays(name: str, policy: dict[str, Any], domains: list[str]) -> list[tuple[str, str]]:
    """Fixed in-sandbox relays of a profile as (listen, upstream). The upstream must itself be allowlisted
    (so the relay can never reach more than the profile grants) and the listen side must be loopback."""
    custom = policy.get("profiles", {})
    prof = custom.get(name) if name in custom else BUILTIN_PROFILES.get(name, {})
    out: list[tuple[str, str]] = []
    for r in prof.get("relays", []) or []:
        if not isinstance(r, dict) or not isinstance(r.get("listen"), str) or not isinstance(r.get("upstream"), str):
            raise ProtectError("PREFLIGHT_FAILED", f"network profile {name!r}: malformed relay entry")
        host = r["listen"].rpartition(":")[0]
        if host not in ("127.0.0.1", "::1"):
            raise ProtectError("PREFLIGHT_FAILED", f"network profile {name!r}: relays may only listen on loopback")
        if r["upstream"] not in domains:
            raise ProtectError("PREFLIGHT_FAILED",
                               f"network profile {name!r}: relay upstream {r['upstream']!r} is not in allowedDomains")
        out.append((r["listen"], r["upstream"]))
    return out
