"""Programs executed *inside* the sandbox to observe what it really enforces."""

from __future__ import annotations

import json
import subprocess
import sys

from ..errors import ProtectError
from ..runtime import Runtime, srt_argv

# Reports the filesystem type mounted at each given path, from /proc/self/mountinfo.
# A denied (masked) path shows up as a tmpfs mount; a real directory would show ext4/xfs/...
MOUNT_PROBE = r'''
import json, re, sys
def unesc(s):
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)
mp = {}
for line in open("/proc/self/mountinfo", "rb").read().decode("utf-8", "surrogateescape").splitlines():
    left, _, right = line.partition(" - ")
    a = left.split(" ")
    mp[unesc(a[4])] = right.split(" ")[0]
print(json.dumps({t: mp.get(t) for t in sys.argv[1:]}))
'''


def run_in_sandbox(rt: Runtime, settings_file: str, command: list[str], *, cwd: str,
                   env: dict[str, str] | None = None, timeout: float = 60.0) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(srt_argv(rt, settings_file, command), cwd=cwd, env=env, capture_output=True,
                              text=True, timeout=timeout, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired as exc:
        raise ProtectError("SRT_UNAVAILABLE", f"sandbox probe timed out after {timeout}s") from exc
    except OSError as exc:
        raise ProtectError("SRT_UNAVAILABLE", f"cannot execute the SRT runtime: {exc}") from exc


def probe_masks(rt: Runtime, settings_file: str, target_paths: list[str], *, cwd: str,
                env: dict[str, str] | None = None) -> dict[str, str | None]:
    """Fail closed unless every target shows up as a tmpfs mask inside the *effective* sandbox."""
    proc = run_in_sandbox(rt, settings_file, [sys.executable, "-I", "-c", MOUNT_PROBE, *target_paths],
                          cwd=cwd, env=env)
    if proc.returncode != 0:
        raise ProtectError("SRT_UNAVAILABLE",
                           "the sandbox failed to start with the effective settings",
                           details={"returncode": proc.returncode,
                                    "stderr": proc.stderr.strip()[-400:]},
                           hint="Run 'protect-folder doctor'. The agent was NOT launched.")
    try:
        seen = json.loads(proc.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError) as exc:
        raise ProtectError("SRT_UNAVAILABLE", "could not read the sandbox probe result") from exc
    unmasked = [t for t in target_paths if seen.get(t) != "tmpfs"]
    if unmasked:
        raise ProtectError("PREFLIGHT_FAILED",
                           "effective sandbox settings do not mask: " + ", ".join(unmasked),
                           details={"observed": seen},
                           hint="The agent was NOT launched (fail closed).")
    return seen
