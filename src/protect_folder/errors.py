"""Stable machine-readable reason codes and exit codes."""

from __future__ import annotations

# reason_code -> exit code. 0 success, 2 reserved for argparse usage errors.
EXIT_CODES: dict[str, int] = {
    "OK": 0,
    "ERROR": 1,
    "USAGE": 2,
    "NOT_ROOT": 3,
    "IS_ROOT": 4,
    "ALREADY_PROTECTED": 10,
    "NOT_PROTECTED": 11,
    "PATH_NOT_FOUND": 12,
    "NOT_A_DIRECTORY": 13,
    "FORBIDDEN_PATH": 14,
    "OVERLAPS_TRUSTED": 15,
    "NESTED_TARGET": 16,
    "SYMLINK_TARGET": 17,
    "UNSUPPORTED_FILESYSTEM": 18,
    "UNEXPECTED_ACL": 19,
    "IDENTITY_MISMATCH": 20,
    "MOUNT_MISSING": 21,
    "STALE": 22,
    "LOCKED": 23,
    "RECOVERY_REQUIRED": 24,
    "TAMPERED": 25,
    "SCHEMA_UNSUPPORTED": 26,
    "APPLY_FAILED": 27,
    "CONFIRMATION_REQUIRED": 28,
    "NOT_INSTALLED": 29,
    "PREFLIGHT_FAILED": 30,
    "SRT_UNAVAILABLE": 31,
    "LAYERS_INSUFFICIENT": 32,
    "NOT_IMPLEMENTED": 33,
    "VERIFY_FAILED": 34,
    "ADAPTER_INVALID": 35,
    "NO_LAYERS_ENABLED": 36,
}


class ProtectError(Exception):
    """An expected, reportable failure carrying a stable reason code."""

    def __init__(self, code: str, message: str, *, details: dict | None = None,
                 hint: str | None = None):
        super().__init__(message)
        if code not in EXIT_CODES:
            raise ValueError(f"unknown reason code {code!r}")
        self.code = code
        self.message = message
        self.details = details or {}
        self.hint = hint

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.code]
