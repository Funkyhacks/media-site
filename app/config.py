"""Runtime configuration for the SecWeb backend.

Every secret is read from the environment (12-factor). Tests override these
via :func:`configure` (a simple global override) so the app can run hermetically.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from app import __version__

# ---------------------------------------------------------------------------
# Test hook — a simple module-level override so pytest can point the app at a
# temp dir / fakeredis without touching real env vars.
# ---------------------------------------------------------------------------
_OVERRIDES: dict[str, str] = {}

_DEFAULTS: dict[str, str] = {
    "SECWEB_JWT_SECRET": "dev-insecure-secret-change-me",
    "SECWEB_JWT_TTL_SECONDS": "3600",
    "SECWEB_STORAGE_DIR": "storage",
    "SECWEB_DB_PATH": "storage/secweb.db",
    "SECWEB_REDIS_URL": "redis://localhost:6379/0",
    "SECWEB_DEFAULT_TTL_SECONDS": "300",
}


def configure(**overrides: str | None) -> None:
    """Set config values (used by tests). Pass ``None`` to clear a key."""
    for key, value in overrides.items():
        if value is None:
            _OVERRIDES.pop(key, None)
        else:
            _OVERRIDES[key] = value


def reset_configure() -> None:
    """Clear all test overrides."""
    _OVERRIDES.clear()


def _env(key: str) -> str:
    return _OVERRIDES.get(key) or os.environ.get(key) or _DEFAULTS[key]


@dataclass(frozen=True)
class Settings:
    # --- crypto / auth ---
    jwt_secret: str
    jwt_ttl_seconds: int

    # --- storage ---
    storage_dir: str
    db_path: str

    # --- cache ---
    redis_url: str
    default_ttl_seconds: int

    # --- metadata ---
    version: str = __version__


def get_settings() -> Settings:
    """Build :class:`Settings` from the environment (or the test override)."""
    return Settings(
        jwt_secret=_env("SECWEB_JWT_SECRET"),
        jwt_ttl_seconds=int(_env("SECWEB_JWT_TTL_SECONDS")),
        storage_dir=_env("SECWEB_STORAGE_DIR"),
        db_path=_env("SECWEB_DB_PATH"),
        redis_url=_env("SECWEB_REDIS_URL"),
        default_ttl_seconds=int(_env("SECWEB_DEFAULT_TTL_SECONDS")),
    )
