# Copyright (C) 2026 Blue Networks srl <support+github@bluenetworks.it>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Single source of truth for env-derived configuration.

Every setting the control plane reads from the environment is declared once
here instead of scattered `os.environ.get(...)` calls with hand-copied
defaults in each consumer module. `_check_production_secrets` below compares
live values against the same dev-default constants, so the two can't drift
out of sync.
"""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# Dev-only defaults. Never used outside a recognized dev environment
# (_check_production_secrets below refuses to boot if any are still active).
JWT_DEV_SECRET = "dev-insecure-secret-change-me"
WEBHOOK_DEV_KEY_MATERIAL = "dev-insecure-webhook-key-change-me"
INTERNAL_TOKEN_DEV_DEFAULT = "dev-insecure-internal-token"
ADMIN_PASSWORD_DEV_DEFAULT = "change-me-now"

# MANTIS_ENV values that opt OUT of the secure-secrets gate below. Deliberately
# an allow-list rather than checking `MANTIS_ENV == "production"`: the old
# exact-match check meant a typo'd or unrecognized value (e.g. "prod", "prd",
# a stray space) silently landed on the "not production" branch and left dev
# secrets active with zero warning. Anything not explicitly listed here now
# gets the full secure-secrets check — including "staging" and other
# not-quite-production labels, which should be held to the same bar.
_DEV_ENV_VALUES = {"", "development", "dev", "local", "test"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(case_sensitive=True)

    MANTIS_ENV: str = ""

    MANTIS_JWT_SECRET: str = JWT_DEV_SECRET
    # Empty means "derive a deterministic dev key from WEBHOOK_DEV_KEY_MATERIAL"
    # (see crypto.py) — that fallback only makes sense outside production.
    MANTIS_WEBHOOK_SECRET_KEY: str = ""
    MANTIS_SERVICE_TOKEN: str = ""
    MANTIS_INTERNAL_TOKEN: str = INTERNAL_TOKEN_DEV_DEFAULT
    MANTIS_TRUSTED_PROXY_IPS: str = ""
    MANTIS_SIGNING_KEY_PATH: Path = Path("signing_key.bin")
    MANTIS_SIGNING_KEY_ID: str = "control-key-1"

    # Sprint 2/5: local disk. Swap for S3 + etcd per design.md §5.2 without
    # touching callers — see build_policy_bundle.store_bundle.
    BUNDLE_STORAGE_DIR: Path = Path("bundles")
    FEED_STORAGE_DIR: Path = Path("feed_domains")

    DATABASE_URL: str = "postgresql+psycopg://mantis:mantis@localhost:5432/mantis"
    CORS_ALLOW_ORIGINS: str = "http://localhost:5173"

    ADMIN_EMAIL: str = "admin@mantis.local"
    ADMIN_PASSWORD: str = ADMIN_PASSWORD_DEV_DEFAULT

    DHCP_LEASE_SYNC_INTERVAL_S: int = 60

    # query_events has no other bound on growth — every DNS query on every
    # filter node becomes one row forever without this (see retention.py).
    # 90 days is a reasonable default log-retention window; a consuming SIEM
    # (webhook push or the /siem/events pull API) is expected to keep up
    # within it.
    QUERY_EVENT_RETENTION_DAYS: int = 90

    @property
    def is_production(self) -> bool:
        """True for anything other than a recognized dev/test label — see
        _DEV_ENV_VALUES. Named `is_production` because that's the common
        case, but really means "hold this deployment to the secure bar"."""
        return self.MANTIS_ENV.strip().lower() not in _DEV_ENV_VALUES

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.CORS_ALLOW_ORIGINS.split(",") if origin.strip()]

    @property
    def trusted_proxy_ips(self) -> set[str]:
        return {ip.strip() for ip in self.MANTIS_TRUSTED_PROXY_IPS.split(",") if ip.strip()}


settings = Settings()


def _check_production_secrets() -> None:
    """Refuse to start when MANTIS_ENV isn't a recognized dev/test label (see
    _DEV_ENV_VALUES) but dev-default secrets are still in use. Runs at import
    time (below) rather than only from the FastAPI lifespan, so every
    entrypoint that touches mantis_control — the server, alembic, a future
    CLI/worker — gets the same guarantee."""
    if not settings.is_production:
        return
    errors: list[str] = []
    if settings.MANTIS_JWT_SECRET == JWT_DEV_SECRET:
        errors.append("MANTIS_JWT_SECRET is the insecure dev default — set a strong random value")
    elif len(settings.MANTIS_JWT_SECRET) < 32:
        errors.append("MANTIS_JWT_SECRET is too short — minimum 32 characters required")
    if not settings.MANTIS_WEBHOOK_SECRET_KEY:
        errors.append("MANTIS_WEBHOOK_SECRET_KEY is not set")
    if settings.MANTIS_INTERNAL_TOKEN == INTERNAL_TOKEN_DEV_DEFAULT:
        errors.append("MANTIS_INTERNAL_TOKEN is the insecure dev default — set a strong random value")
    if not settings.MANTIS_SERVICE_TOKEN:
        errors.append("MANTIS_SERVICE_TOKEN is not set — filter-node M2M endpoints would be unauthenticated")
    if settings.ADMIN_PASSWORD == ADMIN_PASSWORD_DEV_DEFAULT:
        errors.append("ADMIN_PASSWORD is the insecure dev default — set it before first boot")
    if not settings.MANTIS_SIGNING_KEY_PATH.is_absolute():
        # load_or_create_signing_key() silently generates a brand-new keypair
        # if the file isn't found — a relative path resolves against the
        # process's current working directory, which a reinstall/redeploy
        # can easily change. That regenerates the key with zero warning,
        # invalidating every already-running filter node's cached public key
        # (they only fetch it once at startup) until someone manually
        # restarts them and notices bundles were being silently rejected.
        errors.append(
            f"MANTIS_SIGNING_KEY_PATH ({settings.MANTIS_SIGNING_KEY_PATH}) is a relative path — "
            "set it to a stable absolute path outside the deployment directory"
        )
    for name, path in (
        ("FEED_STORAGE_DIR", settings.FEED_STORAGE_DIR),
        ("BUNDLE_STORAGE_DIR", settings.BUNDLE_STORAGE_DIR),
    ):
        if not path.is_absolute():
            # Same hazard as MANTIS_SIGNING_KEY_PATH above, and just as
            # silent: a relative path resolves against the process's CWD,
            # which install-rocky.sh's `rm -rf $INSTALL_DIR/app` (redeploy)
            # or a plain `docker compose up -d` after a new image (no
            # matching volume) wipes clean. last_domain_count/bundle_version
            # in the DB survive (separate storage), so every feed reads back
            # as "ingested" with zero actual domains — compiled bundles embed
            # near-empty bloom filters and silently stop blocking anything,
            # with no error anywhere.
            errors.append(
                f"{name} ({path}) is a relative path — "
                "set it to a stable absolute path outside the deployment directory"
            )
    if errors:
        raise RuntimeError(
            f"Refusing to start: MANTIS_ENV={settings.MANTIS_ENV!r} is not a recognized "
            "dev/test value but insecure secrets were detected: " + "; ".join(errors)
        )


_check_production_secrets()

BUNDLE_STORAGE_DIR = settings.BUNDLE_STORAGE_DIR
FEED_STORAGE_DIR = settings.FEED_STORAGE_DIR
