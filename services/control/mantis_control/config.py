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
defaults in each consumer module. `main.py`'s production-secret check
compares live values against the same dev-default constants, so the two
can't drift out of sync.
"""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# Dev-only defaults. Never used when MANTIS_ENV=production (main.py's
# _check_production_secrets refuses to boot if any of these are still active).
JWT_DEV_SECRET = "dev-insecure-secret-change-me"
WEBHOOK_DEV_KEY_MATERIAL = "dev-insecure-webhook-key-change-me"
INTERNAL_TOKEN_DEV_DEFAULT = "dev-insecure-internal-token"
ADMIN_PASSWORD_DEV_DEFAULT = "change-me-now"


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

    DATABASE_URL: str = "postgresql+psycopg://mantis:mantis@localhost:5432/mantis"
    CORS_ALLOW_ORIGINS: str = "http://localhost:5173"

    ADMIN_EMAIL: str = "admin@mantis.local"
    ADMIN_PASSWORD: str = ADMIN_PASSWORD_DEV_DEFAULT

    DHCP_LEASE_SYNC_INTERVAL_S: int = 60

    @property
    def is_production(self) -> bool:
        return self.MANTIS_ENV.lower() == "production"

    @property
    def cors_origins(self) -> list[str]:
        return self.CORS_ALLOW_ORIGINS.split(",")

    @property
    def trusted_proxy_ips(self) -> set[str]:
        return {ip.strip() for ip in self.MANTIS_TRUSTED_PROXY_IPS.split(",") if ip.strip()}


settings = Settings()

# Sprint 2/5: local disk. Swap for S3 + etcd per design.md §5.2 without
# touching callers — see build_policy_bundle.store_bundle.
BUNDLE_STORAGE_DIR = Path("bundles")
FEED_STORAGE_DIR = Path("feed_domains")
