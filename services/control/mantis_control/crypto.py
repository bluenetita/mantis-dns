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

"""Symmetric encryption for secrets stored at rest (webhook signing secrets).

No Vault/KMS yet (design.md §9 lists that as the target) — this is the same
pragmatic stopgap as `auth.py`'s dev JWT secret: a deterministic key derived
from an env var (or an insecure documented default) rather than leaving
secrets in plaintext in Postgres. Set MANTIS_WEBHOOK_SECRET_KEY before any
non-dev deployment.
"""

from __future__ import annotations

import base64
import hashlib
from functools import lru_cache

from cryptography.fernet import Fernet

from mantis_control.config import WEBHOOK_DEV_KEY_MATERIAL, settings


@lru_cache(maxsize=1)
def _fernet() -> Fernet:
    # Fernet requires exactly 32 url-safe-base64 bytes — every generator of
    # MANTIS_WEBHOOK_SECRET_KEY (bootstrap.sh/.ps1, lxc installers,
    # cloud-init) emits `openssl rand -hex 32`, i.e. 64 hex chars / 32 raw
    # bytes that aren't base64 at all. Passing that straight to Fernet() used
    # to raise ValueError on first use in every real deployment. Hash
    # whatever string is configured down to a valid key instead, exactly
    # like the dev-default derivation below — accepts any input material of
    # any length/encoding.
    raw = settings.MANTIS_WEBHOOK_SECRET_KEY or WEBHOOK_DEV_KEY_MATERIAL
    key = base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest())
    return Fernet(key)


def encrypt_secret(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    return _fernet().decrypt(ciphertext.encode()).decode()
