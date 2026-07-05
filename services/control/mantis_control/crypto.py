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

from cryptography.fernet import Fernet

from mantis_control.config import WEBHOOK_DEV_KEY_MATERIAL, settings


def _fernet() -> Fernet:
    raw = settings.MANTIS_WEBHOOK_SECRET_KEY
    if raw:
        key = raw.encode()
    else:
        # Deterministic (not random) so restarts can still decrypt existing
        # secrets without MANTIS_WEBHOOK_SECRET_KEY set — dev convenience only.
        key = base64.urlsafe_b64encode(hashlib.sha256(WEBHOOK_DEV_KEY_MATERIAL.encode()).digest())
    return Fernet(key)


def encrypt_secret(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    return _fernet().decrypt(ciphertext.encode()).decode()
