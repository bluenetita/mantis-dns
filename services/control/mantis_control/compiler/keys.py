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

"""Control-plane signing key, persisted to disk so a restart doesn't invalidate
bundles already trusted by filter nodes. Sprint 2: local file. Replace with
Vault/KMS before HA hardening (design.md §9, sprint-plan.md Sprint 9)."""

from __future__ import annotations

import os
from functools import lru_cache

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mantis_control.compiler.signing import public_key_raw_bytes
from mantis_control.config import settings

KEY_PATH = settings.MANTIS_SIGNING_KEY_PATH
KEY_ID = settings.MANTIS_SIGNING_KEY_ID


@lru_cache(maxsize=1)
def load_or_create_signing_key() -> Ed25519PrivateKey:
    if KEY_PATH.exists():
        return Ed25519PrivateKey.from_private_bytes(KEY_PATH.read_bytes())

    key = Ed25519PrivateKey.generate()
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    raw = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # This key signs every policy bundle every filter node trusts — anyone
    # who can read it can forge bundles. Create the file with 0600 from the
    # moment it exists (os.open + explicit mode), rather than writing it with
    # the process's default umask and chmod-ing afterward, which would leave
    # a window where it's readable at whatever the umask allows.
    fd = os.open(KEY_PATH, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
    return key


def public_key_bytes_for(key: Ed25519PrivateKey) -> bytes:
    return public_key_raw_bytes(key.public_key())
