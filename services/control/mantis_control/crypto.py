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
import os

from cryptography.fernet import Fernet

_KEY_ENV = "MANTIS_WEBHOOK_SECRET_KEY"
_DEV_DEFAULT_MATERIAL = b"dev-insecure-webhook-key-change-me"


def _fernet() -> Fernet:
    raw = os.environ.get(_KEY_ENV)
    if raw:
        key = raw.encode()
    else:
        # Deterministic (not random) so restarts can still decrypt existing
        # secrets without MANTIS_WEBHOOK_SECRET_KEY set — dev convenience only.
        key = base64.urlsafe_b64encode(hashlib.sha256(_DEV_DEFAULT_MATERIAL).digest())
    return Fernet(key)


def encrypt_secret(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    return _fernet().decrypt(ciphertext.encode()).decode()
