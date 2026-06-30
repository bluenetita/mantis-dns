"""Control-plane signing key, persisted to disk so a restart doesn't invalidate
bundles already trusted by filter nodes. Sprint 2: local file. Replace with
Vault/KMS before HA hardening (design.md §9, sprint-plan.md Sprint 9)."""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis_control.compiler.signing import public_key_raw_bytes

KEY_PATH = Path(os.environ.get("AEGIS_SIGNING_KEY_PATH", "signing_key.bin"))
KEY_ID = os.environ.get("AEGIS_SIGNING_KEY_ID", "control-key-1")


def load_or_create_signing_key() -> Ed25519PrivateKey:
    if KEY_PATH.exists():
        return Ed25519PrivateKey.from_private_bytes(KEY_PATH.read_bytes())

    key = Ed25519PrivateKey.generate()
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    KEY_PATH.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return key


def public_key_bytes_for(key: Ed25519PrivateKey) -> bytes:
    return public_key_raw_bytes(key.public_key())
