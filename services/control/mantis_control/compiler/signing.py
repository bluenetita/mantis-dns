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

"""Ed25519 signing for policy bundles.

CROSS-LANGUAGE CONTRACT: signature is computed over the serialized Bundle
message with the `signature` field cleared first. The Rust side
(services/filter/mantis-bundle/src/lib.rs::verify) does the same before
checking, so both sides must agree on this convention.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

from mantis_control.gen import bundle_pb2


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def sign_bundle(bundle: bundle_pb2.Bundle, private_key: Ed25519PrivateKey, key_id: str) -> bytes:
    """Clears signature, serializes, signs, sets signature, returns final serialized bytes."""
    bundle.signature = b""
    bundle.signer_key_id = key_id
    payload = bundle.SerializeToString()
    signature = private_key.sign(payload)
    bundle.signature = signature
    return bytes(bundle.SerializeToString())


def public_key_raw_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
