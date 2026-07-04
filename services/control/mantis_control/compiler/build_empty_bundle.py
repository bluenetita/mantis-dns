"""Sprint 1 exit-criteria script: emit a signed, empty bundle.

Run: python -m mantis_control.compiler.build_empty_bundle
Produces bundle.bin + bundle_pubkey.bin in the working directory, which the
Rust side loads and verifies (see services/filter/mantis-bundle/examples/verify_bundle.rs).
"""

from __future__ import annotations

import time

from mantis_control.compiler.signing import generate_keypair, sign_bundle, public_key_raw_bytes
from mantis_control.gen import bundle_pb2


def main() -> None:
    private_key, public_key = generate_keypair()

    bundle = bundle_pb2.Bundle(
        tenant_id="tenant-dev",
        group_id="group-default",
        version=1,
        built_at_unix=int(time.time()),
        on_load_failure=bundle_pb2.FAIL_OPEN,
    )

    signed_bytes = sign_bundle(bundle, private_key, key_id="dev-key-1")

    with open("bundle.bin", "wb") as f:
        f.write(signed_bytes)
    with open("bundle_pubkey.bin", "wb") as f:
        f.write(public_key_raw_bytes(public_key))

    print(f"wrote bundle.bin ({len(signed_bytes)} bytes) and bundle_pubkey.bin (32 bytes)")


if __name__ == "__main__":
    main()
