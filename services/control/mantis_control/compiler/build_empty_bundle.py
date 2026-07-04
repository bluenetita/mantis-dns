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
