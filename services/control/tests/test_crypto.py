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

from mantis_control import crypto


def test_roundtrip_with_hex_secret_from_openssl_rand(monkeypatch):
    """Every installer (bootstrap.sh/.ps1, lxc install*.sh, cloud-init) sets
    MANTIS_WEBHOOK_SECRET_KEY via `openssl rand -hex 32` — 64 hex chars, not
    a 32-byte urlsafe-base64 string. This used to raise ValueError from
    Fernet() on the very first encrypt/decrypt in any real deployment."""
    monkeypatch.setattr(crypto.settings, "MANTIS_WEBHOOK_SECRET_KEY", "a" * 64)
    crypto._fernet.cache_clear()
    try:
        ciphertext = crypto.encrypt_secret("hello world")
        assert crypto.decrypt_secret(ciphertext) == "hello world"
    finally:
        crypto._fernet.cache_clear()


def test_roundtrip_with_empty_secret_uses_dev_default(monkeypatch):
    monkeypatch.setattr(crypto.settings, "MANTIS_WEBHOOK_SECRET_KEY", "")
    crypto._fernet.cache_clear()
    try:
        ciphertext = crypto.encrypt_secret("hello world")
        assert crypto.decrypt_secret(ciphertext) == "hello world"
    finally:
        crypto._fernet.cache_clear()


def test_roundtrip_with_arbitrary_length_secret(monkeypatch):
    monkeypatch.setattr(crypto.settings, "MANTIS_WEBHOOK_SECRET_KEY", "short")
    crypto._fernet.cache_clear()
    try:
        ciphertext = crypto.encrypt_secret("hello world")
        assert crypto.decrypt_secret(ciphertext) == "hello world"
    finally:
        crypto._fernet.cache_clear()
