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

from pathlib import Path

import pytest

from mantis_control import config


def _set_all_secrets_strong(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config.settings, "MANTIS_JWT_SECRET", "x" * 32)
    monkeypatch.setattr(config.settings, "MANTIS_WEBHOOK_SECRET_KEY", "some-strong-key")
    monkeypatch.setattr(config.settings, "MANTIS_INTERNAL_TOKEN", "some-strong-token")
    monkeypatch.setattr(config.settings, "MANTIS_SERVICE_TOKEN", "some-strong-service-token")
    monkeypatch.setattr(config.settings, "ADMIN_PASSWORD", "some-strong-password")
    monkeypatch.setattr(config.settings, "MANTIS_SIGNING_KEY_PATH", Path.cwd() / "signing_key.bin")


def test_non_production_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config.settings, "MANTIS_ENV", "")
    config._check_production_secrets()  # all dev defaults, but not production


def test_production_with_all_dev_defaults_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config.settings, "MANTIS_ENV", "production")
    with pytest.raises(RuntimeError) as exc_info:
        config._check_production_secrets()
    message = str(exc_info.value)
    assert "MANTIS_JWT_SECRET" in message
    assert "MANTIS_WEBHOOK_SECRET_KEY" in message
    assert "MANTIS_INTERNAL_TOKEN" in message
    assert "MANTIS_SERVICE_TOKEN" in message
    assert "ADMIN_PASSWORD" in message
    assert "MANTIS_SIGNING_KEY_PATH" in message


def test_production_with_all_strong_secrets_does_not_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config.settings, "MANTIS_ENV", "production")
    _set_all_secrets_strong(monkeypatch)
    config._check_production_secrets()


def test_production_with_short_jwt_secret_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config.settings, "MANTIS_ENV", "production")
    _set_all_secrets_strong(monkeypatch)
    monkeypatch.setattr(config.settings, "MANTIS_JWT_SECRET", "too-short")

    with pytest.raises(RuntimeError, match="MANTIS_JWT_SECRET is too short"):
        config._check_production_secrets()


@pytest.mark.parametrize(
    "attr,value",
    [
        ("MANTIS_WEBHOOK_SECRET_KEY", ""),
        ("MANTIS_SERVICE_TOKEN", ""),
        ("MANTIS_INTERNAL_TOKEN", config.INTERNAL_TOKEN_DEV_DEFAULT),
        ("ADMIN_PASSWORD", config.ADMIN_PASSWORD_DEV_DEFAULT),
        ("MANTIS_SIGNING_KEY_PATH", Path("signing_key.bin")),
    ],
)
def test_production_rejects_each_insecure_default_individually(
    monkeypatch: pytest.MonkeyPatch, attr: str, value: str
) -> None:
    monkeypatch.setattr(config.settings, "MANTIS_ENV", "production")
    _set_all_secrets_strong(monkeypatch)
    monkeypatch.setattr(config.settings, attr, value)

    with pytest.raises(RuntimeError, match=attr):
        config._check_production_secrets()


def test_production_rejects_relative_signing_key_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """A relative MANTIS_SIGNING_KEY_PATH resolves against the process's cwd —
    a reinstall/redeploy that changes the working directory silently
    regenerates the signing key, which every already-running filter node's
    cached public key then fails to verify against (they only fetch it once
    at startup) until someone notices bundles are being rejected and manually
    restarts each one."""
    monkeypatch.setattr(config.settings, "MANTIS_ENV", "production")
    _set_all_secrets_strong(monkeypatch)
    monkeypatch.setattr(config.settings, "MANTIS_SIGNING_KEY_PATH", Path("relative/signing_key.bin"))

    with pytest.raises(RuntimeError, match="MANTIS_SIGNING_KEY_PATH"):
        config._check_production_secrets()


def test_production_accepts_absolute_signing_key_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config.settings, "MANTIS_ENV", "production")
    _set_all_secrets_strong(monkeypatch)
    monkeypatch.setattr(config.settings, "MANTIS_SIGNING_KEY_PATH", Path.cwd() / "signing_key.bin")

    config._check_production_secrets()
