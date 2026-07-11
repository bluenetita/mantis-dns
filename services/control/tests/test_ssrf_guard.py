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

import pytest

from mantis_control.ssrf_guard import (
    check_host_safe,
    check_probe_target_safe,
    check_url_safe,
    check_webhook_url_safe,
    resolve_pinned_url,
    resolve_pinned_webhook_url,
)


def test_check_url_safe_rejects_non_http_scheme():
    with pytest.raises(ValueError):
        check_url_safe("ftp://example.com/x")


def test_check_url_safe_rejects_private_ip_literal():
    with pytest.raises(ValueError):
        check_url_safe("http://10.0.0.5/x")


def test_check_url_safe_rejects_loopback():
    with pytest.raises(ValueError):
        check_url_safe("http://127.0.0.1/x")


def test_check_url_safe_rejects_link_local_metadata():
    with pytest.raises(ValueError):
        check_url_safe("http://169.254.169.254/latest/meta-data")


def test_check_url_safe_allows_public_ip_literal():
    check_url_safe("https://93.184.216.34/x")  # must not raise


def test_resolve_pinned_url_ip_literal_is_unchanged():
    pinned, host = resolve_pinned_url("https://93.184.216.34:443/path")
    assert pinned == "https://93.184.216.34:443/path"
    assert host == "93.184.216.34"


def test_resolve_pinned_url_rejects_blocked_literal():
    with pytest.raises(ValueError):
        resolve_pinned_url("http://127.0.0.1/x")


def test_check_host_safe_blocks_rfc1918():
    """Unlike check_probe_target_safe, the generic host guard blocks private
    ranges too — this is used for feed fetch targets, not DNS resolver
    addresses or SIEM webhooks (see check_webhook_url_safe)."""
    with pytest.raises(ValueError):
        check_host_safe("10.8.1.1")


def test_check_probe_target_safe_allows_private_resolver():
    """Private upstream DNS resolvers are a legitimate, common config —
    the probe guard must not block RFC-1918/ULA."""
    check_probe_target_safe("10.8.1.1")  # must not raise
    check_probe_target_safe("192.168.1.1")  # must not raise


def test_check_probe_target_safe_blocks_loopback():
    with pytest.raises(ValueError):
        check_probe_target_safe("127.0.0.1")


def test_check_probe_target_safe_blocks_metadata():
    with pytest.raises(ValueError):
        check_probe_target_safe("169.254.169.254")


def test_check_webhook_url_safe_allows_private_target():
    """Self-hosted SIEMs (e.g. Wazuh) are commonly reachable only on a
    private/RFC-1918 address — the webhook guard must not block that."""
    check_webhook_url_safe("https://10.8.1.20:9200/mantis-events")  # must not raise
    check_webhook_url_safe("http://192.168.1.5:8080/hook")  # must not raise


def test_check_webhook_url_safe_blocks_loopback():
    with pytest.raises(ValueError):
        check_webhook_url_safe("http://127.0.0.1/hook")


def test_check_webhook_url_safe_blocks_metadata():
    with pytest.raises(ValueError):
        check_webhook_url_safe("http://169.254.169.254/hook")


def test_check_webhook_url_safe_rejects_non_http_scheme():
    with pytest.raises(ValueError):
        check_webhook_url_safe("ftp://10.8.1.20/hook")


def test_resolve_pinned_webhook_url_private_literal_is_unchanged():
    pinned, host = resolve_pinned_webhook_url("https://10.8.1.20:9200/path")
    assert pinned == "https://10.8.1.20:9200/path"
    assert host == "10.8.1.20"


def test_resolve_pinned_webhook_url_rejects_loopback_literal():
    with pytest.raises(ValueError):
        resolve_pinned_webhook_url("http://127.0.0.1/x")
