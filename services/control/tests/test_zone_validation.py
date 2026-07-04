import pytest
from pydantic import ValidationError

from aegis_control.api.zone_routers import RecordIn, RecordUpdate, ZoneCreate, ZoneUpdate


def test_record_in_accepts_normal_values():
    r = RecordIn(name="www", record_type="A", data="10.0.0.1")
    assert r.name == "www"
    assert r.data == "10.0.0.1"


def test_record_in_rejects_leading_dollar_in_name():
    with pytest.raises(ValidationError):
        RecordIn(name="$INCLUDE /etc/passwd", record_type="TXT", data="x")


def test_record_in_rejects_leading_dollar_in_data():
    with pytest.raises(ValidationError):
        RecordIn(name="www", record_type="TXT", data="$GENERATE 1-100 host$ A 10.0.0.$")


def test_record_in_rejects_empty_name():
    with pytest.raises(ValidationError):
        RecordIn(name="   ", record_type="A", data="10.0.0.1")


def test_record_update_rejects_leading_dollar():
    with pytest.raises(ValidationError):
        RecordUpdate(name="$INCLUDE /etc/passwd")
    with pytest.raises(ValidationError):
        RecordUpdate(data="$GENERATE 1-100")


def test_record_update_allows_unset_fields():
    u = RecordUpdate()
    assert u.name is None
    assert u.data is None


def test_zone_create_accepts_normal_fqdn():
    z = ZoneCreate(tenant_id="t1", name="Corp.Example.COM", zone_type="local")
    assert z.name == "corp.example.com"


def test_zone_create_accepts_single_label_name():
    z = ZoneCreate(tenant_id="t1", name="lan", zone_type="local")
    assert z.name == "lan"


def test_zone_create_rejects_dollar_directive_smuggled_into_name():
    """export_zone() writes z.name verbatim into $ORIGIN/SOA/NS lines of a
    file handed to a real nameserver — a name containing a newline + '$'
    could smuggle a BIND control directive (e.g. $INCLUDE) into that file."""
    with pytest.raises(ValidationError):
        ZoneCreate(tenant_id="t1", name="ok\n$INCLUDE /etc/passwd", zone_type="local")


def test_zone_create_rejects_embedded_newline():
    with pytest.raises(ValidationError):
        ZoneCreate(tenant_id="t1", name="ok\nX-Injected: 1", zone_type="local")


def test_zone_create_rejects_empty_name():
    with pytest.raises(ValidationError):
        ZoneCreate(tenant_id="t1", name="   ", zone_type="local")


def test_zone_update_rejects_dollar_directive_smuggled_into_name():
    """ZoneUpdate previously had no name validator at all, so PATCH could
    bypass the create-time check entirely."""
    with pytest.raises(ValidationError):
        ZoneUpdate(name="ok\n$INCLUDE /etc/passwd")


def test_zone_update_allows_unset_name():
    u = ZoneUpdate()
    assert u.name is None


def test_zone_update_accepts_normal_name():
    u = ZoneUpdate(name="Corp.Example.COM")
    assert u.name == "corp.example.com"
