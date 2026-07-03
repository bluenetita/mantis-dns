import pytest
from pydantic import ValidationError

from aegis_control.api.zone_routers import RecordIn, RecordUpdate


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
