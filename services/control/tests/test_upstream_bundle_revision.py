# Copyright (C) 2026 Blue Networks srl <support+github@bluenetworks.it>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from mantis_control.api.upstream_routers import _bump_bundle_version, _bundle_version
from mantis_control.db.models import Base, UpstreamBundleRevision


def test_upstream_bundle_revision_is_monotonic_and_stable_between_mutations():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[UpstreamBundleRevision.__table__])
    db = sessionmaker(bind=engine)()
    try:
        assert _bundle_version(db) == 0
        assert _bump_bundle_version(db) == 1
        db.commit()
        assert _bundle_version(db) == 1
        assert _bundle_version(db) == 1
        assert _bump_bundle_version(db) == 2
        db.commit()
        assert _bundle_version(db) == 2
    finally:
        db.close()
