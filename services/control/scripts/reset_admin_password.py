#!/usr/bin/env python
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

"""Resets a user's password directly in the database, for when nobody can log
in to do it through the UI (e.g. the admin password was rotated and then
forgotten - the seed value in mantis-control.env is a first-boot default
only, never updated after that).

Connects directly to DATABASE_URL (same as the API process) and hashes with
the same bcrypt path auth.hash_password/verify_password use, so the result is
indistinguishable from a password set through the UI. No running control-
plane server required; the password is only ever read via getpass, never
taken as an argv (would otherwise land in shell history / `ps`).

Usage:
    set -a; source /etc/mantis-control/mantis-control.env; set +a
    python scripts/reset_admin_password.py --email admin@mantis.local

DATABASE_URL is only auto-loaded from mantis-control.env by systemd's
EnvironmentFile= for the running service - an interactive root shell does not
source it. Run this without sourcing that file first and it will silently
connect to config.py's DEV DEFAULT database instead of the real one, updating
nothing a live login actually checks. The line below prints exactly which
host/database it connected to so that mistake is visible instead of silent.
"""
from __future__ import annotations

import argparse
import getpass
import sys

from sqlalchemy.orm import sessionmaker

from mantis_control.auth import hash_password
from mantis_control.db import models
from mantis_control.db.session import engine


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--email", required=True, help="Email of the user to reset")
    args = parser.parse_args()

    url = engine.url
    print(f"Connecting to {url.drivername}://{url.host}:{url.port}/{url.database} as {url.username!r}", file=sys.stderr)

    password = getpass.getpass("New password: ")
    if not password:
        print("password must not be empty", file=sys.stderr)
        return 2
    if password != getpass.getpass("Confirm new password: "):
        print("passwords did not match", file=sys.stderr)
        return 2

    db = sessionmaker(bind=engine)()
    try:
        user = db.query(models.User).filter(models.User.email == args.email).first()
        if user is None:
            print(f"no user with email {args.email!r}", file=sys.stderr)
            return 1
        user.password_hash = hash_password(password)
        db.commit()
        print(f"password reset for {args.email!r} (role={user.role})")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
