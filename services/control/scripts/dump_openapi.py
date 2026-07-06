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

"""Dumps the control-plane's OpenAPI schema to stdout.

`FastAPI.openapi()` builds the schema from the route/model definitions
already loaded in-process — no running server, Postgres, or network call
needed. Used by `apps/ui`'s `gen:api` script and CI's schema-drift check so
regenerating apps/ui/src/api/schema.ts doesn't require standing up the whole
stack first.
"""

import json
import sys

from mantis_control.main import app

json.dump(app.openapi(), sys.stdout, indent=2)
sys.stdout.write("\n")
