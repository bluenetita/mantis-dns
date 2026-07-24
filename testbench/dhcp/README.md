# DHCP testbench

Standalone Docker stack that builds `mantis-dhcp`/`mantis-dhcp6`/`control`
from source and deeply exercises DHCPv4, DHCPv6, HA, DDNS (including a real
control-plane outage), conflict detection, relay, PXE, and lease-expiry
against real packets on the wire (design.md §22). Separate from the
top-level `docker-compose.yml` — see that file's `dhcp`/`dhcp6` service
comments for why (`network_mode: host`, needed in production, isn't a fit
for a repeatable local testbench).

## Run it

```bash
scripts/dhcp_testbench.sh
```

Builds everything, runs every phase in order, tears the stack down, and
exits non-zero if anything failed. Takes several minutes (deliberately —
the DDNS-retry and lease-expiry phases wait out real timers rather than
faking them).

Flags:
- `--keep` — leave the stack running after the run (pass/fail) instead of
  tearing it down, so you can poke at it (`docker compose -f
  testbench/dhcp/docker-compose.yml -p dhcp-testbench exec runner sh`,
  `... logs dhcp -f`, the control API at `http://localhost:18000`, etc).
- `--skip-v6` — skip the DHCPv6 phase, e.g. on a Docker daemon without
  IPv6-enabled bridge network support.

## Layout

- `docker-compose.yml` — postgres, control, two independent `mantis-dhcp`
  instances (`dhcp`/`dhcp-ha`, the second only for the HA phase, own compose
  profile), `mantis-dhcp6`, a throwaway `squatter` container for
  conflict-detection, and the `runner` test client.
- `runner/` — the test client: `lib/api.py` (control-plane REST calls, the
  same ones the UI would make), `lib/dhcp4.py`/`lib/dhcp6.py` (plain UDP
  socket clients; scapy is used only as a wire-format codec, never for
  raw/L2 sending — see their docstrings), `run_all.py` (every test case,
  grouped into phases).
- `state/run.json` — bind-mounted scratch file the phases use to pass
  created ids (tenant/zone/scope/...) to each other, since
  `docker compose run`/`exec` calls each start fresh.

## Running one phase by hand

Useful while iterating. Bring the stack up once, then run phases directly:

```bash
docker compose -f testbench/dhcp/docker-compose.yml -p dhcp-testbench up -d postgres control dhcp dhcp6 squatter runner
docker compose -f testbench/dhcp/docker-compose.yml -p dhcp-testbench exec -T runner python run_all.py --phase setup
docker compose -f testbench/dhcp/docker-compose.yml -p dhcp-testbench exec -T runner python run_all.py --phase core
```

Phases, in the order `scripts/dhcp_testbench.sh` runs them: `setup`, `core`,
`v6`, `ha` (needs `--profile ha up -d dhcp-ha` first), `ddns-trigger` (run
while `control` is stopped), `ddns-verify` (after restarting it),
`expiry`. `setup` must run first; the rest mostly don't depend on each
other except where noted, but running them out of order against a
DB that already has leftover state from a previous run isn't guaranteed
idempotent (e.g. the IA_PD phase's "the scope's one delegated prefix is
already held" case) — start from a clean stack (script does this
automatically) if you hit a confusing failure.
