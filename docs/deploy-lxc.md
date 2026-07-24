# Deploying on Proxmox LXC

Mantis-DNS's usual audience (SMB/MSP DNS filtering, homelab, edge network
appliances) runs heavily on Proxmox, where LXC — not a full VM — is the
default way to stand up a service. This page covers four ways to get
Mantis-DNS running in an LXC container, cheapest/fastest first.

**mantis-dhcp** (native DHCPv4 server) and **mantis-dhcp6** (native DHCPv6
server, RFC 8415) — both built from `services/dhcp` — need host networking and
L2 broadcast (v4) or multicast (v6) reachability to the client subnet (see
[`ARCHITECTURE.md`](../ARCHITECTURE.md)), so both are opt-in everywhere below:
via `docker compose --profile dhcp up -d` / `--profile dhcp6 up -d` in
[`docker-compose.prod.yml`](../docker-compose.prod.yml), on their own host, or
with the Rocky native installer's `INSTALL_DHCP=1` / `INSTALL_DHCP6=1` options
when this LXC is meant to serve DHCP directly. Both talk to Postgres directly
and report lease/DDNS events to the control plane's `/internal/dhcp-event`
endpoint — there is no management API/port to reach or publish, unlike Kea;
the only thing to get right is `MANTIS_DHCP_SERVER_IP` for v4 (this host's
DHCP-serving interface address, which clients echo back on every renewal) or
`MANTIS_DHCP6_SERVER_ID` for v6 (a stable IPv6 address used only to derive
this server's DUID) — each daemon refuses to start without its respective
variable.

## Option A — full stack, Docker Compose inside LXC

Fastest path if you're fine with Docker-in-LXC. Requires a **privileged**
container (or an unprivileged one with nesting) because Docker needs to
create its own nested cgroups/namespaces:

```
pct create <vmid> <template> --features nesting=1,keyctl=1 --unprivileged 1 ...
pct start <vmid>
pct exec <vmid> -- bash -c '
  apt-get update && apt-get install -y ca-certificates curl gnupg git
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list
  apt-get update && apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
  git clone <repo> /opt/mantis-dns && cd /opt/mantis-dns
  ./scripts/bootstrap.sh --prod
'
```

Trade-off: Docker-in-LXC is officially discouraged by Proxmox — nesting works
today but can break across kernel/Proxmox upgrades, and you're running a
full Postgres + 3 more containers for what's ultimately a DNS filter. See
Option C if you'd rather avoid that.

### Upgrading

```
pct exec <vmid> -- bash -c 'cd /opt/mantis-dns && MANTIS_VERSION=<new-tag> ./scripts/update.sh'
```

[`scripts/update.sh`](../scripts/update.sh) backs up the database (`pg_dump`
into `./backups/`) before pulling the new images, then health-checks the
control plane once the stack is back up. On failure it prints the exact
`docker compose up -d`/`pg_restore` commands to roll back instead of running
them itself.

## Option B — filter node only, native `.deb`

If you already have a control plane running somewhere (Option A/C, cloud-init
VM, Docker Compose, or Kubernetes) and just want an edge DNS resolver in a
lightweight LXC per site, install the standalone package — no Docker, no
nesting required, works in a plain unprivileged container:

```
pct create <vmid> <debian-12-template> --unprivileged 1 --cores 1 --memory 256 ...
pct start <vmid>
pct exec <vmid> -- bash -c '
  apt-get update && apt-get install -y curl
  curl -fsSLO https://github.com/<owner>/mantis-dns/releases/download/<tag>/mantis-filter_<version>_amd64.deb
  dpkg -i mantis-filter_<version>_amd64.deb
'
```

Then edit `/etc/mantis-filter/mantis-filter.env` on the container — at minimum
set `CONTROL_URL` to your control plane's address and `MANTIS_SERVICE_TOKEN`
to match its `MANTIS_SERVICE_TOKEN` — and `systemctl enable --now mantis-filter`.
See [`packaging/filter/mantis-filter.env`](../packaging/filter/mantis-filter.env)
for the full list of variables.

`CAP_NET_BIND_SERVICE` (for binding `:53` unprivileged) is granted by the
systemd unit itself and works fine in an unprivileged LXC — no `NET_ADMIN`,
no privileged container needed for the filter node alone.

## Option C — management plane, native install (no Docker)

Recommended if you want the control plane + UI on Proxmox without the
Docker-in-LXC trade-offs from Option A. [`infra/lxc/install.sh`](../infra/lxc/install.sh)
installs Postgres, the control plane (Python venv + systemd unit), and the
UI (static build served by nginx, reverse-proxying `/api/` to the control
plane) directly on a plain **unprivileged** Debian 12 LXC:

```
pct create <vmid> <debian-12-template> --unprivileged 1 --cores 2 --memory 1024 ...
pct start <vmid>
pct exec <vmid> -- bash -c '
  apt-get update && apt-get install -y git
  git clone <repo> /opt/mantis-dns-src && cd /opt/mantis-dns-src
  CORS_ALLOW_ORIGINS=https://<this-host-hostname-or-ip> ./infra/lxc/install.sh
'
```

The script generates and stores secrets in
`/etc/mantis-control/mantis-control.env` on first run (including a random
`ADMIN_PASSWORD`, printed once) and is safe to re-run after `git pull` to
redeploy a new version — it reuses the existing Postgres role and secrets
rather than regenerating them.

This script does not install mantis-dhcp or mantis-dhcp6 — they need L2
broadcast/multicast reachability this management-plane LXC shouldn't have
(see the intro above). Run either via `docker-compose.prod.yml` or their own
host, pointed at this LXC's Postgres directly (both read scopes and write
leases straight to the DB — no control-plane-facing port to configure).

Combine with Option B: point one or more edge `mantis-filter` LXCs at this
container's address as `CONTROL_URL`.

### Upgrading

```
pct exec <vmid> -- bash -c 'cd /opt/mantis-dns-src && git fetch --tags && git checkout <new-tag> && ./infra/lxc/install.sh'
```

Re-running the installer against an existing install now also backs up the
database (`pg_dump` to `/var/backups/mantis-dns/`) before touching anything,
keeps the previous code as `/opt/mantis-dns/app.previous` and
`venv.previous`, and checks that the new code boots before switching traffic
to it. If the health check fails, the script exits with the exact `mv`/
`pg_restore` commands needed to roll back — it never restores anything
automatically.

## Option D — full stack, native install on Rocky Linux 10

[`infra/lxc/install-rocky.sh`](../infra/lxc/install-rocky.sh) is the `dnf`
sibling of Option C's script, extended to also build and install
`mantis-filter` from source (no `.rpm` is published — CI only ships a
`.deb`). By default a single Rocky 10 LXC runs Postgres, the control plane,
UI, and the DNS filter listening on `:53`. mantis-dhcp and mantis-dhcp6 are
available as an explicit opt-in because they need L2 broadcast/multicast
reachability most LXC network setups don't have:

```
pct create <vmid> <rocky-10-template> --unprivileged 1 --cores 2 --memory 1024 ...
pct start <vmid>
pct exec <vmid> -- bash -c '
  dnf -y install git
  git clone <repo> /opt/mantis-dns-src && cd /opt/mantis-dns-src
  CORS_ALLOW_ORIGINS=https://<this-host-hostname-or-ip> ./infra/lxc/install-rocky.sh
'
```

When `CORS_ALLOW_ORIGINS` starts with `https://`, the Rocky installer
configures nginx on port `443` and generates a local self-signed certificate
with the LXC's primary IP address in its Subject Alternative Name. Browsers
will still warn until that certificate is trusted by the client, or until you
replace `/etc/pki/tls/certs/mantis-dns.crt` and
`/etc/pki/tls/private/mantis-dns.key` with a CA-issued certificate.

Set `INSTALL_FILTER=0` in the environment to skip the `mantis-filter` build
and get management-plane-only behavior equivalent to Option C, e.g. if edge
DNS nodes live on separate hosts.

Set `INSTALL_DHCP=1` (with `MANTIS_DHCP_SERVER_IP` set to this LXC's
DHCP-serving interface address) to build and install mantis-dhcp from source
and create `mantis-dhcp.service`:

```
CORS_ALLOW_ORIGINS=https://<this-host-hostname-or-ip> \
  INSTALL_DHCP=1 MANTIS_DHCP_SERVER_IP=<this-lxc's-dhcp-interface-ip> \
  ./infra/lxc/install-rocky.sh
systemctl status mantis-dhcp --no-pager
```

If `mantis-dhcp` fails to start with a permission error binding `:67`, the
`setcap cap_net_bind_service` step didn't take (rare — check `getcap
/usr/bin/mantis-dhcp`). If it starts but no client on the LAN gets a lease,
the LXC's network setup likely isn't on the same L2 broadcast domain as those
clients — use a privileged LXC, a VM, or a bridged (not NAT'd) network
interface.

Set `INSTALL_DHCP6=1` (with `MANTIS_DHCP6_SERVER_ID` set to a stable IPv6
address identifying this server — used only to derive its DUID, never itself
handed out to a client) to build and install mantis-dhcp6 from source and
create `mantis-dhcp6.service`:

```
CORS_ALLOW_ORIGINS=https://<this-host-hostname-or-ip> \
  INSTALL_DHCP6=1 MANTIS_DHCP6_SERVER_ID=<a-stable-ipv6-address> \
  ./infra/lxc/install-rocky.sh
systemctl status mantis-dhcp6 --no-pager
```

Same failure modes apply: a permission error binding `:547` means
`setcap cap_net_bind_service` didn't take (check `getcap
/usr/bin/mantis-dhcp6`); no leases on the LAN means the LXC's network setup
isn't reachable by IPv6 multicast from those clients.

Same idempotency as Option C: re-running after `git pull` redeploys code and
restarts services, reusing the existing Postgres role/secrets in
`/etc/mantis-control/mantis-control.env`.

Two things Rocky needs that Debian's package manager handles implicitly:
- **SELinux** (enforcing by default) — the script runs
  `setsebool -P httpd_can_network_connect 1` so nginx's `proxy_pass` to the
  control plane isn't blocked.
- **firewalld** (active by default) — the script opens the `http` service
  (plus `dhcp`/`dhcpv6` when `INSTALL_DHCP=1`/`INSTALL_DHCP6=1`).

### Upgrading

```
pct exec <vmid> -- bash -c 'cd /opt/mantis-dns-src && git fetch --tags && git checkout <new-tag> && ./infra/lxc/install-rocky.sh'
```

Same backup-then-health-check-then-switch behavior as Option C's Upgrading
section above.
