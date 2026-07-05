# Deploying on Proxmox LXC

Mantis-DNS's usual audience (SMB/MSP DNS filtering, homelab, edge network
appliances) runs heavily on Proxmox, where LXC — not a full VM — is the
default way to stand up a service. This page covers four ways to get
Mantis-DNS running in an LXC container, cheapest/fastest first.

Kea (DHCP) is out of scope for all options below — it needs
`NET_ADMIN` and L2 broadcast/relay reachability that varies per network (see
[`ARCHITECTURE.md`](../ARCHITECTURE.md)). Run it via
[`docker-compose.prod.yml`](../docker-compose.prod.yml) on a host that can
give it that access, pointed at whichever control plane you deploy below.

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

Combine with Option B: point one or more edge `mantis-filter` LXCs at this
container's address as `CONTROL_URL`.

### Upgrading

```
pct exec <vmid> -- bash -c 'cd /opt/mantis-dns-src && git fetch --tags && git checkout <new-tag> && ./infra/lxc/install.sh'
```

## Option D — full stack, native install on Rocky Linux 10

[`infra/lxc/install-rocky.sh`](../infra/lxc/install-rocky.sh) is the `dnf`
sibling of Option C's script, extended to also build and install
`mantis-filter` from source (no `.rpm` is published — CI only ships a
`.deb`), so a single Rocky 10 LXC ends up running the whole stack except
Kea: Postgres, control plane, UI, and the DNS filter listening on `:53`.
Works on a plain **unprivileged** container:

```
pct create <vmid> <rocky-10-template> --unprivileged 1 --cores 2 --memory 1024 ...
pct start <vmid>
pct exec <vmid> -- bash -c '
  dnf -y install git
  git clone <repo> /opt/mantis-dns-src && cd /opt/mantis-dns-src
  CORS_ALLOW_ORIGINS=https://<this-host-hostname-or-ip> ./infra/lxc/install-rocky.sh
'
```

Set `INSTALL_FILTER=0` in the environment to skip the `mantis-filter` build
and get management-plane-only behavior equivalent to Option C, e.g. if edge
DNS nodes live on separate hosts.

Same idempotency as Option C: re-running after `git pull` redeploys code and
restarts services, reusing the existing Postgres role/secrets in
`/etc/mantis-control/mantis-control.env`.

Two things Rocky needs that Debian's package manager handles implicitly:
- **SELinux** (enforcing by default) — the script runs
  `setsebool -P httpd_can_network_connect 1` so nginx's `proxy_pass` to the
  control plane isn't blocked.
- **firewalld** (active by default) — the script opens the `http` service.

### Upgrading

```
pct exec <vmid> -- bash -c 'cd /opt/mantis-dns-src && git fetch --tags && git checkout <new-tag> && ./infra/lxc/install-rocky.sh'
```
