<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/brand/logo-lockup-dark.svg">
  <img alt="Mantis-DNS" src="docs/brand/logo-lockup-light.svg" height="60">
</picture>

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![CI](https://github.com/<your-owner>/mantis-dns/actions/workflows/ci.yml/badge.svg)](https://github.com/<your-owner>/mantis-dns/actions/workflows/ci.yml)

Enterprise DNS filtering platform. See [`ARCHITECTURE.md`](ARCHITECTURE.md) for
a system overview and [`docs/`](docs/) for the full design and sprint plan.

## Quick start (Docker)

Requires Docker + Docker Compose. No local Rust/Python/Node toolchain needed.

```
git clone <repo> && cd mantis-dns
./scripts/bootstrap.sh        # Windows: .\scripts\bootstrap.ps1
```

This generates a `.env` with random secrets and runs `docker compose up --build -d`
(Postgres, control plane, filter node, Kea DHCP, UI). Migrations and the initial
admin user are applied automatically on first boot.

- UI: http://localhost:5173
- API: http://localhost:8000
- Log in with `ADMIN_EMAIL` / `ADMIN_PASSWORD` from `.env` (default `admin@mantis.local` / `change-me-now`), then rotate the password.

To customize ports, tokens, or CORS origins, copy [`.env.example`](.env.example) to
`.env` yourself and edit it before running `docker compose up --build`.
Deploying with `MANTIS_ENV=production` requires every secret in `.env.example`
to be set to a strong value — the control plane refuses to boot otherwise.

## Production deploy

All release artifacts are built and published by
[`.github/workflows/release.yml`](.github/workflows/release.yml) on every
`v*` tag. Pick the option that matches your environment:

| Option | What you get | Use when |
| --- | --- | --- |
| `docker-compose.prod.yml` | All 5 services, pre-built GHCR images, one host | Single-node install, VM/bare metal with Docker |
| `packaging/filter/*.deb` | Standalone `mantis-filter` systemd service, no Docker | Edge DNS node separate from the control plane host |
| `charts/mantis-dns/` (Helm) | Control + UI on Kubernetes | Control plane needs to scale/run in an existing k8s cluster |
| `infra/cloud-init/` | Self-installing all-in-one VM image | Handing someone a single cloud/VM template to launch |

Kea (DHCP) and `mantis-filter` are intentionally never scheduled onto a k8s pod
network: Kea needs `NET_ADMIN` and L2 broadcast/relay reachability, and filter
nodes belong at the network edge. Run them via compose or the `.deb` and
point them at the control plane's address (`CONTROL_URL`/`MANTIS_CTRL_URL`),
regardless of where control/UI itself runs.

### Docker Compose (single host)

No clone or build required on the target host:

```
./scripts/bootstrap.sh --prod      # Windows: .\scripts\bootstrap.ps1 -Prod
```

This pulls images and runs [`docker-compose.prod.yml`](docker-compose.prod.yml)
instead of building from source — no bind-mounted source, no Vite dev server
(the UI is a static build served by nginx, which also reverse-proxies `/api/`
to the control plane). Set `CORS_ALLOW_ORIGINS` in `.env` to your public UI
origin(s) before starting; override `IMAGE_PREFIX`/`MANTIS_VERSION` if you
publish to your own registry/fork.

### Standalone filter node (no Docker)

Each `v*` release attaches `mantis-filter_<version>_<amd64|arm64>.deb` (systemd
unit + env file at `/etc/mantis-filter/mantis-filter.env`) and a raw static
binary. See [`packaging/filter/`](packaging/filter/) for the unit file and
nfpm config, or build/package it yourself:

```
cargo build --release -p mantis-filter --target x86_64-unknown-linux-musl
BIN_PATH=target/x86_64-unknown-linux-musl/release/mantis-filter VERSION=0.1.0 \
  nfpm package -f packaging/filter/nfpm.yaml -p deb -t .
```

```
sudo dpkg -i mantis-filter_0.1.0_amd64.deb
sudo $EDITOR /etc/mantis-filter/mantis-filter.env   # set CONTROL_URL, MANTIS_SERVICE_TOKEN
sudo systemctl enable --now mantis-filter
```

### Kubernetes (control plane + UI)

```
helm dependency update charts/mantis-dns
kubectl create secret generic mantis-dns-secrets \
  --from-literal=MANTIS_INTERNAL_TOKEN=$(openssl rand -hex 32) \
  --from-literal=MANTIS_SERVICE_TOKEN=$(openssl rand -hex 32) \
  --from-literal=MANTIS_JWT_SECRET=$(openssl rand -hex 32) \
  --from-literal=MANTIS_WEBHOOK_SECRET_KEY=$(openssl rand -hex 32) \
  --from-literal=ADMIN_PASSWORD=$(openssl rand -hex 16)
helm install mantis-dns charts/mantis-dns \
  --set secrets.existingSecret=mantis-dns-secrets \
  --set control.corsAllowOrigins=https://dns.example.com \
  --set image.registry=ghcr.io/<your-owner>/mantis-dns
```

See [`charts/mantis-dns/values.yaml`](charts/mantis-dns/values.yaml) for the
embedded-vs-external Postgres toggle and ingress options.

### VM / cloud-init appliance (all-in-one)

For handing someone a single template to launch on any cloud/hypervisor that
accepts cloud-init user-data (AWS, Hetzner, DigitalOcean, Proxmox, ...).
Render it first — the template embeds the current
`docker-compose.prod.yml` and `.env.example` so there's nothing to keep in
sync by hand:

```
./scripts/render-cloud-init.sh --cors https://dns.example.com
# Windows: .\scripts\render-cloud-init.ps1 -Cors https://dns.example.com
```

This writes `infra/cloud-init/user-data.yaml` — paste its contents into the
provider's user-data field when launching a Debian/Ubuntu VM. On first boot
it installs Docker, generates fresh per-instance secrets (never baked into
the template), and runs `docker compose -f docker-compose.prod.yml up -d`.
The generated `ADMIN_PASSWORD` is only ever written to
`/opt/mantis-dns/.env` on the instance — retrieve it via
`grep ADMIN_ /opt/mantis-dns/.env` over SSH, not the provider's console log.

This appliance runs everything (including Kea and the filter node) on one
box — fine for evaluation or small deployments. For the filter node at the
edge on separate hardware, use the `.deb` above instead.

## Layout

```
proto/                      shared protobuf schema (bundle.proto) — the Rust/Python contract
services/filter/            Rust workspace: mantis-filter (bin), mantis-bundle, mantis-policy
services/control/           Python control plane: mantis_control (FastAPI)
apps/ui/                    TypeScript/React management UI (Vite)
```

## Dev setup

**Rust** (filter node)
```
cd services/filter   # or repo root, workspace covers all filter crates
cargo build
cargo test
```
Requires MSVC Build Tools on Windows (`winget install Microsoft.VisualStudio.2022.BuildTools`, C++ workload).

**Python** (control plane)
```
cd services/control
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
pytest
uvicorn mantis_control.main:app --reload
```

**TypeScript** (UI)
```
cd apps/ui
npm install
npm run dev
```

## Cross-language contract

`proto/bundle.proto` is the wire format both Rust and Python build against.
The bloom-filter hashing scheme is duplicated (not shared as code) in:
- `services/filter/mantis-policy/src/lib.rs`
- `services/control/mantis_control/compiler/bloom.py`

These two MUST stay in lockstep — see the fixture tests in
`services/control/tests/test_bloom.py` and `mantis-policy`'s unit tests.
Any change to the hashing scheme requires updating both sides in the same PR.

Python protobuf bindings are generated and committed at
`services/control/mantis_control/gen/`. Regenerate after editing `bundle.proto`:
```
cd services/control
.venv/Scripts/python -m grpc_tools.protoc -I../../proto --python_out=mantis_control/gen --pyi_out=mantis_control/gen ../../proto/bundle.proto
```

Sprint 1 exit-criteria check (Python signs a bundle, Rust verifies it):
```
cd services/control && .venv/Scripts/python -m mantis_control.compiler.build_empty_bundle
cd .. && cargo run -p mantis-bundle --example verify_bundle -- services/control/bundle.bin services/control/bundle_pubkey.bin
```

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for dev setup, the cross-language
contract rules, and PR expectations. This project follows the
[Contributor Covenant](CODE_OF_CONDUCT.md).

## Security

See [`SECURITY.md`](SECURITY.md) to report a vulnerability. Please don't file
public issues for security problems.

## License

Mantis-DNS is licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only).
AGPL requires that anyone who runs a modified version of this software as a
network service also make their modified source available to that service's
users — see the [license text](LICENSE) for the exact terms.
