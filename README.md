# Aegis-DNS

Enterprise DNS filtering platform. See [`docs/`](docs/) for the full design and sprint plan.

## Layout

```
proto/                      shared protobuf schema (bundle.proto) — the Rust/Python contract
services/filter/            Rust workspace: aegis-filter (bin), aegis-bundle, aegis-policy
services/control/           Python control plane: aegis_control (FastAPI)
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
uvicorn aegis_control.main:app --reload
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
- `services/filter/aegis-policy/src/lib.rs`
- `services/control/aegis_control/compiler/bloom.py`

These two MUST stay in lockstep — see the fixture tests in
`services/control/tests/test_bloom.py` and `aegis-policy`'s unit tests.
Any change to the hashing scheme requires updating both sides in the same PR.
