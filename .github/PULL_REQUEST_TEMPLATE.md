## What / why

## Component(s) touched
- [ ] `services/filter` (Rust)
- [ ] `services/control` (Python)
- [ ] `apps/ui` (TypeScript)
- [ ] `services/dhcp` (Rust)
- [ ] `proto/bundle.proto` (both Rust *and* Python side updated — required, see CONTRIBUTING.md)
- [ ] `packaging/` / `charts/` / `infra/`

## Checklist
- [ ] Relevant checks pass locally (`cargo test` / `pytest` / `npm test` as applicable)
- [ ] If `bundle.proto` or the bloom-filter hashing scheme changed, both
      `mantis-policy` (Rust) and `mantis_control/compiler/bloom.py` (Python)
      were updated together and fixture tests pass
- [ ] Docs updated (`README.md`, `docs/design.md`, `ARCHITECTURE.md`) if this
      changes behavior, config, or architecture

## Related issue
Closes #
