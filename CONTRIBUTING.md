# Contributing to Mantis-DNS

Thanks for taking the time to contribute.

## Before you start

- For anything beyond a small fix, open an issue first to discuss the
  approach — this project spans three languages (Rust, Python, TypeScript)
  and a shared wire format, so changes often have cross-cutting impact.
- Check [`docs/design.md`](docs/design.md) and [`docs/sprint-plan.md`](docs/sprint-plan.md)
  for the intended architecture and current phase before proposing something
  that reshapes a component.

## Dev setup

See the [README's Dev setup section](README.md#dev-setup) for the Rust,
Python, and TypeScript toolchains.

## Cross-language contract

`proto/bundle.proto` is the schema both the Rust filter node and the Python
control plane build against. **Any change to the bloom-filter hashing scheme
must update both**:
- `services/filter/mantis-policy/src/lib.rs`
- `services/control/mantis_control/compiler/bloom.py`

in the same pull request, with the fixture tests in
`services/control/tests/test_bloom.py` and `mantis-policy`'s unit tests kept
green. A PR that changes one side without the other will fail review.

After editing `bundle.proto`, regenerate the committed Python bindings (see
README) — do not hand-edit `services/control/mantis_control/gen/`.

## Code style & checks

Run the same checks CI runs before opening a PR:

| Component | Commands |
|---|---|
| Rust (`services/filter`) | `cargo build --workspace`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace` |
| Python (`services/control`) | `ruff check .`, `mypy mantis_control`, `pytest` |
| TypeScript (`apps/ui`) | `npm run build`, `npm run size`, `npm test` |

## Commit / PR

- Keep commits focused; write commit messages that explain *why*, not just what.
- Reference the issue a PR resolves, if any.
- New source files should carry an SPDX license identifier where practical:
  `SPDX-License-Identifier: AGPL-3.0-only`.
- By submitting a contribution, you agree it is licensed under this project's
  [AGPL-3.0 license](LICENSE).

## Reporting bugs / requesting features

Use the GitHub issue templates. For security vulnerabilities, do **not** open
a public issue — see [SECURITY.md](SECURITY.md).
