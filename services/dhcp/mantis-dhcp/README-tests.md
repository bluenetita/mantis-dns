# Running mantis-dhcp's tests

Most tests need a real Postgres with the control plane's schema applied —
`db.rs`'s allocation logic is deliberately tested against the actual
`pg_advisory_xact_lock`/`ON CONFLICT` behavior, not mocked.

```bash
docker run -d --rm --name mantis-dhcp-testdb -p 15432:5432 \
  -e POSTGRES_PASSWORD=test -e POSTGRES_USER=test -e POSTGRES_DB=test \
  postgres:17-alpine

cd services/control
DATABASE_URL="postgresql+psycopg://test:test@localhost:15432/test" \
  .venv/Scripts/python.exe -m alembic upgrade head   # or venv/bin/python on Linux/macOS

cd ../dhcp
TEST_DATABASE_URL="postgresql://test:test@localhost:15432/test" cargo test -p mantis-dhcp
```

`TEST_DATABASE_URL` defaults to `postgresql://test:test@localhost:15432/test`
if unset. Each test creates its own fresh tenant + scope row (random UUID),
so tests never collide with each other's rows and run fine concurrently
(`cargo test` parallelizes by default) — no fixture teardown needed between
runs, though the container itself is throwaway (`--rm`, no volume) so a
restart gives you a clean slate.

`server.rs` and `options.rs` also have pure unit tests (no DB) covering the
DORA helper functions and option-building logic — those run regardless of
`TEST_DATABASE_URL`.
