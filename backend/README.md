# TriageLens backend

FastAPI service, ingestion pipeline, parsers, detection engine and IOC engine.
All Python code lives in the `app` package; the modules below it are
deliberately free of web-framework imports so they can be used as a library.

## Layout

| Path | Contents |
|---|---|
| `app/main.py` | application factory, middleware stack, static mount |
| `app/config.py` | `config.toml` + `TRIAGELENS_*` loading and validation |
| `app/errors.py` | stable error codes and the spec 06 error envelope |
| `app/db/` | connections, pragmas, migration runner, repositories |
| `app/models/` | typed records mirroring the SQLite schema |
| `app/ingest/` | intake, archive expansion, format detection, pipeline |
| `app/parsers/` | one module per log format plus the registry |
| `app/detect/` | Sigma loading, SQL compilation, correlation, scoring |
| `app/mitre/` | offline ATT&CK STIX loader and tag resolution |
| `app/ioc/` | extraction, refang, decoding, scoring, allowlists |
| `app/reports/` | HTML/Markdown/JSON/CSV report generation |
| `app/api/` | routers, request dependencies, ASGI middleware |
| `app/jobs/` | asyncio job manager and progress bus |
| `app/util/` | time, hashing, ids, structured logging |
| `migrations/` | forward-only SQL migrations |
| `rules/` | vendored SigmaHQ rules, built-in rules, logsource map |
| `data/` | bundled ATT&CK bundle, IANA TLDs, allowlist, profiles |
| `tests/` | unit, integration and security tests |

## Running

From the repository root:

```sh
make install     # create the virtualenv and install pinned dependencies
make dev         # API on :8787 with reload, Vite dev server on :5173
make build       # build the frontend into app/static
make test        # ruff, mypy --strict, pytest
```

See the root `Makefile` for every target and `DECISIONS.md` for the choices made
where the specification was silent.