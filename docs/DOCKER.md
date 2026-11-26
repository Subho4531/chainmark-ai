# Docker test environment

Run the full Chainmark AI stack locally with one command. The images build from
this repository, so the test environment always matches the branch you are on.

## Services & ports

| Service | Container | URL on the host | Purpose |
| --- | --- | --- | --- |
| console | `chainmark-test-frontend` | http://localhost:8080 | React/Vite UI served by nginx |
| rust gateway | `chainmark-test-proxy` | http://localhost:8010 | `/v1`, `/cloak`, `/uncloak`, `/health`, `/api/sessions` |
| cloud API | `chainmark-test-api` | http://localhost:3002 | `/api/auth`, `/api/keys`, `/api/analytics`, `/api/ingest` |
| postgres | `chainmark-test-postgres` | localhost:5433 | Drizzle schema, vault records, Merkle events |

Inside the compose network the console proxies same-origin requests to
`api:3001` and `proxy:8000`, so the browser only talks to port **8080**.

The default host ports differ from the usual dev ports (`8000`, `3001`, `5432`)
so this stack can run next to a local `uv run` / `bun run` loop.

## Start

```powershell
.\scripts\docker_up.ps1
```

or directly:

```bash
docker compose up -d --build
```

First build compiles the Rust workspace and installs the Bun/Node dependencies,
so it takes a few minutes. A one-shot `migrate` service runs
`drizzle-kit push --force` after Postgres is healthy and before the API and
gateway start.

## Verify

```bash
curl http://localhost:8010/health
curl http://localhost:3002/api/cloud/health
curl http://localhost:8080/healthz
```

Open http://localhost:8080, sign up (any email + 8-character password), and the
console is ready. Create a `cm_live_...` API key under **API Keys** if you want
the gateway to forward signed telemetry to the cloud API.

## Configure

All tunables live in `.env.docker.example`:

```bash
Copy-Item .env.docker.example .env.docker
docker compose --env-file .env.docker up -d --build
```

The defaults are test-only secrets. Override `DOCKER_MASTER_KEY` and
`DOCKER_AUTH_SECRET` for anything other than a local sandbox.

## Useful commands

```bash
docker compose ps                 # service state / health
docker compose logs -f api proxy  # follow API + gateway logs
docker compose restart api        # restart one service
docker compose down               # stop and remove containers
docker compose down -v            # also delete the Postgres volume
```
