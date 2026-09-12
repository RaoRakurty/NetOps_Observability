# mock-servicenow — ServiceNow Table API stub (#78)

A tiny, **stdlib-only** stand-in for the ServiceNow *incident* Table API. Its one
job is to let you exercise Correlix's **RCA auto-ticketing create leg**
end-to-end — sweeper → outbox → worker → **real HTTP** → ticket link → RCA
Inspector Ticket card — **without a real ServiceNow instance**.

It is a **test fixture**, never a production dependency: off by default (compose
profile `mock-snow`), in-memory only (a restart clears everything), and it
implements only the endpoints the Correlix adapter
(`src/backend/ticketing_servicenow.go`) actually calls.

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/healthz` | Liveness (unauthenticated) |
| `GET`  | `/api/now/table/incident?sysparm_query=correlation_id=<id>` | Lookup-by-correlation_id (dedupe anchor) |
| `GET`  | `/api/now/table/incident?sysparm_limit=N` | Health/auth probe (echoes recent rows) |
| `POST` | `/api/now/table/incident` | Create incident → `{result:{number,sys_id}}` |
| `PATCH`| `/api/now/table/incident/{sys_id}` | Update / work note / resolve |
| `GET`  | `/inspect` | **Watch what landed** — all incidents as JSON (auth-guarded) |
| `POST` | `/_control/fail?n=K` | Chaos: fail the next K create/patch with 503 (exercise retry/backoff) |

Auth: HTTP **Basic** (`MOCK_SNOW_USER` / `MOCK_SNOW_PASSWORD`); a `MOCK_SNOW_TOKEN`
also enables **Bearer**. Wrong creds → `401` (so the adapter's no-secret-leak path
is hit against a real peer).

## Config (env)

| Var | Default | Notes |
|-----|---------|-------|
| `MOCK_SNOW_ADDR` | `:8090` | Listen address |
| `MOCK_SNOW_USER` | `correlix` | Basic-auth user |
| `MOCK_SNOW_PASSWORD` | `correlix-mock-secret` | Basic-auth password |
| `MOCK_SNOW_TOKEN` | _(empty)_ | Optional Bearer token |
| `MOCK_SNOW_FAIL_NEXT` | `0` | Fail the first N create/patch at boot |

## Run it (with the stack)

```bash
cd deployment/docker

# 1. start the mock on the netops network (host :8099 → container :8090 for /inspect)
docker compose --profile mock-snow up -d --build mock-servicenow

# 2. let the api reach this private host + enable RCA ticketing, then recreate api
#    (add to deployment/docker/.env)
#      SSRF_ALLOWED_HOSTS=mock-servicenow
#      FEATURE_RCA_TICKETING=true
docker compose up -d api

# 3. point a tenant's connection at the mock (Admin → Incident Response →
#    Integrations), or via API — instance_url=http://mock-servicenow:8090,
#    user/pass = MOCK_SNOW_USER/MOCK_SNOW_PASSWORD, enabled=true.

# 4. watch incidents land
curl -s -u correlix:correlix-mock-secret http://localhost:8099/inspect | jq
```

The repeatable end-to-end driver is
[`scripts/validate-rca-ticketing-e2e.sh`](../../../scripts/validate-rca-ticketing-e2e.sh)
— it configures the connection, relaxes the global tenant's policy, drives a real
correlation through the sweeper+worker, and asserts an `INC` was created with the
right `correlation_id` + `u_correlix_*` fields.

## Standalone (no stack)

```bash
go run .                         # listens on :8090
MOCK_SNOW_ADDR=:18090 go run .   # or pick a port
```
