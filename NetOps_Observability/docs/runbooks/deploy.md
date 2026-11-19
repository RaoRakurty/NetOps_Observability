# Runbook — deploying a change with `scripts/deploy.sh`

`scripts/deploy.sh` is the operator's way to roll a new build of one or more
services onto a running stack (a lab, or an appliance being patched by an
engineer). The customer upgrade path is `scripts/update.sh`
(`docs/UPGRADE.md`), which does more — read the table at the end before
choosing.

## What it does

```
scripts/deploy.sh [--reload-changed-config] [service ...]   # default: frontend api
```

In order:

1. **Builds the frontend bundle fresh** when `frontend` is among the services
   (the frontend image ships a pre-built `dist/`; rebuilding the container
   without rebuilding `dist` would serve the old bundle). A failed build aborts
   with the stack untouched.
2. **Migrates `.env`** — `python3 scripts/install.py --migrate-env`: appends
   only the keys this tree introduced (never changes a value), backs `.env` up
   0600 first (`.env.pre-migrate-<stamp>`), prints key names only. A failure
   aborts before anything is touched.
3. **Renders the service credential files** under `data/secrets` from `.env`.
4. **Records the running images** (the rollback target), then rebuilds and
   recreates the named services. Compose runs from `deployment/docker` with no
   `-f`, so the `COMPOSE_FILE` overlay chain in `.env` (TLS, offline images, …)
   is kept.
5. **Recreates named services whose bind-mounted config changed** — compose does
   not restart a container when only a mounted file (vector VRL, syslog-ng conf,
   vmalert rules) changed. Every *other* running service whose mounted config
   changed is warned about by name and left on its old config;
   `--reload-changed-config` recreates those too. The first run records a
   fingerprint baseline (`data/.deploy/config-fingerprints.json`) and recreates
   nothing extra.
6. **Health gate** (the app and API answer on `:8000`) and, for the frontend, a
   **freshness gate** (the served bundle hash equals the one just built).
7. On any failure it **rolls the services back** to the recorded images and
   checks the stack is healthy again.

| Exit | Meaning |
|---|---|
| `0` | deployed and healthy |
| `1` | aborted — stack untouched, or rolled back and healthy |
| `2` | manual intervention required |
| `3` | deployed and healthy, but the mounted-config fingerprint record could not be written (the next deploy may recreate config-changed services again) |

## What it does NOT do

`deploy.sh` runs **no bootstrap**. It does not run:

* `kafka-init` (topics) or the Kafka ACL matrix,
* `opensearch-security-init` (OpenSearch users, roles, mappings),
* `opensearch-init` (ISM retention, snapshot repository),
* `scripts/bootstrap-opensearch.sh` (the index templates).

A healthy `deploy.sh` exit therefore proves the named containers answer — not
that a new lane can be written or that the engines are consuming. Always finish
with:

```
scripts/deploy-qualify.sh        # must print QUALIFIED
```

`deploy-qualify.sh` re-runs the idempotent Kafka ACLs, `kafka-init` and
`opensearch-init` (B1–B3), audits read-only that every router lane has its role
grant and template (B4), and proves the engines are consuming (Q1–Q11). It does
**not** apply index templates or the security config.

## Procedure: a change that adds an OpenSearch family

A new index family (e.g. tracker 410's `netops-syslogroutine-*` and
`netops-syslogrollup-*`) is defined across the security roles, the ISM policy,
the index template, the api's readers and the router's sink. A router that
writes the family before its role grant and template exist has its batches
refused (`indices:admin/create`) and **dropped**. Deploy in this order:

```
scripts/deploy.sh opensearch-security-init   # roles.yml: netops_writer grants the new pattern
scripts/deploy.sh opensearch-init            # ISM policy for the family
bash scripts/bootstrap-opensearch.sh         # index-templates.json (+ mapping sync of today's indices)
scripts/deploy.sh api                        # the readers (and any api-owned writer)
scripts/deploy-qualify.sh                    # B4: every router lane writable; must be QUALIFIED
scripts/deploy.sh vector-router              # only now start writing the family
scripts/deploy-qualify.sh                    # again, with the router live
```

`opensearch-security-init` only runs on a TLS install (the `security` compose
profile). See `docs/runbooks/upgrade-bootstraps.md` for the full bootstrap list
and the five files every lane needs.

## `deploy.sh` vs `update.sh`

| | `deploy.sh` | `update.sh` |
|---|---|---|
| Who | operator / engineer | customer upgrade |
| Services | the ones you name (default `frontend api`) | the whole stack |
| `.env` migration | yes | yes |
| Pre-change backup tarball | no | yes (`--no-backup` to skip) |
| Mounted-config recreation | named services (`--reload-changed-config` for all) | every changed service |
| One-shot bootstraps | **none** | `compose up -d` runs the active profiles' one-shots, then `bootstrap-opensearch.sh` |
| Rollback | automatic, to the recorded images | the pre-upgrade tarball (`docs/UPGRADE.md`) |
| Proof | run `deploy-qualify.sh` | run `deploy-qualify.sh` |
