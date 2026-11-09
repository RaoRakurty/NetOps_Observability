# Secret Rotation — Operator Runbook

How to rotate the credentials in `deployment/docker/.env` **without taking the
stack down**, and why the installer will sometimes refuse.

## TL;DR

```bash
cd /path/to/NetOps_Observability

# Rotate everything that can be rotated for real, right now. Safe on a running
# install: it reconciles the live stores, verifies each new credential, and
# leaves every operator edit in .env alone.
python3 scripts/install.py --rotate-app-secrets
cd deployment/docker && docker compose up -d --force-recreate
```

`--reset-env` still exists and is still the "rotate everything" switch, but on a
**started** install it now refuses (exit 2, `.env` untouched) unless every secret
it would touch can genuinely be rotated. That refusal is the feature.

---

## 1. Why a `.env` rewrite is not a rotation

A secret is only rotated when the thing that **validates** it has changed too.
Most values in `.env` were consumed exactly once — on the first boot of an empty
volume — and the store has owned the credential ever since.

Before this was enforced (audit **FUNC-HIGH-1**), `--reset-env` regenerated every
value and applied none of them. On a running install that was not a rotation, it
was an outage:

* **`KAFKA_CLUSTER_ID`** was regenerated even though the generated `.env`'s own
  comment says it must never change after first start. Nothing wiped
  `data/kafka`, so the embedded broker refused its own formatted volume and
  crash-looped — taking the whole bus and ingest path with it.
* **`DB_PASSWORD` / `CLICKHOUSE_PASSWORD` / `NETBOX_DB_PASSWORD`** were rewritten
  in `.env` but never applied to Postgres / ClickHouse / the NetBox database, so
  the API could no longer authenticate to its own stores.

Both are the same mistake: writing a new value where nothing consumes it and
calling that "rotated".

---

## 2. The classification (the whole matrix)

Every secret `install.py` generates carries a rotation class in
`scripts/secret_rotation.py`. A generated secret without one fails the build
(`tests/test_secret_rotation.py`).

| Secret | Class | What rotation does now |
|---|---|---|
| `JWT_SECRET` | free | New value in `.env`; applied on the next `up -d`. **All issued access/refresh tokens stop working — everyone signs in again.** |
| `ENCRYPTION_KEY` | free | New value in `.env`. Injected into the API; no code path consumes it today (the tenant-secret vault uses its own sealed KEK). |
| `INGEST_TOKEN` | free | New value in `.env`; every in-stack producer and the Vector ingest sources read it at start. Recreate them together or ingest 401s until you do. |
| `NETBOX_SECRET_KEY` | free | New value in `.env`. Django re-reads it at boot; **existing NetBox sessions are invalidated**, data is untouched. |
| `DB_PASSWORD` | alter | `ALTER USER` on the **live** Postgres, verified over TCP with the new password, **before** `.env` is written. |
| `APP_DB_PASSWORD` | alter | `ALTER ROLE netops_app` on the live Postgres, verified, then `.env` and `data/secrets/postgres/api/pgpass`. No restart: the api re-reads the file for every new connection (§10). Kept when the store is an external database, because that role is not this tool's to change. |
| `NETBOX_DB_PASSWORD` | alter | Same, against the bundled `netbox-postgres`. |
| `GRAFANA_CH_PASSWORD` | alter | `CREATE OR ALTER USER grafana` in ClickHouse (still pinned `tenant_scope='' CONST, readonly=2`), verified. Grafana reads the rendered file at start, so recreate it (§7). |
| `CLICKHOUSE_PASSWORD` | recreate | Tries `ALTER USER`; if the admin user is config-file-defined (`users.d/default-user.xml`, which the image regenerates from the environment at every start) it force-recreates **only** the `clickhouse` service and verifies. On failure the value is rolled back in `.env`. |
| `ADMIN_INITIAL_PASSWORD` | seeded | **Refused** once `data/api/users.json` exists — the value is inert there. Change the password in the dashboard, or use `scripts/reset-admin.sh` (which deliberately wipes the whole local user store). |
| `GRAFANA_ADMIN_PASSWORD` | seeded | **Refused** once `data/grafana/grafana.db` exists. Rotate inside Grafana (below). |
| `KEYCLOAK_ADMIN_PASSWORD` | seeded | **Refused** once Postgres is initialized **and** the `sso` profile is active. Rotate in the Keycloak console. |
| `NETBOX_SUPERUSER_PASSWORD` | seeded | **Refused** once the NetBox DB exists — NetBox never updates an existing superuser from the environment. |
| `NETBOX_TOKEN` | seeded | **Refused** once the NetBox DB exists — a new value would make the API present a token NetBox rejects. Mint a replacement in NetBox and paste it in. |
| `VMAUTH_API_PASSWORD`, `VMAUTH_PROBER_PASSWORD`, `VMAUTH_VMALERT_PASSWORD`, `VMAUTH_GRAFANA_PASSWORD`, `VMAUTH_GNMIC_PASSWORD`, `VMAUTH_VECTOR_PASSWORD` | overlap | `--rotate-app-secrets` swaps them in one step (a short 401 window until vmauth and every client have the new value). **Prefer `--rotate-secret`** (§9): vmauth accepts old and new while the clients move, so no request is refused. |
| `OS_*_PASSWORD` | free | Re-applied by the `opensearch-security-init` bootstrap on the next start, from the files under `data/secrets/opensearch/`. **Not** overlap-capable: OpenSearch's internal user store holds one password hash per user (§9). |
| `KAFKA_CLUSTER_ID` | immutable | Never rotated in place. Requires `--rotate-kafka-cluster-id`, which moves `data/kafka` aside first (see §5). |

**On an install that has never started, every one of these is freely
rotatable** — the store adopts whatever `.env` says on its first boot. That state
is *detected* from the `data/` volumes (marker files such as
`data/postgres/PG_VERSION`, `data/kafka/meta.properties`), never assumed, and the
detection is fail-safe: anything that cannot be proven fresh is treated as
started.

---

## 3. What the refusal looks like

```
[fail ] --reset-env cannot rotate 6 of the 14 generated secrets on this install.
Nothing was written: a .env that no longer matches the running stores is
worse than no rotation at all.

  ADMIN_INITIAL_PASSWORD     seeded into its store on first boot only
                                  This value only seeds the FIRST admin when the user store is empty.
                                  The store already exists, so it is inert — and deleting it to force
                                  a re-seed would destroy every account created since.
                               -> change the password in the dashboard (Settings -> Change password),
                                  or, if you are locked out, wipe the user store deliberately with
                                  scripts/reset-admin.sh

  KAFKA_CLUSTER_ID           immutable after first start
                                  The embedded broker formatted data/kafka with this id. A new id
                                  makes the broker refuse its own volume on the next start and takes
                                  the entire bus/ingest path down with it.
                               -> keep it (recommended), or re-run with --rotate-kafka-cluster-id to
                                  rotate the id AND move data/kafka aside — DESTRUCTIVE: every topic,
                                  offset and in-flight message on the embedded bus is discarded

  ... (GRAFANA_ADMIN_PASSWORD, KEYCLOAK_ADMIN_PASSWORD, NETBOX_SUPERUSER_PASSWORD, NETBOX_TOKEN)

  Rotate everything that CAN be rotated safely right now (application
  secrets plus every live store credential this tool can reconcile and
  verify), leaving the entries above untouched:

      python3 scripts/install.py --rotate-app-secrets

  See docs/runbooks/secret-rotation.md for the full matrix.
```

Exit code **2** means *refused, nothing changed* (distinct from `1`, the
installer's generic failure). Secrets are never printed — names only.

If a store the plan depends on is **initialized but unreachable** (stack down,
container unhealthy), that is also a refusal before any write: start the store
and re-run.

---

## 4. The order of operations (why it cannot half-brick you)

1. Classify every secret against the on-disk state of `data/`.
2. Refuse (`--reset-env`) or skip (`--rotate-app-secrets`) anything blocked.
3. Preflight every live store the plan needs. **Nothing is written yet.**
4. Apply the `alter`-class credentials to the live stores and verify them —
   still before `.env` moves.
5. Back up `.env` to `.env.rotate.bak` (mode `0600`), then rewrite the changed
   `KEY=` lines **in place**. Operator edits (feature flags, SMTP, OIDC, the
   managed resource-plan block, an offline `COMPOSE_FILE`) survive, because the
   template is not regenerated.
6. Apply the `recreate`-class credentials, verify, and **roll the value back in
   `.env`** if the store did not accept it.

So `.env` always describes the credentials the running stores actually accept. A
partial failure exits non-zero and names exactly which secrets kept their old
value.

Re-running is safe: every reconciler checks whether the store already accepts the
new credential and returns without re-issuing the change.

---

## 5. Rotating `KAFKA_CLUSTER_ID` (destructive)

Only do this if the id itself must change — it is a storage identity, not a
credential, and leaking it discloses nothing.

```bash
python3 scripts/install.py --reset-env --rotate-kafka-cluster-id
```

It prints the exact directory it will move (`data/kafka` →
`data/kafka.pre-rotate-<UTC timestamp>`) and asks for confirmation. A
non-interactive run refuses unless you pass `--assume-yes` — a destructive
default must never be reachable from cron.

**What you lose:** every topic, consumer offset and in-flight message on the
embedded bus. The durable copies in OpenSearch / VictoriaMetrics / ClickHouse are
untouched. Delete the moved directory once the new broker is healthy.

---

## 6. Rotating the secrets the installer refuses

| Secret | Rotate it here |
|---|---|
| `ADMIN_INITIAL_PASSWORD` (the real admin password) | Dashboard → Settings → Change password. Locked out? `scripts/reset-admin.sh` — it wipes `data/api/users.json`, i.e. **every local account**, and re-seeds from the current `.env`. |
| `GRAFANA_ADMIN_PASSWORD` | `docker compose exec -T grafana grafana cli admin reset-admin-password --password-from-stdin`, then set the same value in `.env`. |
| `KEYCLOAK_ADMIN_PASSWORD` | Keycloak console → Users → `admin` → Credentials, then set the same value in `.env`. |
| `NETBOX_SUPERUSER_PASSWORD` | NetBox UI (`/netbox/`) → user → change password, then set the same value in `.env`. |
| `NETBOX_TOKEN` | NetBox → Admin → API Tokens: mint a replacement, revoke the old one, set the new value in `.env`, recreate `api`. |

In each case `.env` is being made to *match* a change you made in the store — the
opposite direction from the defect this runbook exists to prevent.

---

## 7. After any rotation

```bash
cd deployment/docker && docker compose up -d --force-recreate
```

`docker compose restart` is **not** enough: it bounces containers with the
environment they were created with. Only a recreate re-reads `.env`.

Then verify:

```bash
curl -fs http://localhost:8000/admin/health | jq
docker compose ps          # nothing restarting
docker compose logs api --tail=50   # no auth failures against postgres/clickhouse
```

Keep `.env.rotate.bak` until you have confirmed the stack is healthy; it is the
one-command way back (`cp .env.rotate.bak .env && docker compose up -d
--force-recreate`). It contains live credentials — mode `0600`, never commit it.

---

## 8. Known-leak response

If a secret leaked (a `.env` in a screenshot, a token in a paste, the historical
`deployment/docker/.env` blobs still readable in git history):

1. `python3 scripts/install.py --rotate-app-secrets` — covers `JWT_SECRET`,
   `INGEST_TOKEN`, `ENCRYPTION_KEY`, `NETBOX_SECRET_KEY` and every store
   credential the tool can reconcile.
2. Work through §6 for the seeded ones by hand.
3. `KAFKA_CLUSTER_ID` is not a credential — it does not need rotating.
4. Recreate the stack (§7) and confirm sign-in works before closing the incident.
5. For a leaked vmauth credential, use §9 instead of step 1: it revokes the old
   password only after vmauth's counters prove no client still presents it, and
   it drops no telemetry while it runs.

---

## 9. Zero-downtime rotation of the vmauth credentials

The six `VMAUTH_*_PASSWORD` values are the per-service credentials every client
presents to vmauth, the authenticating front of VictoriaMetrics. A one-step swap
refuses some requests: vmauth and each client pick up the new value at different
times. For the write-only lanes (gnmic, vector, prober) a refused request is
telemetry that is lost for good. `--rotate-secret` avoids that by making vmauth
accept the old **and** the new password until every client has moved.

```bash
cd /path/to/NetOps_Observability

# See what it would do. Runs the checks, prints the plan, changes nothing.
python3 scripts/install.py --rotate-secret vmauth-all --dry-run

# One identity, several, or all six:
python3 scripts/install.py --rotate-secret vmauth-gnmic
python3 scripts/install.py --rotate-secret vmauth-api,vmauth-grafana
python3 scripts/install.py --rotate-secret vmauth-all
```

Names: `vmauth-api`, `vmauth-prober`, `vmauth-vmalert`, `vmauth-grafana`,
`vmauth-gnmic`, `vmauth-vector`, or `vmauth-all`. The stack must be running on
a TLS install (vmauth runs only there). The command holds the installer lock, so
it cannot run at the same time as an install or an update.

### What it does, step by step

| Step | What happens | How it is proven |
|---|---|---|
| 1. Check | vmauth is running and its last config reload succeeded; `.env` is complete; the current password of each identity works. | Any failure: exit 2, nothing changed. |
| 2. Mint | A new password goes into `.env`. The old one is kept beside it as `VMAUTH_<ID>_PASSWORD_PREVIOUS`. | `.env` is written before any other change, so an interrupted run is always picked up from here. |
| 3. Overlap | `auth.yml` gets two entries for the user: the new password (`cred="current"`) and the old one (`<user>-previous`, `cred="previous"`). vmauth reloads it (SIGHUP). | vmauth's metrics show both entries and a successful reload. Both passwords are then tried and must work. If this fails on a new rotation, `.env` and `auth.yml` go back to the old password; no client has been touched. |
| 4. Move the clients | The client password files under `data/secrets` are replaced. The api, prober and vmalert read the new file within a second. grafana, gnmic and vector read theirs only at start, so those that are running are restarted (`docker compose restart`). | Each restarted service must be running again. |
| 5. Drain | The tool watches `vmauth_user_requests_total{cred="previous"}`. | It must stay flat for 3 times the slowest client interval (180 s for `vmauth-all`). |
| 6. Revoke | `auth.yml` goes back to one entry per user and vmauth reloads it. | The `-previous` entry is gone from the metrics, the old password gets **401**, the new one works. Only then is `VMAUTH_<ID>_PASSWORD_PREVIOUS` removed from `.env`. |
| 7. Audit | A summary: names, steps, restarts, drain time, request counts. | No password is ever printed or passed on a command line. |

### Exit codes

| Code | Meaning | What to do |
|---|---|---|
| 0 | Done. Only the new passwords work. | Nothing. |
| 2 | Refused before changing anything (vmauth down, last reload failed, `.env` and vmauth already disagree, another rotation still open, unknown name). | Read the message, fix it, run again. |
| 4 | Stopped **with both passwords valid**. Nothing is broken. Usually a client still sends the old password after 10 minutes, or a restart failed. | Find the client named in the message, fix or restart it, then run the **same command again**. It resumes, it does not mint a new password. |
| 1 | A step failed. On a new rotation that failed at step 3 everything was rolled back. | Read the message; `docker compose logs vmauth`. Running the command again resumes if `.env` still holds a `_PREVIOUS` value. |

### If a rotation is left half-done

While `VMAUTH_<ID>_PASSWORD_PREVIOUS` is in `.env`, every render of
`data/secrets` (install, `update.sh`, `deploy.sh`) keeps both passwords valid.
That is safe, but the old password, which you wanted gone, still works. After
one hour the warning alert **CredentialRotationIncomplete** fires (vmalert,
`rules-scale-slo.yaml`). Check `rate(vmauth_user_requests_total{cred="previous"}[5m])`:

* above zero: a client still uses the old password. Fix that client.
* zero: the run was interrupted. Nobody uses the old password, but it still
  works.

In both cases run `python3 scripts/install.py --rotate-secret <name>` again.

Do not edit `_PREVIOUS` lines by hand. To abandon a rotation that never got past
step 3, restore `.env` from `.env.snapshot`.

### Why the OpenSearch credentials cannot do this

OpenSearch stores one password hash per internal user, and the bootstrap
rewrites the whole user list each time. A user cannot accept two passwords. An
overlap would need a second user per service and every client switching its
user name, and the api reads its user name from the container environment, so
that would mean a recreate anyway. The `OS_*` passwords stay on the one-step
path (§2).

---

## 10. The app-state database password

The api connects to Postgres as `netops_app`. Its password is `APP_DB_PASSWORD` in
`.env`, rendered to `data/secrets/postgres/api/pgpass` and named by `PGPASSFILE`.
`DATABASE_URL` names the role and carries no password.

```bash
python3 scripts/install.py --rotate-app-secrets
```

The steps run in this order: `ALTER ROLE` on the live server and prove the new
password over TCP, write `.env`, then replace the file.

**No restart, and open connections are not touched.** The api re-reads the file for
every new connection, and `ALTER ROLE` does not close the ones already open. Pooled
connections move to the new password as they recycle (at most 30 minutes).

**One short window remains.** A Postgres role holds one password, so this cannot
overlap the way §9 does. Between `ALTER ROLE` and the file replacement, a **new**
connection is refused with `password authentication failed`. The steps run next to
each other, with nothing slow between them, so that is normally a few seconds. It
is proven to recover by itself (`TestPGRotationReachesTheNextConnectionWithoutARestart`).
Only a request that needed
a new connection at that moment sees an error; the next one works, with no action
needed. `--rotate-secret` refuses this password for the same reason.

**If it goes wrong.** On a failed `ALTER ROLE`, `.env` and the file both keep the
old password, and the run exits non-zero naming `APP_DB_PASSWORD`. Run it again.

| Check | Healthy |
|---|---|
| `netops_postgres_credential_loaded` on the api's `/metrics` | `1`. `0` means no new connection can open. |
| `netops_postgres_credential_reload_errors_total` | Flat. It rises when the file cannot be read; the last good value stays in use. |
| Log line `Postgres password file cannot be used` | Absent. |
| Security posture finding `CRED-001` naming `DATABASE_URL` | Absent. |

An api that has never been able to read the file refuses to open a connection and
says so in its boot error. It never tries an empty password.

Why not pgx's `PGPASSFILE` alone: the driver reads it once, while parsing the DSN,
and ignores any read error. That would leave the old password in use until a
restart. `TestPGPassfileAloneDoesNotSurviveARotation` keeps that premise honest. The
variable stays set because an api image from before this change, after a rollback,
still authenticates through the driver's own support.

---

## 11. Where each service credential lives

Everything below is rendered from `.env` under `data/secrets/` (mode 0400, owned by
the uid that reads it) by `install.py`, `update.sh`, `deploy.sh` and every rotation,
before anything restarts.

| File | Read by | How |
|---|---|---|
| `vmauth/<identity>/password` | api, prober, vmalert, grafana, gnmic, vector | §9 |
| `vmauth/vmauth/auth.yml` | vmauth | its own config, re-read every 10 s |
| `opensearch/api/password` | api | re-read on change |
| `opensearch/bootstrap/password` | opensearch-init | at each run |
| `opensearch/router/password`, `opensearch/aggregator/password` | vector-router, vector-aggregator | Vector exec backend, at each config load |
| `opensearch/dashboards/opensearch_dashboards.secret.yml` | opensearch-dashboards | second `--config`, at start |
| `opensearch/security-init/OS_*_PASSWORD` | opensearch-security-init | at each run, hashed with `hash.sh -env` |
| `clickhouse/grafana/password` | grafana | `$__file{}` in its provisioning, at start |
| `grafana/admin/password` | grafana | `GF_SECURITY_ADMIN_PASSWORD__FILE`, at start |
| `postgres/api/pgpass` | api | §10 |

**Still in a container's environment, and why.** These were not part of this move:
each needs its own check of what the image supports.

| Value | Where | Why it is still there |
|---|---|---|
| `CLICKHOUSE_PASSWORD` | clickhouse, api, correlation, vector-router | Not yet moved. |
| `REDIS_PASSWORD` | redis (also on its argv as `--requirepass`), api, prober, netbox | Not yet moved. |
| `DB_PASSWORD` | postgres (`POSTGRES_PASSWORD`), keycloak (`KC_DB_PASSWORD`) | Not yet moved. Removed from the api, which never read it. |
| `NETBOX_DB_PASSWORD`, `NETBOX_SUPERUSER_PASSWORD`, `NETBOX_TOKEN`, `KEYCLOAK_ADMIN_PASSWORD` | netbox, netbox-postgres, keycloak, api | Optional profiles; not yet moved. |
| `INGEST_TOKEN*`, `JWT_SECRET`, `ENCRYPTION_KEY`, `ADMIN_INITIAL_PASSWORD`, `CORR_DEBUG_TOKEN`, `VMALERT_WEBHOOK_TOKEN`, integration keys | api and others | Application secrets, not credentials to a platform store; not yet moved. |

`tests/test_no_credential_in_url.py` holds this list in code: a credential that is
not on it fails the build. Remove an entry when its value moves.
