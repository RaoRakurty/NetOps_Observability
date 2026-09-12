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
| `NETBOX_DB_PASSWORD` | alter | Same, against the bundled `netbox-postgres`. |
| `GRAFANA_CH_PASSWORD` | alter | `CREATE OR ALTER USER grafana` in ClickHouse (still pinned `tenant_scope='' CONST, readonly=2`), verified. |
| `CLICKHOUSE_PASSWORD` | recreate | Tries `ALTER USER`; if the admin user is config-file-defined (`users.d/default-user.xml`, which the image regenerates from the environment at every start) it force-recreates **only** the `clickhouse` service and verifies. On failure the value is rolled back in `.env`. |
| `ADMIN_INITIAL_PASSWORD` | seeded | **Refused** once `data/api/users.json` exists — the value is inert there. Change the password in the dashboard, or use `scripts/reset-admin.sh` (which deliberately wipes the whole local user store). |
| `GRAFANA_ADMIN_PASSWORD` | seeded | **Refused** once `data/grafana/grafana.db` exists. Rotate inside Grafana (below). |
| `KEYCLOAK_ADMIN_PASSWORD` | seeded | **Refused** once Postgres is initialized **and** the `sso` profile is active. Rotate in the Keycloak console. |
| `NETBOX_SUPERUSER_PASSWORD` | seeded | **Refused** once the NetBox DB exists — NetBox never updates an existing superuser from the environment. |
| `NETBOX_TOKEN` | seeded | **Refused** once the NetBox DB exists — a new value would make the API present a token NetBox rejects. Mint a replacement in NetBox and paste it in. |
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
