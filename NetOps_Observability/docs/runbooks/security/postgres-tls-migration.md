# Runbook (OUTLINE) — Migrate Postgres to `sslmode=verify-full`

> **Status: OUTLINE. Partially executable today.** The **client** side works now:
> pgx honors the DSN, and `docs/runbooks/tls-mtls.md` already documents the exact
> connection string. The **server** side (Postgres serving TLS with a trusted
> certificate) is deployment configuration that does not exist in compose today —
> the DSN is `sslmode=disable` in practice, and compose only carries a comment
> pointing at `verify-full` (`deployment/docker/docker-compose.yml:1474`).
> Steps marked **[PENDING SEC-011]** need that server-side work.

**Decision record:** ADR-SEC-004, ADR-SEC-008 (violation V6).
**Complements:** [`docs/runbooks/tls-mtls.md`](../tls-mtls.md) "Postgres" section
(the DSN form and the `verify-full` vs `require` warning — **do not duplicate,
follow it**), `docs/DEPLOY_POSTGRES_APPSTATE.md`.

---

## 1. Purpose

Move the app-state database connection from plaintext to TLS with **full**
verification — chain *and* hostname — without breaking FORCE-RLS tenant
isolation or the non-superuser role rule.

## 2. Prerequisites

- [ ] `bootstrap-pki.md` complete, or an enterprise-issued server certificate for
      Postgres.
- [ ] The CA bundle mounted where the API can read it (the mesh CA at
      `/data/tls/ca.pem` in the documented layout).
- [ ] Inventory of every Postgres client: the Go API (`DATABASE_URL`), the
      `correlation` service, migration tooling, backup tooling
      (`scripts/backup.sh`), and any operator `psql` access.
- [ ] A verified backup.
- [ ] Confirmation that the app role is **not** superuser and **not** BYPASSRLS
      (the existing `assertRLSCapable` boot check in `src/backend/db.go` enforces
      this — it must keep passing).

## 3. SAFETY WARNINGS

| Risk | Detail |
|---|---|
| 🔴 **`require` is not verification** | `sslmode=require` encrypts and verifies **nothing** — it accepts any certificate, including an attacker's. `verify-full` checks the chain **and** the hostname. `docs/runbooks/tls-mtls.md` says this explicitly; the intermediate rungs of the ladder are for migration only and must not be left in place. |
| 🔴 **Wrong hostname = total API outage** | `verify-full` matches the certificate against the host in the DSN (`postgres`). A certificate issued for a different name fails, and the API **fails closed at boot**. Get the SAN right before switching. |
| 🔴 **RLS must survive** | Tenant isolation for app state is FORCE-RLS + `withTenant`. Nothing in this migration may change the role's RLS posture. If a "convenience" superuser connection is introduced to get TLS working, isolation is gone. |
| 🟠 **Telemetry impact: indirect but real** | Postgres holds app state, not telemetry — but the API cannot start without it, and a stopped API stops the ingest lanes it fronts. |
| 🟠 **Backup and migration tooling are easy to forget** | They connect with their own DSNs. A migration run that still uses plaintext leaves the violation open and may fail once the server requires TLS. |
| 🟠 **Certificate expiry becomes an outage class** | A Postgres server certificate expiring means the API cannot boot. Monitor it like any other. |
| ⚪ **Reversible** | Postgres can accept both TLS and non-TLS during migration; the DSN ladder (`disable` → `require` → `verify-ca` → `verify-full`) is the staged path, provided the intermediate states are short and recorded. |
| 🔴 **Bootstrap ordering: the minter needs the database** | The api mints the postgres SVID (SEC-003.3) but needs postgres to boot (`STORE_BACKEND=postgres`). Enabling the fail-closed TLS entrypoint BEFORE the first mint deadlocks the stack — postgres refuses to start without certs, the api can't mint without postgres (hit live, 2026-08-04). **First enablement order:** boot postgres stock → api mints under `TLS_SERVICE_CERT_ROOT` → then enable the TLS entrypoint. Steady-state restarts are safe (certs persist on disk). |
| 🟠 **Cold start after >TTL downtime** | If the whole stack is down longer than `TLS_SVID_TTL` (24h), postgres serves an EXPIRED cert on cold boot, `verify-full` clients refuse it, and the api — the only thing that can re-mint — can't boot. Recovery: temporarily step the api DSN down one rung (`verify-ca`→`require`), boot, let re-issuance run, step back up. The durable fix is decoupled issuance (a mint-only pre-store step) — tracked as a SEC-019 rotation-design requirement. |

## 4. Pre-validation

1. Verified backup.
2. Confirm `assertRLSCapable` currently passes and record the role's attributes.
3. Confirm the intended server certificate's SANs include exactly the hostname
   used in every client DSN.
4. Test the full DSN against a scratch instance first.
5. Baseline: connection counts, error rate, API boot time.
6. **[PENDING SEC-008]** Validator run: record violation V6.

## 5. Procedure

1. **[PENDING SEC-011]** Configure the Postgres server to serve TLS with the
   issued certificate and key (correct ownership and `0600` on the key).
2. Restart Postgres; confirm it accepts both TLS and non-TLS connections at this
   stage.
3. **Climb the DSN ladder on the API**, one rung at a time, verifying at each:
   `sslmode=require` → `verify-ca` → **`verify-full`** with
   `sslrootcert=/data/tls/ca.pem`. The exact form is in
   `docs/runbooks/tls-mtls.md` ("Postgres").
4. Repeat for the `correlation` service and for migration/backup tooling.
5. Confirm `assertRLSCapable` still passes on each restart.
6. **[PENDING SEC-011]** Tighten the server to **require** TLS (`hostssl` only in
   `pg_hba.conf`; no `host` fallback). ⚠ Any client not yet migrated is now
   refused.
7. Optionally add client-certificate authentication for the app role (ADR-SEC-004
   target: "SCRAM (+ optional cert)"). **[PENDING SEC-011]**
8. Update transport-policy rows; close the exception **[PENDING SEC-001]**.

## 6. Rollback

| Stage | Action |
|---|---|
| 1–2 | Revert the server TLS config; restart. |
| 3–4 | Step back down the DSN ladder; restart the client. Fast and safe while the server still accepts non-TLS. |
| 6 | Restore the `host` (non-TLS) entry in `pg_hba.conf` and reload. This is the step that can lock out a forgotten client. |
| 7 | Remove the client-certificate requirement; fall back to SCRAM. |

## 7. Audit evidence to capture

- The final DSN with `sslmode`, `sslrootcert` (credentials redacted).
- Server certificate subject, SANs, issuer, validity.
- `pg_hba.conf` before and after.
- Role attributes proving non-superuser / non-BYPASSRLS, before and after.
- `assertRLSCapable` boot-check result after each change.
- Per-client cutover timestamps.
- Confirmation that no intermediate `require`/`verify-ca` state was left in
  place — with the timestamps proving how long each rung lasted.

## 8. Post-checks

1. Every client connects with `verify-full`; none remains on a lower rung.
2. A deliberate non-TLS connection attempt is refused by the server.
3. `assertRLSCapable` passes; RLS policies unchanged.
4. **Negative test:** cross-tenant read attempt through the app role is refused
   by RLS.
5. API boot time and error rate at baseline.
6. Backup and migration tooling complete successfully over TLS.
7. Postgres certificate expiry added to monitoring/alerting.
8. Validator violation V6 clears.
