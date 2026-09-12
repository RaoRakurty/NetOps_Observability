# Runbook (OUTLINE) — Add Valkey authentication (ACL users) and TLS

> **Status: OUTLINE. NOT EXECUTABLE — feature not built.** Valkey runs with **no
> password and no TLS** (`deployment/docker/docker-compose.yml:95-104`:
> `valkey-server --save 60 1 --maxmemory …`, healthcheck `valkey-cli ping`) —
> HLD threat T14, **CRITICAL**. Every step below is **[PENDING SEC-012]**.
>
> **Naming note:** root `CLAUDE.md` records that Redis was removed (#97,
> licensing) and must never be reintroduced. **Valkey is the supported
> replacement and is what runs.** Some older documents — including
> `docs/adr/0001-privileged-network-operations-isolation.md` — still say "Redis";
> read those as Valkey. Do not use this runbook as licence to reintroduce Redis.

**Decision record:** ADR-SEC-004 (native authz per component), ADR-SEC-008
(violation V7).
**Complements:** [`docs/runbooks/tls-mtls.md`](../tls-mtls.md) (the client-side
mesh CA pattern), `docs/runbooks/storage-and-volume-operations.md`.

---

## 1. Purpose

Give Valkey an authentication model (ACL users with per-command and per-key-prefix
scope) and TLS, removing anonymous access to whatever the platform caches or
queues there.

## 2. Prerequisites

- [ ] Inventory of every Valkey client and **exactly which key prefixes and
      commands each one uses** — the ACL is only least-privilege if this is
      accurate. Guessing produces either a lockout or a useless wildcard.
- [ ] Understanding of what is stored: if any of it is regenerable cache, the
      migration is far cheaper than if it is queue state.
- [ ] `bootstrap-pki.md` complete if client certificates are used; otherwise ACL
      passwords sealed through `internal/vault`.
- [ ] Confirmation of the Valkey version's TLS support in the pinned image
      (`valkey/valkey:8-alpine`, digest-pinned at `docker-compose.yml:95`).

## 3. SAFETY WARNINGS

| Risk | Detail |
|---|---|
| 🔴 **An over-tight ACL locks the application out instantly** | Valkey ACLs are per-command and per-key-pattern. A missing command (often a `SCAN`, an `INFO`, or the healthcheck's `PING`) fails at runtime, not at startup, and can present as an obscure application error rather than an auth failure. |
| 🔴 **The compose healthcheck will break** | `valkey-cli ping` (`docker-compose.yml:104`) runs unauthenticated. Once auth is on, the healthcheck fails, the container is marked unhealthy, and dependent services may refuse to start. **Update the healthcheck in the same change**, or the migration takes the stack down for a reason unrelated to security. |
| 🟠 **Data loss on flush/restart** | Persistence is `--save 60 1`. A restart can lose up to a minute of writes. If anything durable lives here, that matters; if it is pure cache, it does not. Know which before restarting. |
| 🟠 **Telemetry impact: indirect** | Valkey is not on the telemetry path, but a dependent service that cannot start will be. |
| 🟠 **TLS may require a second port** | Run TLS alongside plaintext during migration, then remove the plaintext port. |
| ⚪ **Reversible** | ACLs and TLS can both be reverted by configuration + restart, subject to the persistence caveat above. |

## 4. Pre-validation

1. Confirm what is stored and whether it is regenerable. Record it — this
   determines the rollback cost.
2. Capture the actual command/key usage per client (observe, do not assume).
3. Confirm the pinned image supports the ACL and TLS features you intend to use.
4. Baseline: connection counts, hit rate, memory usage, dependent-service health.
5. **[PENDING SEC-008]** Validator run: record violation V7.

## 5. Procedure *(all steps **[PENDING SEC-012]**)*

1. **Define ACL users** — one per client, least privilege, derived from the
   observed usage. Include a separate, minimal user for the **healthcheck**.
2. **Seal the credentials** through `internal/vault` (ADR-SEC-007) — never plain
   in `.env` if avoidable, and never in Git.
3. **Enable ACLs with a permissive default first** if the version supports
   observing denials; otherwise stage in a scratch environment.
4. **Update the compose healthcheck** to authenticate. Do this in the same change
   as step 3.
5. **Migrate clients one at a time**, verifying each works and that no denial
   appears.
6. **Remove the default/anonymous user.** ⚠ Anonymous access closes here.
7. **Enable TLS** on a second port; migrate clients; remove the plaintext port.
8. Update transport-policy rows; close the exception **[PENDING SEC-001]**.

## 6. Rollback

| Stage | Action |
|---|---|
| 1–4 | Revert configuration; restart (accepting up to ~60 s of unpersisted writes). |
| 5 | Point the individual client back at the anonymous path — still available. |
| 6 | Re-enable the default user. Recoverable, but it re-opens the CRITICAL exposure; time-box it. |
| 7 | Re-add the plaintext port. |

## 7. Audit evidence to capture

- The ACL definition as applied, per user, with the reviewer.
- The observed command/key usage that justified each ACL (the evidence that it
  is least-privilege rather than guessed).
- Healthcheck change and its verification.
- Per-client cutover timestamps.
- Confirmation that the default/anonymous user is removed (a deliberate
  unauthenticated connection that is refused).
- Any data loss incurred at restart, and whether it was regenerable.

## 8. Post-checks

1. Unauthenticated connection refused (test it).
2. Every client authenticated and functioning; no denied commands in the log.
3. Compose healthcheck green with the authenticated form.
4. Dependent services healthy; no start-order regressions.
5. Hit rate and memory at baseline.
6. Credentials stored sealed, absent from `.env` and from Git.
7. Validator violation V7 clears for Valkey.
