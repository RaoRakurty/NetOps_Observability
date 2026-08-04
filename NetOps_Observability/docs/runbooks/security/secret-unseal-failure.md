# Runbook (OUTLINE) — The API will not start: secret unseal failure

> **Status: OUTLINE. EXECUTABLE TODAY (diagnosis and recovery).** The sealing
> sidecar and the fail-closed boot path both exist:
> `deployment/docker/docker-compose.yml:1683-1693` (service `secrets-seal`,
> profile `seal`), `src/backend/main.go:271` (`log.Fatalf("secret custody: %v")`)
> and `:279` (sealed fields). `docs/runbooks/tls-mtls.md` "Failure modes" already
> names this outcome: *"swtpm sidecar down at boot with `SEAL_PROVIDER=swtpm` →
> Vault won't unseal → **API refuses to start** (loud, by design)."*
> Steps marked **[PENDING SEC-007]** relate to the not-yet-built `REQUIRE_SEAL`
> enforcement and the improved error text.

**Decision record:** ADR-SEC-007 (sealing provider), ADR-SEC-008 (fail-closed).
**Complements:** [`docs/runbooks/tls-mtls.md`](../tls-mtls.md) (failure modes),
`docs/design/secret-custody.md` (the model),
`ca-compromise-response.md` (escalate there if the KEK may have leaked rather
than merely being unavailable), `restore-encrypted-backup.md` (if the KEK is
genuinely lost).

---

## 1. Purpose

Diagnose and recover from "the API refuses to start because it cannot unseal."
This is an **intended** behaviour, not a bug: there is no plaintext fallback,
ever (`docs/design/secret-custody.md` §5).

**Decide first — availability or confidentiality?**

| Situation | Path |
|---|---|
| Sidecar is down/unhealthy — key intact | §5 Path A (restore custody) — normal case |
| Sidecar state file damaged or lost | §5 Path C — this is a **data-loss event** for sealed secrets |
| KEK may have been **exposed** | Stop. `ca-compromise-response.md` |
| Sealing was never configured and someone set `TLS_INTERNAL_CA=true` | §5 Path D — **the CA key is on disk in plaintext**; treat as exposed |

## 2. Prerequisites

- [ ] Host shell access (the UI is down — it is behind the API).
- [ ] Ability to read container logs and inspect the seal socket.
- [ ] Knowledge of whether a backup of the sealing state exists and where.
- [ ] An incident ticket open before making changes.

## 3. SAFETY WARNINGS

| Risk | Detail |
|---|---|
| 🔴 **Do NOT "fix" this by unsetting `SEAL_PROVIDER`** | Removing the seal provider makes the Vault dormant, which lets the API start — and every secret written while sealed becomes **undecryptable**, while new secrets are written in the clear. It converts an availability incident into a confidentiality incident *and* a data-loss one. This is the single most likely wrong move under pressure. |
| 🔴 **The swtpm state file IS the key custodian** | swtpm is a software emulator whose state is a file (`docs/design/secret-custody.md` §2). Lose or corrupt it and every sealed secret is unrecoverable. Do not delete, re-initialize, or "reset" it to make the container start. |
| 🔴 **Re-initializing the TPM generates a NEW KEK** | Every existing wrapped DEK becomes garbage. All sealed secrets are lost. This is only ever a last resort, with the data-loss consequence accepted in writing. |
| 🟠 **The whole platform is down while this is open** | The API fronts the UI, the ingest lanes' auth and the bus bridge. Telemetry sent during the outage is lost unless upstream buffers cover it. |
| 🟠 **Do not mistake a startup race for a failure** | If the sidecar is merely slow, the API may fail on a race. Check ordering before concluding the key is unavailable (ADR-SEC-008 U4). |
| ⚪ **Lab escape hatch exists but is not a fix** | `DEPLOYMENT_PROFILE=lab` **[PENDING SEC-008]** permits an unsealed start. Using it in production is a declared exception and must be recorded and time-boxed. |

## 4. Pre-validation (triage — do these before changing anything)

1. Read the API's boot log and identify the exact failure: `secret custody`
   (`main.go:271`), `sealed fields` (`:279`), or something else. **Do not assume
   it is sealing just because TLS is configured** — a certificate failure
   (`:285`) looks similar to an operator.
2. Check the `secrets-seal` container: running? healthy? restarting in a loop?
3. Check the socket path exists and has the expected permissions
   (`SEAL_SOCKET`, default `/run/secrets-seal/seal.sock`,
   `docker-compose.yml:1449`).
4. Check the sidecar's own logs for a `tpm2-tools` error.
5. Determine whether the swtpm state volume is present and intact.
6. Record everything **before** remediation — this is the evidence.

## 5. Procedure

### Path A — sidecar unavailable, key intact (the normal case)
1. Start or restart the sidecar:
   `docker compose --profile seal up -d secrets-seal`
2. Confirm it reports healthy and the socket exists.
3. Restart the API; confirm it unseals and starts.
4. If it fails on a race, fix start ordering/health gating — do not paper over it
   with retries in the operator's fingers.

### Path B — sidecar healthy but unseal still fails
5. Verify the API and sidecar agree on the socket path and any per-boot token.
6. Verify the sidecar is pointing at the intended swtpm state (a fresh, empty
   state unseals nothing and looks like corruption).
7. Verify volume permissions and ownership.
8. If the KEK genuinely cannot be unsealed, go to Path C.

### Path C — sealing state lost or corrupt (**data-loss event**)
9. **Stop.** Escalate. Do not re-initialize anything yet.
10. Restore the sealing state from backup if one exists, then Path A.
11. If no backup exists: every sealed secret is unrecoverable. Recovery means
    re-initializing the KEK and **re-entering every reversible secret** — SNMP
    credentials, notification tokens, OIDC client secret, LDAP bind password,
    TACACS+ secret, webhook secrets (`docs/design/secret-custody.md` §7 phase 1c
    lists what is wired). **The internal CA key is among them** — if it is lost,
    the mesh must be re-bootstrapped (`bootstrap-pki.md`) and every service
    identity re-issued.
12. Record the data loss explicitly. Do not let it be discovered later as
    "SNMP polling stopped working".

### Path D — CA enabled without sealing (**confidentiality event**)
13. If `TLS_INTERNAL_CA=true` ran while the Vault was dormant, the CA private key
    was written **in plaintext** (`src/backend/tls_ca.go:22-24`) and is in every
    backup taken since.
14. Enable sealing, **then rotate the CA** (`rotate-workload-ca.md`). Sealing a
    key that has already been written in the clear protects nothing.
15. **[PENDING SEC-007]** Once the boot refusal ships, this path becomes
    impossible to enter.

## 6. Rollback

There is nothing to roll back — the system is refusing to start, which is the
safe state. What must **not** be done as a "rollback" is disabling sealing
(see the first Safety row). If the platform must come up before custody is
restored, use the lab profile **[PENDING SEC-008]** as an explicit, recorded,
time-boxed exception, and treat every secret written during that period as
plaintext.

## 7. Audit evidence to capture

- Incident ticket, opened before remediation.
- The exact boot-log lines and which `log.Fatalf` fired.
- Sidecar state: running/healthy, logs, socket presence and permissions.
- The determination of which Path applied, and why.
- Whether any secret was lost, and the complete list of what had to be re-entered.
- If Path D: the exposure window for the plaintext CA key, and the rotation
  record.
- If the lab escape hatch was used: who authorized it, for how long, and what was
  written during it.
- Total outage duration and any telemetry lost.

## 8. Post-checks

1. API starts cleanly, sealed, with no fatal.
2. A sealed secret round-trips (encrypt→decrypt) — proof the correct KEK is in
   use, not merely *a* KEK.
3. Sidecar health gating prevents a repeat of the startup race.
4. Sealing-state backup exists, is current, and its restore has been **tested**
   (an untested backup of the custodian is the same as no backup).
5. Unseal success/failure and sidecar availability are monitored and alerting —
   a silent custody failure is forbidden (root `CLAUDE.md` §10).
6. If Path D applied: the CA has been rotated and the old root retired.
7. Post-incident: was the failure mode diagnosable from the error message alone?
   If not, that is a defect against ADR-SEC-008 decision 6, not an operator
   problem.
