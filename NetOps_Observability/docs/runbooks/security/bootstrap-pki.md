# Runbook (OUTLINE) — Bootstrap the Correlix PKI

> **Status: OUTLINE. Partially executable today.** The workload CA bootstrap
> (steps 4–6) is implemented and live-validated; the profile/validator gate
> (step 2) and the offline-root path (Appendix A) are **[PENDING SEC-008]** /
> **[PENDING — deferred, ADR-SEC-002]**.
> **Do not execute any step against a live system from this document alone** —
> it is a structural outline, not an approved change.

**Decision record:** ADR-SEC-002 (trust domains), ADR-SEC-003 (workload
identity), ADR-SEC-007 (sealing).
**Complements — read first:** [`docs/runbooks/tls-mtls.md`](../tls-mtls.md) is
the *existing, validated* enable-sequence for the nginx↔API mesh. This runbook
does not replace it; it wraps it in the trust-domain, sealing-order and
verification discipline the ADRs require, and adds the parts tls-mtls.md never
covered (domain separation, bundle distribution, evidence capture).

---

## 1. Purpose

Establish the v1 PKI from nothing to a working state:

- **Domain 1 — public ingress:** the certificate nginx presents to browsers.
  (Separate chain; may be ACME, enterprise PKI, or `scripts/gen-dev-cert.sh` for
  lab.)
- **Domain 2 — workload (`correlix.workload`):** the internal CA that mints every
  service SVID, sealed at rest.
- **Domain 4 — secret-encryption root:** the sealed KEK the workload CA key
  itself depends on.

Out of scope: the **device** domain (Phase 2 — see `rotate-device-ca.md`) and
the **backup** authority (deferred — see `restore-encrypted-backup.md`).

## 2. Prerequisites

- [ ] Owner approval to proceed past the HLD §12 do-not-implement boundary.
- [ ] Docker + Compose v2 plugin (the installer rejects legacy `docker-compose`).
- [ ] Access to `deployment/docker/.env` (gitignored, generated at install).
- [ ] Decided values: `TLS_TRUST_DOMAIN`, leaf TTL, and the SPIFFE namespace
      scheme — **note the migration hazard in ADR-SEC-003: code emits
      `/ns/default/sa/<svc>` today (`src/backend/tls_ca.go:91-93`) and the HLD
      targets per-tier namespaces. Settle this BEFORE first issuance.**
- [ ] A maintenance window: the API restarts.
- [ ] `docs/runbooks/tls-mtls.md` read end to end.

## 3. SAFETY WARNINGS

| Risk | Detail |
|---|---|
| 🔴 **Order is security-critical — sealing MUST precede CA creation** | If `TLS_INTERNAL_CA=true` is enabled *before* a seal provider works, the CA private key is written **in plaintext** (`src/backend/tls_ca.go:22-24`). Sealing afterwards does **not** protect the copy already on disk or in any backup taken since. Recovery is a full CA rotation, not a re-seal (ADR-SEC-007, Migration §3). |
| 🔴 **Can lock operators out** | Enabling API mTLS with `TLS_CLIENT_ALLOWED_URIS` set and nginx *not yet* presenting the matching client SVID makes the UI and API unreachable through nginx. Stage the nginx side and the API side in the documented order, and keep a shell on the host. |
| 🔴 **Boot refusal is by design** | Once ADR-SEC-007/008 land, a broken cert/CA or an unavailable seal sidecar means the **API does not start** (`main.go:271,279,285`; `docs/design/tls-architecture.md` §5). Expect an outage, not a warning. |
| 🟠 **Trust-domain string is effectively irreversible in place** | It is embedded in every issued SVID and every allowlist. Changing it later requires a dual-allowlist window (ADR-SEC-003, Migration §2). |
| 🟠 **Telemetry impact: none in this runbook** | This procedure touches only the API/nginx hop. Collection, Kafka and datastores are untouched — those are separate migration runbooks. |
| ⚪ **Reversible** | Every step here reverts by unsetting the env vars and restarting, *except* the plaintext-CA-key exposure (see the first row). |

## 4. Pre-validation

1. Confirm current state is dormant: no `TLS_*` / `SEAL_*` in the live `.env`.
2. Confirm the seal sidecar image builds (`deployment/docker/swtpm-sidecar/`).
3. Record the baseline: which services are healthy, and the current
   `/api/health` response through `:8000`.
4. Run the config preflight (existing, safe, read-only):
   `scripts/preflight-configs.sh`
5. **[PENDING SEC-008]** Run the security validator in warn-only mode and record
   the violation list as the "before" evidence.

## 5. Procedure

### Phase A — Sealing custody first (domain 4)
1. Bring up the sealing sidecar:
   `docker compose --profile seal up -d secrets-seal`
   (compose service defined at `deployment/docker/docker-compose.yml:1683-1693`.)
2. Verify it is healthy and the socket exists at `SEAL_SOCKET`
   (default `/run/secrets-seal/seal.sock`, `docker-compose.yml:1449`).
3. Set `SEAL_PROVIDER=swtpm` on the `api` service and restart the API.
4. Confirm the API started and the Vault unsealed. **If it did not start, stop
   here** — `secret-unseal-failure.md` is the triage path. Do **not** proceed to
   Phase B with sealing broken.

### Phase B — Workload CA (domain 2)
5. Set on `api` (all already present in compose, dormant by default —
   `docker-compose.yml:1455-1472`), per `docs/runbooks/tls-mtls.md` step 2:
   `TLS_INTERNAL_CA=true`, `TLS_TRUST_DOMAIN=<decided>`,
   `TLS_CERT_FILE`, `TLS_KEY_FILE`, `TLS_CLIENT_CA_FILE`,
   `TLS_NGINX_CERT_DIR`, `TLS_SVID_TTL`.
6. Restart the API. It logs `internal CA bootstrapped` and writes
   `api.{crt,key}`, `ca.pem` and `nginx/nginx.{crt,key}` under the shared TLS dir
   (`tls_ca.go:140-156`).
7. Verify the CA key is **sealed**, not plaintext — inspect the stored
   `tls.ca.key` field for the `v1:` envelope prefix
   (`docs/design/secret-custody.md` §4.3). **[PENDING]** a first-class
   "is the CA sealed?" check; today this is a manual inspection.
8. **[PENDING SEC-002]** Declare `TLS_FEDERATED_BUNDLES` in compose — it is
   implemented in Go but **absent from `docker-compose.yml`**, so the
   trust-domain↔anchoring-root binding is currently unreachable.

### Phase C — nginx client identity + mTLS
9. Mount the shared cert dir into nginx and swap the API upstream to `https://`
   with the `proxy_ssl_*` block — **use `docs/runbooks/tls-mtls.md` step 3
   verbatim**; it is the validated form and is not duplicated here.
10. Set `TLS_CLIENT_ALLOWED_URIS` to the nginx SVID URI **only after** step 9 is
    in place.
11. Reload nginx; verify through `:8000` before narrowing anything.

### Phase D — Public ingress (domain 1)
12. Install or renew the public/enterprise certificate for the nginx TLS front
    (shipped 2026-08-03; lab may use `scripts/gen-dev-cert.sh`).
13. Confirm the public chain and the internal bundle are **separate files** and
    that no internal root appears in the public chain, or vice versa.
14. **[PENDING SEC-008]** Schedule removal of the plaintext `:8000` listener
    (HLD T17) — record the removal date as a declared exception until then.

### Appendix A — Offline root **[PENDING — deferred, ADR-SEC-002]**
Not built in v1. When adopted: ceremony script, two-person control, witnessed
log, intermediate CSR/issuance, and a re-issuance event for every workload leaf.

## 6. Rollback

| From | Rollback |
|---|---|
| Phase D | Revert the nginx server-certificate config; reload. |
| Phase C | Revert the nginx include to the plaintext upstream; unset `TLS_CLIENT_ALLOWED_URIS`; reload. Keep the plaintext API listener available until Phase C is proven. |
| Phase B | Unset `TLS_INTERNAL_CA` and the `TLS_*` file vars; restart the API. **The generated CA material remains on disk — treat it as live key material, not debris.** |
| Phase A | Unset `SEAL_PROVIDER`; restart. ⚠ This returns the Vault to passthrough; anything written while sealed stays encrypted and becomes **undecryptable** — do not roll back Phase A after Phase B has written sealed data without reading ADR-SEC-007 Migration §5. |

## 7. Audit evidence to capture

- Timestamp, operator identity, change ticket, and the approval reference.
- The exact env delta applied (secret **values** redacted; variable **names**
  recorded).
- API boot log lines: `internal CA bootstrapped`, seal provider selection,
  and any refusal.
- CA certificate fingerprint, subject, `NotBefore`/`NotAfter`, and the
  trust-domain string.
- The SPIFFE URIs issued (api, nginx) and the allowlist configured.
- `netops_tls_cert_expiry_seconds` immediately after bootstrap.
- **[PENDING SEC-008]** validator output before and after.

## 8. Post-checks

1. `curl -s http://localhost:8000/api/health` → 200 (through nginx).
2. Direct API call without a client certificate is **rejected** (fail-closed) —
   `docs/runbooks/tls-mtls.md` step 4 has the exact commands.
3. `netops_tls_cert_expiry_seconds` present and sensible; alerting configured.
4. `netops_tls_identity_rejected_total` is zero for legitimate traffic and
   increments when a wrong identity is presented (test it deliberately).
5. Confirm the re-issue loop fires at ~TTL/2 (`tls_ca.go:159-165`) and that
   **nginx is reloaded** to pick up its new client SVID — this is the most
   commonly missed step and it breaks the mesh at TTL/2, not at expiry.
6. Restart the API once more and confirm a clean, sealed, fail-closed boot.
7. File the follow-up items: `TLS_FEDERATED_BUNDLES` in compose, `:8000`
   removal date, namespace decision (ADR-SEC-003 U1).
