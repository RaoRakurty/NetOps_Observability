# Runbook (OUTLINE) — Rotate a single service certificate (leaf SVID)

> **Status: OUTLINE. Executable today for `api` and `nginx`; pending for every
> other service.** The API self-issues both of those SVIDs on boot and re-issues
> at ~TTL/2 with hot reload (`src/backend/tls_ca.go:145-155`, `:159-165`), so
> routine leaf rotation is already automatic. Rotation for Kafka, Vector,
> goflow2, correlation, syslog-ng and the datastores is **[PENDING SEC-003]** —
> no identity is minted for any of them.
> **Do not execute against a live system from this document alone.**

**Decision record:** ADR-SEC-003 (workload identity).
**Complements:** [`docs/runbooks/tls-mtls.md`](../tls-mtls.md) "Rotation"
(leaf-level, three lines) — this expands it into an operable procedure including
the manual/forced case. **Not this runbook:** rotating the *CA* (see
`rotate-workload-ca.md`) or responding to a *theft* (see
`revoke-compromised-identity.md`).

---

## 1. Purpose

Replace one service's leaf certificate and key **without dropping connections**.

Three cases, deliberately distinguished:

| Case | Mechanism | State |
|---|---|---|
| **Routine (automatic)** | Re-issue at ~TTL/2, `CertReloader` hot-swaps on modtime poll | ✅ works today for api/nginx |
| **Forced (operator-initiated)** | Trigger issuance before the loop would, e.g. after a config change or a suspected exposure | Partly — an API restart re-issues; a sub-TTL forced rotation with no restart is **[PENDING SEC-003]** |
| **Extending to other services** | Mint, distribute, reload per service | **[PENDING SEC-003]** |

## 2. Prerequisites

- [ ] The workload CA is bootstrapped and **sealed** (`bootstrap-pki.md`).
- [ ] The target service's identity string is known and matches every allowlist
      that references it (`TLS_CLIENT_ALLOWED_URIS` and peers' policies).
- [ ] For non-Go services: the reload/restart mechanism is known and its
      connection-drop behaviour understood.
- [ ] Current leaf fingerprint and expiry recorded.

## 3. SAFETY WARNINGS

| Risk | Detail |
|---|---|
| 🔴 **nginx does NOT hot-reload its client SVID** | Go services swap via `CertReloader`; nginx must be reloaded explicitly (`tls_ca.go:159-161` says so). Skipping this breaks the nginx→API hop at TTL/2 — i.e. *while everything looks fine*, hours before any expiry alert fires. |
| 🔴 **Changing the identity string is not a rotation** | If the SPIFFE URI changes (namespace or trust-domain migration, ADR-SEC-003), every allowlist must carry both strings first. Otherwise the new certificate is valid and **rejected**. |
| 🟠 **Can drop telemetry (non-api services, at target state)** | A Vector or collector restart to pick up a certificate interrupts ingestion for the restart duration. Check disk-buffer headroom (`deployment/docker/vector/vector.yaml`, buffer blocks) before restarting a producer. |
| 🟠 **A broken certificate is a boot refusal** | Fail-closed by design (`docs/design/tls-architecture.md` §5; `main.go:285`). A malformed key file means the service does not start. |
| 🟠 **Key file permissions** | Leaves are written `0600` for keys, `0644` for certs (`tls_ca.go:95-96`). A widened permission during manual rotation is a credential exposure. |
| ⚪ **Reversible** | The previous cert/key pair can be restored if retained. A runtime reload error keeps the last good certificate and logs (`tls-architecture.md` §5) — serving a still-valid cert beats dropping the listener. |

## 4. Pre-validation

1. Confirm the CA is healthy and sealed; confirm the trust bundle is current.
2. Record the current leaf: subject, SPIFFE URI, fingerprint, `NotAfter`.
3. Confirm `netops_tls_cert_expiry_seconds` and identity-rejection counters are
   at baseline.
4. Confirm the peer allowlists that reference this identity.
5. Take a copy of the current cert/key for rollback (respecting `0600`).

## 5. Procedure

### Case A — routine automatic (api / nginx) — no action required
1. Observe: the re-issue loop fires at ~TTL/2 (`tls_ca.go:162-165`).
2. Confirm the API hot-swapped (no restart, no connection drop).
3. **Confirm nginx was reloaded** to pick up its new client SVID. If this is not
   yet automated in the deployment, it is the one manual step —
   **[PENDING SEC-003]** for an automatic nginx reload hook.

### Case B — forced rotation of the api/nginx pair
4. Restart the API — it re-issues both SVIDs on boot (`tls_ca.go:140-156`).
   This is the supported forced path today.
5. Reload nginx.
6. Verify through `:8000` and verify direct mTLS rejection of a client with no
   certificate (`docs/runbooks/tls-mtls.md` step 4).

### Case C — any other service **[PENDING SEC-003]**
7. Mint the leaf for the service's identity.
8. Distribute cert + key to the service's mount path with correct ownership and
   `0600` on the key.
9. Trigger the service's reload; where a reload is unavailable, restart during a
   window with buffer headroom verified.
10. Verify the peer accepts the new identity and that no allowlist rejected it.

## 6. Rollback

| Case | Action |
|---|---|
| A / B | Restore the retained cert/key pair; reload/restart. Because both are signed by the same CA and the identity is unchanged, no peer configuration changes. |
| C | Same, plus re-verify the peer's allowlist. |
| Identity string changed | **Rollback requires reverting the allowlists too** — revert them first, then the certificate. |

## 7. Audit evidence to capture

- Operator, timestamp, ticket, and the reason (routine / forced / suspected
  exposure — a forced rotation for suspicion should reference
  `revoke-compromised-identity.md`).
- Old and new leaf fingerprints, SPIFFE URIs, validity windows.
- Whether the swap was hot or required a restart, and the observed downtime.
- Confirmation that nginx was reloaded.
- Metric deltas: expiry gauge, identity rejections, handshake errors.

## 8. Post-checks

1. New leaf served (fingerprint matches) and chains to the current CA.
2. `netops_tls_cert_expiry_seconds` reflects the new `NotAfter`.
3. `netops_tls_identity_rejected_total` did not increment for legitimate peers.
4. `/admin/readyz` passes its certificate-validity assertion.
5. Old key material securely removed once the rollback window closes.
6. If this rotation was triggered by suspicion, the old certificate is recorded
   as untrusted-by-policy and the incident ticket references it.
