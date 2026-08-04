# Runbook (OUTLINE) — Rotate the workload CA (dual-root)

> **Status: OUTLINE. Partially executable today.** The underlying capability
> exists — `tlsconfig.TrustBundle` carries multiple roots and `CertReloader`
> hot-swaps leaves without a restart (`docs/design/tls-architecture.md` §4) — but
> there is **no automated dual-root ceremony**: the second root must be produced
> and staged by hand, and `src/backend/tls_ca.go` load-or-creates exactly one CA.
> Steps marked **[PENDING SEC-003]** need tooling that does not exist.
> **Do not execute against a live system from this document alone.**

**Decision record:** ADR-SEC-002 (trust domains), ADR-SEC-003 (workload
identity).
**Complements:** [`docs/runbooks/tls-mtls.md`](../tls-mtls.md) "Rotation" section
states the dual-root principle in three lines; this runbook is the operational
expansion — ordering, overlap arithmetic, verification and rollback.
**Not this runbook:** rotating a *leaf* (see `rotate-service-certificate.md`),
or responding to a *compromise* (see `ca-compromise-response.md` — that is an
emergency variant of this procedure with the overlap window collapsed).

---

## 1. Purpose

Replace the workload trust anchor (`correlix.workload`) with a new one **without
dropping a single connection**, by publishing both roots in the trust bundle,
re-issuing every leaf under the new root, then retiring the old root.

Triggers: scheduled rotation; root approaching expiry (`caValidity` is 10 years,
`tls_ca.go:33`); a change of trust-domain string; migration to an offline root
(ADR-SEC-002, deferred); or as the recovery half of a CA compromise.

## 2. Prerequisites

- [ ] Sealing is working (`SEAL_PROVIDER` set, sidecar healthy). A rotation that
      writes a new CA key while the Vault is dormant writes it **in plaintext**
      (`tls_ca.go:22-24`).
- [ ] The **overlap window** is decided and is longer than the longest leaf TTL
      in the deployment, plus the slowest consumer's reload interval.
- [ ] An inventory of **every** trust-bundle consumer — not just Go services:
      nginx (`proxy_ssl_trusted_certificate`), and at target state Kafka, Vector,
      goflow2, correlation, the datastores.
- [ ] Change window agreed; the API restarts at least once.
- [ ] Current bundle backed up, with its fingerprints recorded.

## 3. SAFETY WARNINGS

| Risk | Detail |
|---|---|
| 🔴 **Can take the whole stack down** | Once TLS is enforced, a consumer holding only the *old* root while a peer presents a *new*-root leaf rejects the connection. If both roots are not published everywhere first, this is a total internal outage — and with fail-closed boot (ADR-SEC-008) the API may not restart into a recoverable state. |
| 🔴 **Can lock operators out** | The nginx→API hop is the UI's path. Break it and the only remaining access is host shell. Keep one open for the whole procedure. |
| 🔴 **Overlap too short = silent breakage at TTL/2, not at expiry** | Leaves are re-issued at half TTL (`tls_ca.go:159-165`); a consumer that has not received the new root by then starts rejecting. |
| 🟠 **nginx does not hot-reload its client SVID** | Go services hot-swap via `CertReloader`; nginx needs an explicit reload (`tls_ca.go:159-161`). Forgetting it is the single most common rotation failure. |
| 🟠 **Telemetry impact at target state** | If Kafka/Vector/collectors are on the mesh, a mis-ordered rotation drops ingestion. Check consumer lag and buffer headroom before starting (`deployment/docker/vector/vector.yaml` disk-buffer blocks on the Kafka sinks). |
| 🟠 **Irreversible once the old root is deleted** | Step 9 is the point of no return. Anything still holding an old-root leaf is permanently rejected. |
| ⚪ **Reversible before step 9** | Up to and including step 8, reverting to the old root alone is safe. |

## 4. Pre-validation

1. Record every current root fingerprint and every leaf's issuer.
2. Confirm `netops_tls_cert_expiry_seconds` for all leaves; confirm none expires
   inside the planned window.
3. Confirm `netops_tls_identity_rejected_total` is at a stable baseline (a
   non-zero drift *before* rotation means something is already wrong).
4. Verify each consumer's trust-bundle path is writable and watched.
5. **[PENDING SEC-008]** Validator dry-run: no violations before starting.
6. Rehearse in staging with the production profile. Rotation is the one
   procedure where "we'll find out in prod" is unacceptable.

## 5. Procedure

1. **Generate the new CA** under the new trust anchor.
   **[PENDING SEC-003]** — `tls_ca.go` load-or-creates a single CA and has no
   "issue a second, staged root" path. Today this means producing the root
   out-of-band and importing it (`internalca.FromPEM`, `internalca/ca.go:78`),
   which is exactly the tooling gap this marker denotes.
2. **Seal the new CA key** through the same platform-DEK field discipline as the
   existing one (`caKeyField`, `tls_ca.go:31`). Never let it touch disk unsealed.
3. **Publish BOTH roots** into the trust bundle file every consumer reads
   (`TLS_CLIENT_CA_FILE`). `TrustBundle` supports multiple roots by design.
4. **Distribute the two-root bundle everywhere** and confirm each consumer has
   picked it up: Go services by reload, nginx by explicit `nginx -s reload`,
   others by their own mechanism. **Do not proceed until every consumer is
   confirmed** — this is the step that makes the rest safe.
5. **Wait out one full leaf TTL** with both roots trusted and no re-issuance, to
   prove the two-root state is stable under normal operation.
6. **Switch issuance to the new root.** Leaves are re-issued under the new
   anchor; Go services hot-swap. **Reload nginx.**
7. **Verify every peer** now presents a new-root leaf and every connection still
   succeeds. Watch identity-rejection and handshake-error metrics continuously.
8. **Soak** for the agreed overlap window (recommend ≥ the longest TTL, and at
   minimum long enough for every non-Go consumer to have restarted once).
9. **Retire the old root:** remove it from the bundle, redistribute, reload.
   ⚠ **Point of no return.**
10. Update the transport-policy records and any pinned issuer references
    **[PENDING SEC-001]**.

## 6. Rollback

| Stage | Action |
|---|---|
| Steps 1–3 | Discard the new root; no consumer has seen it. |
| Steps 4–5 | Remove the new root from the bundle, redistribute, reload. No leaf was issued under it. |
| Steps 6–8 | Switch issuance back to the old root and re-issue; both roots are still trusted, so this is non-disruptive. Reload nginx. |
| After step 9 | **No rollback.** Recovery = re-add the old root to the bundle and redistribute *before* anything holding an old leaf reconnects; if leaves have already expired, this becomes a re-bootstrap (`bootstrap-pki.md`). |

## 7. Audit evidence to capture

- Operator, timestamp, ticket, approval, and the reason for rotation.
- Old and new root fingerprints, subjects, validity windows.
- The exact overlap window used, and the justification for its length.
- Per-consumer confirmation of two-root bundle receipt (step 4) — this is the
  evidence that the rotation was safe, not merely successful.
- Metric series across the whole window:
  `netops_tls_cert_expiry_seconds`, `netops_tls_identity_rejected_total`,
  handshake errors.
- Timestamp of old-root retirement (step 9) and who authorized it.

## 8. Post-checks

1. Every leaf chains to the new root; no leaf chains to the old one.
2. Identity-rejection and handshake-error counters flat at baseline.
3. `/admin/readyz` asserts certificate validity (5-minute margin) on the API.
4. nginx serves through `:8000`/`:443` and presents its new client SVID upstream.
5. At target state: Kafka produce/consume healthy, consumer lag recovered, no
   gap in ingestion (compare event counts across the window).
6. Restart the API deliberately and confirm a clean fail-closed boot on the new
   root.
7. Expiry alerting re-pointed at the new root's `NotAfter`.
