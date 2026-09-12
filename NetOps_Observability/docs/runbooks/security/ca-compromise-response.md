# Runbook (OUTLINE) — CA compromise response

> **Status: OUTLINE. Partially executable today.** The recovery *mechanism*
> exists (dual-root rotation via `tlsconfig.TrustBundle`, re-issuance on boot),
> but the ceremony tooling does not (**[PENDING SEC-003]**, see
> `rotate-workload-ca.md` step 1), and there is **no CRL/OCSP** — revocation is
> by expiry and by allowlist removal only
> (`docs/design/tls-architecture.md` §0 row 4).
> **This is an incident runbook. Do not rehearse it against production.**

**Decision record:** ADR-SEC-002 (trust domains — the reason blast radius is
bounded), ADR-SEC-003 (short TTLs), ADR-SEC-007 (sealing — the control that
makes this event unlikely).
**Complements:** `rotate-workload-ca.md` (the mechanics, executed here under
compressed timelines), `revoke-compromised-identity.md` (for a *leaf*, not a
CA), `secret-unseal-failure.md`, `restore-encrypted-backup.md`,
[`docs/runbooks/tls-mtls.md`](../tls-mtls.md).

---

## 1. Purpose

Respond to suspected or confirmed compromise of a **certificate authority
private key**. A CA key signs every identity in its domain: whoever holds it can
impersonate any service (workload domain) or any device (device domain, Phase 2).

**Scope first — which CA?**

| CA | Blast radius | Notes |
|---|---|---|
| **Workload CA** (`correlix.workload`) | Every intra-stack service identity | v1's only internal CA; in-process root (ADR-SEC-002) |
| **Device CA** (Phase 2) | Every device identity, tenant bindings | Does not exist yet |
| **Public/enterprise CA** (nginx server cert) | Browser-facing trust | Usually the customer's or a public CA — their incident process, coordinate |
| **Sealing KEK** | *Not* a CA, but it protects the CA key | `secret-unseal-failure.md` Path D, then here |

**The most likely real-world cause is not an attack.** It is
`TLS_INTERNAL_CA=true` having been enabled without a seal provider, writing the
CA key in plaintext (`src/backend/tls_ca.go:22-24`) — into every backup taken
since. Treat that as a confirmed compromise, not a hypothetical.

## 2. Prerequisites

- [ ] Incident declared and an owner assigned **before** any change.
- [ ] Authority to cause a full internal outage — recovery requires it.
- [ ] Host access independent of the platform (the UI may become unreachable).
- [ ] Sealing working, or fixed first — issuing a new CA into an unsealed store
      repeats the original mistake.
- [ ] Evidence preservation agreed: do **not** destroy the old key material.

## 3. SAFETY WARNINGS

| Risk | Detail |
|---|---|
| 🔴 **There is no revocation. None.** | No CRL, no OCSP. A leaked CA can mint valid certificates until its root is removed from every trust bundle. **Removing the old root from the bundles is the only real containment** — and it instantly breaks every service still holding an old-root leaf. Containment and outage are the same action. |
| 🔴 **Full internal outage is expected** | The compressed rotation has no comfortable overlap window: that overlap is exactly what an attacker would exploit. Decide consciously how much overlap risk to accept vs how much downtime. |
| 🔴 **Will drop telemetry** | Once collectors, Vector and Kafka are on the mesh, breaking trust stops ingestion. Buffers cover minutes, not hours. Quantify before starting. |
| 🔴 **Backups may contain the leaked key** | Especially in the unsealed-CA case. Backups taken during the exposure window must be treated as containing live key material and handled accordingly. |
| 🔴 **Assume impersonation already happened** | Anything the CA could authenticate to should be reviewed for anomalous access during the exposure window. Rotation stops the future, not the past. |
| 🟠 **Do not reuse the trust-domain string carelessly** | If the same domain string is reused, an old-root leaf and a new-root leaf are indistinguishable by identity alone — the `FederationTrust` binding (`src/backend/tlsconfig/federation.go`) helps only across domains. Removing the old root from the bundle is what actually distinguishes them. |
| 🟠 **Do not skip sealing "to move fast"** | Repeating the original defect during the recovery is the classic second incident. |
| ⚪ **Preserve evidence** | Old key material, logs, timelines, and the bundle history are the forensic record. |

## 4. Pre-validation (triage)

1. Establish **what** leaked (which CA), **when** (exposure window start), and
   **how** (unsealed disk write? backup? host compromise?).
2. If the *host* is compromised, everything on it is suspect — including the
   sealing state. Scope accordingly before trusting any local artifact.
3. Enumerate every trust-bundle consumer and every identity in the affected
   domain.
4. Check `netops_tls_identity_rejected_total` and handshake-error history for
   anomalies during the window.
5. Review audit logs for access patterns consistent with impersonation.
6. Decide the containment posture: **immediate cutover** (outage now, exposure
   ends now) vs **compressed dual-root** (short overlap, some residual exposure).
   Record the decision and its reasoning.

## 5. Procedure

### Containment
1. If the host is compromised, isolate it first; nothing below is meaningful on a
   hostile host.
2. **[PENDING SEC-001]** Tighten peer allowlists to the minimum set required to
   operate — allowlists reject an attacker's forged identity even when the chain
   validates, because the URI must also be allowed.
3. Preserve evidence: copy the compromised key material, bundles and logs to
   secure storage before changing anything.

### Recovery (compressed `rotate-workload-ca.md`)
4. Ensure sealing is working (`secret-unseal-failure.md`) **before** generating
   anything.
5. Generate a **new** CA under a new key. **[PENDING SEC-003]** for the staged
   second-root tooling; today this is an out-of-band generate + import
   (`internalca.FromPEM`, `internalca/ca.go:78`).
6. Distribute a bundle containing **only the new root** if taking the immediate
   cutover posture, or both roots for a deliberately short overlap.
7. Re-issue every leaf under the new CA (API restart re-issues api + nginx —
   `tls_ca.go:140-156`; other services **[PENDING SEC-003]**).
8. **Reload nginx** and every non-Go consumer.
9. Remove the old root from every bundle. **This is the containment moment** —
   until it is done, forged certificates are still accepted.
10. Verify every hop is up on the new root; verify a forged old-root certificate
    is now rejected (test it deliberately).

### Aftermath
11. Rotate anything the compromised CA could have protected or reached: service
    credentials, tokens, and any secret that transited a hop an attacker could
    have MITM'd during the window.
12. Review the exposure window for evidence of actual misuse; report per the
    customer's/organization's obligations.
13. Handle backups containing the leaked key: inventory, restrict, and destroy or
    re-encrypt per policy.

## 6. Rollback

**There is no rollback from a CA compromise response.** You cannot un-distrust a
leaked key. The only reversible decision is the *overlap posture* — if the
immediate cutover proves too disruptive, briefly re-adding the old root restores
service **at the cost of re-opening the exposure**. That is a deliberate,
recorded, time-boxed trade, authorized by the incident owner, never a quiet fix.

## 7. Audit evidence to capture

- Incident ticket, declaration time, owner, and the containment posture decision
  with its reasoning.
- Exposure window: start, end, and how each was determined.
- The compromised CA's fingerprint, subject, validity, and where it was exposed.
- Preserved evidence inventory and its storage location.
- Every bundle change with timestamp and per-consumer confirmation.
- The moment the old root was removed everywhere (**the containment timestamp**).
- Every identity re-issued, with new fingerprints.
- Findings from the impersonation review — including "no evidence found", which
  is itself a finding.
- Backups identified as containing the key, and their disposition.
- Total outage duration; telemetry lost, by lane and tenant.

## 8. Post-checks

1. No consumer trusts the old root (verify per consumer; do not assume).
2. A certificate signed by the old CA is **rejected** — tested, not asserted.
3. Every service is up on a new-root leaf; identity-rejection metrics at
   baseline.
4. The new CA key is **sealed** — verified, not presumed
   (`ADR-SEC-007`; the whole incident may have started from this).
5. Telemetry continuity confirmed per lane and per tenant; losses quantified.
6. Backups containing the leaked key are handled per policy.
7. Post-incident review answers: why was the key exposed, and which control
   would have prevented it? If the answer is "the boot refusal in ADR-SEC-007",
   that item's priority is now non-negotiable.
8. `bootstrap-pki.md` sequencing (sealing before CA) re-verified in every
   environment, not just the one that failed.
