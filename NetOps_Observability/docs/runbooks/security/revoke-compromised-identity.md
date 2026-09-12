# Runbook (OUTLINE) — Revoke a compromised identity

> **Status: OUTLINE. Partially executable today, with an honest limitation you
> must read before relying on it.** Correlix deliberately has **no CRL and no
> OCSP**: short-lived certificates plus fast rotation are the revocation strategy
> (`docs/design/tls-architecture.md` §0 row 4, §4 "Revocation"). That means
> revocation is **eventual, bounded by the leaf TTL** — not immediate. The
> immediate controls (allowlist removal, credential invalidation) exist; a true
> "deny this certificate now" mechanism is **[PENDING SEC-003]**.
> **Do not execute against a live system from this document alone.**

**Decision record:** ADR-SEC-003 (revocation by expiry), ADR-SEC-006 (devices —
where the model breaks, see §3), ADR-SEC-001 (policy as the enforcement point).
**Complements:** [`docs/runbooks/tls-mtls.md`](../tls-mtls.md) (failure modes),
`rotate-service-certificate.md` (the mechanical rotation),
`ca-compromise-response.md` (escalate there if the **CA**, not a leaf, is
suspect), `docs/runbooks/secret-rotation.md` (existing, for `.env` credentials).

---

## 1. Purpose

Contain a compromised or suspected-compromised identity: a stolen service key, a
leaked token, a device certificate on decommissioned or seized hardware, or a
credential exposed in a log or a support bundle.

**Decide first — what is compromised?**

| Scope | Go to |
|---|---|
| One leaf certificate / one service key | **this runbook** |
| The CA private key | `ca-compromise-response.md` — **stop and escalate** |
| A `.env` credential (JWT secret, DB password) | `docs/runbooks/secret-rotation.md` (existing, executable) |
| The sealing KEK / sidecar | `secret-unseal-failure.md` then `ca-compromise-response.md` |
| A device certificate | this runbook, but read §3's device row first |

## 2. Prerequisites

- [ ] The compromise is *scoped*: which identity, since when, what it could
      reach. Guessing wide is safer than guessing narrow.
- [ ] Authority to cause an outage — containment here can be disruptive by
      design.
- [ ] The current leaf TTL for the affected identity (this is your **exposure
      window** if allowlist removal is not possible).
- [ ] An incident ticket open before the first change.

## 3. SAFETY WARNINGS

| Risk | Detail |
|---|---|
| 🔴 **Revocation is NOT immediate** | With no CRL/OCSP, a stolen certificate remains cryptographically valid until it expires. The only *immediate* controls are (a) removing the identity from peer allowlists, (b) rotating the CA (`rotate-workload-ca.md` — heavy), (c) network-level isolation. Do not tell anyone the credential is "revoked" when it is merely "no longer re-issued". |
| 🔴 **Allowlist removal will break the service** | Removing an identity from `TLS_CLIENT_ALLOWED_URIS` or a peer policy is the fastest containment and it **stops that service working immediately**. For `nginx` that means the UI and API are down. This is usually correct during an incident — but it must be a decision, not a surprise. |
| 🔴 **Devices: the expiry model does not save you** | Device certificates cannot have 24 h TTLs (ADR-SEC-006 U3, unresolved), so "revocation by expiry" may mean months. For devices the real controls are the collector-side allowlist/denylist and network segmentation. **[PENDING SEC-013…017]** — no device denylist exists. |
| 🔴 **Rotating the CA is the nuclear option** | It revokes *everything*, including the compromised leaf, at the cost of a full re-issuance across the deployment. Justified for a high-value identity; disproportionate for a low-value one. |
| 🟠 **Can drop telemetry** | Cutting off a collector or a Vector identity stops ingestion for that lane. Check buffer headroom and accept the loss consciously. |
| 🟠 **Do not destroy evidence** | Preserve the compromised key material, logs and timelines *before* rotating. Forensics needs the artifact. |
| ⚪ **Rotation itself is reversible; the compromise is not** | Assume anything the identity could read was read. |

## 4. Pre-validation

1. Establish the exposure window (first possible compromise → now) and list
   everything the identity could authenticate to.
2. Capture evidence: the certificate, its fingerprint and SPIFFE URI; relevant
   audit records; `netops_tls_identity_rejected_total` history; any anomalous
   connection patterns.
3. Confirm whether the CA itself could be affected — if yes, **stop** and go to
   `ca-compromise-response.md`.
4. Determine the leaf TTL, i.e. the worst-case window if you take no immediate
   action.
5. Decide the containment level (allowlist removal vs rotation vs CA rotation)
   and get it authorized.

## 5. Procedure

### Immediate containment (minutes)
1. **Remove the identity from every peer allowlist** that accepts it —
   `TLS_CLIENT_ALLOWED_URIS` on the API, plus any transport-policy
   `inbound_peer.allowed_identities` **[PENDING SEC-001]**. Reload the peers.
   *This is the only genuinely immediate control available today.*
2. Where the identity is also a Kafka/datastore principal
   **[PENDING SEC-005/008…012]**: revoke its ACLs, drop its user, or disable its
   role at the component.
3. If containment cannot be surgical, isolate at the network layer.

### Rotation (same session)
4. Rotate the affected service's leaf (`rotate-service-certificate.md`) so the
   legitimate service is running on new key material.
5. Restore the *new* identity to the allowlists; verify the service recovers.
6. Confirm the old identity is not re-issued anywhere
   (this is what "revoke by refusing to re-issue" means in practice).

### Escalation decision
7. If the identity was high-value, widely trusted, or the exposure window is
   long relative to the TTL: rotate the **CA** (`rotate-workload-ca.md`) — with
   the overlap window deliberately shortened, accepting the disruption.
8. Record an explicit decision either way, with the reasoning. "We chose not to
   rotate the CA because …" is an audit artifact.

### Devices **[PENDING — Phase 2]**
9. Add the device certificate to a collector-side denylist; until that exists,
   the controls are the exporter/source allowlist and segmentation.
10. Mark the device record; require re-enrolment before it is trusted again;
    **never** let it re-appear via auto-creation (ADR-SEC-006 decision 3).

## 6. Rollback

There is no "rollback" of a revocation — you do not un-revoke a compromised
credential. What is reversible:

| Action | Reversal |
|---|---|
| Allowlist removal (if the compromise report was wrong) | Re-add the identity, reload. Do this only after positive confirmation the report was false, and record why. |
| Service leaf rotation | None needed; the new leaf is legitimate. |
| CA rotation | See `rotate-workload-ca.md` §6 — reversible only before the old root is retired. |

## 7. Audit evidence to capture

- Incident ticket, opened **before** the first change.
- The compromised identity: SPIFFE URI, fingerprint, issue/expiry, where it was
  deployed.
- Exposure window and how it was determined.
- Every containment action with its timestamp and the operator.
- The explicit CA-rotation decision (yes/no) and its justification.
- Everything the identity could have accessed, and whether any access is
  evidenced in audit logs.
- Whether telemetry was lost, for how long, and for which tenants.
- **State plainly in the record that no CRL/OCSP revocation occurred** and what
  the residual exposure window was. Do not let "rotated" be read as "revoked".

## 8. Post-checks

1. The compromised identity is rejected by every peer (verify deliberately, do
   not assume).
2. The legitimate service is healthy on new key material.
3. Identity-rejection metrics show rejections for the old identity if it is
   still being presented — that is a live indicator of whether the attacker is
   still trying.
4. No re-issuance path can produce the old identity.
5. Telemetry continuity verified per affected lane and tenant.
6. Post-incident: was the exposure window acceptable? If the answer is no, the
   leaf TTL or the missing denylist mechanism becomes a backlog item —
   revocation-by-expiry is only a strategy while the TTLs are honestly short.
