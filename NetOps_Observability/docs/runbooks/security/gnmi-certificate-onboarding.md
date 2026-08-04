# Runbook (OUTLINE) — Onboard a gNMI target with certificate verification

> **Status: PHASE 2 for the full model — but ONE PART IS ACTIONABLE TODAY.**
> `deployment/docker/gnmic/gnmic.yaml` sets `skip-verify: true` globally
> (`:13`) and `insecure: true` on five targets (`:30,35,40,45,50`). gnmic
> natively supports per-target `tls-ca`, so **replacing `insecure: true` with a
> verified TLS connection is configuration work that can be done now** for any
> device that presents a certificate. The full model — Correlix-issued **client**
> certificates from a device trust domain, per-target policy generation, and
> production refusal of `skip-verify` — is **[PENDING SEC-016]** and Phase 2
> (ADR-SEC-006, owner decision 2026-08-04).
> **Do not execute against live devices from this document alone.**

**Decision record:** ADR-SEC-006 (device identity), ADR-SEC-001
(`skip-verify` becomes a *declared exception*, not a default), ADR-SEC-008
(violation V13).
**Complements:** [`docs/runbooks/tls-mtls.md`](../tls-mtls.md) (workload mesh —
gNMI is the device domain, do not mix the bundles), `rotate-device-ca.md`.

---

## 1. Purpose

Move a gNMI target from "encrypted but unverified" (or plainly `insecure`) to a
verified TLS connection, and — in Phase 2 — to mutual TLS where Correlix presents
a client certificate the device authenticates.

Three rungs, in order of what is achievable:

| Rung | Meaning | State |
|---|---|---|
| **0. `insecure: true`** | No TLS at all; credentials in the clear | current for 5 targets |
| **1. TLS + `skip-verify: true`** | Encrypted, device identity unverified — MITM-able | current global default |
| **2. TLS + `tls-ca`** | Device's certificate verified against a CA | **actionable today** per target |
| **3. Mutual TLS** | Device also verifies Correlix's client certificate | **[PENDING SEC-016]**, Phase 2 |

## 2. Prerequisites

- [ ] The device's own certificate and its issuing CA (usually the customer's
      device PKI, **not** Correlix's).
- [ ] The exact hostname/IP gnmic dials, matching a SAN on the device
      certificate.
- [ ] For rung 3: the device trust domain and Correlix-issued client certificates
      (Phase 2).
- [ ] A change window — a gnmic target reconfiguration interrupts that target's
      subscription.

## 3. SAFETY WARNINGS

| Risk | Detail |
|---|---|
| 🔴 **WILL drop this target's telemetry during the change** | gNMI is a streaming subscription. Reconfiguring the target tears down the stream; gaps appear in metrics for that device. Change one target at a time. |
| 🔴 **A SAN mismatch fails closed and is common** | Devices frequently present certificates with an IP-only SAN, a management-VRF name, or a self-signed subject. Verify the actual certificate **before** flipping `skip-verify` off, or the target simply stops. |
| 🟠 **`skip-verify: true` is currently GLOBAL** (`gnmic.yaml:13`) | Removing it globally changes every target at once. **Do not.** Move it to a per-target declared exception and remove targets from it individually. |
| 🟠 **Do not mix trust bundles** | The device CA is a different trust domain from the workload mesh CA (ADR-SEC-002). Pointing `tls-ca` at the mesh bundle would be a domain-confusion defect, even if it "works". |
| 🟠 **Credentials transit `insecure` targets in the clear today** | Any target still on rung 0 is leaking its gNMI username/password on every connection. Those credentials should be rotated once the target reaches rung 2. |
| 🟠 **Production must refuse `insecure`/`skip-verify`** | ADR-SEC-008 V13. Enabling that check before the targets are migrated would refuse to boot — sequence the validator rule after the migration. |
| ⚪ **Reversible per target** | Revert the target block and restart gnmic. |

## 4. Pre-validation

1. Retrieve and inspect the device's certificate: subject, SANs, issuer,
   validity. Confirm a SAN matches the dialled address exactly.
2. Confirm which CA signs it and obtain that CA bundle.
3. Baseline the target's metric flow rate so a post-change gap is detectable.
4. Confirm the change window with the customer if the device is theirs.
5. **[PENDING SEC-008]** Record violation V13 for this target.

## 5. Procedure

### Rungs 0 → 2 (actionable today)
1. Add the device CA bundle to the gnmic configuration and reference it as
   `tls-ca` **on this target only**.
2. Remove `insecure: true` from this target's block.
3. Keep the target's `skip-verify` **explicitly declared** during the transition
   if the SAN situation is uncertain — as a *named exception with an expiry*, not
   as the global default.
4. Restart/reload gnmic; verify the subscription re-establishes and metrics
   resume at the baseline rate.
5. Once verified, remove the per-target `skip-verify`; verify again.
6. Rotate the gNMI credentials that previously transited in the clear.
7. Repeat per target. **Only when every target is at rung 2**, remove the global
   `skip-verify: true` at `gnmic.yaml:13`.

### Rung 3 — mutual TLS **[PENDING SEC-016]**
8. Issue a Correlix client certificate from the device trust domain.
9. Configure the target with the client certificate/key; configure the device to
   require and verify it.
10. Verify, then record the target as mutually authenticated in the policy table.

## 6. Rollback

| Stage | Action |
|---|---|
| 1–3 | Restore the previous target block; restart gnmic. |
| 4–5 | Re-add the per-target `skip-verify` (as a declared exception) if a SAN problem appears; the stream recovers. |
| 6 | Credential rotation is not reversible; re-rotate if needed. |
| 7 | Restore the global setting — but treat this as a signal that a target was missed, and find it. |
| 8–10 | Remove the client certificate from the target block; the device must also stop requiring it. |

## 7. Audit evidence to capture

- Per target: device certificate subject/SANs/issuer/fingerprint and the CA used.
- The rung before and after, with timestamps.
- Any `skip-verify` exception granted, its owner, reason and expiry.
- Metric-flow rate before and after (gap evidence).
- Credential rotation record for targets that were on rung 0.
- The final removal of the global `skip-verify`, and the evidence that every
  target had already been migrated.

## 8. Post-checks

1. The target's subscription is live and metrics are at the baseline rate.
2. `insecure: true` is absent for this target.
3. No `skip-verify` remains except as a declared, unexpired exception.
4. **Negative test:** presenting a wrong/untrusted certificate is refused.
5. Old gNMI credentials rotated and invalidated.
6. Policy row updated for this peer **[PENDING SEC-001]**.
7. Once all targets are migrated: the global `skip-verify: true` is gone and
   validator violation V13 clears.
