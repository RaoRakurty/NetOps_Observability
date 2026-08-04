# Runbook (OUTLINE) — Rotate the device CA

> **Status: PHASE 2 — OUTLINE ONLY, FEATURE NOT YET BUILT.**
> There is no device trust domain, no device CA and no device certificate in
> Correlix today: `src/backend/tls_ca.go:140-156` mints exactly two identities,
> `api` and `nginx`. Owner decision 2026-08-04 defers device PKI to Phase 2; the
> v1 device answer is protocol-native security (SNMPv3 `authPriv`) + honest
> labeling (`transport_authenticated=false`) + network segmentation
> (ADR-SEC-006).
> **Nothing in this document is executable. It is written properly now so it is
> ready when Phase 2 starts.** Every step is **[PENDING SEC-013…017]**.

**Decision record:** ADR-SEC-006 (device identity), ADR-SEC-002 (domain 3).
**Complements:** [`docs/runbooks/tls-mtls.md`](../tls-mtls.md) (workload mesh —
unaffected by this procedure, which is the entire point of separating the
domains), `rotate-workload-ca.md` (same dual-root mechanics, very different
blast radius), `syslog-tls-onboarding.md` and `gnmi-certificate-onboarding.md`
(the lanes whose peers hold these certificates).

---

## 1. Purpose

Rotate the trust anchor of the **device** domain (`correlix.device`) — the CA
that signs certificates held by equipment **outside Correlix's control**: syslog
senders on the RFC 5425 lane, gNMI targets, remote vantages, future site
gateways.

Why it is a separate runbook from `rotate-workload-ca.md`: the peers are on
customer premises, they are re-provisioned through the customer's change process,
their certificates cannot have 24 h TTLs, and there may be thousands of them.
The mechanics are the same dual-root ceremony; the **timescale is weeks, not
hours**, and a mistake stops customer telemetry rather than an internal hop.

## 2. Prerequisites *(all pending Phase 2)*

- [ ] Device trust domain exists and is separately rooted (ADR-SEC-002 domain 3).
- [ ] A complete device inventory: every peer holding a device certificate, its
      tenant, its device kind, its lane, and **who at the customer can
      re-provision it**.
- [ ] Device certificate TTL decided (ADR-SEC-006 U3 — unresolved).
- [ ] A distribution mechanism for the new bundle to devices, and confirmation
      that each device platform supports carrying two trust anchors during
      overlap (**many do not** — see Safety).
- [ ] Customer change windows agreed per site.
- [ ] The legacy plaintext lane still available as the fallback path.

## 3. SAFETY WARNINGS

| Risk | Detail |
|---|---|
| 🔴 **Will drop telemetry if mis-sequenced** | Every device on the secure lane stops sending the moment its certificate no longer chains to a trusted root. Unlike an internal hop, you cannot fix it by restarting a container — a truck roll or a customer change request may be required. |
| 🔴 **Some device platforms cannot hold two trust anchors** | Where dual-root overlap is impossible, rotation becomes a **flag-day per device**, and the only safe design is: fall back to the legacy declared-plaintext lane during the swap, then return. That fallback must be pre-authorized as an exception (ADR-SEC-001), not improvised. |
| 🔴 **Tenant binding must be re-verified after rotation** | Device identities carry the tenant (`spiffe://correlix.device/tenant/<t>/…`). A re-issued certificate with a wrong tenant field routes telemetry into another tenant — a **cross-tenant write**. The check-against-inventory rule (ADR-SEC-006 decision 3) must be exercised, and an identity naming an unknown tenant/device must be **rejected, never auto-created**. |
| 🔴 **Irreversible for any device already re-provisioned** | You cannot un-install a certificate remotely on equipment you do not control. |
| 🟠 **Never touches the workload domain** | If a device-CA rotation affects an intra-stack connection, the domains are not actually separate and the rotation must stop immediately — that is a design defect, not an operational one. |
| 🟠 **Rotation is a fleet-scale operation** | Batch it. A single global cutover across thousands of devices has no safe rollback. |
| ⚪ **Legacy lanes are unaffected** | Devices on the unauthenticated legacy lane keep sending throughout; that is the safety net and it must not be retired until this procedure is proven. |

## 4. Pre-validation *(pending)*

1. Reconcile the device inventory against what is actually connecting — a device
   that is not in inventory will be rejected after rotation.
2. Confirm every device's current certificate expiry; none may expire mid-window.
3. Confirm per-device dual-anchor capability; segment the fleet into
   "overlap-capable" and "flag-day" groups.
4. Confirm the legacy lane and its declared exceptions are live for the flag-day
   group.
5. Baseline per-device event rates so a post-rotation drop is detectable.
6. Rehearse on a pilot group of low-criticality devices in one tenant.

## 5. Procedure *(all steps **[PENDING SEC-013…017]**)*

1. Generate the new device root; seal its key (ADR-SEC-007 discipline applies
   identically).
2. Publish **both** device roots in the trust bundle used by the **collectors**
   (syslog TLS listener, gNMI, vantage ingest). Correlix-side first, always.
3. Confirm collectors accept certificates from both roots. Verify with a test
   device before touching any real one.
4. **Batch 1 (pilot):** re-issue and install new-root certificates on a small,
   low-criticality set. Verify each device reconnects, is authenticated, and lands
   in the **correct tenant**.
5. Verify no batch-1 device auto-created a tenant or device record.
6. **Batches 2..N:** proceed by tenant/site with per-batch verification. Never
   run two batches concurrently in the same tenant.
7. **Flag-day group:** move each device to the legacy declared-plaintext lane,
   swap the anchor, return it to the secure lane, verify, and close the temporary
   exception explicitly.
8. Soak the full fleet on the new root for the agreed window.
9. Retire the old device root from the collector bundles. ⚠ **Point of no
   return** for any device not yet migrated.
10. Update device transport-policy records and close the rotation ticket.

## 6. Rollback *(pending)*

| Stage | Action |
|---|---|
| Steps 1–3 | Remove the new root from the collector bundle. No device touched. |
| Steps 4–8 | Both roots trusted → any device may revert to its old certificate; per-device rollback is available but requires touching the device. |
| Step 7 (flag-day) | Device sits on the legacy plaintext lane until resolved — telemetry continues, authenticity does not. Exception must remain open and visible. |
| After step 9 | **No rollback.** Any device still on the old root is silently dark. Recovery = re-add the old root to the collector bundle immediately, then complete migration. |

## 7. Audit evidence to capture *(pending)*

- Old/new device-root fingerprints and validity windows.
- Per-batch device lists with issue timestamps and the tenant asserted vs the
  tenant registered — the cross-tenant evidence.
- Every rejected connection during the window, with reason
  (`unknown device`, `tenant mismatch`, `untrusted chain`).
- Every temporary legacy-lane exception opened for the flag-day group, with
  owner and closure timestamp.
- Per-device event-rate before/after, proving no silent telemetry loss.
- Customer change-request references per site.

## 8. Post-checks *(pending)*

1. Every device on the secure lane chains to the new root; zero old-root chains.
2. Zero `tenant mismatch` rejections; zero auto-created tenants or devices.
3. Per-tenant event volumes match the pre-rotation baseline.
4. No device silently moved to the legacy lane and stayed there — reconcile the
   exception table against the policy table.
5. Workload-domain metrics untouched throughout (proof of domain separation).
6. Device-certificate expiry monitoring re-pointed at the new issuance.
