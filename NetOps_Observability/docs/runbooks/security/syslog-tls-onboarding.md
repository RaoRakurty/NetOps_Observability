# Runbook (OUTLINE) — Onboard a device onto the secure syslog lane (RFC 5425)

> **Status: PHASE 2 — OUTLINE ONLY, FEATURE NOT YET BUILT.**
> There is no TLS syslog lane. `deployment/docker/syslog-ng/syslog-ng.conf:84-85`
> listens on UDP **and** TCP port 514 only, and the config's own comment at
> `:42-43` states that this source has "NO ACL and NO authentication: the
> hostname is an UNVERIFIED CLAIM by whoever sent the packet." Owner decision
> 2026-08-04 defers device PKI to Phase 2; the v1 answer for syslog is **honest
> labeling + segmentation**, not encryption (ADR-SEC-006).
> Every step below is **[PENDING SEC-013/014]**. Nothing here is executable.

**Decision record:** ADR-SEC-006 (device identity), ADR-SEC-002 (device trust
domain), ADR-SEC-001 (`accept`-set migration).
**Complements:** [`docs/runbooks/tls-mtls.md`](../tls-mtls.md) (workload mesh —
different domain, different lifecycle), `rotate-device-ca.md`,
`docs/INGESTION.md`.

---

## 1. Purpose

Move a device from the unauthenticated syslog lane (UDP/TCP 514) to an
**RFC 5425 syslog-over-TLS lane on 6514** with a client certificate, so that
**tenancy is bound to the certificate instead of to a spoofable hostname.**

This is the single highest-value integrity improvement available to the
ingestion plane — and the one with the most customer-side cost.

## 2. What v1 does instead (do this today)

Until Phase 2 ships, a device onboarding onto syslog gets:

1. A device record and a `device_tenant.csv` entry — Vector's enrichment table is
   the **only** authority on tenancy (`deployment/docker/vector/vector.yaml:391`,
   lookups at `:409,469,576,593`).
2. `transport_authenticated=false` on its events, and a **declared plaintext
   exception** with owner and expiry in the transport-policy table
   **[PENDING SEC-001]**.
3. Network controls: dedicated telemetry VLAN/interface, source allowlist, rate
   limiting (HLD §6.6).
4. **No claim of authenticity anywhere** — not in the UI, not in an RCA evidence
   chain, not in a report.

## 3. Prerequisites *(Phase 2)*

- [ ] Device trust domain exists (ADR-SEC-002 domain 3, deferred).
- [ ] The 6514 TLS listener exists on syslog-ng (`tls()` block) **or** on the
      Vector `syslog_in` source — decided, not both.
- [ ] The device is **registered** with a device record and a tenant. Enrolment
      is an explicit admin act; ingestion must never create it.
- [ ] The device platform supports syslog over TLS with a client certificate
      (many do not — check before promising it).
- [ ] Customer change window and a rollback path to the legacy lane.

## 4. SAFETY WARNINGS

| Risk | Detail |
|---|---|
| 🔴 **WILL drop this device's logs if mis-sequenced** | Syslog has no retry and no buffer on most devices. Anything sent while the lane is misconfigured is **gone** — there is no backfill. Keep the legacy lane accepting throughout the cutover. |
| 🔴 **Tenant misbinding is a cross-tenant write** | The certificate carries `tenant/<tenant_id>`. It must be **checked against the registered device record**; a mismatch is rejected. An identity naming an unknown tenant or device is rejected and **never auto-creates** either (ADR-SEC-006 decision 3). Getting this wrong puts one customer's logs in another customer's index. |
| 🔴 **Do not retire the legacy lane per-device on the same day** | Overlap is the safety net. Retire only after sustained verified delivery on the secure lane. |
| 🟠 **UDP 514 cannot be secured at all** | If the device only speaks UDP syslog, this runbook does not apply — it stays a declared exception with segmentation (HLD §6.6). Say so plainly rather than implying a partial fix. |
| 🟠 **Certificate expiry on a device is an outage you cannot fix remotely** | Device TTLs are unresolved (ADR-SEC-006 U3). Whatever is chosen, expiry monitoring must exist before the first device is onboarded. |
| 🟠 **Hostname-based enrichment and certificate-based tenancy must agree** | Two authorities on tenancy is a defect. A disagreement must be alertable, not silently resolved by precedence. |
| ⚪ **Reversible per device** | Point the device back at 514 until the legacy lane is retired. |

## 5. Pre-validation *(Phase 2)*

1. Confirm the device is registered, with the correct tenant, before issuing
   anything.
2. Confirm the device's syslog-TLS capability and its trust-store behaviour.
3. Baseline the device's current event rate on the legacy lane — this is how you
   detect a silent cutover failure.
4. Verify the 6514 listener with a test client before touching the device.
5. Confirm `device_tenant.csv` and the device record agree.

## 6. Procedure *(all steps **[PENDING SEC-013/014]**)*

1. Issue the device certificate under the device domain with the identity
   `spiffe://correlix.device/tenant/<tenant_id>/kind/device/id/<device_id>`.
2. Deliver the certificate, key and CA bundle to the device through the
   customer's change process. **Correlix never holds the device's private key.**
3. Configure the device to send syslog over TLS to 6514, **while continuing to
   send on the legacy lane** (accept-set widened: `[plaintext, mtls]`).
4. Verify on the Correlix side: the connection authenticates, the certificate's
   tenant matches the registered device, and events arrive with
   `transport_authenticated=true`.
5. Verify **no duplication** downstream, or accept and document it for the
   overlap period.
6. Soak for the agreed period at the baseline event rate.
7. Stop the legacy lane for this device; narrow the accept-set to `[mtls]`.
8. Close the plaintext exception for this device explicitly
   **[PENDING SEC-001]**.

## 7. Rollback *(Phase 2)*

| Stage | Action |
|---|---|
| 1–2 | Nothing sent; discard the certificate. |
| 3–6 | Device is on both lanes; simply stop the TLS sender. Zero loss. |
| 7 | Re-enable the legacy sender on the device (requires a customer change) and re-open the exception. Logs sent in between are lost. |

## 8. Audit evidence to capture *(Phase 2)*

- Device record, tenant, and the certificate's SPIFFE URI + fingerprint.
- Proof the tenant in the certificate was **checked against inventory**, and the
  result.
- Customer change reference and the operator on both sides.
- Event rates on both lanes across the overlap, proving continuity.
- The moment `transport_authenticated` flipped to `true` for this device.
- Exception closure record with timestamp.

## 9. Post-checks *(Phase 2)*

1. Events arrive on 6514 only; the legacy lane is idle for this device.
2. `transport_authenticated=true` on every event from it.
3. Tenant routing correct — spot-check that events land in the right tenant's
   index and **only** there.
4. Event rate matches the pre-cutover baseline (no silent partial loss).
5. Zero `tenant mismatch` / `unknown device` rejections for this device.
6. No tenant or device record was auto-created during the process.
7. Certificate expiry registered in monitoring.
8. Policy row shows `accept: [mtls]` with no open exception.
