# Correlix Security v1 — Scope

**Status: scope FROZEN by owner decision 2026-08-04.** Changes to this file
require owner approval; it is the contract the HLD, LLD, backlog and posture
page are measured against.

Companions: `CORRELIX_SECURITY_CLAIMS.md` (what we may/may not say),
`CORRELIX_SECURITY_EVIDENCE_MATRIX.md` (what is actually implemented),
`CORRELIX_SECURITY_DESIGN_ERRATA.md` (what we got wrong and fixed),
`CORRELIX_SECURITY_OPEN_UNKNOWNS.md` (what we do not know yet).

---

## 1. The one-sentence boundary

> **Security v1 secures the components Correlix controls.** It does not secure
> the wire between a customer's devices and our collectors, because we do not
> control those devices and several of those protocols cannot be secured at all.

Everything below follows from that sentence.

---

## 2. In scope (P0 — all twelve are v1)

| # | Control | Why it is v1 |
|---|---|---|
| 1 | Architecture + security documentation reconciliation | Design decisions built on stale docs are worthless; drift is already proven (§7 of the HLD) |
| 2 | Security inventory with **evidence classification** | Every control labeled verified / disabled / partial / documented-only / proposed / unknown / contradicted. No claim without a file path |
| 3 | Versioned environment profiles (lab · development · staging · production) | The mechanism that keeps insecure defaults out of production while lab keeps working |
| 4 | **Production fail-closed validator** (executable) | Prose cannot enforce anything. This is the control that makes every other control real |
| 5 | Browser → nginx HTTPS | Already shipped 2026-08-03; v1 hardens and validates it |
| 6 | nginx → API mTLS | The first internal hop, and the one whose machinery already exists |
| 7 | Production-required secret sealing | Closes the verified plaintext-CA-key foot-gun and the unseal-fallback path |
| 8 | **Correlation service authentication + authorization review and remediation** | Unauthenticated *and* cross-tenant-capable — the single most serious finding |
| 9 | Protection of the highest-risk **unauthenticated** datastore paths | Prioritized in §4, not blanket-applied |
| 10 | Minimal read-only security posture page | The customer-visible deliverable, and our own drift detector |
| 11 | Failure-behavior tests | A control without a test proving it *fails* correctly is a claim, not a control |
| 12 | Operator runbooks + rollback procedures | Every v1 change must be reversible by someone who did not design it |

---

## 3. Out of scope for v1 (deferred, designed, not built)

Each is fully designed in the LLD and retained there so Phase 2 is a scheduling
decision rather than a re-derivation.

| Deferred | Why deferred | Becomes needed when |
|---|---|---|
| Kafka TLS + ACL migration | Highest telemetry-loss risk in the programme; **gated separately** (§6) | Evidence shows it is required for the minimum claim, or a customer demands bus encryption |
| Full ClickHouse mTLS rollout | Row policies already carry the tenant boundary; transport is the smaller risk | After the P0 datastores |
| Universal SPIFFE/SPIRE rollout | Our own CA already issues SPIFFE-shaped IDs; SPIRE adds an operational component for no v1 gain | Multi-cluster or federated deployments |
| Service mesh | No Kubernetes substrate exists; cannot secure devices; would mask insecure backends | Kubernetes + generic HTTP/gRPC scale-out |
| Device PKI · syslog TLS fleet · SNMPv3 fleet migration · gNMI certificate lifecycle · flow gateways · device enrollment/rotation | We do not control customer devices, and **not all devices support certificates or mTLS** | Sold as a commercial capability, or a customer's estate is uniformly capable |
| Separate backup-encryption key domain | Owner decision #1 — a second key hierarchy must not be half-built | A customer requires verifiable backup encryption |
| Advanced compliance evidence packages | Commercial capability, not a safety control | Regulated customers |
| Broad Kubernetes migration | #114 not started | k8s packaging ships |

**Rule that governs this list:** *"Do not let 'secure every datastore' become an
unbounded rewrite."* Prioritize by exposure, tenant risk and deployability.

---

## 4. Datastore prioritization method

Assignment is `v1-mandatory` / `v1-only-if-dependency` / `deferred`, decided on
seven axes: unauthenticated exposure · tenant impact · host-or-internet
exposure · privilege level · ease of exploitation · migration risk ·
availability impact. **No datastore is P0 by default.** The evidence and the
resulting table live in the evidence matrix and HLD §7; the shortlist under
investigation is OpenSearch (Security plugin disabled), Valkey (anonymous
access), VictoriaMetrics (direct unauthenticated access),
correlation→ClickHouse identity/privilege, and PostgreSQL TLS + service auth.

---

## 5. Security claim boundary

**Approved statement (verbatim, owner-approved):**

> "Correlix secures communications between Correlix-managed services and
> protects stored application secrets and tenant access boundaries. Security of
> telemetry between customer devices and collectors depends on the protocol and
> device configuration."

**Prohibited:** *"Correlix provides end-to-end encrypted telemetry."*

Device-plane work permitted in v1 is limited to: inventory · posture
visibility · explicit legacy/insecure labeling · production validation of
already-supported secure configurations where practical. Nothing else.

Full text, including questionnaire language, in `CORRELIX_SECURITY_CLAIMS.md`.

---

## 6. Product packaging boundary

**Base product — included, enabled by default, never withheld to create an
upsell:** HTTPS ingress · internal TLS for v1-covered paths · workload/service
authentication · certificate + hostname verification · no silent plaintext
fallback · tenant authorization · production fail-closed validation · required
secret sealing · basic read-only posture visibility · certificate-expiry
warnings · clear legacy/insecure findings.

**Potential commercial capabilities:** customer-managed keys · external KMS/HSM
integration · advanced key-rotation workflows · device PKI enrollment and
lifecycle · compliance evidence packages · signed posture reports · long-term
security audit retention · multi-region key hierarchies · automated standards
mappings.

**Governing rule:** *do not create artificial insecurity in the base edition to
manufacture a paid upgrade.* The minimal posture page is a **v1 base
requirement**, not a paid feature.

---

## 7. Backup encryption (owner decision #1)

- Backup-specific encryption with a separate key domain is **explicitly out of
  v1**, recorded here as a **known deferred gap**.
- **We may not claim "all data at rest is encrypted"** unless backups are
  covered. They are not.
- The posture page must **raise a finding when backup encryption cannot be
  verified**, shown as `deferred / unverified` — never as green.
- **Production automated backups must not silently write to an unencrypted
  destination.** v1 satisfies this by *requiring an operator-provided encrypted
  volume or destination* and failing/telling the operator when it is absent —
  not by encrypting inside the product.
- The future backup key boundary is **designed** (keys separate from live
  service credentials and from transport PKI) and **not implemented**. A second
  key hierarchy must not be half-built.

---

## 8. Dependencies

| v1 item | Depends on |
|---|---|
| nginx → API mTLS (6) | Secret sealing (7) + CA bootstrap — enabling the CA without sealing writes a **plaintext CA key**, so sealing is a hard prerequisite, not a parallel task |
| Datastore protection (9) | Validator (4) to prove the state, profiles (3) to keep lab working |
| Posture page (10) | Inventory (2) + validator (4) — the page renders *their* output; it must never compute "secure" independently |
| Everything | Documentation reconciliation (1) + evidence classification (2) |

---

## 9. Acceptance criteria

v1 is complete when **all** of the following are true and demonstrable:

1. A production profile missing any required control **refuses to start**, with
   an error naming the control, component, config source, observed value,
   required value, and remediation.
2. Browser→nginx is HTTPS; nginx→API is mTLS with SAN verification; an
   unrelated valid workload identity is **rejected**.
3. Production cannot start with sealing unavailable; no plaintext fallback
   exists; secret values never appear in logs.
4. The correlation service rejects unauthenticated callers, is not publicly
   reachable, uses a dedicated ClickHouse identity that cannot alter schema or
   row policies, and **a tenant caller cannot cause an arbitrary cross-tenant
   read** — proven by test.
5. Each datastore marked v1-mandatory rejects unauthenticated access, proven by
   test.
6. ClickHouse strict row policies survive bootstrap **and** access-storage reset
   paths, proven by test.
7. The posture page shows every v1 control with an honest state —
   `configured / observed / unknown / failed / not applicable / deferred` — and
   shows **"unverified"** wherever runtime verification is absent.
8. Backup encryption shows as `deferred / unverified`, never green.
9. Device-plane telemetry is labeled outside-v1 or legacy, and no prohibited
   claim appears in product, docs or UI.
10. Every v1 change has a runbook and a tested rollback.
11. Telemetry does not stop unexpectedly as a result of v1 changes.
12. No control is marked implemented anywhere without repository evidence.

---

## 10. Explicit non-goals

- Securing customer device→collector wire protocols.
- Claiming end-to-end telemetry encryption.
- Encrypting backups inside the product.
- Migrating Kafka (unless §6 gating says otherwise).
- Deploying a service mesh, SPIRE, or Kubernetes.
- Rewriting tenant isolation — it is already database-enforced and must not be
  weakened to simplify anything here.
- A broad `IGNORE_SECURITY_ERRORS` production switch. **Prohibited outright.**

---

## 11. Risks

| Risk | Mitigation |
|---|---|
| Fail-closed stops a production upgrade | Precise errors + runbook + staging rehearsal; accepted deliberately by the owner |
| Correlation remediation breaks RCA | Separate *legitimate platform scope* from *unauthenticated unrestricted access* — do not blindly force tenant scoping |
| Datastore auth breaks ingestion | Per-store staged rollout, dual-credential window, continuity tests |
| Posture page over-claims | States distinguish configured vs observed; absent runtime verification renders **unverified** |
| Scope creep into Kafka/devices | This document is the contract; changes need owner approval |
| Emergency exceptions become permanent | Narrow, owned, justified, audited, time-bounded, **auto-expiring** |

---

## 12. Approval gates

| Gate | Requires |
|---|---|
| G0 → start | This scope + claims + evidence matrix reviewed by the owner |
| G1 → enable mTLS on any path | Sealing enforced; rollback rehearsed |
| G2 → correlation remediation | Investigation conclusion accepted; platform-scope justification agreed |
| G3 → datastore changes | Per-store prioritization accepted; continuity tests green |
| G4 → production fail-closed **enforcing** (not warn-only) | All v1 tests green; runbooks published |
| G5 → any Kafka work | Separate explicit authorization (owner decision #6) |
| G6 → any device-plane work | Separate explicit authorization (owner decision #2) |
