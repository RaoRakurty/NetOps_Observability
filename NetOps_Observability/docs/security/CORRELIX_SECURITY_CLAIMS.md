# Correlix Security Claims — what we may and may not say

**Status: owner-approved 2026-08-04. Evidence status refreshed 2026-08-12**
after the tracker #151 programme (enforce wave 2026-08-09 → 13-phase assurance
run → step-3 fixes F-1…F-12 incl. F-11 seal-or-quarantine); see §2a. This
document governs marketing copy, sales answers, security questionnaires, the
product UI, and the docs portal. If a claim is not listed as permitted here,
it may not be made.

**The governing principle:** a security claim is a *promise about behavior*.
Every claim below is paired with the evidence that must exist before it is
spoken. A claim we cannot evidence is a claim we cannot make — and if a
customer later discovers the gap, we lose far more than the deal it won.

---

## 1. The approved statement (verbatim)

> "Correlix secures communications between Correlix-managed services and
> protects stored application secrets and tenant access boundaries. Security of
> telemetry between customer devices and collectors depends on the protocol and
> device configuration."

Use this sentence, or a subset of it, as the anchor for any security
conversation. It is deliberately precise about where our control ends.

---

## 2. Claims Correlix MAY make (once the evidence exists)

| # | Permitted claim | Evidence required before saying it |
|---|---|---|
| C1 | "Communications between Correlix-managed services are encrypted with TLS." | Every v1-covered path verified at BOTH ends; production validator enforcing; posture page showing `observed` (not merely `configured`) |
| C2 | "Service-to-service connections are mutually authenticated with certificates issued by the deployment's internal CA and rotated automatically." | mTLS live on v1 paths; SAN verification on; auto-reissue proven; a *wrong* identity proven rejected by test |
| C3 | "Browser traffic to Correlix is served over HTTPS with modern TLS." | Ingress TLS shipped + validator check + no plaintext listener published in production |
| C4 | "Application secrets are encrypted at rest with per-tenant keys, and production refuses to start if sealing is unavailable." | Sealing enforced in production profile; unseal-failure test; secrets absent from logs test |
| C5 | "Tenant data access is enforced in the database, not only in application code." | ClickHouse row policies + Postgres FORCE-RLS + the tests that fail when a policy is written leniently |
| C6 | "Correlix refuses to start in production when a required security control is missing or invalid, and tells you exactly which one." | Validator implemented, each prohibited configuration covered by a test asserting the specific error |
| C7 | "Correlix shows you its own security posture, and marks anything it cannot verify as unverified." | Posture page live, states distinguish configured / observed / unknown / failed / n-a / deferred |
| C8 | "Telemetry that arrives over unauthenticated protocols is labeled as such." | The labeling implemented end-to-end (note: this is NEW work — see errata E7) |
| C9 | "When sealing custody is enabled, telemetry that cannot be attributed to a tenant is quarantined encrypted under a dedicated key scope — it is never stored in plaintext because attribution failed." | F-11 verdict PASS + F11.1–F11.12 acceptance battery run live (assurance report, step-3 2026-08-12 section); isolation guard `TestQuarantineIndexUnreachableFromTenantPaths`; workflow gates `TestQuarantineRoutesArePlatformOnly` + `TestQuarantineReattributeRequiresSensitiveDataAdmin`; retention policy `netops-quarantine-retention` attached |

**Rule for all of the above: none may be spoken while the control is
`implemented but disabled`.** Built-and-off is not a security property.
C9 carries this rule *inside its own wording*: the quarantine seal exists only
when sealing custody (`FEATURE_SEALED_FIELDS` + a seal provider) is enabled —
that is the feature's own boundary (with custody off, no tenant sealing exists
either, so there is no attribution asymmetry). For a deployment running
without sealing custody, C9 may not be spoken at all.

---

## 2a. Evidence status — 2026-08-12 (tracker #151, steps 1–3)

Dated status per claim. "EVIDENCED" means the required evidence exists TODAY
and is cited; anything less says exactly what is missing. Sources: the
13-phase run + step-3 fix log in
`TLS_ASSURANCE_REPORT_2026_08.md` ("the report"), the as-built
`transport-inventory.yaml` / `mtls-edges.yaml`, and named tests.

- **C1 — EVIDENCED, with declared exceptions (2026-08-12).** Report phase 3
  (all 34→56 inventory edges compared achieved-vs-target, every deliberate
  plaintext row carries a dated `exception`), phase 5 (wire identity verify=0
  per endpoint), F-1 fix 2026-08-11 (the last undeclared intra-stack plaintext
  hop, syslog-ng→aggregator, converted to mesh TLS + required client cert).
  The honest exceptions, all declared in `transport-inventory.yaml`:
  `device-goflow2` (protocol cannot encrypt) and lab-only mocks;
  `goflow2-kafka` rides TLS-**anon** on FLOWS:9095 per owner option-1
  (encrypted + ACL-bounded, not client-authenticated); `api-gotenberg` and two
  metrics-scrape hops remain declared plaintext pending owner decision (F-5
  rows). Device-side legs are outside this claim per the §1 anchor sentence.
- **C2 — EVIDENCED for the contracted mesh edges (2026-08-12).** Report
  phase 4 (28/28 registry SVIDs on disk, exact SPIFFE URI SANs, one CA
  bundle), phase 5 (9/9 wire), phase 6 (wrong-identity refused AND observable
  via `netops_tls_identity_rejected_total`), phase 10 (three consecutive
  rotations, distinct serials, zero lane interruption). Say it per-path, per
  `mtls-edges.yaml`: two owner-accepted shapes are authenticated but not
  client-cert mutual — OpenSearch clients use per-identity basic-in-TLS and
  goflow2 is TLS-anon (F-3, decisions recorded in the rows' `target.notes`).
- **C3 — EVIDENCED on the enforced lab state; one shipped-variant exception
  (2026-08-12).** Report phase 5 (ingress TLS, HSTS, HTTP/2) + phase 12
  (handshake latency). Plaintext `:8000` was removed on the lab 2026-08-09
  (`browser-nginx` inventory row), but `compose.tls.yml` still publishes
  `:8000` until `install.py` messaging is TLS-aware — so "no plaintext
  listener published" may NOT yet be claimed for a fresh shipped install.
- **C4 — EVIDENCED (2026-08-12).** Sealing custody live (`SEAL_PROVIDER=swtpm`,
  installer default), CA-key seal gate boot refusal + tests (2026-08-04),
  `REQUIRE_SEAL` fail-closed path, secprofile sealed-secrets rule; per-tenant
  sealed-fields e2e re-run PASS 2026-08-11 (report step-3: sealed doc in
  tenant index, zero plaintext, audited unseal round-trip); key-unavailable ⇒
  Vector exit-78 refusal, live-demonstrated (report F11.6/F11.7).
- **C5 — EVIDENCED (2026-08-12).** ClickHouse row policies + Postgres
  FORCE-RLS; `TestAppRoleCannotBypassRLS` executed live and green with the
  restored pgintegration suite, 6/6 proofs (F-12 fix 2026-08-11); report
  phase 11 full Go isolation suite PASS.
- **C6 — EVIDENCED (2026-08-12).** `internal/secprofile` (16 rules, per-rule
  tests naming the exact control/observed/required values); live boot
  validator fatal=0 warn=1 (BKP-001, deferred) at the assurance-run start.
  Honest gap, keep stating it: no secprofile rule yet covers the bus or the
  ingest lanes (INVARIANTS §8) — a prod boot with a plaintext bus would not
  be refused by the validator today.
- **C7 — EVIDENCED (2026-08-12).** SEC-020.1/021.1 posture page + exportable
  report (states configured/observed/unknown/failed/n-a/deferred); tlsprobe
  wire-watches 10 endpoints (`probe_ok`, expiry); SEC-020.2 posture drift
  alerts, promtool-tested.
- **C8 — PARTIAL (2026-08-12) — do not claim fully.** What exists: the
  posture view labels the unauthenticated-protocol device lanes as such
  (`secobs.DeviceLaneRows`, SEC-021.1); per-event attribution stamps
  (`tenant_attribution`, `tenant_registry`) on the device lanes (F-11 work);
  the trap lane's `authenticated` field. What errata E7 requires for the full
  claim — a stack-wide per-event `transport_authenticated` stamp — is still
  NOT built (the string exists only in a secprofile remedy text). C8 may be
  spoken only in its lane-level/posture-view form.
- **C9 — EVIDENCED, boundary stated (2026-08-12).** Report step-3 F-11
  section: verdict PASS after the live F11.1–F11.12 battery — unknown-identity
  telemetry lands in `netops-quarantine-*` with the whole event sealed
  (`<enc:v1:quarantine:…>`), unreachable from every tenant/dashboards/
  correlation read path, restorable only through the audited, doubly-gated
  re-attribution workflow, retention-bounded (30 d ISM policy attached;
  30-day wall-clock deletion not simulated). BOUNDARY: holds only when
  sealing custody is enabled — see the rule note above. Known residuals are
  stated in the report §8 (syslog hostname-spoof *injection*, Kafka
  segment retention bytes, the pre-existing plaintext deadletter index).

---

## 3. Claims Correlix MUST NOT make

| # | Prohibited claim | Why it is false or unprovable |
|---|---|---|
| P1 | **"Correlix provides end-to-end encrypted telemetry."** *(explicitly prohibited by the owner)* | The device→collector leg is outside our control. NetFlow/sFlow/syslog-UDP/SNMPv2c cannot be authenticated at all |
| P2 | "All data at rest is encrypted." | Backup encryption is explicitly out of v1. Until backups are covered, this is false |
| P3 | "Correlix is compliant with SOC 2 / ISO 27001 / PCI / HIPAA." | A product is not compliant; an organization's *deployment* achieves compliance. We may say the product *supports controls required by* those frameworks |
| P4 | "Device telemetry is authenticated." | True only for SNMPv3 authPriv and only where the customer configured it. Never as a blanket statement |
| P5 | "Our internal network is secure because containers share a private Docker network." | Network topology is not authentication. Explicitly rejected as a design position |
| P6 | "TLS means access is authorized." | TLS authenticates a peer; authorization is row policies, RLS, ACLs and RBAC. Never conflate them |
| P7 | "Zero trust" as an unqualified product claim | Only defensible per-path, with evidence. Use the specific claim instead |
| P8 | "Encryption is available as a premium upgrade." | Base-product security is included by decision. Withholding it would be both a bad-faith and a competitively fatal position |
| P9 | Any claim about a control that is `implemented but disabled` | Built ≠ enforced. This is the single easiest way to make an untrue statement in good faith |

---

## 4. Customer security-questionnaire language

Copy-paste answers. Each is honest under the current state and remains honest
after v1 ships.

**"Is data encrypted in transit?"**
> Between Correlix-managed services, yes — TLS with mutually authenticated
> certificates issued by the deployment's internal CA and rotated
> automatically. Browser access is HTTPS. Telemetry sent from your network
> devices to our collectors is secured according to what each protocol and
> device supports: SNMPv3 with authPriv and syslog over TLS are supported where
> your devices offer them, while NetFlow, sFlow and classic syslog are
> unauthenticated by protocol design and should be carried on a management
> network. Correlix labels telemetry that arrives over unauthenticated
> transports so you can see exactly what is and is not authenticated.

**"Is data encrypted at rest?"**
> Application secrets are encrypted with per-tenant keys under a sealed root
> key. Datastore volume encryption and backup encryption are the responsibility
> of the deployment environment — Correlix requires an operator-provided
> encrypted volume or destination for backups and reports when that cannot be
> verified. We do not claim product-level backup encryption.

**"How is multi-tenancy enforced?"**
> In the database, not only in application code: ClickHouse row policies and
> PostgreSQL row-level security scope every query to the caller's tenant, with
> per-tenant indices in the search store, plus role-based authorization in the
> API. Automated tests fail the build if a tenant policy is written permissively.

**"How do services authenticate to each other?"**
> With X.509 certificates carrying SPIFFE-style workload identities, issued by
> the deployment's internal certificate authority, short-lived and rotated
> automatically. Peer identities are allowlisted per connection; hostname and
> SAN verification are mandatory and cannot be disabled in production.

**"What happens if security is misconfigured?"**
> Production refuses to start and names the exact control, component,
> configuration source, observed value and required value, with a link to the
> remediation runbook. There is no global override switch. Emergency exceptions
> are narrow, owned, justified, audited, time-bounded and expire automatically.

**"Do you support customer-managed keys / HSM?"**
> Not in the base product today. It is on the roadmap as a commercial
> capability; the key hierarchy is designed to accommodate an external KMS or
> HSM without changing the application.

---

## 5. Device-telemetry limitations (say these plainly)

| Protocol | What we can honestly say |
|---|---|
| SNMPv3 (authPriv) | Authenticated and encrypted by the protocol, **when the customer configures it**. Correlix supports and can require it per device |
| SNMPv1/v2c | **Unauthenticated and cleartext.** Community strings are not credentials in any meaningful sense |
| SNMP traps v1/v2c | **Spoofable.** Correlix already marks these as unauthenticated in the event record |
| Syslog over TLS (RFC 5425) | Supportable — device-plane work is deferred; do not imply it ships today |
| Syslog UDP/TCP 514 | **Unauthenticated; the hostname is an unverified claim.** Carry on a management network |
| NetFlow / IPFIX / sFlow | **Unauthenticated UDP; the exporter address is spoofable.** No cryptographic authenticity is possible in-protocol |
| gNMI | TLS-capable; certificate lifecycle management is deferred. Do not claim managed device certificates |

---

## 6. Backup limitations (say these plainly)

- Correlix does **not** provide backup-specific encryption with its own key
  domain in v1. It is a known, documented, deferred gap.
- Production backups must target an **operator-provided encrypted volume or
  destination**; Correlix reports when encryption cannot be verified rather
  than silently writing to an unencrypted target.
- Backup keys, when built, will be **separate from live service credentials and
  from the transport PKI**. That separation is designed, not implemented.
- Therefore: **never answer "yes" to "are backups encrypted?"** on our behalf.
  The correct answer is that it depends on the destination the operator
  provides, and Correlix surfaces the verification state.

---

## 7. Review rule

Any new security claim — in a deck, a datasheet, the UI, the docs portal, or a
questionnaire response — must be added to §2 with its evidence requirement
before it is used externally. If it cannot be evidenced from the repository or
a live posture reading, it does not ship.
