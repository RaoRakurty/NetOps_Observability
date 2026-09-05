# Correlix licensing model (design of record, 2026-09-04)

Owner decisions this document implements: root licence = **Apache-2.0 open core with
clearly separated commercial add-ons**; tiers Community / Team / Enterprise with the cut
lines in `TIERING_PLAN_2026-09-03.md`; the licensing story must be identical in the source
tree, the container manifests, the About/licences UI and the shipped third-party notices.
Owner spec of 2026-09-04 (afternoon) is BINDING and refines this document: one repository,
one binary, a REAL directory boundary (`enterprise/`), SPDX headers (`Apache-2.0` /
`LicenseRef-Correlix-Enterprise`), core never imports enterprise (stdlib import checker in
CI, fail closed on unclassified directories), a machine-readable `licensing-policy.json`
that `LICENSING.md` mirrors, a concise mixed-licence root `LICENSE` (never the bare Apache
text), `LICENSES/Apache-2.0.txt` + `LICENSES/Correlix-Enterprise.txt` (the latter ONLY when
lawyer-approved — **no invented legal text**, same for the CLA), central semantic
entitlements (FeatureSAML, FeatureSCIM, FeatureLDAP, FeatureSIEMExport,
FeatureSecurityDialects, FeatureMSPManagement, FeatureSecurityFindings) instead of tier
checks, and the invariant that a licence problem can never weaken isolation, RLS, authz,
integrity or core authentication (OIDC stays core).
Companion documents: `LICENSING.md` (generated from `licensing-policy.json`), `LICENSE`
(mixed-licence notice), `LICENSES/`, `NOTICE`, `THIRD_PARTY_NOTICES`,
`TIERING_PLAN_2026-09-03.md` (tiers), `docs/security/LICENSE_AUDIT_2026-09-03.md`.

## 1. Two licences, one repository, one binary
| | Core | Commercial add-ons |
|---|---|---|
| Licence | Apache-2.0 (`SPDX-License-Identifier: Apache-2.0`) | Correlix Enterprise (`SPDX-License-Identifier: LicenseRef-Correlix-Enterprise`) — **text to be approved by counsel; not written here** |
| Where | every path `licensing-policy.json` maps to Apache-2.0 | `enterprise/**` (physically bounded); core → enterprise imports are forbidden and CI-checked; only the assembly layer (`cmd/`, root wiring) imports both |
| What (LOCKED) | collection, correlation and topology fundamentals, **tenant isolation + RLS/data separation (safety property, never entitlement-gated)**, OIDC, normal single-tenant operation, the entitlement abstractions, Community ceilings (25 devices, 5 watched prefixes — product limits inside Apache code) | Team: security findings. Enterprise: security dialects, SIEM export, MSP/fleet management of many tenants, SAML, SCIM, LDAP. Everything else in the tiering plan is a PROPOSAL, not gated until decided. |
| Build | one binary, one image set (tiers are data, not builds) | same binary; the code is present but gated by the licence file (§3) |
| Contributions | CLA required (keeps relicensing rights) | same CLA |

Why one binary: the tiering plan's rule "enforce by data, not by hiding code" — customers
upgrade by installing a licence file, never by swapping images; the offline bundle stays
one artifact. The commercial code being readable is deliberate (source-available); the
enforcement is contractual plus the gate below. Isolation is never commercial: it is a
safety property of every tier.

## 2. Tiers (decided)
Community: 25 MONITORED devices (discovery is unlimited and free), 1 tenant, 7-day retention, 5 watched prefixes, hardening + exposure
with the default two frameworks, evidence-only Iris. Team: 250 devices, 5 tenants / 1 org,
30-day retention, 100 prefixes + BMP, security findings + frameworks + drift + pcap + threat
lane + advisory, BYO provider key. Enterprise: unlimited per licence, org hierarchy, 90-day +
archive, unlimited prefixes, all dialects + SIEM export + 90-day findings retention, hosted
provider quota, SAML/SCIM, reports, 24×7 support. (Full table in the tiering plan.)

## 2a. Tiering is not licensing
Source licence (Apache-2.0 / Correlix Enterprise) and runtime entitlement (Community /
Team / Enterprise) are separate axes: Apache code carries Community product limits; an
Enterprise-licensed file may implement a Team feature. Business code asks "is feature X
entitled?" through one central entitlement service, never "is this Enterprise?".

## 3. The licence file (mechanism)
- **Format:** JSON, signed with ed25519 (Go stdlib `crypto/ed25519`), detached signature
  base64 in the same file. Fields: `licence_id`, `customer`, `tier`, `issued_at`, `expires_at`,
  `ceilings{devices, tenants, orgs, retention_days, watched_prefixes, skills, provider_tokens_per_day}`,
  `features[]` (closed vocabulary), `support{level, contact}`, `grace_days`.
- **Keys:** Correlix holds the private key offline (HSM/air-gapped signer, key ceremony
  recorded); the public key is embedded in the binary AND printed in the docs so a customer
  can verify a file themselves. Key rotation: the binary carries the current + previous key.
- **Install:** upload on the platform-admin Licence page or drop the file at
  `data/api/licence.json`; validated at boot and on change; the page shows customer, tier,
  ceilings, expiry, and what the current usage is against each ceiling.
- **No licence file = Community**, no key needed, no phone-home. Trials are a Team/Enterprise
  file with a short `expires_at`.
- **Expiry and grace: OWNER DECISION PENDING** — no commercial policy is invented here. The
  mechanism carries `expires_at` and an issuer-set `grace_days` (no built-in default) and,
  whatever the policy becomes, it is technically impossible for expiry to touch isolation,
  RLS, authorization, integrity or OIDC; degradation of commercial capabilities is always
  honest (listed, never hidden).
- **Offline:** everything above works with no network. There is no activation server.

## 4. Enforcement points (all existing chokepoints)
| ceiling / feature | where it is enforced |
|---|---|
| devices (UNIT: **monitored** devices — owner C4, 2026-09-05) | the monitoring transition, wherever it happens: `PUT /api/devices/{id}/monitoring`, `POST /api/devices` (a manually created device is monitored), and a discovery SOURCE reporting a device that would default to monitored (which withholds the COLLECTION and lists it, never the inventory row). Discovery itself is never refused. The check and the write share one hold of the device registry's lock, so concurrent activations cannot both take the last slot |
| tenants / orgs | `POST /api/tenants`, org create |
| retention | ISM/TTL bootstrap values (already env-driven) |
| watched prefixes | watchlist store `Add` |
| frameworks / dialects | per-tenant framework enablement API; dialect registry |
| security findings (Team), dialects, SIEM export, MSP management, SAML/SCIM/LDAP (Enterprise) | central entitlement service: `Entitled(FeatureX)`; the route/handler asks for the semantic feature, never the tier |
| Iris skills | skill ingestion cap |
Every refusal returns a structured 402-style error naming the ceiling and the tier that lifts
it; the UI renders it as an upgrade card, never as a broken page.

## 5. Metering (per-device pricing)
A daily usage record per tenant (devices, tenants, retention actually configured, prefixes,
provider tokens) written to the platform DB and exported as metrics; a signed usage report
the customer can download for true-ups. No automatic phone-home; an opt-in "send usage
report" for hosted support later.

## 6. Consistency guarantee (owner: non-negotiable before rc1)
`tests/test_licensing_consistency.py` fails the build unless all of these agree: root
`LICENSE` (Apache-2.0 text), `LICENSING.md` (every top-level directory mapped once),
`NOTICE`, every Dockerfile's `org.opencontainers.image.licenses` label, the frontend
About/licences page, README's licence section, the generated `THIRD_PARTY_LICENSES.md`
header, and the installer bundle's `LICENSES.md`.

## 7. Build order
1. Legal + boundary structure: mixed-licence `LICENSE`, `LICENSES/Apache-2.0.txt`, placeholder
   slot for `LICENSES/Correlix-Enterprise.txt` (approved text pending — blocker),
   `licensing-policy.json` → generated `LICENSING.md`, SPDX headers, stdlib import checker +
   CI boundary gate (A–H of the owner spec), CONTRIBUTING CLA requirement (text pending —
   blocker), release-artifact inclusion checks (in flight, 2026-09-04).
1b. Physical `enterprise/` move of the commercial implementations (dialects, SIEM export,
   MSP management, SAML/SCIM/LDAP) — its own wave after the current builds land.
2. Licence file: package `internal/licence` (parse, verify, ceilings, grace), boot + page,
   `requireFeature`, the seven enforcement points, Community defaults with no file.
   **DONE 2026-09-04.** `internal/entitlement` (closed Feature/Ceiling vocabulary, `Require`
   /`CheckCeiling`, the structured 402, `safety_invariant_test.go`) + `internal/licence`
   (`document.go` canonical payload, `verify.go` ed25519 + expiry/grace evaluation,
   `state.go` honest degradation + overages, `store.go` atomic file store, `service.go`
   entitlement projection + the two gauges, `api.go` the route) + `internal/licence/signer`
   (never in the api's import graph). Route `GET|PUT|DELETE /api/system/licence`
   (`requirePlatformAdmin`, audited both outcomes); file at `/data/api/licence.json`
   (`LICENCE_FILE`). CLI `cmd/correlix-licence` (keygen/sign/verify/show). Page
   `src/frontend/src/pages/Licence.tsx` + `licence.model.ts`. Alerts: `rules.yaml` group
   `licence` (`LicenceExpiringSoon`/`InGrace`/`Degraded`, all `tier: warning`) with
   `rules-tests/licence.test.yaml`. Tests: `internal/licence/licence_test.go`,
   `internal/entitlement/{entitlement,safety_invariant}_test.go`, `licence_routes_test.go`.
   Runbook `docs/runbooks/licensing.md`; operator page
   `docs-portal/docs/administration/licence.md`. ENFORCED ceilings are `devices` and
   `watched_prefixes` only; the other five are carried and labelled un-enforced. Expiry
   policy remains the open owner decision (grace has no built-in default). `siem_export` and
   `scim` are in the locked vocabulary with no route yet
   (`TestLicenceGatesReadyForAbsentFeatures`). The signing key embedded today is the LAB key;
   the production key ceremony is still pending.
3. Metering + signed usage report + Licence page usage bars.
4. Separate the mixed directories into clean commercial packages (tracked; today most
   commercial code shares packages with core code — `LICENSING.md` lists them).
5. Signer tooling (offline key ceremony, `correlix-licence sign`), docs-portal "Licensing"
   page, pricing copy.
