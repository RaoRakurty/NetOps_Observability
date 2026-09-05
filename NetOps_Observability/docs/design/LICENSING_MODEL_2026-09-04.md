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
- **Expiry and grace: DECIDED 2026-09-05** — see the addendum "Expiry, grace and overage"
  at the end of this document. The mechanism still carries `expires_at` and an issuer-set
  `grace_days` with no default IN THE FORMAT; the defaults are applied by the ISSUER
  (`correlix-licence sign`: 30 days paid, 7 for a trial) and land in the file as explicit
  numbers, so a licence already issued is never re-termed by a later policy. Expiry remains
  technically incapable of touching isolation, RLS, authorization, integrity or OIDC;
  degradation of commercial capabilities is always honest (listed, never hidden).
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

---
**2026-09-05 addendum (owner feedback):** the commercial strategy of record is
`docs/design/research/LICENSING_TIERING_STRATEGY_2026-09-05.md`, summarised in
`docs/design/TIERING_PLAN_2026-09-03.md` §9. It KEEPS everything in this document (Apache-2.0 open core +
`enterprise/` boundary, one binary, signed offline entitlement, semantic features, three runtime tiers, the
safety invariant) and adds: the monitored-device unit (C4), an Enterprise MSP contract profile on the
Enterprise entitlement (no fourth tier in code), the paid expiry/grace policy, trial issuance, metering as
a separate data contract, and production signing-key ceremony as a GA prerequisite (the lab key must never
sign a production release).


---

## 8. Expiry, grace and overage (DECIDED 2026-09-05) — replaces the "owner decision pending" note in §3

Owner decision, recorded in `docs/design/TIERING_PLAN_2026-09-03.md` §9 (rows "Paid expiry /
grace (adopted)", "Trials", Team/Enterprise "Soft overage + alerts (80/90/100 %)", Community
"Hard block at the 26th activation"). Implemented as tracker row 257.

### 8.1 The state machine

`internal/licence.evaluate()` puts every authenticated document in exactly one of three
phases, and the phase is a first-class field (`entitlement.Phase`, on the wire as `phase`,
and on every 402 as `licence_state`):

| phase | when | what the customer experiences |
|---|---|---|
| `valid` | `now <= expires_at` — and always, for Community, which has no expiry | everything the licence grants |
| `in_grace` | `expires_at < now <= expires_at + grace_days` | **nothing changes at all.** The licensed tier, ceilings and features stay in force. The Licence page shows the runway and `LicenceInGrace` fires as a warning |
| `post_grace` | past that | ceilings and features fall back to Community for **creation and configuration only** |

`InGrace` / `Degraded` remain on the wire as the same fact in the older boolean shape, because
the metric family `netops_licence_state{tier,degraded,in_grace}` and the installed SPA read
them. `Degraded == (phase == post_grace)`.

### 8.2 What `post_grace` refuses, and what it must never touch

REFUSED — creation and configuration of paid capability, with the existing structured 402 plus
`licence_state: "post_grace"` and **no `lifted_by`** (the remedy is a renewal, not an upgrade,
and naming a tier to buy would send the operator to the wrong purchase):

- a new monitoring activation beyond the Community allowance of 25 monitored devices;
- a second tenant or a second organisation (the first of each is core single-tenant operation
  and is never gated);
- any non-GET on a feature-gated route — configuring SAML, writing an LDAP configuration,
  installing a new dialect, creating a SIEM export.

KEPT WORKING — everything that reads or exports what already exists. The rule is the HTTP verb:
`GET`/`HEAD` on a feature-gated route runs `entitlement.RequireRead`, which admits any feature
the lapsed document granted (`State.LapsedFeatures`). Enumerated and tested route by route in
`licence_expiry_routes_test.go`:

| surface | after grace |
|---|---|
| `GET /api/security/findings`, `/facets`, `/trend`, `/{id}` | served |
| non-GET on any of those | 402 `post_grace` |
| `GET /api/auth/ldap/config` | served |
| `PUT`/`POST /api/auth/ldap/config`, `POST /api/auth/ldap/test` | 402 `post_grace` |
| `GET /api/tenants`, `GET /api/orgs` | served |
| `POST /api/tenants` (second+), `POST /api/orgs` (second+) | 402 `post_grace` |
| every device already monitored | still monitored — nothing is disabled |
| the over-ceiling state | LISTED, per ceiling and per device, on the Licence page and in `GET /api/system/licence` |

NEVER TOUCHED — isolation, RLS, authorization, integrity, authentication (OIDC included). The
structural proof is `internal/entitlement/safety_invariant_test.go` (the safety paths cannot
reach this package at all); the behavioural proof over the new phases is
`TestLicencePostGraceChangesNoAuthorizationDecision`, which asserts that every
(principal, module, level) authorization decision is byte-identical with no licence, a live
licence, in grace, past grace and after an expired trial.

Nothing is ever deleted, and **nothing chooses which devices "lose"**. The over-ceiling device
list is ordered most-recently-enabled-first purely so the size and shape of the overage are
visible, and the API says so verbatim (`licence.OverCeilingNoteText`).

### 8.3 Grace defaults and trials (issuer-side)

`correlix-licence sign` applies the policy; the FORMAT keeps no default, so an issued file is a
complete statement of its own terms and a policy change can never silently re-term a licence
somebody is holding.

| | grace | expiry |
|---|---|---|
| team / enterprise | 30 days | `--expires` (required) |
| `--trial` (team / enterprise only) | 7 days | 30 days from issue, unless `--expires` overrides |
| community | 0 | — |
| explicit `--grace-days N` | exactly `N`, including 0 | — |

`--trial` also stamps `trial: true` in the document. The field is `omitempty` in the canonical
signing payload, so a NON-trial document signs over byte-for-byte the payload it always did and
**every licence issued before the field existed still verifies**; a trial's flag is covered by
the signature and can be neither added nor stripped. A trial grants exactly what its tier,
ceilings and features say — the flag changes the words (`show`, `verify`, the Licence page's
"Evaluation licence · N days left"), never the enforcement.

### 8.4 Soft overage on paid tiers

On Team and Enterprise the monitored-device ceiling is **not a block**. Activation beyond it
succeeds, is recorded, and is surfaced; "never a kill switch during an incident".

- `entitlement.SoftCeiling(name, tier)` is the whole policy: monitored devices, Team and above.
  Watched prefixes stay hard at every tier; Community stays hard at the 26th activation, which
  is a published free ceiling.
- `internal/licence.OverageTracker` is the durable register beside the licence
  (`licence-overage.json`): it records `overage_since` and the episode's peak, survives a
  restart, forgets a closed episode, and **fails soft** — a register that cannot be written
  costs the start time and nothing else.
- **No contractual window is encoded anywhere.** The product records when an overage started
  and how big it is; how long it may run and what it costs are order-form terms. The rule text
  and the UI say "true-up".
- Metrics: `netops_licence_ceiling{ceiling,unit}`, `netops_licence_usage{ceiling,unit}`,
  `netops_licence_ceiling_soft{ceiling}`, `netops_licence_overage_devices`,
  `netops_licence_overage_since_seconds{ceiling}`.
- Alerts (`rules.yaml` group `licence-ceilings`, all `tier: warning`, promtool-tested in
  `rules-tests/licence-ceilings.test.yaml`): `LicenceCeilingApproaching` (80–90 %),
  `LicenceCeilingReached` (90–100 %), `LicenceOverage` (over). **Every one joins on
  `netops_licence_ceiling_soft == 1`**, which is the Community guard: a free tier publishes 0
  and cannot fire any of them however full its fleet is.
- The post-grace rule was renamed `LicenceDegraded` → `LicenceExpired` to match the phase
  vocabulary; the expression is unchanged.

### 8.5 Where it is implemented

`internal/entitlement` (Phase, Lifecycle, RequireRead, SoftCeiling, `licence_state` on
ErrLicence) · `internal/licence` (`policy.go` issuance defaults, `overage.go` the register,
`state.go` phase + lapsed features + soft overage messages, `verify.go` the machine,
`service.go` Lifecycle + usage metrics, `api.go` the view) · `internal/discovery`
(`MonitoredOverCeiling`) · `cmd/correlix-licence` (`--trial`, grace defaults, `show`/`verify`
output) · `main.go` (the verb-based feature gate, the register wiring, the metrics) ·
`src/frontend/src/pages/{Licence.tsx,licence.model.ts,Devices.tsx}` · `src/config/rules.yaml`.
