# Correlix licensing model (design of record, 2026-09-04)

Owner decisions this document implements: root licence = **Apache-2.0 open core with
clearly separated commercial add-ons**; tiers Community / Team / Enterprise with the cut
lines in `TIERING_PLAN_2026-09-03.md`; the licensing story must be identical in the source
tree, the container manifests, the About/licences UI and the shipped third-party notices.
Companion documents: `LICENSING.md` (directory → licence map), `LICENSE` (Apache-2.0),
`LICENSE-ENTERPRISE.md` (source-available commercial terms), `TIERING_PLAN_2026-09-03.md`
(what each tier gets), `docs/security/LICENSE_AUDIT_2026-09-03.md` (third-party).

## 1. Two licences, one repository, one binary
| | Core | Commercial add-ons |
|---|---|---|
| Licence | Apache-2.0 | Correlix Enterprise License (source-available: read, build, evaluate; no production use without a commercial licence; no redistribution) |
| Where | everything not listed as commercial in `LICENSING.md` | directories listed in `LICENSING.md` with their own `LICENSE` notice file and file headers |
| What | discovery, telemetry ingestion, storage, correlation/RCA, investigation surface, protocol diagnostics, Iris evidence-only, IGP/VRF/interface depth, BGP public-data views, **tenant isolation**, local auth + OIDC, alerting delivery, Community ceilings | security dialects + frameworks beyond the default two, SIEM/findings export, BGP watchlist/alerting beyond the Community caps + BMP, SAML/SCIM/LDAP, MSP/org-hierarchy management, reports/PDF, owner-doc skills beyond 10, hosted provider quota, support entitlements |
| Build | one binary, one image set (tiers are data, not builds) | same binary; the code is present but gated by the licence file (§3) |
| Contributions | CLA required (keeps relicensing rights) | same CLA |

Why one binary: the tiering plan's rule "enforce by data, not by hiding code" — customers
upgrade by installing a licence file, never by swapping images; the offline bundle stays
one artifact. The commercial code being readable is deliberate (source-available); the
enforcement is contractual plus the gate below. Isolation is never commercial: it is a
safety property of every tier.

## 2. Tiers (decided)
Community: 25 devices, 1 tenant, 7-day retention, 5 watched prefixes, hardening + exposure
with the default two frameworks, evidence-only Iris. Team: 250 devices, 5 tenants / 1 org,
30-day retention, 100 prefixes + BMP, security findings + frameworks + drift + pcap + threat
lane + advisory, BYO provider key. Enterprise: unlimited per licence, org hierarchy, 90-day +
archive, unlimited prefixes, all dialects + SIEM export + 90-day findings retention, hosted
provider quota, SAML/SCIM, reports, 24×7 support. (Full table in the tiering plan.)

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
- **Expiry and grace:** at `expires_at` the product keeps running at the licensed tier for
  `grace_days` (default 30) with a banner and a warning alert; after grace it degrades to
  Community ceilings **honestly**: over-ceiling devices are listed as "not monitored: licence
  ceiling", nothing is deleted, nothing is hidden silently.
- **Offline:** everything above works with no network. There is no activation server.

## 4. Enforcement points (all existing chokepoints)
| ceiling / feature | where it is enforced |
|---|---|
| devices | discovery admission + manual device create (`POST /api/devices`) |
| tenants / orgs | `POST /api/tenants`, org create |
| retention | ISM/TTL bootstrap values (already env-driven) |
| watched prefixes | watchlist store `Add` |
| frameworks / dialects | per-tenant framework enablement API; dialect registry |
| SIEM export, reports, SAML/SCIM/LDAP, hosted provider quota | feature switch read from the licence at the route (`requireFeature("siem_export")`) |
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
1. Legal structure: `LICENSE`, `LICENSE-ENTERPRISE.md`, `LICENSING.md`, CLA note, consistency
   test (in flight, 2026-09-04).
2. Licence file: package `internal/licence` (parse, verify, ceilings, grace), boot + page,
   `requireFeature`, the seven enforcement points, Community defaults with no file.
3. Metering + signed usage report + Licence page usage bars.
4. Separate the mixed directories into clean commercial packages (tracked; today most
   commercial code shares packages with core code — `LICENSING.md` lists them).
5. Signer tooling (offline key ceremony, `correlix-licence sign`), docs-portal "Licensing"
   page, pricing copy.
