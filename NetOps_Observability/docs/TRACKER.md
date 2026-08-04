# NetOps_Observability — Current Work Tracker

**Reconciled 2026-07-26.** This file lists what is OPEN. Shipped work is not
re-listed here — `git log` is the record of what landed, and
`docs/audit/INVARIANTS.md` is the record of what is *proven* versus merely built.

> History through 2026-07-20 lives in
> `docs/archive/TRACKER-ARCHIVE-through-2026-07-20.DO-NOT-USE-AS-CURRENT.md`.
> Read it only to recover the rationale behind a past decision. It is frozen and
> was already wrong in places when frozen; never cite it for current state.

**Rules for this file**

1. An entry earns its place by being open. **When it ships, DELETE the row** —
   don't convert it to a ✅ row. The archived tracker reached 263 KB because
   nothing was ever removed, and the rot stayed invisible until an item filed as
   "open research" turned out to have shipped months earlier.
2. Keep the 4-column table shape (`# | Item | Pri | Status`) with a **numeric
   id** — `scripts/tracker_staleness.py` (blocking in `tracker-ci`) parses
   exactly that and cross-checks each open id against `feat()`/`fix()` commits.
   A different shape silently makes the guard inert.
3. Verify a premise against the code before building on it. The staleness guard
   catches shipped-but-not-marked-done; it cannot catch "premise went moot".

---

## 👤 Blocked on owner — nothing moves without these

Not numbered: no commit will ever close these, so the staleness guard correctly
ignores them.

- **O1 · GCP project + service-account key.** No `GCP_*`/`GOOGLE_*` keys exist in
  the environment at all (verified 2026-07-25). GCP is explicitly FIRST in the
  #105 ordering — nothing GCP starts without this.
- **O2 · AWS access key + secret** for the lab tenant. `AWS_REGION` is set;
  `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` are empty. Blocks all AWS live
  validation and the T5 counter drills.
- **O3 · `az provider register --namespace Microsoft.ResourceHealth`.** One
  command, needs subscription rights. Azure is otherwise fully configured.
- **O4 · Spend decisions:** AWS fidelity Terraform apply (~$2–3/drill day) ·
  ALB for target-health (~$16/mo; no ALB exists in the lab) · Azure VNet flow
  logs (needs a storage account — real engineering, "the next big lane").
- **O5 · Decision:** `aws.json`/`azure.json` are poller-rewritten but still
  git-tracked, so they churn the working tree on every poll. Gitignore + seed a
  fixture, or keep tracked?
- **O6 · Decision:** 8 stale agent worktrees under `.claude/worktrees/` (890 MB,
  each on an unmerged branch with commits). Merge or drop, per branch.
- **O7 · Wireless hardware (Q8, item 128):** any WLC + AP + client — lab,
  loaner, or first customer. Blocks Phase 9 live validation, the doc_claimed→
  live fidelity promotion, and the first real remediation executor. Everything
  else in the wireless programme shipped without it.
  **ON HOLD (owner, 2026-07-27): all hardware-dependent work demoted to Low.**
  When revisited: the minimal build is researched and costed in
  `docs/design/research/wireless-lab-setup.md` (hybrid 9800-CL VMs + 2 physical
  APs, ~$150–350; no virtual CAPWAP AP exists, OpenWrt APs cannot join a Cisco
  WLC).
- **O8 · Wireless PII decisions (Q4/Q5, item 128):** client-MAC retention
  length + pseudonymization point, and whether per-user location history is
  Sensitive or Restricted. Blocks the client-history Iris tools (deliberately
  unregistered until decided).

---

## 🔧 Open engineering

| # | Item | Pri | Status |
|---|------|-----|--------|
| 114 | **Kubernetes deployment packaging** — Helm chart over the 19-service stack (StatefulSets + PVCs for CH/OS/PG/Kafka), per-service requests from `RESOURCE_SIZING.md`, ingress replacing nginx, secrets from the installer `.env` contract, air-gapped image bundle for k8s registries, CI packaging leg alongside `make-installer.sh`. Customers get single-host artifacts only today. | High | ⏳ not started — confirmed absent 2026-07-20; **a project, not a task** |
| 129 | **Sealed Fields (reversible masking) — polish.** COMPLETE 2026-07-31 end to end: `sealing` package (CryptoProvider over the vault envelope model, `<enc:v1:…>` token, edge VRL, Vector↔Go cipher parity vs the pinned binary — where Vector's CTR was found to be Ctr64LE not Go's Ctr128BE), versioned per-tenant DEKs (additive; v1 IS the legacy key), the `seal` action, the reveal path (`POST …/unseal`, `sensitive_data` RBAC module, audit with token fingerprints + no plaintext, `netops_unmask_requests_total`, reveal UI), and EDGE KEY DELIVERY (`/internal/sealing/edge-keys` + Vector `exec` secret backend; fail-closed verified — no key ⇒ router will not start, exit 78). Docs: `docs/design/sealed-fields.md`. REMAINING (nice-to-have, not blocking): (a) a **Sensitive Data Access Audit** page filtering the trail to unseal events; (b) key-rotation runbook + an operator-facing rotate control; (c) a managed `seal` preset for card/SSN. | Low | 🟢 feature COMPLETE; only polish remains |
| 130 | **Path trace — cloud endpoints.** CORRECTION: this was filed claiming the path engine was "reachable only from a detected correlation". WRONG — an ad-hoc trace already exists (`mode=path_trace` + src/dst pickers, `TopologyCanvas.tsx:212,272,752`). The REAL gap is narrower: `endpointOptions` is built from `view.nodes` (`TopologyCanvas.tsx:438`), so only what is already on the canvas is selectable — you cannot pick a VPC or a region. Blocked on #131's projection; once cloud entities reach the view, they become selectable endpoints for free. | Medium | 🟡 premise corrected; blocked on #131 |
| 131 | **Cloud projection into the topology canvas — region/VPC blocks + cloud path.** The Cloud domain tab EXISTS and its blurb already promises "VPCs/VNets, subnets, gateways, NVAs, seams" — but the backend emits no cloud-kind node (`topology_view.go` has zero cloud refs), so the tab is EMPTY. Same class as the >1000-node escape hatch: a promise the UI makes and the code does not keep; an operator concludes they have no cloud rather than that we never projected it. AUDIT VERDICT 2026-08-01: **build on, do not restart.** `pathgraph` is a frozen contract whose observed/inferred split is TYPE-ENFORCED (rank 6 route tables can never become an authoritative edge); `CloudResource` already carries tenant/provider/region/`VpcID`/`SubnetIDs` plus `AttachedVpcIDs`/`AttachedRegions` on seam endpoints, so VPC↔VPC and region↔region links are DISCOVERED, not inferred; `groups`+`regroupView` is the existing nesting primitive for segmented blocks. WORK: (a) projection `CloudResource` → topology nodes/groups (region = outer group, VPC = nested, subnets localize); (b) region + VPC as `GROUP_DIMENSIONS` entries; (c) lateral links from Attached*; (d) cloud nodes classified by FACT (provider/region/vpc fields) — explicitly NOT by extending `domainOfNode`'s hostname regex, which is the one genuinely weak piece here and must not spread to cloud. Keep Cloud a FILTER over one canvas, never a separate page — cloud↔on-prem tracing needs both ends on the same canvas. **PREMISE UPDATE 2026-08-02:** "the tab is EMPTY" is no longer the symptom — the separate Cloud DOMAIN does now render a real projection (`cloud/topology_view.go` → `GET /api/topology/cloud`, 15 nodes / 19 edges / 5 groups off the deployed fixtures). What this row asks for is still open and unchanged: cloud entities on the ONE unified canvas (region/VPC as `GROUP_DIMENSIONS`, lateral Attached* links, cloud↔on-prem paths), which the separate-tab projection does not provide. | High | ⏳ scoped, not started |
| 132 | **Data Explorer (unbounded query surface) — RECOMMEND DROPPING, owner decision pending.** Two independent reasons. (1) It contradicts the owner principle in `cloud-ingestion.md` §0/§2: "we define causal relevance first and ingest only what strengthens causality", with flow ingestion deliberately Layer-1 SEAM-ONLY. An ENI/subnet/VPC-pair explorer queries data we deliberately do not capture, so it returns empty and reads as "no traffic" rather than "never ingested" — a silent lie. (2) Owner scoping 2026-08-01: the actual need is HOP-LEVEL PATH TROUBLESHOOTING (#131), not a query builder. Keep the row only so the decision is recorded, not re-litigated. | Low | 🔴 recommend drop — pending owner sign-off |
| 133 | **Topology canvas — remaining polish.** The canvas B-list was tracked NOWHERE (no row here; "minimap" appeared in zero files) while a lot of built, working work was equally unrecorded. Audited 2026-07-31 and the defects fixed 2026-08-01 (`729369c8`): filter-drives-canvas (the >1000-node card advertised an escape hatch that did not exist), badge-tier edge anchoring, edge-label zoom LOD, minimap, zoom-ladder regression guard, stale-comment/dead-file/stale-ledger hygiene. Cross-tenant metric leak fixed separately (`2954e408`). STILL OPEN: (a) **URL-serialized canvas state** — mode/overlay/selection/domain/groupBy/arrange live in `useState` only, so an investigation cannot be shared and does not survive F5 (M); (b) **edge bundling is dead end-to-end** — `utils/edgeBundling.ts` is called by nothing and the backend never emits `bundle_id`/`bundle_count`, so LAG members render as stacked parallel edges; wire it or delete it (S–M); (c) **`TopologyCanvas.tsx` has zero tests** despite holding the most behaviour (fetch state machine, auto-pin, 60s refresh, trace states) (M); (d) `/api/topology/view` still lacks a dedicated HTTP isolation test (baseline row remains). | Medium | 🟡 audited; defects fixed, polish open |
| 134 | **Nested topology groups (region → VPC) are silently dropped.** `topologyToReactFlow` derives a group's box from `g.children`, i.e. its direct NODE members, and skips any group with none (`memberNodes.length === 0 \|\| !bbox → continue`). A region group's children are other GROUPS (VPCs nest via `parent_id`), so every region is discarded: the deployed cloud view declares 2 regions and the canvas draws 0 region boundaries — `aws · us-west-2` and the Azure region are invisible, and two VPCs in the same region look no different from two in different clouds. ELK already lays the nesting out correctly (containers inside containers), so only the *rendering* half is missing: a container group's box should be the union of its descendant groups' boxes, not of its direct nodes. Found 2026-08-02 while fixing the Cloud tab crash. | Medium | ⏳ verified against the code, not started |
| 148 | **Install-bundle size — remaining levers (owner goal 2026-08-03: smaller bundle).** Shipped 2026-08-04: slim OpenSearch (920→385 MB, flattened; `deployment/docker/opensearch/Dockerfile`) + correlation numpy removal (86→65 MB). Remaining, in leverage order, each needing its own validation: (a) **syslog-ng → Vector consolidation** (~180 MB + one fewer service — Vector is already in-stack and has a syslog source; functional migration of the syslog intake configs, medium risk); (b) **apache/kafka → apache/kafka-native** (GraalVM image, ~150 MB saving; upstream positions native for dev/test — evaluate prod-worthiness for a single-node KRaft appliance before switching); (c) **OSD add-on pack trim** (427 MB pack; same flatten-and-trim treatment as the server image); (d) longer-term: correlation service Python→Go rewrite would drop the ~120 MB python base (its deps are now thin: fastapi/kafka/pg). Base-image bumps (kafka/grafana/syslog-ng versions) also pending normal upgrade cycles. | Med | open |
| 135 | **Native SAML SP in Correlix (own ACS) — decision + build.** Correlix speaks OIDC only and brokers SAML through Keycloak (`oidc.go`, `IDENTITY_ACCESS.md`). Validated against a real Okta org 2026-08-03: SP-initiated works for SAML and OIDC, and OIDC IdP-initiated works — but **IdP-initiated SAML cannot reach an OIDC client**. Evidence: `clientId="null"` + `invalid_redirect_uri`; every part of Keycloak's IdP-initiated machinery (`saml_idp_initiated_sso_url_name`, `/broker/{alias}/endpoint/clients/{name}`, the "IDP Initiated SSO URL Name" field) resolves a **SAML client**, and ours is `openid-connect`. Root cause is architectural, not config: the broker TERMINATES SAML and starts a fresh OIDC flow, and an unsolicited assertion has no OIDC authorization request to anchor to. Okta's own docs put RelayState's deep-link role in the SP-initiated echo and say IdP-initiated lands on "a generic landing page" — the SP owns the ACS and defines RelayState. **Owner input: SAML is the majority protocol and high-security customers prefer IdP-initiated**, so this is a market gap, not a lab curiosity. WORK: (a) decide — bookmark workaround (ships today, same UX via silent SP-initiated) vs native SP; (b) if native: audited SAML lib (`crewjam/saml` / `gosaml2`) + §6 allowlist amendment — do NOT hand-roll XML-DSig/c14n; (c) IdP-initiated hardening is mandatory and now specified: an unsolicited assertion has **no `InResponseTo`**, so there is no request correlation to lean on — cache `AssertionID`/`SessionIndex` and reject duplicates inside the validity window; keep assertions short-lived (2-5 min via `NotBefore`/`NotOnOrAfter`); validate issuer + audience strictly; **treat an unsolicited response that DOES carry `InResponseTo` as a replay indicator and reject it**; and allowlist RelayState or accept relative paths only (open-redirect risk). Industry guidance (scalekit 2026) is that products "must support both to meet enterprise expectations" — SP-initiated is the SaaS norm, IdP-initiated is what enterprise portals and internal tools use, which is exactly our target segment; (d) per-tenant SP config + cert with §3a isolation (a tenant's IdP must not assert into another tenant), productized like the ServiceNow connector page; (e) keep Keycloak for LDAP/AD + multi-IdP brokering — native SAML is an ADDITIONAL front door, not a replacement. Design: `docs/design/sso-saml-oidc-design-2026-08-03.md` (v3, dated file is the only authoritative version — all earlier drafts/review docs superseded). Full evidence + both wrong turns: `docs/runbooks/okta-sso-setup.md`. | High | ⏸ **DEFERRED until SaaS** (owner 2026-08-03). Design v3 was approved with 8 owner-ordered preconditions (design §13 Phase 0) and stands ready; until then **Keycloak brokering is the supported SSO path** and the Okta Bookmark tile is the supported IdP-initiated experience. Do not start implementation without re-confirming with the owner |
| 123 | **`docs-portal` advisory triage** — 46 npm advisories (14 high). Only 2 were Trivy-visible (`ignore-unfixed: true`) and are fixed. Triage the rest so what is deferred is deferred knowingly. | Low | ⏳ not started |
| 128 | **Wireless — Phase 9 live validation + the doc_claimed→lab/live fidelity ladder.** Phases 1–8 SHIPPED 2026-07-26 (report `docs/Wireslessdesign.md` signed off; canonical model + mig 0030 · Catalyst 9800 connector · correlation integration RF=-1 + 9 signatures · onboarding/session lanes + #126 fix · 9-model architecture proof · Iris module · UI · guarded remediation, five gates fail-closed, `FEATURE_WIRELESS_ACTIONS=false`). OPEN: **Phase 9 needs hardware (Q8 — a WLC + AP + client; owner decision O7)**: verify the Cisco-IOS-XE-wireless-* leaf spellings the connector authored doc_claimed, run the physical fault-injection battery (report §23), promote fidelity, then build the first real action executor behind gate 4 (which fails closed until it exists). Follow-ons unblocked but not started: Aruba/Meraki/Mist connectors over the proven model; client-history Iris tools once the pseudonymization contract (Q4/Q5) is decided. | Low | 🟡 Phases 1–8 shipped; Phase 9 **ON HOLD** (owner 2026-07-27: hardware-dependent work → Low; lab design saved in `docs/design/research/wireless-lab-setup.md`) |
| 125 | **Stale customer bundle** — the pre-push hook warns on every push; `make bundle` when ready to ship. Note `6092adce` deliberately took this off its daily cron per §16.4, so rebuild is event-driven and manual by design. | Low | ⏳ not started |

---

## 🏷️ Deferred by design — not open, do not re-file

- **Off-host DR + disk sizing (F-55)** — CODE-COMPLETE, tagged for first-customer
  validation (`TAG:OFFHOST-DR`, `TAG:F55-DISK` in
  `docs/runbooks/first-customer-acceptance.md` §9). The lab has no off-host store
  and no large disk to finish the proof against; a real customer environment
  does. Not code. INVARIANTS standing gap #1.
- **#70 AWS leg of the cross-seam network** — DROPPED 2026-07-25, superseded by
  the cloud program that actually shipped (#104/#105/#110).
- **#73 multi-vendor telemetry coverage** — DROPPED 2026-07-25, build items ①–⑥
  included. BGP all-AFI is **not** being refiled; `profiles.go:68` stays
  IPv4-only as a known, accepted state. The 23 verified groundings remain in
  `docs/design/telemetry-coverage-reference.md`.
- **Item 121 scoped-out tails (shipped 2026-07-30, see
  `docs/design/pipeline-processors.md`)** — (a) **on-prem deploy events as a
  feed source**: there is no on-prem deploy/config-push producer to record;
  cloud change events cover the cloud half via the admitted `cloud` source.
  Reopen trigger = an on-prem config-push/deploy pipeline exists. (b)
  **processor shaping of the correlation lane**: the correlation engine
  consumes the bus upstream of the router hooks; v2 options documented.
- **T4 (#67 replay calibration)** — parked; reopen trigger = promoted-incident
  history exists.
- **T6 Stream 6** — parked; designs saved. Revisit before scale.
- **#55 per-role session policy UI** — won't do (owner, 2026-06-09).

---

## 📌 Remaining INVARIANTS standing gaps

`docs/audit/INVARIANTS.md` — not this file — is authoritative for what is *proven*.

| Gap | State |
|-----|-------|
| #1 Off-host DR / disk sizing | Deferred to first customer (above) |
| #3 Tenant-create rollback compile-reviewed only | CLOSED 2026-07-26 (item 116) — `s.tenants` is now the `tenantRepo` interface; `failRestrictRepo` injects the mid-request failure and both F-81 rollbacks (create + onboard) are exercised end-to-end, proven to fire |
| #4 Postgres paths compile-reviewed only | CLOSED 2026-07-25 (`33cb45f2`) — the `pg-integration` job in `backend-ci.yml` runs them against a pinned postgres:16-alpine |
| #5 `go test -race` runs only in CI | No local gate; the sandboxes used had no cgo |
| #6 Documented env switches unverified as a class | One was found lying; nothing checks the rest |
| #7 API response-shape stability is prose | Totals ride on headers; a header-blind client silently misses them |
