# Correlix — Open-source licence audit, 2026-09-03

**Question asked:** *"Ensure all the package-related items have no obligations
with open-source licensing."*

**Short answer:** we cannot have *no* obligations — every open-source licence in
the stack imposes at least an attribution duty, and that is unavoidable for any
product built on OSS. What we can have, and now largely do, is **no obligation
that touches Correlix's own source code**. Nothing in the product requires us to
publish, open-source, or relicense a single line we wrote.

But the audit is not clean. It found **five distinct attribution obligations we
are currently carrying and NOT meeting**, and **six items needing an owner
decision**. None is an emergency; all are cheap to fix. Details below.

> **STATUS UPDATE (later the same day).** All five attribution obligations in
> §2 are now CLOSED — the notices ship with every distribution unit: the
> frontend image serves `/licenses/` (rendered inventory + the EPL-2.0 text and
> source pointer for elkjs, the four OFL-1.1 font licences, the Feather/Lucide
> notice), reachable from the account menu; the correlation image carries the
> notices at `/app/licenses`; `make-installer.sh` now GENERATES the bundle's
> `LICENSES.md` from `docs/THIRD_PARTY_LICENSES.md` and fails the build if the
> licence gate is not green; NOTICE gained the four missing attributions; and
> the housekeeping items (dead Jira/ServiceNow marks, the stale
> `verify_modules.go` path, the CLAUDE.md §6 x/crypto version) are done. Those
> five exceptions are recorded `status: FIXED` with evidence paths in
> `scripts/license-data.json`, so the gate no longer prints them.
> **The six owner decisions in §4 (D1–D6) remain OPEN** and are still printed by
> every audit run (tracker #227).

Scope: `NetOps_Observability/` at `feat/observability-platform`. Method and
tooling: `scripts/license-audit.py` (re-runnable, offline), backed by the
human-reviewed facts in `scripts/license-data.json`. Container-image and
in-tree-content licences were verified against upstream `LICENSE` files at the
pinned tag, not from memory.

---

## 1. Headline numbers

**1,428 components inventoried** across five ecosystems: npm 1,350 · pypi 31 ·
container images 29 · Go 9 · hand-copied in-tree content 9.

Of those, **1,297 are build-only** (compilers, bundlers, test runners, the
Docusaurus static-site generator). They are never distributed and therefore
carry no notice obligation. **127 components are actually distributed.**

| Category | Distributed count | Verdict |
|---|---|---|
| Permissive (MIT / Apache-2.0 / BSD / ISC / 0BSD / PSF / PostgreSQL / curl / CC0) | 115 | No action beyond attribution |
| Weak, file-level copyleft (MPL-2.0, EPL-2.0) | 3 | Notice + source pointer only — **2 not currently met** |
| Permissive-with-notice (OFL-1.1 fonts) | 4 | **Not currently met** |
| Strong copyleft, separate container (GPL-2.0+, AGPL-3.0) | 2 | Documented; needs owner ratification |
| No licence grant at all (vendor MIBs, vendor marks) | 3 | **Owner decision required** |
| Source-available / non-OSS (SSPL, BUSL, Elastic, RSAL) | **0** | Clean |
| Strong copyleft linked into our own binaries | **0** | Clean |

### The two results that matter most

**Nothing copyleft is linked into anything we build.** The Go backend links 9
vendored modules — 4× MIT (jackc/pgx family) and 5× BSD-3-Clause (golang.org/x).
The SPA bundles 49 runtime packages: 44 MIT/ISC/BSD/Apache/0BSD, 4 OFL-1.1
fonts, and one EPL-2.0 library (elkjs, §2.1).
The correlation image installs 27 Python packages, 26 permissive. No GPL, AGPL,
SSPL, BUSL or Elastic-licensed code is compiled, linked, or bundled into a
Correlix artifact. **Correlix's own source is under no disclosure obligation
from any dependency.**

**The 2026-07-03 licensing gate held.** Redis (RSALv2/SSPL) → Valkey (BSD-3) and
Redpanda (BSL) → Apache Kafka are both confirmed gone from every bundle, and
`make-installer.sh` still hard-fails if either returns. Prometheus is likewise
absent from the shipped set. OpenSearch 2.16.0 was re-verified as genuinely
Apache-2.0 (the pre-SSPL Elasticsearch 7.10.2 fork lineage), not Elastic-licensed.

---

## 2. Obligations we ARE carrying and are NOT meeting

These are real, current, and fixable in an afternoon. All five are attribution
failures — none requires disclosing our source.

### 2.1 elkjs (EPL-2.0) is bundled into the SPA with its notice stripped

`elkjs@0.11.1` is a **runtime dependency** of the topology canvas. Vite emits it
as its own chunk — verified present at
`src/frontend/dist/assets/elk.bundled-*.js`, which is baked into the
`netops-frontend` image. The bundle carries **no licence banner**: esbuild's
default `legalComments` setting drops them, and a grep of the shipped assets
finds only React's.

EPL-2.0 §3.2 requires that a recipient of the Object Code be told the licence
and how to obtain the Source. We currently tell them neither.

- **What we owe:** the EPL-2.0 text plus a pointer to elkjs's source, shipped
  with the frontend.
- **What we do NOT owe:** anything about our own code. EPL-2.0 is *file-level*
  copyleft. We do not modify elkjs, so no Correlix file is affected. This is the
  single most-misunderstood point in the audit and it is worth stating plainly:
  bundling EPL code does **not** make the SPA EPL.
- **Fix:** ship `docs/THIRD_PARTY_LICENSES.md` (generated) in the frontend image
  and the bundle. Optionally set Vite's `build.rollupOptions.output.banner` or
  `esbuild.legalComments: 'external'` to preserve banners.

### 2.2 Four OFL-1.1 font families ship without their licences

99 `.woff`/`.woff2` files ship in the frontend image: **Inter, IBM Plex Mono,
Space Grotesk** and **Manrope**, all SIL OFL-1.1. Each `@fontsource` package
carries a `LICENSE` in `node_modules`, but Vite copies only the binaries into
`dist/`, so the licences never leave the build host.

OFL-1.1 §2 requires the copyright notice and licence to accompany redistributed
font files.

- **What we owe:** the OFL text and the four copyright lines, distributed with
  the fonts.
- **Also note:** OFL forbids selling the fonts on their own (we don't) and
  reusing a Reserved Font Name in a modified version (we don't modify them).
- **Fix:** covered by the generated notices file; optionally drop an `OFL.txt`
  into `dist/assets/`.

### 2.3 ~20 icons are Feather/Lucide path data with zero attribution

`src/frontend/src/components/Icon.tsx` describes itself as a "Lucide-style"
inlined set. Spot-checking coordinates against upstream shows roughly twenty
glyphs are **verbatim**, not merely similar — e.g. `shield` is
`M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z`, character-for-character Feather's
`shield`. Others confirmed identical: `explore` (Feather `compass`), `settings`
(`sliders`), `lock`/`unlock`, `reports`/`docs` (`file-text`), `dashboards`
(`grid`), `close`, the `arrow-*` family, `maximize`, `logout`, plus the Lucide
`check`/`chevron`/`external-link`/`mail` set. Around fifteen others are genuinely
original.

Feather is MIT (© 2013–2023 Cole Bemis); Lucide is ISC and itself retains
Feather's MIT notice. **Both licences require the notice to be retained in
redistributions.** A tree-wide grep finds no attribution anywhere — the only
"lucide" hits are a header comment and a passing CSS comment.

- **What we owe:** an MIT + ISC notice crediting Feather and Lucide.
- **Fix:** in the generated notices file and NOTICE. Low legal risk, but it is a
  live licence-condition failure, not a stylistic quibble.
- **Separate, non-legal point for the owner:** the product's brand glyph
  (`Icon.tsx` `logo`, reused by `favicon.svg`) is `M2 12h4l3 8 4-16 3 8h6` —
  Feather's `activity` icon. Legal to use with attribution; whether the brand
  mark *should* be a stock icon is a product decision, and it sits oddly beside
  the deliberate BLOGO5 identity work.

### 2.4 certifi (MPL-2.0) ships in the correlation image unattributed

`certifi==2026.5.20` is installed into `site-packages` in `netops-correlation`.
MPL-2.0 is file-level copyleft; we modify nothing, so the obligation is the
notice plus a pointer to upstream source. Currently absent.

### 2.5 The bundle's `LICENSES.md` is incomplete and contains an error

`dist/*/LICENSES.md` is a hand-written heredoc in `scripts/make-installer.sh`
(~line 387). It lists 14 container images and **zero libraries** — none of the
Go, npm, or Python components above appear. It also omits Keycloak (which now
ships, since `--profile sso` is in `BASE_PROFILES`), curl, and kafka-exporter.

It additionally **misstates syslog-ng as GPL-3.0**. It is not: syslog-ng OSE
4.7.1 is **LGPL-2.1-or-later** for the core (`lib/`, `syslog-ng/`,
`syslog-ng-ctl/`) and **GPL-2.0-or-later** for `modules/` and `scl/`, verified
against `COPYING` at tag `syslog-ng-4.7.1`. Since the stock image loads all
modules, the running combination is effectively GPL-2.0-or-later. There is also
**no OpenSSL linking exception** in that COPYING, contrary to what one might
assume from other projects of its era.

- **Fix:** replace the heredoc with the generated `docs/THIRD_PARTY_LICENSES.md`.

---

## 3. Obligations we DO NOT carry (and why)

Worth stating explicitly, because these are the ones people worry about.

**We do not have to release Correlix source because of Grafana's AGPL.** AGPL-3.0
§13 obliges *the operator of a modified version* to offer that version's source
to its network users. Grafana ships unmodified, in its own container, in an
**optional** `self-monitoring` add-on pack, reached on its own route. No
Correlix code links to it, embeds it, derives from it, or is combined with it
beyond configuration. Our source is untouched by it. What we DO owe is the
AGPL-3.0 text and an offer for *Grafana's* corresponding source.

**We do not have to release source because of syslog-ng's GPL.** Same reasoning:
separate process, unmodified upstream image, communicating over the network and
a config file. GPL-2.0-or-later governs the syslog-ng combination only. We owe
its licence texts and a source offer for syslog-ng.

**Vector's MPL-2.0 costs us nothing beyond a notice.** MPL-2.0 is file-level. We
run the stock image; `vector-router` only layers `apk add curl` on top and
touches no Vector source. Our `vector.yaml`, VRL transforms and
`cx-secret-backend.sh` are **configuration**, explicitly permitted as a Larger
Work under MPL §1.10/§3.3 — they are not modifications of MPL-covered files.
MPL has **no AGPL-style network clause**.

**Bundling EPL-2.0 elkjs does not relicense the SPA.** See §2.1.

**Build-only tooling owes nothing.** TypeScript, Vite, Vitest, Playwright,
esbuild, the entire Docusaurus toolchain (1,074 packages), the Go toolchain
image — none is distributed. Only Docusaurus's *built output* ships, and that
client bundle is React + MIT-licensed runtime. This is why `require-like`
(no declared licence) and `node-forge` (BSD-3 **OR** GPL-2.0, taken under BSD-3)
are non-issues: they are dev-server dependencies that never leave the build host.

**Dual licences resolve our way.** `BSD-3-Clause OR GPL-2.0` (node-forge),
`MIT OR CC0-1.0` (type-fest), `MIT OR Apache-2.0` (sniffio),
`Apache-2.0 OR BSD-2-Clause` (packaging) — a disjunction is the licensee's
choice, and we take the permissive branch in every case. The audit tool encodes
this so a dual licence never blocks a merge spuriously.

**GeoIP and ASN data were correctly never bundled.** `flows.go` explicitly notes
*"licensing forbids bundling GeoIP data"* and expects the operator to supply the
CSV; `seam_bootstrap.go` says the same for ASN data. No `.mmdb`, no OUI table,
no threat-intel feed, no CVE corpus anywhere in the tree. This is the single
best licensing decision already in the codebase and should not be reversed for
convenience. The one dataset that *is* bundled —
`src/frontend/src/assets/world-110m.geo.json` — is Natural Earth 1:110m, which
is **public domain**; no obligation, though a courtesy credit is included.

**NetClaw attribution is already correct.** No NetClaw code is present. The
knowledge-derivation notice in NOTICE is accurate and is restated in the file
header of `src/backend/internal/verify/modules.go` (the file moved from
`verify_modules.go` during package decomposition; **NOTICE's path reference is
now stale and should be updated**). Attribution is arguably more generous than
Apache-2.0 §4 requires for knowledge-only derivation. Non-issue.

**`src/backend/ai/skills/` is original.** The 13 embedded `SKILL.md` files follow
the Agent-Skills *format* but the frontmatter schema, vocabulary (seams, verdict
tiers, evidence classes) and tool names are Correlix's own. No external
derivation found.

---

## 4. Owner decisions required

Six. All are recorded as `status: OPEN` exceptions in `scripts/license-data.json`
and printed by every `license-audit.py` run, so they cannot rot silently.

### D1 — Grafana AGPL posture in the customer bundle *(highest visibility)*
Grafana 11.2.0 is **AGPL-3.0-only** (confirmed at upstream `package.json` and
`LICENSING.md`; relicensed from Apache-2.0 at v9.0). It ships **only** in the
optional `self-monitoring` add-on pack, unmodified.

The current posture is defensible and needs no code change. What it needs is a
ratified decision, because AGPL in a commercial appliance is the first thing a
customer's legal team will grep for:
- **(a) Keep as-is** — optional add-on pack, unmodified, with the AGPL text and
  a source offer shipped. *Recommended.*
- **(b) Drop it** — replace self-monitoring dashboards with native Correlix
  views and remove the AGPL component from the product entirely. Cleanest story
  for enterprise procurement; costs dashboard work.

Whichever is chosen, **never modify or rebrand the Grafana UI** — that is what
would convert §13 into a real obligation.

### D2 — syslog-ng edition and source offer
syslog-ng OSE 4.7.1, GPL-2.0-or-later combined, in the **core** archive. We must
be able to honour a source request for three years.
- Decide whether to **mirror the upstream tarball** alongside each release (a few
  MB, removes all doubt) or rely on the upstream GitHub tag.
- Note two facts: there is **no OpenSSL linking exception**; and 4.7.1 is
  precisely the point at which syslog-ng's founder forked **AxoSyslog** at
  Axoflow. The `balabit/syslog-ng` Docker Hub image is still actively published,
  but the old `balabit/syslog-ng-docker` build repo is deprecated. A future move
  to AxoSyslog or to the `syslog-ng/syslog-ng`-published image is worth
  considering on maintenance grounds, not licence grounds.

### D3 — Cisco-headered MIB extracts
`src/backend/collectors/mibs/vendored/SNMPv2-TC` and `SNMPv2-CONF` are Cisco's
edited extracts of RFC 1903/1904, headed *"Copyright (c) 1994,1996 by cisco
Systems, Inc. All rights reserved."* with **no licence grant**. They are tracked
in git and **do ship** inside `correlix-source-*.tar.gz` (verified).

Mitigating: only `mibs/index/oididx.json` is `go:embed`'d into the binary, and it
holds 3,837 bare `{OID → name, kind, severity_hint}` facts with no MIB prose —
essentially uncopyrightable. Exposure is limited to source-tarball recipients.

- **Recommended fix:** substitute the canonical IETF RFC 1903/1904 module text.
  The content is equivalent, the IETF version is unambiguously redistributable
  as an RFC Code Component, and the ambiguity disappears. ~30 minutes of work.

### D4 — Arista enterprise MIBs
`ARISTA-SMI-MIB` and `ARISTA-BRIDGE-EXT-MIB` carry *"Copyright (c) 2008 Arista
Networks, Inc. All rights reserved."* with no licence text, sourced from the
LibreNMS mirror. Same source-tarball exposure.

- **Recommended fix:** fetch them at build time exactly as the other ~55 vendor
  MIBs already are (`gen_index.py` keeps only extracted OIDs and vendors
  nothing). That pattern is already correct and in use — these two are the
  outliers. Alternatively, obtain and record Arista's redistribution position.

### D5 — Cloud vendor marks embedded in the backend binary
`aws.svg`, `azure.svg`, `gcp.svg` are `go:embed`'d via
`internal/rca/rca_report_icons.go` and rendered in RCA reports. These are
**trademark** questions, not copyright: the official AWS Architecture Icons,
Azure Public Service Icons and Google Cloud symbol.

The asset READMEs already record each source package, its terms URL, and the
render-as-is/never-recolour rule — genuinely good practice that materially
reduces risk. Two gaps:
- The AWS asset is the **AWS Cloud logo**, not a service icon. The Architecture
  Icons ToU permits diagram use; logo use is additionally governed by AWS
  trademark guidelines. **Confirm this is intended.**
- The terms live in asset READMEs, so they do **not travel with the binary that
  embeds them**. Move them into NOTICE.

### D6 — Two images that need a posture, one that needs a rule
- **Keycloak** (`quay.io/keycloak/keycloak:25.0`) is Apache-2.0, but its base is
  **Red Hat `ubi9-micro`**, governed by the **Red Hat UBI EULA** — not an OSS
  licence. The `sso` profile IS in `BASE_PROFILES`, so this ships in the core
  bundle. UBI redistribution is permitted with conditions; those conditions need
  a read for an on-prem appliance, or Keycloak needs a non-UBI base.
- **Gotenberg** (`pdf` profile) is the highest-risk image in the repo and, happily,
  **ships in nothing today**. Its own code is MIT, but the `debian:12-slim` image
  bundles **PDFtk (GPL-2.0-or-later)**, LibreOffice (MPL-2.0),
  **`ttf-mscorefonts-installer` (proprietary Microsoft EULA with redistribution
  restrictions)** and, on amd64, **Google Chrome (proprietary, not Chromium)**.
  It is also pinned to a floating `:8` major tag, so its bundled-component
  licences can change under us between rebuilds. **Rule to adopt: the `pdf`
  profile never enters a customer bundle** unless it is first switched to a slim
  variant without msttcorefonts and PDFtk.
- **NetBox** (`netbox` profile) is Apache-2.0 for both app and image build and
  also ships in nothing. Its Ubuntu-based Python tree is unaudited *because* it
  never ships; auditing becomes necessary only if that changes.

### Housekeeping (no decision needed, just do it)
- Delete `src/frontend/src/assets/connectors/jira.svg` and `servicenow.svg` —
  Atlassian and ServiceNow marks with no terms recorded and **zero references**
  anywhere in the frontend. They are dead files that still ship in the source
  tarball.
- Update the NOTICE path reference from `src/backend/verify_modules.go` to
  `src/backend/internal/verify/modules.go`.
- CLAUDE.md §6 records `golang.org/x/crypto` as pinned `v0.55.0`; `go.mod` says
  **`v0.56.0`**. Harmless drift, but the allowlist should match reality.

---

## 5. Base-image licences (context, not action)

Container base layers carry their own mixed licences. This is normal, universally
accepted, and creates no obligation we can practically discharge beyond pointing
at the distro — but it should be understood rather than assumed away:

- **Alpine-based images** (~12 of ours): mostly MIT/BSD, but `busybox` and
  `apk-tools` are **GPL-2.0-only** (BusyBox is explicit that v2 is the *only*
  version it may be distributed under). Shipped unmodified.
- **Debian/Ubuntu-based** (`python:3.12-slim`, syslog-ng, gotenberg, netbox):
  mixed, including GPL-2.0/GPL-3.0 userland utilities. Source availability is
  satisfied by Debian/Ubuntu themselves.
- **Red Hat UBI** (Keycloak): UBI EULA — see D6.
- **Distroless** (`gcr.io/distroless/static-debian12`, our api image runtime
  base): Apache-2.0 tooling; contents are just ca-certificates, tzdata, passwd.
  The cleanest base in the stack.
- **Apache Kafka's `LICENSE-binary`** pulls in EPL-2.0 (Jersey/HK2), EDL-1.0,
  **CDDL-1.1 + GPL-2.0-with-Classpath-exception** (Jakarta), MIT and BSD, plus a
  Temurin 21 JRE under GPL-2.0-only WITH Classpath-exception. OpenSearch bundles
  an Adoptium JDK on the same terms. All separate-process, all unmodified — the
  Classpath exception exists precisely so this is a non-issue.
- **One modification we DO make:** `deployment/docker/opensearch/Dockerfile`
  strips plugins from the stock OpenSearch image. That is a modification of an
  Apache-2.0 work, which triggers Apache-2.0 §4(b) — a notice stating that we
  changed the files. Recorded in the generated notices.
- **`curl`'s SPDX id is literally `curl`**, not MIT. Filed correctly.

---

## 6. Tooling shipped with this audit

| Artifact | Purpose |
|---|---|
| `scripts/license-audit.py` | Stdlib-only. Rebuilds the whole inventory from the tree (`--check`, `--report`, `--json`), refreshes the reviewed facts file (`--write`), and generates the notices (`--notices`). Offline: every discovery source is checked in. |
| `scripts/license-data.json` | Human-reviewed facts: verified image licences, per-component postures, the exception register with owner decisions, and the licence texts / written source offer. |
| `docs/THIRD_PARTY_LICENSES.md` | **Generated.** Every distributed component, grouped by the distribution unit it actually ships in (api image, frontend image, correlation image, compose bundle, add-on packs, source tarball), plus the written source offer for the copyleft components. |
| `tests/test_license_audit.py` | 14 tests. Runs the gate; asserts no copyleft is linked into our binaries, no SSPL/BUSL/Elastic anywhere, no removed component (Redis/Redpanda/Prometheus) has returned, every exception is reasoned, the notices file is current, and — with synthetic SSPL/AGPL/unlicensed injections — that the gate actually bites. |

**Gate behaviour.** `--check` fails (exit 1) on a *new* dependency whose licence
is outside the allowlist, on any unresolvable licence, and on strong copyleft in
a linked position — which has no exception path at all. The six pre-existing
findings above are recorded as reviewed exceptions with `status: OPEN`: they
print loudly on every run and are listed here, but they do not block merges. A
gate that is red on day one is a gate people learn to switch off; this one is
green today and goes red the moment something new and unreviewed arrives.

**Recommended wiring:** add a `license-gate` job to
`.github/workflows/supply-chain.yml` (alongside Trivy and gitleaks) running
`python3 -m pytest tests/test_license_audit.py`, and replace the hand-written
`LICENSES.md` heredoc in `scripts/make-installer.sh` with the generated
`docs/THIRD_PARTY_LICENSES.md` so the bundle notice can never drift again.

---

## 7. Bottom line

Correlix's own code carries **no open-source disclosure, relicensing, or
network-use obligation**. Nothing copyleft is linked into any artifact we build,
and the 2026-07-03 decision to purge Redis and Redpanda has held — there is no
SSPL, BUSL, Elastic, or RSAL-licensed software anywhere in the product.

What we owe is **attribution**, and we are currently short on five counts:
elkjs's EPL notice, four OFL font licences, the Feather/Lucide icon credit,
certifi's MPL notice, and a bundle `LICENSES.md` that lists no libraries at all
and misstates syslog-ng's licence. Generating and shipping
`docs/THIRD_PARTY_LICENSES.md` closes all five.

Beyond that, six items need an owner call — Grafana's AGPL posture being the one
a customer's counsel will ask about first, and the Cisco/Arista MIB files being
the two with the cheapest fixes.
