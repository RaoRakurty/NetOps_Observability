# `docs-portal` npm advisory triage — 2026-09-06

**Scope:** `NetOps_Observability/docs-portal` (the Docusaurus 3.5.2 customer
documentation portal). Closes tracker row 123.

**Outcome in one line:** the portal went from **41 advisory entries (21 low ·
9 moderate · 11 high, 16 distinct root advisories)** to **15 entries (0 low ·
0 moderate · 15 high, 2 distinct root advisories)** — **14 of 16 root advisories
fixed** by four targeted `overrides`, with the Docusaurus major (and minor)
version untouched at 3.5.2, the production build green, and the dev server
verified still booting. The 2 that remain are **the same advisory pair on
`image-size`, for which no fixed version exists at any release, in any Docusaurus
version** — build-host-only code that never reaches a customer.

---

## 0. The tracker row's premise was stale

| | Row 123 claimed | Measured 2026-09-06 |
|---|---|---|
| total advisories | 46 | **41** |
| high | 14 | **11** |
| moderate | — | 9 |
| low | — | 21 |
| distinct root advisories | — | **16** (across 6 packages) |

The row was written against an older lockfile and an older advisory database.
`npm audit` counts *affected packages*, not advisories: 41 entries collapse to
16 real advisories on 6 packages, and the other 25 entries are "depends on a
vulnerable version of X" chains through the Docusaurus package set.

> **Measurement note.** The very first `npm audit --json` of the session returned
> a *partial* tree (25 entries: 14 moderate / 11 high, 0 low) — it omitted the 16
> "depends on vulnerable webpack" dependents. Two subsequent runs, and the run
> inside `npm audit fix`, all agreed on **41**. 41 is the number used throughout
> this document.

---

## 1. The reachability model — read this before the tables

The portal is **static output**. `docusaurus build` runs on a build host and
emits `docs-portal/build/` (HTML + JS + CSS); `deployment/docker/Dockerfile.frontend`
copies **only that directory** into an `nginx:1.27-alpine` image
(`COPY docs-portal/build /usr/share/nginx/html/docs`) and serves it at `/docs/`.

Consequences, and they are the whole basis of every deferral below:

1. **No npm package ships to a customer.** `node_modules/` is never in an image,
   never on a customer host, and no Node process runs in the product runtime.
   The customer receives pre-rendered files served by nginx.
2. **Build-time-only code — webpack, its loaders and plugins, postcss, svgo,
   the prerenderer — runs exactly once, on our build host, over inputs we
   authored ourselves** (`docs-portal/docs/**`, `static/**`). It is not exposed
   to attacker-controlled input and it is not exposed to a customer.
3. **The dev server (`docusaurus start`) never runs anywhere but a developer's
   laptop.** It is not in the image, not in CI's build path (CI runs
   `npm ci && npm run build`), and not in the installer.
4. **A different and more serious class exists:** code webpack *emits into the
   client bundle* — React, React-DOM, the Docusaurus theme runtime,
   `@mdx-js/react`, `prism-react-renderer`, `clsx`, and any webpack **runtime
   module** webpack injects. That code executes in a customer's browser. It is
   called out separately in §4 and is **not** eligible for a "build-time only"
   deferral.

---

## 2. Summary — before / after

| Severity | Before (2026-09-06) | After | Δ |
|---|---|---|---|
| critical | 0 | 0 | 0 |
| high | 11 | **15** | +4 † |
| moderate | 9 | **0** | −9 |
| low | 21 | **0** | −21 |
| **total entries** | **41** | **15** | **−26** |
| **distinct root advisories** | **16** | **2** | **−14** |

† The high count *rises* while the vulnerability count falls. Nothing got worse.
`npm audit` labels each dependent with the severity of the worst advisory
underneath it. Before, the 14 Docusaurus packages inherited a mix of
low/moderate/high from the six vulnerable roots; now their only remaining root
is `image-size` (high), so all 14 report `high`. **The 15 entries are one
package with a real advisory pair plus 14 dependents of it.**

Package-level truth, which is the number that matters:

| Vulnerable package | Before | After |
|---|---|---|
| `webpack` | 5.88.2 (3 advisories) | **5.110.3 — clean** |
| `serialize-javascript` | 6.0.2 (2 advisories) | **7.1.1 — clean** |
| `qs` | 6.15.3 (2 advisories) | **6.16.0 — clean** |
| `uuid` | 8.3.2 (1 advisory) | **11.1.1 — clean** |
| `webpack-dev-server` | 4.15.2 (6 advisories) | **5.2.6 — clean** |
| `image-size` | 1.2.1 (2 advisories) | **1.2.1 — RESIDUE, no fix exists** |

---

## 3. What was fixed (14 root advisories)

All four fixes are **`overrides` in `docs-portal/package.json`**. No direct
dependency version changed; `@docusaurus/*` stays pinned at **3.5.2**.

| # | GHSA | Package | Sev | CVSS | Vulnerable range | Now | Ships to customer? |
|---|---|---|---|---|---|---|---|
| 1 | [GHSA-4vvj-4cpr-p986](https://github.com/advisories/GHSA-4vvj-4cpr-p986) | `webpack` | moderate | 6.4 | `<5.94.0` | 5.110.3 | **runtime-module class — see §4** |
| 2 | [GHSA-8fgc-7cc6-rx7x](https://github.com/advisories/GHSA-8fgc-7cc6-rx7x) | `webpack` | low | 3.7 | `>=5.49.0 <=5.104.0` | 5.110.3 | no (build host) |
| 3 | [GHSA-38r7-794h-5758](https://github.com/advisories/GHSA-38r7-794h-5758) | `webpack` | low | 3.7 | `>=5.49.0 <5.104.0` | 5.110.3 | no (build host) |
| 4 | [GHSA-5c6j-r48x-rmvq](https://github.com/advisories/GHSA-5c6j-r48x-rmvq) | `serialize-javascript` | **high** | 8.1 | `<=7.0.2` | 7.1.1 | no (build host) |
| 5 | [GHSA-qj8w-gfj5-8c6v](https://github.com/advisories/GHSA-qj8w-gfj5-8c6v) | `serialize-javascript` | moderate | 5.9 | `>=5.0.0 <7.0.5` | 7.1.1 | no (build host) |
| 6 | [GHSA-x5fp-wj9c-mxmx](https://github.com/advisories/GHSA-x5fp-wj9c-mxmx) | `qs` | moderate | 3.7 | `>=6.14.2 <=6.15.3` | 6.16.0 | no (dev server) |
| 7 | [GHSA-4mjr-xmp4-gh2g](https://github.com/advisories/GHSA-4mjr-xmp4-gh2g) | `qs` | moderate | 5.3 | `>=2.2.5 <6.16.0` | 6.16.0 | no (dev server) |
| 8 | [GHSA-w5hq-g745-h8pq](https://github.com/advisories/GHSA-w5hq-g745-h8pq) | `uuid` | moderate | 7.5 | `<11.1.1` | 11.1.1 | no (dev server) |
| 9 | [GHSA-9jgg-88mc-972h](https://github.com/advisories/GHSA-9jgg-88mc-972h) | `webpack-dev-server` | moderate | 6.5 | `<=5.2.0` | 5.2.6 | no (dev server) |
| 10 | [GHSA-4v9v-hfq4-rm2v](https://github.com/advisories/GHSA-4v9v-hfq4-rm2v) | `webpack-dev-server` | moderate | 5.3 | `<=5.2.0` | 5.2.6 | no (dev server) |
| 11 | [GHSA-79cf-xcqc-c78w](https://github.com/advisories/GHSA-79cf-xcqc-c78w) | `webpack-dev-server` | moderate | 5.3 | `<=5.2.3` | 5.2.6 | no (dev server) |
| 12 | [GHSA-mx8g-39q3-5c79](https://github.com/advisories/GHSA-mx8g-39q3-5c79) | `webpack-dev-server` | moderate | 5.3 | `<5.2.5` | 5.2.6 | no (dev server) |
| 13 | [GHSA-f5vj-f2hx-8m93](https://github.com/advisories/GHSA-f5vj-f2hx-8m93) | `webpack-dev-server` | moderate | 4.7 | `<=5.2.5` | 5.2.6 | no (dev server) |
| 14 | [GHSA-m28w-2pqf-7qgj](https://github.com/advisories/GHSA-m28w-2pqf-7qgj) | `webpack-dev-server` | moderate | 5.3 | `<=5.2.5` | 5.2.6 | no (dev server) |

### 3.1 The `overrides` diff and why each one is safe

```diff
   "overrides": {
-    "webpack": "5.88.2",
     "brace-expansion": "^5.0.8",
     "fast-uri": "^3.1.6",
-    "svgo": "^3.3.4"
+    "qs": "^6.16.0",
+    "serialize-javascript": "^7.0.5",
+    "svgo": "^3.3.4",
+    "uuid": "^11.1.1",
+    "webpack": "^5.104.1",
+    "webpack-dev-server": "^5.2.6",
+    "webpackbar": "^7.0.0"
   }
```

- **`webpack` `5.88.2` → `^5.104.1`** (resolves 5.110.3). The old pin was
  deliberate, and its reason is recorded in the portal's first commit
  (`f24b90e5`): *"webpack pinned to 5.88.2 to build under the local Node 18"*.
  **That constraint is gone** — the build host runs Node v22.23.1 and CI builds
  the portal on Node 20 (`fresh-install-integrity.yml`,
  `scale-miniladder-nightly.yml`). `^5.104.1` is the floor that clears all three
  webpack advisories (`>5.104.0` for the two buildHttp SSRF issues, `>=5.94.0`
  for the DOM-clobbering gadget). Same major, no API change we consume.
- **`serialize-javascript` `^7.0.5`.** Pulled by `copy-webpack-plugin@11` and
  `css-minimizer-webpack-plugin@5`, both of which declare `^6.0.0`. This is a
  deliberate major-crossing override: v7's `serialize()` signature is unchanged
  and both consumers use only that. **Proven by the build passing** — both
  plugins run on every `docusaurus build`.
- **`qs` `^6.16.0`.** Same major as the resolved 6.15.3; consumed only by
  `express@4` under the dev server.
- **`uuid` `^11.1.1`.** Consumed only by `sockjs@0.3.24`, which does exactly
  `require('uuid').v4` (`node_modules/sockjs/lib/transport.js:9`). uuid v11 ships
  a CJS build (`exports["."].node.require → ./dist/cjs/index.js`) that still
  exports the named `v4`, so the call site is unchanged across the three major
  versions.
- **`webpack-dev-server` `^5.2.6`.** A v4 → v5 major override. Safe *because
  Docusaurus 3.5.2 already writes a v5-shaped dev-server config* — it uses
  `setupMiddlewares`, `devMiddleware`, `client.webSocketURL` and `server: {type:
  'https'}`, none of the v4-only options v5 removed
  (`node_modules/@docusaurus/core/lib/commands/start/webpack.js`). **Verified
  empirically, not assumed:** `docusaurus start --host 127.0.0.1 --port 3999`
  was booted against the new tree and `GET http://127.0.0.1:3999/docs/` returned
  **HTTP 200**.
- **`webpackbar` `5.0.2` → `^7.0.0`** — *not a security fix; a prerequisite.*
  Recent webpack validates `ProgressPlugin`'s options lazily on the
  `compiler.hooks.validate` hook (`webpack/lib/ProgressPlugin.js:483`).
  `webpackbar` 5.0.2 **and** 6.0.1 both stash their own keys (`name`, `color`,
  `reporter`, `reporters`) on `this.options`, which that schema rejects — the
  build dies with *"Progress Plugin has been initialized using an options object
  that does not match the API schema"*. Both were tried and both failed; 7.0.0
  is the first release that keeps its options out of the validated object. Its
  `@rspack/core` peer is `optional: true`, so nothing extra is installed. It is
  a build-host progress bar; it emits nothing into the bundle.

---

## 4. The class that DOES ship — stated separately and honestly

Code that reaches a customer browser is everything webpack emits into
`docs-portal/build/assets/js/`: **React 18.3.1, React-DOM 18.3.1,
`@docusaurus/theme-classic` + `theme-common` runtime, `@mdx-js/react`,
`prism-react-renderer`, `clsx`, and the webpack runtime modules**.

**None of these carried an advisory — before or after.** Every one of the 16
root advisories landed on build-host or dev-server code. That is a finding, not
a convenience: the portal's shipped surface is currently advisory-free.

The one advisory that sits on the boundary is **GHSA-4vvj-4cpr-p986** (webpack
`AutoPublicPathRuntimeModule` DOM Clobbering → XSS), because webpack *injects*
that runtime module into the emitted bundle. It is **fixed** (webpack 5.110.3).
Independently of the fix, it was also **not present in our output**: webpack only
emits that module when `output.publicPath === 'auto'`, and Docusaurus sets
`publicPath` to `baseUrl` (`/docs/`) unless the experimental hash router is on —
`node_modules/@docusaurus/core/lib/webpack/base.js:91`. Verification on the
rebuilt tree: `grep -rl currentScript build/assets/js/` returns **0 files**.

Both statements are recorded because either alone would be weaker: the fix
removes the gadget from the toolchain, and the grep proves it was never in the
artifact.

---

## 5. Residue — deferred knowingly (2 advisories, both high)

### R1 · `image-size` — 2 HIGH, no fix exists anywhere

| Field | Value |
|---|---|
| Advisories | [GHSA-w3rx-r6r6-pgpr](https://github.com/advisories/GHSA-w3rx-r6r6-pgpr) — ICNS parser infinite loop (DoS)<br>[GHSA-5p2g-fcmc-qvqq](https://github.com/advisories/GHSA-5p2g-fcmc-qvqq) — JXL and HEIF parser infinite loops (DoS) |
| Severity | high, CVSS 3.1 **7.5** each (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`) — availability only, CWE-835 |
| Package / version | `image-size@1.2.1` |
| Direct or transitive | **transitive** |
| Chain | `correlix-docs` → `@docusaurus/core@3.5.2` → `@docusaurus/mdx-loader@3.5.2` → `image-size@1.2.1` |
| Dependency class | **build-time only** (`devDependency`-equivalent: a webpack loader) |
| Vulnerable range | `<=2.0.2` |
| **Is there an upstream fix?** | **No.** The latest published `image-size` is **2.0.2**, which is *inside* the vulnerable range. `npm audit` now reports `"fixAvailable": false` / *"No fix available"*. |
| Does a Docusaurus upgrade fix it? | **No.** `npm audit` initially suggested `@docusaurus/preset-classic@3.10.2`; that suggestion is wrong. `@docusaurus/mdx-loader@3.10.2` still declares `image-size: ^2.0.2` — still vulnerable. Verified with `npm view @docusaurus/mdx-loader@3.10.2 dependencies`. |
| Why the 14 extra entries | `@docusaurus/mdx-loader`, `core`, `preset-classic`, the 5 `plugin-*`, `theme-classic`, `theme-common`, `theme-search-algolia`, `plugin-content-{blog,docs,pages}` are all "depends on a vulnerable version of" chains from this one package. There is no separate defect in any of them. |

**Reasoning for deferral — can it reach a customer?**

**No.** Three independent barriers, any one of which is sufficient:

1. **`image-size` never ships.** It is a build-time image-dimension reader used
   by the MDX loader to add `width`/`height` to `<img>` tags. Its code is not
   emitted into the bundle (verified: it is not among the shipped runtime
   packages in §4) and `node_modules/` is not in the frontend image — only
   `docs-portal/build/` is copied in.
2. **The input is not attacker-controlled.** The only images it parses are the
   ones committed under `docs-portal/docs/**` and `docs-portal/static/**` — our
   own repository content, reviewed before merge. An external party has no path
   to hand a crafted ICNS/JXL/HEIF file to this parser. Reaching it would require
   commit access to the repo, at which point the parser is not the weak link.
3. **The impact is availability-only, on the build host.** Both advisories are
   infinite loops (CWE-835): worst case the *documentation build* hangs and CI
   times out. There is no confidentiality or integrity impact (`C:N/I:N`), and
   the product runtime — nginx serving static files — is untouched.

**Accepted. No action possible and none warranted.** Revisit when
`image-size` publishes a fixed release (>2.0.2); `npm audit` will surface it
automatically and the fix is then a one-line `overrides` entry.

### R2 · nothing else

There is no second residue item. Every other advisory measured on 2026-09-06 is
fixed in the tree.

---

## 6. Effect on the Trivy supply-chain gate

The gate runs Trivy with `ignore-unfixed: true`, which is why row 123 said only
2 of the advisories were ever visible to it. After this change, `image-size` has
**no fixed version**, so `ignore-unfixed: true` suppresses it: the portal's Trivy
surface is now **zero findings**, and it is zero for the right reason (nothing
fixable is unfixed) rather than by accident. `npm audit`, which does not filter
by fixability, remains the authoritative view and is the tool this document is
written against.

**One exception was DELETED, not re-justified.** `.trivyignore.yaml` carried
`GHSA-5c6j-r48x-rmvq` (serialize-javascript RCE) for
`docs-portal/package-lock.json`, on the stated grounds that "the fixed major
(v7) requires Node ≥20 and breaks the Docusaurus chain on the supported Node 18
toolchain". That premise expired — CI builds the portal on Node 20 and the lab
host runs Node 22 — and this triage pinned `serialize-javascript` to **7.1.1**
with the portal building clean. The advisory is fixed, so the ignore entry is
gone. An exception that outlives its reason is worse than no exception: it
suppresses the finding silently on the day the dependency regresses. Nothing in
§5's residue replaces it, because none of the residue is Trivy-visible under
`ignore-unfixed: true` in the first place.

---

## 7. Reproducing this triage

Run from the repository root
(`/home/rao/Projects/NetOps_Observability/NetOps_Observability`).

```bash
# 1. baseline
cd docs-portal
npm audit --json > /tmp/audit-before.json
npm audit                                  # 41 (21 low, 9 moderate, 11 high)

# 2. non-forced fix first — changed nothing (every dep is pinned by Docusaurus)
npm audit fix                              # no package.json / package-lock.json diff

# 3. targeted overrides (see §3.1), then
npm install --no-audit --no-fund
npm audit                                  # 15 (0 low, 0 moderate, 15 high)

# 4. prove the build (docusaurus.config.js has onBrokenLinks: 'throw')
npm run build                              # [SUCCESS] Generated static files in "build"
npm test                                   # node --test tests/voice.test.js — see §8

# 5. prove the dev server still boots on webpack-dev-server v5
BROWSER=none npx docusaurus start --host 127.0.0.1 --port 3999 --no-open &
curl -s -o /dev/null -w '%{http_code}\n' --retry 40 --retry-connrefused \
     http://127.0.0.1:3999/docs/          # 200
pkill -f 'docusaurus start'

# 6. confirm the shipped bundle carries no auto-public-path runtime
grep -rl currentScript build/assets/js/ | wc -l   # 0

# 7. SBOM + gates, from the repo root
cd ..
python3 scripts/sbom.py
python3 -m pytest tests/test_sbom.py -x -q
python3 scripts/license-audit.py --check
python3 scripts/licensing-gate.py
```

`npm audit` results move as GitHub publishes advisories; the counts above are
the state on **2026-09-06**.

---

## 8. Verification results

| Check | Result |
|---|---|
| `npm run build` (docs-portal) | **PASS** — `[SUCCESS] Generated static files in "build"`, 9.9 MB, `onBrokenLinks: 'throw'` satisfied |
| `docusaurus start` on wds v5 | **PASS** — `GET /docs/` → HTTP 200 |
| `npm test` (`tests/voice.test.js`) | 13 tests, **10 pass / 3 fail** — `addresses the reader as "you"`, `em dashes stay rare`, `sentences stay under 45 words`. **Pre-existing and unrelated:** these are prose-style assertions over `docs-portal/docs/**`, and no portal content was touched by this change (`git status docs-portal/` shows only `package.json` and `package-lock.json`). Out of scope for row 123; not introduced here. |
| `python3 -m pytest tests/test_sbom.py -x -q` | **PASS** — `36 passed in 8.13s` |
| `python3 scripts/license-audit.py --check` | **PASS** — `1631 components [FORBIDDEN=52 NOTICE_REQUIRED=5 PERMISSIVE=1510 REVIEW_REQUIRED=17 SEPARATE_PROCESS=47]` … `OK — every component is permissive, or a reviewed exception covers it`. The one acknowledged finding it still prints (inherited base-image layers, tracker 238) predates this change. |
| `python3 scripts/licensing-gate.py` | **PASS (eight checks)** |

### 8.1 SBOM delta

`python3 scripts/sbom.py` regenerated `docs/sbom/npm-docs-portal.cdx.json`:
**1085 → 1125 components** (76 added, 36 removed). Added entries are the
dev-server-only transitive tree that webpack-dev-server v5 brings
(`memfs` + `@jsonjoy.com/*`, `@peculiar/x509` + `pkijs` behind `selfsigned@5`,
`open`/`is-wsl`/`default-browser`), plus the six bumped packages themselves.
Removed entries are their v4-era predecessors (`node-forge`, `selfsigned@2`,
`default-gateway`, `execa@5`, `eslint-scope`, `consola@2`, …). Every added
package is build-host or dev-server scope; none is in the shipped bundle.

The licence audit was re-run **after** the SBOM regeneration precisely because
40 net-new npm components entered the inventory; it returned no new
non-permissive licence.

---

## 9. Files changed by this triage

- `docs-portal/package.json` — `overrides` only (4 security bumps + 1
  prerequisite; `webpack` pin replaced)
- `docs-portal/package-lock.json` — regenerated by `npm install`
- `docs/sbom/npm-docs-portal.cdx.json` — regenerated
- `docs/sbom/correlix.cdx.json` — regenerated (aggregate)
- `docs/sbom/container-images.cdx.json` — regenerated (see the note below)
- `docs/security/DOCS_PORTAL_ADVISORY_TRIAGE_2026-09-06.md` — this document

No portal content (`docs-portal/docs/**`) was touched, so
`scripts/sync-docs-corpus.sh` was not required.

> **Note on `container-images.cdx.json`.** `scripts/sbom.py` writes all six
> documents in one pass; it cannot regenerate one in isolation. That pass picked
> up a **pre-existing, unrelated drift**: `deployment/docker/Dockerfile.correlation`
> had already been changed in the working tree from a digest-pinned
> `python:3.12-slim` to a digest-pinned `python:3.12-alpine` (tracker 263)
> without the SBOM being regenerated, so `python3 scripts/sbom.py --check` — and therefore
> `tests/test_sbom.py::test_committed_sbom_matches_the_current_dependency_tree` —
> was already failing before this triage began. Regenerating fixed it. The
> container-image delta in `container-images.cdx.json`, and the corresponding
> container components inside `correlix.cdx.json`, belong to that change, not to
> this one.
