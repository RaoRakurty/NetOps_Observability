# npm advisory triage — 2026-10-04

**Scope:** every `package.json` in the tree — `src/frontend`, `docs-portal`,
`scripts/lab/traffic-generator/webui`. Supersedes the residue section of
[`DOCS_PORTAL_ADVISORY_TRIAGE_2026-09-06.md`](DOCS_PORTAL_ADVISORY_TRIAGE_2026-09-06.md)
(its "no fixed `image-size` exists" premise expired: 2.0.3 shipped).

**Why:** new advisories turned two blocking gates red on every branch —
`frontend-ci` → `npm audit --audit-level=high` (undici) and `supply-chain` →
Trivy fs (`image-size`, `joi`, `brace-expansion` in the docs-portal lockfile).

**Outcome:** both gates green. `src/frontend` and the lab webui report **0**
advisories; `docs-portal` is down to **2 root advisories with no fixed release
at any version** (§3). No ignore entry was added anywhere — neither residue is
visible to Trivy under `ignore-unfixed: true`, and `npm audit` gates only the
frontend.

---

## 1. `src/frontend`

| Package | Was | Now | Advisories | How |
|---|---|---|---|---|
| `undici` | 7.29.0 | **removed** | GHSA-3wwx-pv8p-q78v, -pmjh-fq2x-6v4x, -r53p-7pc4-xj5r, -rfgv-xxqx-mfg5, -3xpg-4rpp-hhhm, -2jfj-6hjv-fm6j, -2gqq-gqf2-x968, -w293-vg96-wgc3, -8436-99hf-9mmv, -rx4f-c7p8-82vq (high) | Came only through `jsdom`, which vitest 3 auto-installed as a peer. The suite runs on happy-dom (`vitest.config.ts`), nothing imports jsdom, and vitest 4 stops pulling it, so the whole jsdom/undici subtree leaves the lockfile. |
| `vitest` / `@vitest/mocker` | 3.2.6 | **4.1.11** | GHSA-82fw-gwwq-j7x9 (moderate, `<4.1.11`) | First fixed release. Dev-only; never in the bundle. |

Two test-harness adjustments the vitest major required, nothing else:

- `src/test/setup.ts` — happy-dom implements no `window.confirm/alert/prompt`.
  Vitest 4's `vi.spyOn` refuses a missing property, so eight tests that stub
  `confirm` failed. The setup now defines the three as functions that **throw**
  if a test reaches one un-stubbed (the same fail-loud outcome as the old
  undefined global).
- `vitest.perf.config.ts` — `poolOptions` was removed in vitest 4; its
  single-thread knob is now top-level `maxWorkers: 1`.

Vitest 4 declares `node >=20`; `frontend-ci` still runs Node 18 but runs only
`npm ci` / build / Playwright there (an engines mismatch is a warning, not an
`npm ci` failure), so nothing in CI changes.

**Verified:** `npm ci` (npm 10) · `npm audit` 0 · `npm run build` ·
`npx vitest run` 4429/4429 · Playwright 21/21 · `perf:budget` 7/8, identical
to `main` (the `licence` budget already fails on `main` under vitest 3 — not
caused by this change and not a CI gate).

## 2. `docs-portal` — Docusaurus 3.5.2 → 3.10.2

`image-size` was the blocker. Its fix (2.0.3) is a major whose API dropped the
file-path+callback call that Docusaurus 3.5.2's `mdx-loader` makes
(`promisify(sizeOf)(path)`), so a bare override would break image handling.
Docusaurus **3.10.2** (same major) already depends on `image-size ^2.0.2` and
calls `imageSizeFromFile`. It needs Node ≥20 — the portal already builds on
Node 20 in CI and Node 22 on the lab host, so `engines` moves to `>=20.0`; this
was the fix the 2026-09-03 patch-automation plan named.

| Package | Was | Now | Advisory | How |
|---|---|---|---|---|
| `image-size` | 1.2.1 | **2.0.4** | CVE-2025-71329 / -71330 (GHSA-5p2g-fcmc-qvqq, GHSA-w3rx-r6r6-pgpr) | Docusaurus 3.10.2 + `overrides` floor `^2.0.3` |
| `joi` | 17.13.4 | **17.13.8** | GHSA-6h2x-m376-mqjq, -6w3j-5fw6-r9vr, -gg4h-3hg2-grpc | `overrides` `^17.13.7` (same major) |
| `brace-expansion` | 5.0.9 | **5.0.12** | CVE-2026-102276 / -102278 (GHSA-q2hr-2g5m-vwhr, -qhr7-859c-m2p7, -6j4f-fj2g-mc7p) | existing override raised to `^5.0.12` |
| `serialize-javascript` | 7.1.1 | **7.1.2** | GHSA-gfhx-hw2g-v5hg | existing override raised to `^7.1.2` |
| `fast-uri` | 3.1.7 | **3.1.8** | GHSA-hrr3-gc8f-f4qj | existing override raised to `^3.1.8` |
| `colord` | 2.9.3 | **2.10.0** | GHSA-2wm5-q62r-hmrv | `overrides` `^2.9.4` |

`docusaurus.config.js`: the top-level `onBrokenMarkdownLinks` is deprecated in
3.9+ and moved to `markdown.hooks.onBrokenMarkdownLinks` (still `'throw'` —
re-proven by injecting a dead link, which fails the build).

**Verified:** `npm ci` · `npm run build` with 0 warnings · the same 148 pages
as the 3.5.2 build, with identical article text on every page (the only diff
is whitespace beside heading-anchor zero-width spaces on three pages) ·
`grep -rl currentScript build/assets/js` still 0 (§4 of the 2026-09-06 doc) ·
`npm test` 10/3, identical to `main` (the three failures are voice/prose rules
on existing pages, unrelated).

## 3. Residue — no fixed version exists (justified, not ignored)

Both affect **every published release** of the package, so there is no version
to bump to and nothing to override with. Neither is Trivy-gated
(`ignore-unfixed: true`), so no `.trivyignore.yaml` entry exists or is needed;
the justification lives here.

| GHSA | Package | Sev | Range | Chain | Why it is not customer-reachable |
|---|---|---|---|---|---|
| [GHSA-vfj7-8cjw-p6xm](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm) | `braces` 3.0.3 (latest) | high (7.5) | `<=3.0.3` | `@docusaurus/core` → `chokidar@3` / `@docusaurus/utils` → `micromatch@4` | Stack-exhaustion DoS from a deeply nested **glob pattern**. The patterns are our own Docusaurus config and plugin globs, evaluated once on the build host (and by the dev-server file watcher on a developer laptop). No attacker supplies a pattern, and no Node process ships — the image carries only `docs-portal/build/`. |
| [GHSA-ch52-4w7c-c8xp](https://github.com/advisories/GHSA-ch52-4w7c-c8xp) | `http-cache-semantics` 4.2.0 (latest) | high (7.5) | `<=4.2.0` | `@docusaurus/core` → `update-notifier@6` → `latest-version` → `package-json` → `got@12` → `cacheable-request` | Cross-user disclosure from a **shared** HTTP cache honouring `max-stale`. The only caller is Docusaurus's "new version available" check against the npm registry, run by one user on the build host — a private client cache with no second user to leak to. Not present at runtime. |

Re-check both on every patch train (`docs/runbooks/patch-train.md` step 4);
the day a fixed release appears, bump it and delete its row.

## 4. `scripts/lab/traffic-generator/webui` (lab-only, not in the bundle)

`vite` ^5.4.0 → **^6.4.3** (same as `src/frontend`; clears vite GHSA-4w7w-66w2-5vf9,
-v6wh-96g9-6wx3, -fx2h-pf6j-xcff and esbuild GHSA-67mh-4wv8-2f99 via esbuild
0.25), `@vitejs/plugin-react` floor → ^4.7.0, and lockfile updates for
`browserslist` 4.29.3, `nanoid` 3.3.19, `postcss` 8.5.28,
`baseline-browser-mapping` 2.11.27. `npm audit` 0; `npm run build` green.

## 5. Gates re-run locally

- Trivy 0.69.3 fs, the CI flags (`vuln,secret,misconfig`, `CRITICAL,HIGH`,
  `--ignore-unfixed`, `.trivyignore.yaml`) over the repo root: exit 0.
- `python3 scripts/sbom.py` regenerated `docs/sbom/`; `--check` current.
- `tests/test_license_audit.py` + `tests/test_sbom.py`: 86 passed, 1 skipped;
  `license-audit.py --notices` produced no diff.
