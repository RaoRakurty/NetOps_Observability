# evidence-capture — light-mode, high-DPI Correlix screenshot harness

Headless capture for the Cloud Demo evidence book
(`docs/design/cloud-demo-traffic-program.md` §4). Drives the **running** Correlix
UI at `http://localhost:8000`, forces the **light theme**, logs in, navigates to
a hash route, **asserts the DOM is actually light**, and writes a crisp
(`deviceScaleFactor=2`) PNG — optionally scoped+zoomed to one CSS selector.

This makes capture **repeatable**; it fabricates nothing. Every pixel is
whatever the live stack really renders. With cloud instances down the cloud
lanes render sparse/empty — the honest state; the harness validates *mechanics*,
not content.

Playwright is used **only** here (already vendored under
`src/frontend/node_modules` per the program brief). It is **never** added to the
Go backend or any product dependency. Chromium comes from the ms-playwright
cache (`~/.cache/ms-playwright`).

## Prerequisites

- The stack is up on `:8000` (`python3 scripts/install.py`).
- Playwright + its Chromium are installed in `src/frontend/node_modules`
  (they are, if `npm install` has run there). The harness auto-locates them even
  from a git worktree (worktrees share the main checkout's `node_modules`); set
  `CORRELIX_FRONTEND=/path/to/src/frontend` to override.

## The one-liner (per scenario, during the live window)

```bash
cd scripts/lab/evidence-capture
./capture-scenario.sh aws 2-waf all         # at fault peak → 03-signal + 04-rca
#   ... revert the injection, wait the soak ...
./capture-scenario.sh aws 2-waf recovery    # → 05-recovery
```

Shots land in `docs/demos/cloud-fidelity-evidence/<provider>/<scenario>/` with
the plan's §4 names (`03-correlix-signal.png`, `04-correlix-rca.png`,
`05-recovery.png`).

## Direct use / other routes

```bash
# Service View cloud lane (viewport):
node capture.mjs --route '#/monitoring/appobs' \
  --out ../../docs/demos/cloud-fidelity-evidence/aws/2-waf/03-correlix-signal.png

# A specific log lane, zoomed to the content panel (type the lane query into the
# Log Search bar first, e.g. `cloud_waf_log AND action:BLOCK`):
node capture.mjs --route '#/logs/logs' --selector '.main' \
  --out ../../docs/demos/cloud-fidelity-evidence/aws/2-waf/03-correlix-signal.png
```

Flags: `--route <#/hash>` `--out <path.png>` `--selector <css>` (element-scoped
zoom) `--width 1600` `--height 900` `--scale 2` `--settle-ms 1500`.

### Canonical Correlix routes (verified against `src/frontend/src/nav.tsx`)

| Evidence | Route |
|----------|-------|
| Service View — **cloud lane** (signal / recovery) | `#/monitoring/appobs` |
| Incidents / correlation groups (RCA) | `#/monitoring/incidents` |
| Correlations | `#/monitoring/correlations` |
| Anomalies (findings) | `#/monitoring/anomalies` |
| Log Search (cloud_*_log evidence) | `#/logs/logs` |
| Flow Trace | `#/infrastructure/flowtrace` |

> The Log Search query is set via the in-app search bar (not the URL), so for a
> log-scoped shot: navigate, type the lane query, run it, then capture `.main`.

## How light + auth are forced

Before the app's first paint the harness seeds `localStorage` via a Playwright
init script (keys verified in the source):

- `netops.theme = light`, `netops.chrome = white` — the binary appearance knob
  (`src/frontend/src/theme/prefs.ts`); the harness then asserts
  `document.documentElement[data-theme] === "light"` **and** a light body
  background luminance, and **refuses to write** a mis-themed shot.
- `netops_token` — the session JWT (`src/frontend/src/services/api.ts`),
  obtained by a headless `POST /api/auth/login`.

## No secrets in code

Credentials come from env — `CORRELIX_USER` / `CORRELIX_PASS` (default to the
lab admin, overridable), `CORRELIX_BASE` (default `http://localhost:8000`). No
password is committed except the documented lab default, matching the repo's
existing lab-tooling convention.

## Validation

Smoke-tested against the live local stack: authenticated, forced + asserted
light theme (`data-theme=light`, `body-bg=rgb(245,246,248)`), 2× DPI
(3200×1800 viewport shots; 3112×1680 element-scoped), and the parameterized
route/selector/output-path all confirmed working on `#/monitoring/appobs`
(Service View cloud lane) and `#/logs/logs`.
