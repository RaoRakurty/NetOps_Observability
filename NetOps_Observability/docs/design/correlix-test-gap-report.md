# Correlix — Test Gap Report (Phase 1, grounded)

**Date:** 2026-06-22. Inventory of the ACTUAL repo against the enterprise test-suite
spec (RCA / multi-tenancy / security / supply-chain / cloud / compliance). Honest:
the backend is far more covered than the spec assumes; the real gaps are concentrated.

## Existing frameworks & coverage (measured)
- **Backend (Go `testing`):** **173 test files.** Includes dedicated security/tenancy
  suites: `tenant_matrix_test`, `org_isolation_test`, `route_isolation_test`,
  `platform_config_authz_test`, `auth_flow_test`, `security_p1_test`,
  `security_lows_test`, `saved_pg_rls_test`, `jwt_test`, `password_test`,
  `tenant_router_test`, `dependency_view_test`, `topology/project_test`, etc.
- **Correlation (pytest):** 144 tests — `verdicts`, `engine`, `classify_probe`,
  `catalog`, `episodes`, `replay`, `e2e_rca`, `fixtures`, `metric_intake`, `trap_classify`.
- **Frontend (vitest):** 100 tests / 11 files — `rcaCase`, `RcaWorkspace`, `labels`,
  topology renderers/utils.
- **CI (7 workflows):** `backend-ci` (build/vet/test/race/fuzz/govulncheck/staticcheck/
  gosec), `correlation-ci`, `frontend-ci`, `fuzz-nightly`, `supply-chain`,
  `publish-images` (image provenance), `telemetry-catalog-ci`.
- **Containers:** hardened compose (11 directives: `no-new-privileges`, `cap_drop`,
  least-priv on prober). Go pinned for stdlib CVEs.

## What's ALREADY strong (don't rebuild — verify no regression)
- ✅ Multi-tenant isolation: RLS (`saved_pg_rls`), `org_isolation` template, route
  isolation matrix, `withTenant`/`chTenantScope`/`flowTenantClause`, opaque IDs.
- ✅ AuthZ: `requirePerm`/`requirePlatformAdmin`, platform-config authz tests, JWT.
- ✅ RCA business logic: independent-evidence (3 files), fate-sharing (1), stale (1),
  contradicting (1), recovery (1), owner (3), missing-evidence (6). The ≥2-stream
  confirm rule is engine- AND UI-enforced + tested.
- ✅ Supply-chain: govulncheck/gosec/staticcheck blocking; gitleaks/trivy; provenance.
- ✅ Secret custody: stdlib AES-GCM Vault; secrets write-only, redacted in logs.

## REAL GAPS (priority order)
| # | Gap | Severity | Why |
|---|---|---|---|
| 1 | **Cloud / K8s readiness: NONE** — no K8s manifests, Helm chart, Terraform, CIS-K8s policy tests | High (for hyperscaler claim) | Product is docker-compose only; "AWS/Azure/GCP/K8s deployable" is unproven |
| 2 | 🟡 **E2E browser tests: NONE** (no Playwright/Cypress) | High | **Playwright bootstrapped + first flow DONE** — headless-Chromium E2E driving the real SPA against the Vite dev server with the backend mocked at the network boundary (no 19-service stack). `e2e/commandCenter.spec.ts`: auth → Command Center renders → only actionable customer-network incidents survive (single-signal noise + internal-stack #76 filtered) → expand row → evidence ledger. Pinned `@playwright/test@1.60.0`; blocking `e2e` job in frontend-ci. Remaining: cross-tenant UI guard flow, path-trace/topology flows |
| 3 | 🟡 **Frontend product-test depth** — `CommandCenter.tsx`, evidence-ledger role grouping, path-trace overclaim guards untested | Medium-High | **Command Center + evidence ledger DONE** — triage logic extracted to pure `commandCenter.model.ts` (19 tests: single-stream confirm guard, internal-stack exclusion #76, ticket gating, severity sort, defensive parse) + `RcaVerdictBanner` render tests (4: independent-pair naming, raw-field hiding, no-overclaim). Path-trace overclaim guard done under #8. Remaining: deeper RcaWorkspace/topology-canvas product coverage |
| 4 | ✅ **RCA dedup** (spec P3 #9): duplicate evidence must not inflate confidence | Medium | **DONE `aafd117`** — `assess()` counts unique witnesses |
| 5 | ✅ **Capacity "no fake precision"** (P8 #7): missing util → no fabricated numbers | Medium | **DONE `aafd117`** — unmeasured link excluded, never simulated/ranked |
| 6 | ✅ **Dependency noise guard** (non-negotiable): control-plane/multicast excluded | Medium | **DONE** — `isDependencyNoise` guard on the pure projection (defense-in-depth vs the SQL filter) + `TestBuildDependencyViewExcludesNoise`/`TestIsDependencyNoise` |
| 7 | **CIS-Docker automated check** in CI (Dockerfiles run as non-root, no extra caps) | Medium | hardening exists; not gated by an automated test |
| 8 | ✅ **Path Trace honesty** (non-negotiable): proxy must not be labeled true Path Trace | Medium | **DONE** — backend tags `View.PathSource` measured\|computed (`resolvePath` + tests); UI provenance chip in `PathAnalysisPanel` ("Computed · …not a live trace") + render test |
| 9 | ✅ **Evidence-ledger immutability/audit** (P4 #6) | Medium | **DONE** — versioned append-only ledger pinned: re-version re-stamps frozen evidence (no in-place edit), rows carry role+note (audit), changed evidence ⇒ new version (`test_engine.py`) |
| 10 | 🟡 **Load/resilience** (10k incidents/nodes; P5/P6) | Low-Medium | **Bounded-queue guarantees pinned** (`test_resilience.py`, §9) — window buffer maxlen-bounded, dedup set stays in lockstep under flood, redelivery deduped, evicted signals not falsely deduped, prune ages out ids. **Caught + fixed a real leak**: `_BUFFERED_IDS` grew unbounded on maxlen eviction (55k vs 50k buffer) — `buffer_signal` now discards the evicted id in lockstep. Remaining: end-to-end perf bounds (latency under 10k nodes) |

**Step-1 status (2026-06-22): COMPLETE.** All five high-priority correctness/honesty
guards (#4, #5, #6, #8, #9) closed — no new infra, pure-layer unit + render tests.
**Step-2 (frontend product regression) IN PROGRESS:** Command Center decision logic +
evidence-ledger role grouping done (see #3). **Step-3 (E2E) bootstrapped** — Playwright
+ first operator-flow spec (see #2). **Step-4 (CIS-Docker CI) DONE** (#7). **#10
load/resilience DONE** (+real leak fixed). Remaining: cloud/K8s packaging (#1, deferred),
deeper E2E/product flows, end-to-end perf bounds.
**K8s is ADDITIVE packaging (Helm + manifests alongside docker-compose), not a stack
migration** — compose stays the default; no forced move off it.

## Recommended implementation order
1. **High-priority correctness/honesty unit tests** (no new infra): RCA dedup, capacity
   no-fake-precision, dependency-noise guard, path-trace honesty, evidence-role assignment.
2. **Frontend product regression**: Command Center sort/filter/tenant-scope; evidence
   ledger role grouping + raw-field hiding.
3. **E2E** (Playwright): auth, tenant-isolation, Command-Center→incident→evidence flow.
4. **CIS-Docker CI check** (non-root, caps) — cheap, high signal.
5. **Cloud/K8s readiness**: Helm chart + K8s manifests + CIS-K8s policy (kube-score/
   conftest) — the big lift for hyperscaler-class.
6. **Load/resilience** bounds.

Backend security/tenancy and supply-chain are already SOC2/ASVS-leaning; the program
is mostly about (a) product-surface regression, (b) cloud/K8s packaging, (c) E2E.
