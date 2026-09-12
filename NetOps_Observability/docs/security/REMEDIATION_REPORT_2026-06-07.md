# Security & Supply-Chain Remediation / Compliance Report — 2026-06-07

Companion to [`SECURITY_AUDIT_2026-06-07.md`](SECURITY_AUDIT_2026-06-07.md) (the
point-in-time assessment). This report records what was **remediated**, the
**evidence** (commit + verification), and the **residual risk**.

- **Scope:** the full audit — security code review (SR-001…031) + supply-chain
  review (SC-001…011), repository `NetOps_Observability`.
- **Branch:** `feat/observability-platform`.
- **Status date:** 2026-06-07.

---

## 1. Executive summary

| Class | Total | Resolved | Open | Notes |
|-------|-------|----------|------|-------|
| Security — Critical | 1 | 1 | 0 | SR-002 |
| Security — High | 5 | 5 | 0 | SR-003…007 |
| Security — Medium | 9 | 9 | 0 | SR-008…016 |
| Security — Low | 14 | 14 | 0 | SR-017…030 (SR-026 confirmed-by-design; SR-028 mitigated/deferred) |
| Security — Housekeeping | 1 | 1 | 0 | SR-031 |
| Supply-chain | 11 | 11 | 0 | SC-001…011 (incl. both halves of SC-006) |

**Every audit finding is now remediated and verified.** Two Lows are closed by
disposition rather than a code change: SR-026 (tenant-local super-admins) is
confirmed safe by design (tenant-confined; a tenant admin cannot mint a global
owner), and SR-028 (swtpm seal-socket SO_PEERCRED) is mitigated by the
container/FS boundary with a true peer-cred listener deferred (dormant subsystem).
No High/Critical risk remains.

---

## 2. Methodology & verification

Remediation was worked in the audit's recommended priority order. Each fix was
committed with its finding ID in the message and **verified** by one or more of:

- **CI gates** (4 workflows green at commit `3f425f0`): backend-ci (build/vet/
  test/race/govulncheck/gosec/golangci-lint), correlation-ci (pytest/ruff/bandit/
  mypy/pip-audit), frontend-ci, supply-chain (Trivy/gitleaks/SBOM).
- **Local tooling:** `golangci-lint v2.12.2` → 0 issues; `gitleaks v8.30.1` →
  clean across 259 commits; OSV API checks on pinned dependency sets;
  `go test ./...` full suite.
- **Live-stack checks** against the running deployment on `:8000` (curl probes,
  container uid inspection, boot-log assertions) — noted per finding below.

---

## 3. Security code review — remediation register

| ID | Sev | Finding (short) | Status | Fix commit | Verification |
|----|-----|-----------------|--------|-----------|--------------|
| SR-001 | High | Grafana console reachable unauth | ✅ Resolved | `bf2ba29` | nginx `auth_request` platform-owner gate |
| SR-002 | Critical | Cross-tenant report-exec IDOR | ✅ Resolved | `b08bae0` | `canSeeSaved` check; authz tests |
| SR-003 | High | Missing write-authz on device/rule/discovery | ✅ Resolved | `b08bae0` | `requirePerm` per handler |
| SR-004 | High | Alert rules global, no tenant model | ✅ Resolved | `b08bae0` | platform-owner gate on rules |
| SR-005 | High | CORS wildcard `*` | ✅ Resolved | `d2d6a75` | live: no ACAO for foreign Origin |
| SR-006 | High | No Origin check on WS (CSWSH) | ✅ Resolved | `d2d6a75` | `wsOriginAllowed` on both upgrades; live 403 |
| SR-007 | High | Missing edge security headers | ✅ Resolved | `d2d6a75` | live: XFO/CSP/nosniff/Referrer-Policy present |
| SR-008 | Med | `/prometheus/`+`/metrics` unauth | ✅ Resolved | `00aa867` | nginx gate; live denial page |
| SR-009 | Med | `/admin/health` recon leak | ✅ Resolved | `83d37d7` | live: minimal liveness; `/api/health` 401 |
| SR-010 | Med | GraphQL resolver bypasses gate | ✅ Resolved | `b08bae0` | cross-tenant gate in `graphql.go` |
| SR-011 | Med | ClickHouse `severity` SQL injection | ✅ Resolved | `00aa867` | enum allowlist (`isAlphaToken`) |
| SR-012 | Med | No request body-size cap | ✅ Resolved | `00aa867` | `withBodyLimit` middleware + `MaxHeaderBytes` |
| SR-013 | Med | No max password length (PBKDF2 DoS) | ✅ Resolved | `00aa867` | length cap in `validatePassword`; test |
| SR-014 | Med | LDAP TLS bypasses `tlsconfig` | ✅ Resolved | `928227e` | routed via `tlsconfig`; insecure gated; tests |
| SR-015 | Med | SSRF via tenant-configurable URLs | ✅ Resolved | `81f0388` | `safehttp` dial-time guard; tests |
| SR-016 | Med | Dormant Vault = plaintext at rest, silent | ✅ Resolved | `928227e` | boot `logWarn` (live) + `REQUIRE_SEAL` |
| SR-017 | Low | Weak fallback `JWT_SECRET` | ✅ Resolved | `928227e` | `ensureSigningSecret` fail-closed; test |
| SR-018 | Low | Report-view link tenant-unbound | ✅ Resolved | `05d89fa` | tenant bound into token + enforced vs exec; test |
| SR-019 | Low | ServiceNow webhook no signature/replay | ✅ Resolved | `600e491` | optional HMAC+timestamp mode (5-min window) |
| SR-020 | Low | PagerDuty/Jira webhooks no replay protection | ✅ Resolved | `600e491` | body-timestamp replay window; stale-reject tests |
| SR-021 | Low | No rate limit on `/api/copilot/chat` | ✅ Resolved | `f003ed2` | per-principal limiter (`COPILOT_RATE_PER_MIN`) |
| SR-022 | Low | Copilot relays raw provider error body | ✅ Resolved | `f003ed2` | `relayProviderResponse` redacts non-2xx |
| SR-023 | Low | Netbox follows upstream pagination URL w/ token | ✅ Resolved | `05d89fa` | pagination pinned to configured host |
| SR-024 | Low | JWT no `iat`/`nbf`; not revocable pre-exp | ✅ Resolved | `0eb1435` | iat/nbf enforced (skew); test (revocation = separate feature) |
| SR-025 | Low | Federated default tenant = platform tenant | ✅ Resolved | `ac7f8f9` | `guardFederatedRole` blocks silent platform-owner |
| SR-026 | Low | Tenant admin mints tenant-local super-admins | ✅ Confirmed by design | `ac7f8f9` | tenant-confined (`if !cross { req.TenantID = tenant }`); no global escalation |
| SR-027 | Low | Wrapped-DEK map no top-level integrity | ✅ Resolved | `ac989c8` | root-KEK HMAC over map, fail-closed; tamper test |
| SR-028 | Low | swtpm KEK socket unauthenticated | 🟡 Mitigated/deferred | — | container+FS boundary; SO_PEERCRED listener deferred (dormant) |
| SR-029 | Low | `verifyPassword` honors caller iteration count | ✅ Resolved | `0eb1435` | rehash-on-login at current cost; test |
| SR-030 | Low | `Secure` cookie flag off by default | ✅ Resolved | `0eb1435` | auto-Secure on HTTPS (TLS / XFP); test |
| SR-031 | Housekeeping | Stale CLAUDE.md `.env` warning | ✅ Resolved | `6c02200` | `.env` untracked + gitignored |

---

## 4. Supply-chain — remediation register

| ID | Sev | Gap | Status | Fix commit | Verification |
|----|-----|-----|--------|-----------|--------------|
| SC-001 | High | No image/IaC scanning | ✅ Resolved | `ca04850` | `supply-chain.yml` Trivy fs (blocking); CI green |
| SC-002 | High | Actions pinned to mutable tags | ✅ Resolved | `ca04850` | all `uses:` 40-char SHA-pinned |
| SC-003 | High | Images not digest-pinned; `gnmic:latest` floats | ✅ Resolved | `ca04850` + `7e348ee` | every `FROM`/`image:` `@sha256`; live stack on pins |
| SC-004 | Med | No Dependabot/Renovate | ✅ Resolved | `ca04850` | `.github/dependabot.yml` (5 ecosystems) |
| SC-005 | Med | `pip-audit` soft | ✅ Resolved | `ca04850` | blocking; starlette/fastapi bumped to pass |
| SC-006 | Med | No SBOM / provenance | ✅ Resolved | `9771889` + `8407f9e` | CycloneDX SBOM job; `publish-images.yml` SLSA provenance + per-image SBOM |
| SC-007 | Med | No CI secret scanning | ✅ Resolved | `ca04850` | gitleaks full-history (blocking); history verified clean |
| SC-008 | Med | Containers run as root | ✅ Resolved | `8a006d1` | live uids: nginx/frontend 101, correlation 10001, api distroless-nonroot; `no-new-privileges`+`cap_drop:[ALL]` |
| SC-009 | Low | Lab default creds in compose | ✅ Resolved | `8a006d1` | Keycloak `:?`; gnmic lab creds documented |
| SC-010 | Low | `gosec` `@latest` | ✅ Resolved | `ca04850` | pinned `v2.27.1` |
| SC-011 | Low | Python deps not hash-pinned | ✅ Resolved | `9771889` + `3f425f0` | `pip-compile --generate-hashes`; `--require-hashes` enforced; OSV-clean |

> CI-stabilization commit `a1c5b7d` cleared real findings the new/stricter gates
> surfaced: golangci-lint backlog (errorlint/noctx/gosec G101), Trivy CRITICAL
> `pgx` CVE-2026-33816 (bumped v5.7.5 → v5.9.2), and the starlette advisories.

---

## 5. Exceptions register (accepted risk / documented deviations)

| Item | Decision | Rationale |
|------|----------|-----------|
| Trivy **DS-0002** (no `USER`) on swtpm sidecar | Path-scoped ignore (`.trivyignore.yaml`) | Dormant (SEAL_PROVIDER-gated) software-TPM custodian managing a bind-mounted state dir; stays root-managed by design. All other Dockerfiles run non-root and remain enforced. |
| gnmic `SRL_GNMI_PASS` / `EOS_GNMI_PASS` lab defaults | Kept as documented lab-fabric **device** creds | Not platform secrets; not installer-generatable (must match lab device config). Override in `.env` for a real fabric. |
| LDAP `UseTLS`/`StartTLS` defaults unchanged | Warn, don't flip | Flipping defaults would hard-break working plaintext-`:389` deployments; insecure-skip-verify is now gated behind `ALLOW_DEV_SECRETS`. |
| `publish-images.yml` inactive until first tag | Activation is owner's action | Publishing is outward-facing/semi-permanent; PRIVATE GHCR, release-triggered, deploy still builds locally (offline ethos preserved). |

---

## 6. CI/CD gate status (at `3f425f0`)

| Workflow | Result | Enforces |
|----------|--------|----------|
| backend-ci | ✅ green | build · vet · test · race · govulncheck · gosec · staticcheck · golangci-lint |
| correlation-ci | ✅ green | pytest · ruff · bandit · mypy · **pip-audit (blocking)** |
| frontend-ci | ✅ green | tsc · build · npm audit |
| supply-chain | ✅ green | **Trivy fs** · **gitleaks (full history)** · **CycloneDX SBOM** |
| publish-images | inactive | builds/pushes + SLSA provenance + SBOM on `v*.*.*` tag |

---

## 7. Residual risk & recommended next steps

1. **Security Lows — all closed** (SR-017…030). One residual engineering item:
   SR-028 swtpm seal-socket SO_PEERCRED — implement a peer-cred-checking listener
   to replace `socat` if/when the swtpm sealing provider is run in production
   (dormant by default; interim control = container + FS boundary).
2. **Activate `publish-images`** by cutting a `v*.*.*` tag, then confirm GHCR
   package visibility is **private** and verify an attestation
   (`gh attestation verify oci://…`).
3. **Keep the dependency floor moving** — Dependabot now opens weekly PRs across
   gomod/npm/pip/docker/actions; the blocking scanners (govulncheck/pip-audit/
   npm-audit/Trivy/gitleaks) gate them.

---

*Generated 2026-06-07. Evidence: commit range `bf2ba29…56b3d95` on
`feat/observability-platform`. See per-finding detail in
`SECURITY_AUDIT_2026-06-07.md`.*
