# Security Audit & Supply-Chain Review — 2026-06-07

> Branch: `feat/observability-platform` · Scope: full backend (Go), correlation
> (Python), frontend (React), deployment (nginx/compose/CI). Method: 5 parallel
> read-only specialist audits (authz/tenancy, crypto/secret-custody,
> injection/input-validation, LLM+web/transport, supply-chain) reconciled and
> de-duplicated. No code was modified during the audit.

## Executive summary

The platform's **security design is strong and unusually well-reasoned** — the hard
parts are correct: the `tlsconfig`/`internalca` packages, the AES-256-GCM Vault
(nonce/AAD/DEK-KEK handling), PBKDF2 password hashing (600k iters, constant-time),
JWT algorithm-confusion defenses, SSH host-key TOFU, the central `Authorize()`
tenancy chokepoint, parameterized pgx SQL, ClickHouse row-policy tenant scoping, and
the copilot's OWASP-LLM hardening all pass. Dependency hygiene is good (vendored+pinned
Go, committed lockfile, `==`-pinned Python, blocking govulncheck/gosec/staticcheck/
npm-audit/bandit).

The findings are concentrated in **enforcement gaps at the edges**, not the crypto core:
one Critical cross-tenant IDOR, missing write-level authorization on a few mutation
routes, web-tier hardening (headers/CORS/WebSocket-origin/unauthenticated infra
consoles), and the **supply-chain perimeter** (no image scanning / SBOM / Dependabot /
SHA-pinned actions / digest-pinned images).

**False positive cleared:** an initial finding claimed real secrets persist in git
history via `deployment/docker/.env`. Verified untrue — the only `.env` ever committed
(`4f37c7b`) contained placeholder comments only; **no secret values were ever committed.**
No secret rotation or history rewrite is required. (The CLAUDE.md warning about a tracked
`.env` is **stale** — resolved in `6c02200`; see SR-031.)

### Counts
| Severity | Count | IDs |
|---|---|---|
| Critical | 1 | SR-002 |
| High | 5 | SR-003 – SR-007 |
| Medium | 9 | SR-008 – SR-016 |
| Low | 14 | SR-017 – SR-030 |
| Supply-chain | 11 | SC-001 – SC-011 |
| Housekeeping | 1 | SR-031 |

---

## Findings register

### CRITICAL

#### SR-002 — Cross-tenant report-execution IDOR via `POST /api/reports/run`
- **Files:** `report_scheduler.go:74` (`handleReportRunNow`) → `report_pipeline.go:182` (`EnqueueNow`)
- After gating on `reports:write`, the handler resolves the report with the **unscoped**
  `s.saved.Get(id)` and never checks `canSeeSaved`/tenant ownership; `EnqueueNow` then runs
  under the *report's* `TenantID`, not the caller's.
- **Exploit:** a tenant-A user with `reports:write` guesses/enumerates a tenant-B report id,
  POSTs it; the platform renders tenant-B's report and delivers it to **tenant-B's configured
  channels**. With link-delivery, the attacker can obtain the resulting capability URL
  (compounds with SR-018) → cross-tenant data exfiltration.
- **Fix:** resolve `tenant, cross := principalTenant(claims)` and reject `!canSeeSaved(o, tenant, cross)`
  with 404 before enqueue — mirror `handleSavedByID` / `handleReportExecutions` (which *are* scoped).

### HIGH

#### SR-003 — Missing write-level authorization on device / rule / discovery mutations
- **Files:** `main.go:617` `handleDevices` POST, `main.go:644` `handleDeviceByID` DELETE,
  `main.go:713` `handleRules` GET/POST, `main.go:747` `handleDiscoveryRefresh`
- The middleware chain (`withCORS→withLogging→withAuth→withAudit→mux`) enforces
  **authentication only**; there is no per-route RBAC wrapper, and these handlers never call
  `requirePerm`. (Most other handlers — `snmp_handlers.go`, `incidents_http.go`, `report_*` —
  correctly do.)
- **Exploit:** any authenticated principal incl. a `read-only` user or least-priv `api-client`
  key can create/delete devices, inject **platform-wide** alert rules, and trigger discovery
  scans against the configured CIDR.
- **Fix:** add `requirePerm(..., "infrastructure", LevelWrite)` to device write paths + discovery
  refresh; `requirePerm(..., "alerts", LevelWrite)` (likely platform-owner — see SR-004) to rule
  mutation.

#### SR-004 — Alert rules are platform-global with no tenant model
- **Files:** `main.go:713`, `graphql.go:71` (`rules` query)
- Rules have no `TenantID`; they are returned in full to any authenticated caller and (per SR-003)
  writable by any authenticated caller. A scoped tenant can read every rule (device names,
  thresholds, infra topology) and add rules that fire platform-wide.
- **Fix:** treat rules as platform-owner-scoped (`requireCrossTenant`) or add a tenant column; at
  minimum gate writes.

#### SR-005 — CORS wildcard `Access-Control-Allow-Origin: *` on all API responses
- **File:** `main.go:800-811`
- **Assessment:** auth is Bearer-in-header (not cookie) and `Allow-Credentials` is unset, so this
  is **not** the classic credentialed-wildcard CSRF hole — but it is over-permissive (any site can
  read API JSON if it holds a token; broadcasts the full method surface).
- **Fix:** the app is same-origin behind nginx on `:8000` — remove CORS entirely or reflect a
  configured origin allow-list.

#### SR-006 — No Origin check on WebSocket upgrades (CSWSH risk)
- **Files:** `events.go:130-167` (`/api/events`), `device_ssh.go:466` (`wsUpgrade`)
- Upgrade handlers validate `Upgrade`/`Sec-WebSocket-Key` but never check `Origin` (WS is exempt
  from CORS). Token-in-query (`?token=`) partially mitigates (attacker needs a valid JWT) but tokens
  in URLs leak to logs/history (see SR-030/L1).
- **Fix:** validate `Origin` against an allow-list on both upgrades (403 on mismatch); prefer carrying
  the token in `Sec-WebSocket-Protocol` to keep it out of logs.

#### SR-007 — Missing security headers at the nginx edge
- **Files:** `deployment/docker/nginx/default.conf` (no `add_header`), `main.go:423` (HSTS only when
  Go terminates TLS)
- No CSP, `X-Frame-Options`/`frame-ancestors` (SPA is frameable → clickjacking), `X-Content-Type-Options:
  nosniff`, `Referrer-Policy`; HSTS absent in the default plain-HTTP nginx deployment.
- **Fix:** add `add_header` directives on the SPA `location /` (X-Frame-Options DENY, nosniff, a CSP,
  Referrer-Policy no-referrer); emit HSTS at the nginx TLS edge once TLS is on.

### MEDIUM

#### SR-008 — `/prometheus/` and `/metrics` proxied with NO auth gate (unauthenticated infra-metrics leak)
- **File:** `nginx/default.conf:97-104` (`/prometheus/`), `:90-93` (`/metrics`); `auth.go:330` (`/metrics`
  in `publicPaths`)
- Unlike `/grafana/` and `/search/` (gated by `auth_request /__osd_auth`), `/prometheus/` has no gate.
  Anyone hitting `:8000/prometheus/` gets the full Prometheus UI — all platform/infra series, targets,
  internal hostnames, scrape configs.
- **Fix:** add `auth_request /__osd_auth;` to `/prometheus/`; restrict `/metrics` to the scraper network
  (nginx `allow`/`deny`) rather than public.

#### SR-009 — Unauthenticated `/admin/health` leaks fleet + collector internals & version
- **Files:** `main.go:586` `handleHealth`, `auth.go:317` (`/admin/health` in `publicPaths`); also via
  GraphQL (SR-010)
- Anonymous `curl :8000/admin/health` returns version (`0.1.0-scaffold`), discovery per-source device
  stats, and collector inventory/health — recon/fingerprinting surface.
- **Fix:** make `/admin/health` minimal liveness (`{status,version?}`); move detailed health to an
  authenticated endpoint.

#### SR-010 — GraphQL `health`/`collectors`/`discovery`/`rules` resolver bypasses the platform-owner gate
- **File:** `graphql.go:74-82`
- The REST equivalents (`handleCollectors`) use `requireCrossTenant` precisely so a tenant can't learn
  global fleet size; the GraphQL resolver returns the same data to any authenticated principal.
- **Fix:** scope/omit these fields for non-cross-tenant callers.

#### SR-011 — ClickHouse SQL injection via `severity` parameter
- **File:** `flows.go:114` — `"severity = '"+strings.ReplaceAll(sev,"'","")+"'"`
- Quote-stripping only; ClickHouse honors **backslash escapes**, so `?severity=\` breaks out of the
  string literal. **Tenant isolation is NOT bypassable** (the `tenant_scope` is a URL param enforced by
  CH row policies — defense in depth holds); impact is query-shape manipulation / read-amplification within
  already-allowed rows. The Python service already guards this exact case (`severity.isalpha()`).
- **Fix:** validate against the severity enum / allowlist (mirror `flowTypeClause`), or escape backslash
  **and** quote.

#### SR-012 — No global request body-size cap; ~20 handlers decode unbounded JSON
- **Files:** `main.go:398,416-420` (no body cap, no `MaxHeaderBytes`); unbounded `json.NewDecoder(r.Body)`
  at `auth.go:114` (**pre-auth login**), `logs.go:89`, `report_preview_http.go:50`, `graphql.go:40`, +~15 more.
  Only 5 files use `MaxBytesReader`.
- nginx caps at 50 MB, but (a) 50 MB → Go struct per request is an amplifier on pre-auth login, and (b) in
  TLS/mTLS mode the Go server is reachable directly, bypassing nginx → unbounded.
- **Fix:** wrap `r.Body = http.MaxBytesReader(...)` in a middleware so every route is covered; set
  `http.Server.MaxHeaderBytes`.

#### SR-013 — No maximum password length → PBKDF2 (600k-iter) DoS
- **Files:** `users.go:403-408` (only checks `< 8`), `password.go:31-36`
- No upper bound; PBKDF2-600k runs over the full input on **every login and change-password**. A multi-MB
  "password" forces heavy CPU per request (amplification DoS), unauthenticated on login.
- **Fix:** cap length (~64–128) in `validatePassword` and bound the auth request body (pairs with SR-012).

#### SR-014 — LDAP TLS bypasses `tlsconfig`; `InsecureSkipVerify` + plaintext-bind default
- **File:** `ldap.go:370` (`tls.Config{InsecureSkipVerify: ...}` //nolint:gosec), defaults `:78-89`
- The one TLS path that skips the hardened package: `LDAP_INSECURE_SKIP_VERIFY=true` disables verification
  (MITM the bind), and `UseTLS`/`StartTLS` default **false** → the service bind password and **every user's
  password** transit `:389` in cleartext (bind-as-user is the credential check).
- **Fix:** route LDAP TLS through `tlsconfig.ClientConfig`; default to StartTLS/LDAPS; gate any insecure mode
  behind a loud dev-only flag.

#### SR-015 — SSRF via tenant-admin-configurable outbound integration URLs
- **Files:** `itsm_config.go:331-346` (validates only scheme), `notify_config.go` → `notify/{servicenow,jira,slack}.go`
- A tenant admin can set `ServiceNow.InstanceURL`/`Jira.BaseURL`/`Slack.WebhookURL` to arbitrary hosts; no
  internal-range block. Backend then makes authenticated requests there → probe internal network, hit cloud
  metadata (`169.254.169.254`), or exfil the configured API token to an attacker host.
- **Fix:** shared SSRF guard — resolve host, reject loopback/link-local/private/CGNAT/multicast/metadata
  (and on redirect); optional host allowlist. Apply to Netbox/ITSM/Slack/all webhook targets.

#### SR-016 — Vault dormant-by-default = plaintext secrets at rest, unflagged at runtime
- **Files:** `secrets.go:30-34,119-122`, `secrets_config.go:32`
- With no `SEAL_PROVIDER`, `Encrypt` returns plaintext; out of the box all reversible secrets
  (SMTP/Twilio/Slack/PD/OIDC client-secret/LDAP bind pw/TACACS/SNMP creds/integration webhook secrets/internal-CA
  key) are stored cleartext. The Vault's value ("RLS bug leaks ciphertext not secrets") is inactive by default
  and nothing surfaces the condition.
- **Fix:** boot `logWarn` when reversible secrets are written with a dormant Vault; consider `REQUIRE_SEAL=true`
  to fail closed in production profiles.

### LOW

| ID | Title | File |
|---|---|---|
| SR-017 | Weak fallback `JWT_SECRET` (`dev-only-…`) also keys report/export links when env unset → forgeable sessions+links; should fail closed in prod unless `ALLOW_DEV_SECRETS=true` | `auth.go:524-532`, `report_links.go:25` |
| SR-018 | 7-day report-view link is execID-only, **tenant-unbound** (export links bind tenant + 5–15 min TTL); compounds SR-002 | `report_links.go:32-73,162` |
| SR-019 | ServiceNow webhook auth = static bearer secret, no signature/replay protection (siblings use HMAC) | `integration/servicenow.go:26` |
| SR-020 | PagerDuty/Jira webhooks lack replay protection (Slack has timestamp-skew) | `integration/{pagerduty,jira}.go` |
| SR-021 | No per-user/tenant rate limit on `/api/copilot/chat` → provider-cost DoS | `copilot.go:98` |
| SR-022 | Copilot relays raw provider error body verbatim → upstream metadata leak | `copilot.go:189-191,228-230` |
| SR-023 | Netbox poller follows upstream-supplied pagination URL with API token attached → SSRF/token leak | `discovery.go:488-551` |
| SR-024 | JWT verify has no `iat`/`nbf` enforcement; access tokens not revocable before `exp` (1h) | `jwt.go:36-60` |
| SR-025 | Federated default tenant = global/platform tenant → a mis-mapped federated super-admin becomes platform owner | `ldap.go:88`, `oidc.go:115` |
| SR-026 | Tenant admin can mint **tenant-local** super-admins (stays tenant-confined, but confirm intent) | `identity_handlers.go:114-187` |
| SR-027 | Wrapped-DEK map has no top-level integrity (delete entry → next write mints new DEK → tenant ciphertext unrecoverable; tamper/DoS) | `secrets.go:227-251` |
| SR-028 | swtpm KEK socket unauthenticated (relies on FS perms); peer should be auth'd (SO_PEERCRED) | `secrets_swtpm.go:41-92` |
| SR-029 | `verifyPassword` honors caller-supplied low iteration count; should rehash-on-login if `iter < current` | `password.go:50-64` |
| SR-030 | `Secure` cookie flag off by default (HTTP deploy → JWT-bearing `netops_osd` cookie in cleartext) | `auth.go:462-498` |

### HOUSEKEEPING

#### SR-031 — Stale CLAUDE.md warning about tracked `.env`
- CLAUDE.md warns `.env` is tracked with secrets in history. **Resolved** in `6c02200` (untracked + gitignored);
  history never contained real secrets (verified). Remove the warning.

---

## Supply-chain review

**Strong baseline:** vendored+pinned Go with full `go.sum` + blocking `govulncheck`; committed `package-lock.json`
+ `npm ci` + blocking `npm audit --audit-level=high`; `==`-pinned Python with blocking ruff/bandit/mypy; all
workflows `permissions: contents: read`; no `pull_request_target`; fail-closed `:?` on hard app secrets; secret
generation via Python `secrets`. **Git history clean of secrets.**

| ID | Sev | Gap | Fix |
|---|---|---|---|
| SC-001 | High | No container image scanning for the ~22 service images | Add Trivy (`fs` + per-image) job; blocking on own layers, triage on base CVEs |
| SC-002 | High | GitHub Actions pinned to mutable tags (`@v4/@v5/@v7`), not commit SHA | Pin every `uses:` to 40-char SHA (+ `# vX.Y.Z`); add Dependabot `github-actions` |
| SC-003 | High | No Docker image pinned to `@sha256` digest; `ghcr.io/openconfig/gnmic:latest` floats | Pin all `FROM`/`image:` to `tag@sha256:…`; give gnmic a real version first |
| SC-004 | Med | No Dependabot/Renovate | `.github/dependabot.yml`: gomod, npm, pip, docker (×4 dirs), github-actions; weekly |
| SC-005 | Med | `pip-audit` is soft (`continue-on-error: true`) — Python is the outlier | Make blocking in `correlation-ci.yml` |
| SC-006 | Med | No SBOM / provenance | `anchore/sbom-action` (CycloneDX) per artifact; `attest-build-provenance` on release images |
| SC-007 | Med | No secret scanning in CI | `gitleaks` on push+PR, full-history (`fetch-depth: 0`), blocking |
| SC-008 | Med | Containers run as root (correlation `python:slim`, frontend nginx, swtpm); only Go `api` is nonroot-distroless | Add `USER`; `nginx-unprivileged`; `cap_drop:[ALL]`, `no-new-privileges`, `read_only` where feasible |
| SC-009 | Low | Lab default creds in compose (`SRL_GNMI_PASS`, `EOS_GNMI_PASS`, `KEYCLOAK_ADMIN_PASSWORD`) | Switch to `:?`-required when their profile is enabled; document |
| SC-010 | Low | `gosec` installed `@latest` (unpinned) | Pin to `@v2.x.x` |
| SC-011 | Low | Python deps not hash-pinned | `pip-compile --generate-hashes` / `--require-hashes` |

---

## Recommended remediation order

**P0 — reachable by ordinary authenticated users / unauthenticated:**
1. SR-002 (cross-tenant report IDOR) — add the `canSeeSaved` check.
2. SR-003 / SR-004 (missing write-authz + global rules) — add `requirePerm`.
3. SR-008 (unauthenticated `/prometheus/` + `/metrics`) — nginx auth gate.
4. SR-011 (CH severity injection) — enum allowlist (quick).
5. SR-012 / SR-013 (body cap + password length) — one middleware covers both.

**P1 — hardening:**
6. SR-005/006/007 (CORS/WS-origin/security headers) — nginx + middleware.
7. SR-009/010 (health detail leak, REST + GraphQL).
8. SR-014 (LDAP TLS), SR-015 (SSRF guard), SR-016 (dormant-Vault warning), SR-017 (fail-closed JWT_SECRET).
9. Supply-chain P0: SC-001 Trivy, SC-002 pin actions to SHA, SC-003 pin image digests, SC-005 pip-audit blocking.

**P2 — depth + automation:**
10. Remaining Lows (SR-018…SR-030), SC-004/006/007/008 (Dependabot, SBOM, gitleaks, non-root containers).
11. SR-031 housekeeping (CLAUDE.md cleanup).
