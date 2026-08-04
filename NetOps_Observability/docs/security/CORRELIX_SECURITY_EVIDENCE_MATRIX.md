# Correlix Security — Evidence Matrix

**Owner decision #8:** every control is classified, and nothing is called
implemented without a file path and symbol. Verified 2026-08-04 against branch
`feat/observability-platform`.

## Classification vocabulary

| Class | Meaning |
|---|---|
| **VI** | Verified implemented — code exists, is reachable, and is on in the shipped config |
| **IBD** | Implemented **but disabled** — code exists and is wired; configuration switches it off |
| **PI** | Partially implemented — works for some paths/cases only |
| **DO** | Documented only — described in docs, no implementation |
| **PR** | Proposed — design only |
| **UNK** | Unknown — not established by this review |
| **CBE** | **Contradicted by evidence** — a claim that the repository disproves |

**Rule: IBD is not a security property.** A control that is built and off may
not be claimed (see `CORRELIX_SECURITY_CLAIMS.md` §2).

Confidence: **H** = read the code · **M** = read config + inferred behavior ·
**L** = inference only, needs runtime proof.

---

## 1. Transport security

| Control | Class | Evidence | Runtime evidence still needed | Missing tests | v1 disposition | Risk | Conf |
|---|---|---|---|---|---|---|---|
| Browser→nginx HTTPS | **VI** | `nginx/tls.conf.example` (TLS 1.2/1.3, HSTS, PFS, tickets off); live handshake verified 2026-08-03 | Confirm plaintext `:8000` is **not** published in a production profile | Validator test asserting no plaintext listener in prod | **v1** | Med | H |
| nginx→API mTLS | **IBD** | `tls_server.go` (listener), `tls_ca.go:150-155` (nginx SVID minted), `tlsconfig/config.go` (builder) | Everything — no `TLS_*` set in live `.env` | Wrong-SAN / wrong-CA / expired / missing-cert rejection | **v1** | High | H |
| Internal CA + SVID issuance + auto-rotation | **IBD** | `internalca/ca.go:141,181`; `tls_ca.go:91-93` (ID), `:138-156` (issues **api + nginx only**), `:163` (TTL/2 reissue) | CA bootstrap has never run in this deployment | Dual-root rotation; boot refusal when unsealed | **v1** | High | H |
| Backend mTLS client (OpenSearch/CH/VM/correlation) | **IBD** | `backend_client.go:33-79`; 14 call sites via `backendHTTPClient` | Dormant when CA vars empty (`:35-37`) | Per-backend connection tests | **v1** (for v1-covered stores) | High | H |
| TLS policy floor (1.2, AEAD+ECDHE, no renegotiation) | **VI** | `tlsconfig/policy.go:23,31-39,55` | Applies only where TLS is on | — | **v1** | Low | H |
| Peer identity allowlist | **PI** | `tlsconfig/verify.go:21-84` — **but `:62-64`: an empty allowlist accepts ANY CA-signed cert** | — | Unrelated-but-valid identity must be **rejected** | **v1** — allowlist must be non-empty | High | H |
| SPIFFE federation (`TLS_FEDERATED_BUNDLES`) | **CBE** | Implemented (`tls_server.go:81`, `backend_client.go:42`) but **absent from `docker-compose.yml`** — unreachable via supported config | — | — | v1 (declare it) | Low | H |
| LDAP TLS (reference client) | **VI** | `internal/ldap/ldap.go:288-318`; `InsecureSkipVerify` refused outside dev `:311-317` | — | — | keep | Low | H |
| Kafka transport security | **DO** | `docker-compose.yml:207-210` — `PLAINTEXT` only, no SASL/SSL listener | — | — | **deferred** (decision #6) | High | H |
| goflow2→Kafka TLS | **PI (capability)** | v2.2.1 binary flags + upstream `transport/kafka/kafka.go@v2.2.1`: **TLS yes, SASL SCRAM yes, mTLS NO, skip-verify not even reachable, TLS 1.2 hardcoded, system cert pool only** | — | — | deferred with Kafka | Med | H |

## 2. Authentication of services

| Control | Class | Evidence | v1 disposition | Risk | Conf |
|---|---|---|---|---|---|
| API→correlation authentication | **CBE** | **None exists.** `correlations.go:765` sets no headers, no client cert. FastAPI app `main.py:3319` has **zero `Depends`** — all 6 routes unauthenticated | **v1 — P0** | **Critical** | H |
| Correlation `/deadletters` fronted by API authz | **CBE** | Docstring `main.py:3336-3338` claims the Go API fronts it. **`grep deadletter` over `src/backend/*.go` → zero hits.** Nothing fronts it | **v1** | **Critical** | H |
| Ingest lane auth (Vector http_server) | **PI** | `collectors/ingest_auth.go:63-78` Basic; Vector `vector.yaml:126-171` fail-closed — **one shared token**, plaintext transport | v1 (transport), identity deferred | High | H |
| Inbound webhook HMAC (per-connector) | **VI** | `nms_http.go:457-501`, `integrations_http.go:221` | keep | Low | H |
| Session/JWT + RBAC/PBAC | **VI** | `auth.go`, `authz.go`, `internal/rbac` | keep | Low | H |

## 3. Datastore authentication

| Store | Class | Evidence | v1 disposition | Risk | Conf |
|---|---|---|---|---|---|
| OpenSearch | **CBE** | `docker-compose.yml:538` `DISABLE_SECURITY_PLUGIN: "true"`; **no credentials exist anywhere** in the repo; plugin still present in image (`opensearch/Dockerfile:11-13`) | **v1-mandatory** | **Critical** | H |
| Valkey (`redis`) | **CBE** | `docker-compose.yml:100` — no `--requirepass`, no `--tls-port`, no ACL. Client AUTH exists (`collectors/redis.go:68-71`) but gated on `REDIS_PASSWORD`, never set | **v1-mandatory, sequenced** (§5) | **Critical** | H |
| VictoriaMetrics | **CBE** | `docker-compose.yml:616-636` — no `-httpAuth.*`, no TLS. Anonymous **read AND write** + `delete_series` | **v1-mandatory** | **Critical** | H |
| ClickHouse | **PI** | Password required, `default` user removed (image entrypoint `:128-148`) — **but `docker-compose.yml:914` `CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT: "1"` lets the shared app credential DROP its own row policies** | **v1 — privilege reduction, not TLS** | High | H |
| PostgreSQL | **VI (auth) / CBE (TLS)** | scram-sha-256 (image entrypoint `:266-285`, no `POSTGRES_HOST_AUTH_METHOD`); app role `netops_app` is non-superuser so FORCE RLS bites. **But `.env:28` pins `sslmode=disable`**, and the cluster **superuser** is injected into `api:1088-1089` and `correlation:977` where it is provably unused | **v1 — two cheap fixes** | Med | H |

## 4. Tenant isolation

| Control | Class | Evidence | v1 disposition | Risk | Conf |
|---|---|---|---|---|---|
| ClickHouse row policies | **PI** | 23 policies `init.sql:566-1023`, converged `clickhouse_policies.go:25-52`, strictness **test-guarded** `clickhouse_policies_test.go:76-80`. Gaps: all PERMISSIVE (no `AS RESTRICTIVE` anywhere), convergence is best-effort/never-fatal, and `__all__` is an accepted bypass clause | **v1 — durability + guarded recreation** | High | H |
| `users.d/tenant-scope.xml` (scope default) | **CBE** | Referenced by `clickhouse/custom-settings.xml:7`; **the directory does not exist** (8 files, no `users.d/`). Fails closed (unset scope errors) but the reference is a phantom | **v1** | Med | H |
| Postgres FORCE-RLS + `withTenant` | **VI** | `internal/platformdb`, non-superuser app role, boot assertion `db.go:186-207` | keep | Low | H |
| OpenSearch tenant isolation | **PI** | **App-layer only**: per-tenant index names (`vector-router/vector.yaml:548`) + `osTenantFilter` (`logs.go:72`). No server-side enforcement — the store is unauthenticated | **v1** (via auth) | High | H |
| API tenant scoping (`principalTenant`) | **VI** | `tenancy.go:63-80`; `ActingTenant` refused for non-owners `:75-79` | keep | Low | H |
| **Correlation replay honors tenant** | **CBE** | **CROSS-TENANT LEAK.** `correlations.go:462` permission-only gate → `:762-786` proxies caller-supplied UUID with **no ownership check, no claims consulted** → `replay.py:234,241,245` **no tenant predicate** → `main.py:1837` `tenant_scope=__all__` → response relayed verbatim. Sibling `/{id}` correctly 404s (`correlations.go:734-737`) | **v1 — P0, ~15 lines** | **CRITICAL** | H |
| Route isolation coverage guard | **CBE** | `route_isolation_test.go:68` classifies `/api/correlations/` as scoped with a note that is **false for the `/replay` subresource**; guard checks prefixes, so siblings satisfied it | **v1 — guard must check subresources** | High | H |

## 5. Secrets and keys

| Control | Class | Evidence | v1 disposition | Risk | Conf |
|---|---|---|---|---|---|
| Envelope encryption, per-tenant DEK | **VI** | `internal/vault/secrets.go` AES-256-GCM, AAD = tenant\|field | keep | Low | H |
| `REQUIRE_SEAL` production enforcement | **IBD** | Implemented `secrets.go:98-100`; **no `SEAL_*` in live `.env`** → passthrough plaintext. Strict-equality parsing (`TRUE`/`1` would not enable it) | **v1** | High | H |
| CA key sealed | **CBE** | `tls_ca.go:23-24` — enabling `TLS_INTERNAL_CA` **without** a seal provider stores the CA private key **in plaintext** | **v1 — boot refusal** | **Critical** | H |
| Sealing-key distribution | **CBE** | `vector-router/cx-secret-backend.sh:24,55` — per-tenant `cxseal.*`/`cxmac.*` keys fetched over **plaintext HTTP** with the shared Basic token | **v1** | **Critical** | H |
| Backup encryption | **PR** | No implementation. Owner decision #1: **explicitly out of v1** | deferred, posture-visible | Med | H |

## 6. Enforcement, observability, hygiene

| Control | Class | Evidence | v1 disposition | Risk | Conf |
|---|---|---|---|---|---|
| Production fail-closed validator | **PR** | Hooks exist (`scripts/preflight-configs.sh`, `preflight-install.py`); no security validator | **v1 — the keystone** | High | H |
| TLS metrics | **PI** | `tls_server.go:139-159` — **but `writeTLSMetrics` emits nothing when no leaf is loaded**: metrics vanish exactly when broken | **v1** | Med | H |
| Cross-tenant **write** counter | **VI** | `main.py:1792-1793`, exported `:3414` | keep | Low | H |
| Cross-tenant **read** counter | **CBE** | Does not exist — the direction that matters here is uncounted | **v1** | High | H |
| Correlation query audit | **CBE** | No audit on `proxyCorrelationReplay` (siblings audit at `correlations.go:429-453`); none in the Python service | **v1** | High | H |
| `transport_authenticated` labeling | **CBE** | **Does not exist.** Narrower `Authenticated` field on the trap lane only (`snmptrap.go:60`) | **v1** (claims depend on it) | Med | H |
| Healthchecks authenticate | **CBE** | `pg_isready`, `valkey-cli ping`, OpenSearch `_cluster/health`, ClickHouse `/ping`, and `stack_health.go:126-135` (bare TCP) — **all stay green through a botched auth cutover** | **v1 — same change as credentials** | High | H |
| Container hardening | **PI** | `no-new-privileges` on 7 of 32 services; `read_only`/`tmpfs` **nowhere** | deferred | Med | M |
| Kafka topic auto-creation | **CBE** | `KAFKA_AUTO_CREATE_TOPICS_ENABLE: "true"` (`:217`); 4–10 topics exist only by auto-creation | deferred with Kafka | Med | H |
| nginx rate limiting | **CBE** | None (`tls.conf.example` says so explicitly) | deferred | Med | H |

---

## Summary

| Class | Count | Note |
|---|---|---|
| **CBE — contradicted by evidence** | **18** | The headline: most "controls" fail on inspection |
| **IBD — built but switched off** | 5 | The entire PKI. None may be claimed |
| **VI** | 11 | Mostly app-layer: RBAC, RLS, vault, LDAP, webhook HMAC |
| **PI** | 9 | |
| **PR / DO / UNK** | 4 | |

**The two findings that outrank everything else:** the correlation replay
cross-tenant leak (live, browser-reachable, ~15-line fix) and the unauthenticated
datastores (OpenSearch, VictoriaMetrics, Valkey — reachable by any container).


---

## 7. What changed — 2026-08-04 (evening)

The PKI stopped being theoretical. Enabling it also surfaced two bugs that
would have bricked any deployment that tried, which is exactly why "built" was
never the same as "working".

| Control | Was | Now | Evidence |
|---|---|---|---|
| Internal CA + SVID issuance | IBD | **VI** | CA bootstrapped live, valid to 2036; api + nginx SVIDs minted with correct SPIFFE URI SANs; 0 restarts |
| nginx→API mTLS | IBD | **VI** | api listening `(TLS, mTLS=true)`; plaintext→api **400**; TLS without client cert **handshake fails**; login through nginx **200** |
| mTLS peer allowlist | PI | **VI** | `TLS_CLIENT_ALLOWED_URIS=spiffe://netops/ns/default/sa/nginx` — a valid cert issued to another service is refused |
| Secret sealing (`SEAL_PROVIDER`) | IBD | **VI** | swtpm sidecar live; CA key sealed at rest |
| CA key sealed (was the plaintext foot-gun) | CBE | **VI** | Boot refusal shipped (`tls_ca.go` seal gate) + 4 tests incl. the refusal message contract |
| Production validator | PR | **VI** | `internal/secprofile`, 16 rules, 6 test suites; live: `profile=lab, fatal=6, warn=1`, non-blocking |
| Security posture feed | PR | **VI** | `GET /admin/security/posture`, platform-admin gated, structured output |
| Cross-tenant leaks (5) | CBE | **VI (fixed)** | `/replay` + 4 VictoriaMetrics leaks closed, each regression-proven |
| SNMP profile write gate | CBE | **VI (fixed)** | now `requirePlatformAdmin`, matching the ledger's own globalRef contract |
| ClickHouse SETTINGS precedence | UNK | **VI** | verified empirically against CH 24.8: the SQL clause wins, so the 18 cloud sites are safe; pinned by a contract test |

**Two bugs found only by enabling it:**

1. **First-boot ordering** — `initBackendTransport` demanded a trust bundle the
   CA had not minted yet, so enabling internal TLS crash-looped the API.
   Fixed by deferring (never skipping) that one call and re-initializing after
   the CA bootstrap, where it fails closed as before.
2. **Cross-uid key handoff** — the nginx SVID is minted by the API (uid 65532)
   and read by nginx (uid 101); a 0600 key owned by the API made nginx refuse
   to boot. `chown` cannot fix it (this process is deliberately non-root, so
   `EPERM`), so the key mode is now explicit, defaults safe, and warns when
   widened.

**Still outstanding** — the validator names them precisely, which is the point:
API→OpenSearch, →ClickHouse, →VictoriaMetrics, →Postgres, →Valkey and
→correlation remain plaintext (6 fatal findings), plus backup-destination
encryption (1 warn, deferred by decision).
