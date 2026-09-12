# Correlix Security — Evidence Matrix

**Owner decision #8:** every control is classified, and nothing is called
implemented without a file path and symbol. Verified 2026-08-04 against branch
`feat/observability-platform`.

> **Reading order (2026-08-12):** §1–6 are the 2026-08-04 PRE-PROGRAMME
> baseline, kept verbatim as the honest "before" — their `file:line` anchors
> are as-of-that-date and are NOT maintained. §7 (2026-08-04 evening) and
> **§8 (the #151 programme, 2026-08-05…12)** record what changed since; where
> a §1–6 row conflicts with §8, §8 wins. Current per-edge transport truth
> lives in `transport-inventory.yaml` + `mtls-edges.yaml` (contract-pinned);
> the proof ledger is `TLS_ASSURANCE_REPORT_2026_08.md`.

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

## Summary (as of 2026-08-04 — superseded; see §7/§8 for what changed)

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

*(§7's "still outstanding" list is itself history now — every one of those six
fatal findings was closed by the #151 programme below; the live validator
reads fatal=0 warn=1, the warn being BKP-001 backup-destination encryption,
deferred by decision.)*

---

## 8. What changed — tracker #151 programme (2026-08-05 … 2026-08-12)

Report = `TLS_ASSURANCE_REPORT_2026_08.md` (13-phase run 2026-08-09 + step-3
fix log F-1…F-12 + F-11 verdict). Inventory rows = ids in
`transport-inventory.yaml`. All evidence pointers below resolve today.

### 8.1 Transport + datastore controls

| Control | Was | Now | Evidence |
|---|---|---|---|
| Kafka transport + authn | DO | **VI** | MTLS:9094 (client cert required) + FLOWS:9095 TLS-anon; PLAINTEXT:9092 REMOVED, default-deny ACLs (enforce wave `ebadd2af` 2026-08-09); report phase 6: ANONYMOUS sees 1/17 topics, consume refused; rows `vector-aggregator-kafka`, `goflow2-kafka` |
| Kafka topic auto-creation | CBE | **VI (fixed)** | `KAFKA_AUTO_CREATE_TOPICS_ENABLE: "false"` (docker-compose.yml); lane topics ⊆ kafka-init create list pinned in `tests/test_assurance_contracts.py` |
| OpenSearch authn | CBE | **VI** | Security plugin on, HTTPS, 6 least-privilege basic-in-TLS identities (owner-accepted shape, F-3); report phase 6: anon 401, write-only-read 403 |
| VictoriaMetrics authn | CBE | **VI** | vmauth TLS + per-user scoping (`66894727`); report phase 11: write-only users 400 no-route on query paths, wrong password 401 |
| Valkey authn + TLS | CBE | **VI** | TLS 6380 only; report phase 6: NOAUTH / WRONGPASS / plaintext 6379 refused; row `api-valkey` |
| Postgres TLS enforced server-side | CBE (TLS) | **VI** | F-4 fix `e9b9541f` 2026-08-10: wrapper-owned `hostssl` pg_hba; `test_postgres_tls_entrypoint_requires_hostssl` (tests/test_assurance_contracts.py) + `TestPostgresRefusesPlaintextTCP` (src/backend/pg_hostssl_guard_test.go); live: every `pg_stat_ssl` session TLSv1.3 |
| Ingest lane identity | PI | **VI** | SEC-013.1/.2: mTLS client-cert required + per-lane tokens, shared token opens no lane (`c1153aa5`); wave matrix 4× per-lane 200 / shared 401; report phases 5+7 |
| syslog-ng → aggregator hop | CBE (undeclared plaintext, F-1) | **VI** | F-1 fix `4e5e0d00` 2026-08-11: mesh TLS + REQUIRED client cert; `test_syslog_hop_serves_and_requires_mesh_tls`; live: no-cert refused, plaintext reset, marker landed over TLS |
| Sealing-key distribution | CBE | **VI** | SEC-018.1 router-SVID-only; report phase 11 gate matrix (router 200 / wrong SVID 401 / stolen token 401 / no cert refused / feature-off 404), proven feature-ON twice |
| Sealed-fields edge path deliverable | CBE (F-6/F-7: never executable in-image) | **VI** | fixes `95b99e02`; `TestGeneratedConfigSurvivesMultilineActionVRL` (processors/generate_test.go) + `test_router_image_provides_secret_backend_dependencies`; e2e re-run PASS 2026-08-11 (sealed doc in tenant index, audited unseal) |
| Secret sealing enforcement | IBD | **VI** | `SEAL_PROVIDER=swtpm` live + installer default (scripts/install.py); `REQUIRE_SEAL` fail-closed (internal/vault/secrets.go); secprofile sealed-secrets rule |
| Production fail-closed validator | PR | **VI** | `internal/secprofile` 16 rules; live fatal=0 warn=1 (report header). Honest gap: no bus/ingest-lane rule yet (INVARIANTS §8) |
| Inventory completeness | PI (aux edges missing, F-5) | **VI (mechanical)** | 22 rows added (incl. `api-gotenberg`, `keycloak-postgres` tls-unverified, `netbox-valkey` TLS-incompatible — honesty rows); `test_every_compose_service_appears_in_the_transport_inventory` forces a transport decision per compose service |
| Inventory honesty vs shipped epics | CBE (stale rows, F-2/F-3) | **VI** | fixes `bae20f59`; `test_transport_inventory_rows_reflect_shipped_epics` + `test_transport_inventory_targets_record_owner_accepted_shapes` |
| `transport_authenticated` labeling | CBE | **PI — still partial** | Posture view labels device lanes unauthenticated (`secobs.DeviceLaneRows`); `tenant_attribution`/`tenant_registry` per-event stamps on device lanes; trap-lane `authenticated`. The stack-wide per-event stamp E7 requires remains UNBUILT — claim C8 stays partial |
| Rotation continuity | UNK | **VI** | report phase 10: three consecutive rotations, distinct serials, zero lane interruption (honest deviation: interim TTL=168 h, forced mints — not a literal short-TTL soak) |
| Fresh `--tls` install in CI | CBE (F-9) | **VI (built; first run pending)** | blocking `tls-install-boot` job (`76626ffe`); `test_ci_runs_the_tls_install_path`; execution awaits owner push, like all CI on this branch |
| Device→tenant map hot reload | CBE (F-10: restart-only) | **VI** | `cx-enrichment-reload.sh` on both tiers + content-aware export; `TestWriteEnrichmentCSV_UnchangedContentDoesNotRewrite` + `test_vector_tiers_reload_enrichment_on_change`; live convergence 61 s (≤ ~75 s bound) |
| Id-less device rows | CBE (F-8) | **VI (fixed)** | `TestIdlessDeviceCreateDerivesId` + `TestEmptyIDRowIsRepairedAtLoad` (device_persist_test.go); lab fixture healed + deleted 2026-08-11 |
| pgintegration proofs execute | CBE (F-12: suite dead 2 weeks) | **VI** | fix `7616f3d2`; all 6 proofs PASS live incl. `TestAppRoleCannotBypassRLS`; anti-rot `go vet -tags=pgintegration` in backend-ci |

### 8.2 F-11 seal-or-quarantine (owner decision 2026-08-12; verdict PASS)

Design: `docs/design/f11-seal-or-quarantine.md`. Commits `d92f8919`,
`6ad927c8`, `24d7de81`, `fda3452d`, `8124d834`. Boundary: exists only when
sealing custody is enabled (the feature's own boundary).

| Control | Class | Evidence |
|---|---|---|
| Quarantine seal path (registry MISS ⇒ sealed envelope, dedicated `quarantine` key scope, never plaintext) | **VI** | `processors/quarantine.go`+test; F11.2 live: unknown-host syslog → `netops-quarantine-2026.08.12`, payload `<enc:v1:cXVhcmFudGluZQ:...>`, absent from every syslog index |
| Case-1 preservation (authenticated producer stamps never quarantine) | **VI** | F11.1 live + VRL-harness discriminator matrix; `producer_stamped` path unchanged |
| Isolation from tenant/dashboards/correlation reads | **VI** | `TestQuarantineIndexUnreachableFromTenantPaths` (logs_tenant_test.go) + OS roles (writer/api only); F11.8 live scoped search empty; F11.9 correlation refuses (`identity_unattributable`, quarantined NOT persisted) |
| Operator workflow (platform-only, dual-gated, audited; live-inventory-derived tenant; cross-key re-encryption) | **VI** | `TestQuarantineRoutesArePlatformOnly` + `TestQuarantineReattributeRequiresSensitiveDataAdmin` + `TestQuarantineListOmitsSealedPayload` (quarantine_api_test.go); F11.3 live restore, audit row |
| Idempotent re-attribution / replay | **VI** | `id_key: cx_event_id` on the five OS event sinks; F11.11 live: restore → replay → router restart ⇒ exactly ONE tenant doc (a real fix found by the battery). Residual: CH flows re-insert on re-restore (report §8.5) |
| Retention bound | **VI (attachment proven)** | `netops-quarantine-retention` 30 d ISM policy attached live (F11.4); deletion action contract-pinned; 30-day wall-clock NOT simulated |
| Fail-closed on key unavailability | **VI** | Vector exit-78 config refusal (live-demonstrated during the run); runtime seal failure ⇒ drop_on_abort, NO deadletter reroute |
| Observability (3 alerts + depth/age metrics) | **VI** | `QuarantineGrowthAbnormal`, `QuarantineAttributionStalled`, `VectorQuarantineSealFailures` (src/config/rules.yaml; promtool suite src/config/rules-tests/f11-quarantine.test.yaml); `netops_sec_quarantine_depth` served through the mesh (F11.12) |

### 8.3 Known-not-proven (state these, never round up)

| Item | Status |
|---|---|
| CI legs: `-race`, staticcheck, gosec, govulncheck | **NOT EXECUTED on this branch** — no local gcc; awaits the owner's push. Local `go vet` + full test suites green (report phase 13 + F-11 §6/7) |
| Shipped-variant plaintext `:8000` | Still published by `compose.tls.yml` (lab removed it 2026-08-09); claim C3 carries the exception until the installer-messaging work lands |
| Device-side protocols (syslog 514, SNMP v2c/traps, NetFlow/sFlow, gNMI lifecycle) | Out of v1 scope by the anchor sentence; device programme P0–P4. Syslog hostname-spoof INJECTION residual documented (report §8.1) |
| 30-day quarantine wall-clock expiry | Policy attachment + deletion action verified; full wall-clock not simulated |
| api→gotenberg (tenant PDFs) + two metrics-scrape hops | Declared plaintext, owner decision pending (F-5 rows) |
| Backup-destination encryption | BKP-001 warn, deferred by decision — unchanged |
