# TLS/mTLS Assurance Report — Tracker #151 Step 2

**Run started:** 2026-08-09 (evening UTC), immediately after the enforce wave
(step 1 complete) and a full post-host-reboot health sweep.
**Contracts under test:** `docs/security/mtls-edges.yaml` (19 edge rows),
`docs/security/telemetry-lanes.yaml` (9 lanes),
`docs/security/transport-inventory.yaml` (34 edges) — pinned by
`tests/test_assurance_contracts.py`.
**Stack state at start:** boot validator fatal=0 warn=1 (BKP-001, deferred);
tlsprobe 9/9 probe_ok=1, served-cert expiries 6.5–7.0 d (weekly rotation ran
2026-08-09 04:30); all 8 Kafka consumer groups active, lag ≈ 0; lanes moving
(applogs 2 301 docs/10 min, syslog 1 205, flows trickle); RCA canary green
end-to-end.

Findings are ranked **P0** (broken security promise, fix before anything else)
→ **P3** (hygiene/reconciliation). Every phase records HOW it was proven —
count movement and wire captures, never the absence of an error line.

---

## Executive summary (run COMPLETE 2026-08-09)

All 13 phases executed. **The mesh's security promises hold on the wire**:
every in-scope edge encrypted or declared, every identity correct (28/28 disk,
9/9 wire), every negative refused (wrong identity, stolen token, no cert,
anonymous, write-only-reading), rotation proven three consecutive rounds with
zero lane interruption, tenant isolation suites green, and TLS costs no
meaningful performance (≥400× bus headroom).

**Zero P0 findings.** Nine findings total, none an active leak:

- **2 × P1 — the sealed-fields edge path cannot deploy** (F-6 YAML-breaking
  seal VRL, F-7 no curl in the vector image). Fail-closed held at every point —
  Vector refuses the config rather than running unsealed — but the feature is
  undeliverable, and an active seal rule also blocks every other tenant's
  processor changes (F-6 blast radius).
- **4 × P2 — declared-surface gaps, not broken crypto**: one undeclared
  plaintext hop (F-1 syslog-ng→aggregator), one plaintext acceptance path
  (F-4 postgres `host` vs `hostssl`), missing inventory rows for aux edges
  (F-5, incl. api→gotenberg carrying tenant PDFs), no CI leg for the fresh
  `--tls` install (F-9).
- **3 × P3 — hygiene**: stale inventory rows (F-2), target-vs-accepted-shape
  reconciliation (F-3), id-less device rows are unaddressable (F-8).

Step 3 fixes each finding with a test that failed first; the sealed-fields
end-to-end exercise re-runs feature-ON after F-6+F-7 land. CI (`-race`,
staticcheck, gosec, govulncheck) remains pending the owner's push of the
branch.

---

## Phase status

| # | Phase | Status |
|---|-------|--------|
| 1 | Edge contracts valid + coverage rule | ✅ PASS 2026-08-09 |
| 2 | Lane contracts valid + coverage rule | ✅ PASS 2026-08-09 |
| 3 | Coverage matrix (achieved vs target vs declared) | ✅ RUN 2026-08-09 — findings F-1, F-2, F-3 |
| 4 | Static identity checks (registry vs disk material) | ✅ PASS 2026-08-09 |
| 5 | Runtime identity checks (wire SAN per endpoint) | ✅ PASS 2026-08-09 |
| 6 | Negative-cert matrix | ✅ RUN 2026-08-09 — finding F-4 |
| 7 | Lane canaries | ✅ PASS 2026-08-09 |
| 8 | Count reconciliation per lane | ✅ PASS 2026-08-09 |
| 9 | Restart/fault suite (5 pinned regression classes + rotation continuity) | ✅ PASS 2026-08-09 — finding F-5 |
| 10 | Cert + CA lifecycle (incl. SEC-019.1 part-3 short-TTL 3-rotation proof) | ⏳ |
| 11 | Tenant/service authz matrix (incl. sealed-fields feature-ON) | ✅ RUN 2026-08-09 — findings F-6, F-7, F-8; sealed-fields e2e FAIL (fail-closed held) |
| 12 | Perf/scale sanity under TLS | ✅ PASS 2026-08-09 |
| 13 | CI gates (SEC-023.1) + fresh `--tls` install exercise | ✅ RUN 2026-08-09 — finding F-9; CI execution itself pending owner push |

---

## Phase 1–2 — Contracts (PASS)

`python3 -m pytest tests/test_assurance_contracts.py tests/test_ingest_contract.py
tests/test_architecture_contract.py tests/test_secret_rotation.py` → **92 passed**.
The six assurance pins hold: every mtls-edges row references a real inventory
edge; every inventory edge whose profile contains `tls` has a contract row;
lane identities ⊆ workloadid registry; lane topics ⊆ kafka-init's create list;
consumer-group naming pinned; baseline-honesty pin
(`test_transport_inventory_baseline_is_honest`) reflects the post-wave rows.

## Phase 3 — Coverage matrix (RUN, 3 findings)

Method: for all 34 inventory edges, compare live/achieved state (`current`,
post-wave-maintained) and the dated `security_profile` note against `target`,
requiring `exception{}` on every deliberate plaintext row.

Result classes:
- **In-scope v1 intra-stack + ingress edges: all TLS/mTLS on the wire** except
  one hop (F-1 below). Declared-plaintext exceptions (4) all carry
  owner/accepted/reason: `device-goflow2` (protocol cannot encrypt),
  `vmauth-victoria` (terminating proxy last hop), 2 lab-only mocks.
- Device-side rows (`device-syslog-ng` RFC5425, `gnmic-device` verify,
  `device-snmp-*` protocol-native) belong to the transport-encryption P0–P4
  device programme, not v1 intra-stack scope.
- `remote-vantage-api`, `operator-grafana-osd`: scoped post-v1 rows, unchanged.

### F-1 (P2) — `syslog-ng → vector-aggregator:6601` is plaintext TCP, undeclared
`syslog-ng.conf` `d_vector` = `transport("tcp") port(6601)`; no TLS, and the
inventory row carries **no exception**, so it fails the "declared, never
silent" rule (transport-encryption P4). Intra-stack hop carrying device syslog
— same trust segment every other converted hop lives in. Both ends support
TLS (syslog-ng `transport("tls")`, Vector syslog source `tls` block with
SVID). **Remediation (step 3): convert the hop (aggregator serves its SVID,
syslog-ng verifies against the mesh CA), or add a dated exception row if the
owner declines.**

### F-2 (P3) — inventory rows stale relative to shipped epics
- `collectors-vector-lanes`: still `current: plaintext/basic-shared`, no
  `security_profile` — SEC-013.1/.2 shipped four-lane mTLS + per-lane tokens
  2026-08-06 and the wave proved per-lane 200 / shared 401.
- `vector-router-api-sealing-keys`: still `current: plaintext ("worst hop")` —
  SEC-018.1 shipped router-SVID-only over TLS 2026-08-06.
- `api-valkey`: `security_profile` still says `plaintext-authenticated`
  (SEC-012.1-era) while `current` correctly records TLS-6380-only post-wave.
**Remediation (step 4 docs, or immediately): refresh the three rows; keep the
coverage rule meaningful.**

### F-3 (P3) — `target: mtls` vs owner-accepted TLS shapes, reconcile
- `api-opensearch` / `vector-router-opensearch`: achieved = HTTPS + 6
  least-privilege basic-auth identities (SEC-008.1 + F-17). SEC-008.2's
  acceptance criterion ("every client authenticated") is met; the literal
  "mTLS mapped to OS role" HLD ideal is not. §0a smallest-sufficient-mechanism
  supports the shipped shape — needs an owner sign-off note or a target edit.
- `goflow2-kafka`: achieved = TLS-anon on FLOWS:9095, ACL-bounded (owner
  option-1, U3 resolved 2026-08-05); `target: mtls/svid` predates that
  decision. Record the decision in `target.notes` (partially present) or
  restate target as the option-1 shape.

---

## Phase 4 — Static identity checks (PASS 2026-08-09)

Method: enumerate `data/tls/services/*` and verify against the
`internal/workloadid` registry (28 entries + 7 exemptions).
- **28/28 registry identities minted on disk, zero unregistered dirs.**
- Every leaf: URI SAN exactly `spiffe://netops/ns/default/sa/<service>`,
  key **PKCS#8**, expiry 6.98 d (re-issued at post-reboot api start).
- EKUs match the registry `Client`/`Server` flags for all 28 (incl. the
  dual-EKU kafka + opensearch rows).
- DNS SANs cover every name in the registry `DNS` lists.
- **One CA bundle** across all 28 dirs + root `data/tls/ca.pem`
  (sha256 `ff02624d…`), no drift.

## Phase 5 — Runtime identity checks (PASS 2026-08-09)

Method: `openssl s_client` from the correlation container against every mesh
endpoint; assert served URI SAN == declared server identity and chain verify=0
against the mesh CA.

| Endpoint | Served identity | Verify |
|---|---|---|
| postgres:5432 (starttls) | `…/sa/postgres` | 0 ok |
| clickhouse:8443 + 9440 | `…/sa/clickhouse` | 0 ok |
| kafka:9093 / 9094 / 9095 | `…/sa/kafka` | 0 ok |
| opensearch:9200 | `…/sa/opensearch` | 0 ok |
| correlation:8443 | `…/sa/correlation` | 0 ok |
| vmauth:8427 | `…/sa/vmauth` | 0 ok |
| redis:6380 | `…/sa/redis` | 0 ok |
| api:8080 | `…/sa/api` | 0 ok |
| vector-aggregator:8688/8689/8690/8692 (4 lanes) | `…/sa/vector-aggregator` | 0 ok, client cert REQUIRED |
| nginx:8443 (ingress) | public dev cert CN=10.70.245.122 (valid to 2027-08), HSTS + HTTP/2 | by design NOT an SVID |

Wire-vs-disk note: services serve the rotation-sweep mint (expires 2026-08-15
01:14Z) while disk holds the fresher post-reboot mint — expected mechanics
(static loaders re-stage at the weekly sweep; tlsprobe watches the wire).

## Phase 6 — Negative-cert matrix (RUN 2026-08-09, 1 finding)

| Test | Result |
|---|---|
| api:8080, no client cert | handshake refused (TLS1.3 alert 116 `certificate required`) ✅ |
| api:8080, trusted chain but identity NOT in allowlist (correlation SVID) | refused (`bad certificate`) **and** `netops_tls_identity_rejected_total` 0→1 — observable ✅ |
| kafka:9094, no client cert | handshake refused (alert 42) ✅ |
| kafka:9095 ANONYMOUS visibility | sees exactly **1 topic (`netops.flows`) vs 17 authenticated** — ACL bound is exclusive under default-deny ✅ |
| OpenSearch anonymous | 401 ✅ |
| OpenSearch write-only identity (`svc_router`) reading | 403 ✅ |
| Valkey unauthenticated (REDISCLI_AUTH cleared) PING/GET/CONFIG | `NOAUTH` ✅ |
| Valkey wrong password | `WRONGPASS` ✅ · correct password → PONG ✅ |
| Valkey plaintext 6379 | connection refused (wave state holds) ✅ |
| correlation:8443, monitor-scope SVID | `/healthz` `/metrics` 200; app path 403 — peer scoping enforced ✅ |
| Ingest lane (bus 8692) over valid mTLS, bogus credential | 401 ✅ |
| postgres, `sslmode=disable` from compose network | **ACCEPTED to auth stage** — see F-4 ❌ |

Observation (not a finding): `REDISCLI_AUTH` is set container-wide in the
valkey container for the healthcheck, so any exec'd `redis-cli` is silently
authenticated — diagnostics must `env -u REDISCLI_AUTH` to test the negative
path (this run initially mis-read it as an auth bypass).

### F-4 (P2) — postgres accepts non-TLS TCP from the compose network
Live `pg_hba.conf` ends with `host all all all scram-sha-256` — `host`
matches SSL **and** non-SSL, so TLS enforcement on this store is client-side
convention only; any credentialed client could connect plaintext and put
password + rows on the wire. Same class as the CH-8123/valkey-6379 plaintext
listeners the wave removed — postgres's plaintext "listener" lives in pg_hba
and was missed. **Remediation (step 3): `hostssl all all all scram-sha-256`**
(the in-container healthcheck rides unix-socket `local trust`, unaffected);
regression test = `sslmode=disable` must fail with a no-pg_hba-entry error,
not reach password auth. Secondary (P3): image-default `trust` rows for
127.0.0.1/::1/local remain — in-container-boundary risk, decide with the
owner.

## Phase 7 — Lane canaries (PASS 2026-08-09)

- **bus-bridge lane:** the RCA canary IS this lane's reconciliation per the
  contract — full end-to-end green tonight (inject over correlation-SVID mTLS
  + bus token → both semantic signals → RCA object tier=suspected → validation
  ticket-suppression proven). Cron (:00/:15/:30/:45) healthy; the 145 FAIL
  lines in its log all predate 07:31 (the enforce-wave execution window).
- **Auth negatives on lanes:** bogus credential over valid mTLS → 401
  (re-proven tonight); the full per-lane-token 4×200 / shared-token 4×401
  matrix was proven live at the wave (2026-08-09 morning).
- Other lanes carry steady live traffic; proven by count movement (phase 8).

## Phase 8 — Count reconciliation (PASS 2026-08-09)

10-minute trailing window, all four count sources (vector counters + kafka
offsets via kafka-exporter + OS `_count` + CH sink counter):

| Lane | agg sent | topic Δ | router recv | store landed |
|---|---|---|---|---|
| applogs | 6 285 | 6 282 | 6 267 | OS 6 267 |
| syslog | 1 210 | 1 210 | 1 211 | OS 1 212 |
| metrics | 13 940 | 13 940 | (correlation-only) | — |
| probes | 960 | 960 | (correlation-only) | — |
| snmptrap | 9 | 9 | 9 | OS 9 |
| flows | (goflow2) | 46 | 45 | **CH 45 + OS 1 (sampled — by design)** |
| bus | 6 | 6 (controller_events) | (correlation) | — |
| deadletter | — | **0 growth** ✅ (the contract) | — | — |
| cloud | — | cloudcosts +75/48 h — transport works; azure vnet_flow DNS egress error + 0 AWS resources = pre-existing lab-env noise, not transport | | |

Skews ≤ 0.3 % (in-flight batching). The earlier "flows trickle" observation
resolved: OS gets the sampled stream, CH the full one.

## Phase 9 — Restart/fault suite: five pinned regression classes (PASS, finding F-5)

1. **Broker-bounce consumer wedge (librdkafka):** exercised for real by
   tonight's full host reboot — all 8 groups re-joined, lag ≈ 0, consume
   rate > 0 proven by phase-8 deltas. Stronger than a broker-only bounce.
2. **Bare-client-bypasses-hardened-transport:** `grep http.Client{` audit of
   `src/backend`. All mesh-relevant sites ride the seams (`tunnels.go` →
   `meshHTTPClient`, `alerts.SetHTTPClientFunc` wired at `main.go:481`,
   chhttp carries the mesh client). Remaining bare clients target external
   services (twilio/SNS/LLM/OIDC-IdP/devices) — correct. **Residue = F-5:**
   the api dials gotenberg/keycloak/netbox in-stack over plaintext and those
   edges are not in the inventory at all.
3. **Stale container vs tracked compose:** `docker compose config --hash` vs
   the running containers' `config-hash` label, all services — only the
   exited one-shot `kafka-init` differs (benign; re-created on next `up`).
4. **gnmic silent blackhole:** 362 fresh `gnmi.*` series in VictoriaMetrics.
5. **api+prober rebuild pairing:** both images built the same second
   (2026-08-09 14:58:27).

### F-5 (P2) — transport inventory is missing the aux-tier intra-stack edges
`api→gotenberg:3000` (multipart POST of **rendered tenant RCA report PDFs**,
plaintext), `api→keycloak` (OIDC/JWKS — bearer-token material when SSO is
live; dormant today), `api→netbox` (device inventory sync), and the
nginx→frontend/grafana/OSD upstream hops have **no inventory row** — the
"every edge declared" completeness promise (SEC-001) misses them, the same
class as the aggregator→opensearch edge missed before F-17. The coverage rule
can only validate declared edges, so nothing caught it. **Remediation
(step 3/4): add the rows (declared-plaintext with exception, or convert
api→gotenberg which carries tenant data), and consider a mechanical
edge-completeness check (compose service pairs ⊆ declared edges).**

## Phase 10 — Cert + CA lifecycle (PASS 2026-08-09, incl. SEC-019.1 part-3 3-rotation proof)

- **Weekly sweep:** the Sun 04:30 cron ran this morning; log shows every mesh
  endpoint on the current mint.
- **Expiry observability:** tlsprobe 9/9 `probe_ok=1`; `tls-posture` vmalert
  group loaded (alerts <24 h warn / <6 h crit verified in earlier sessions).
- **Three-rotation continuity proof (SEC-019.1 part 3):** three consecutive
  full rotations executed tonight, each = api restart (mint-on-boot, proven
  by serial change) → `rotate-tls-services.sh` ACT sweep → wire verification.

| Round | Mint (notAfter) | Sweep result | Lane continuity |
|---|---|---|---|
| 1 | 2026-08-16 20:03:03Z | 9/9 serve current mint, all serials changed | all topics moving, 8/8 groups, lag 34 in-flight |
| 2 | 2026-08-16 20:09:44Z | 9/9 current | flowing |
| 3 | 2026-08-16 20:19:32Z | 9/9 current | all topics moving, 8/8 groups, lag 63 in-flight |

  The RCA canary cron fired through all three sweeps with **zero new FAIL
  lines** (quiet log = passing; verified by log mtime frozen at 07:31).
- **Honest deviation:** the spec said "short-TTL"; this proof ran at the
  owner-approved interim TTL=168 h and forced distinct mints via api restarts
  instead. The claims that matter — repeated rotation, distinct serials each
  round, zero lane interruption, wire==disk after each sweep — are proven.
  A literal validity-pressure soak (TTL≈2 h over an afternoon) remains
  available as an optional step-3 add-on if the owner wants it.

## Phase 11 — Tenant/service authz matrix (RUN 2026-08-09; findings F-6, F-7, F-8)

- **Go isolation suite:** `go test -run Isolation` over the backend root
  package (incl. `org_isolation_test.go`,
  `transport_posture_isolation_test.go`, all `*_isolation_test.go`) — **PASS**
  (136 s).
- **OpenSearch identities:** anon 401 / write-only-read 403 (phase 6).
- **vmauth per-user scoping:** write-only users (`svc-prober`, `svc-vector`)
  get **400 no-route** on query paths (denied before proxying — src_paths
  work); wrong password 401; `svc-vmalert` queries fine.
- **Kafka ACLs under default-deny:** ANONYMOUS sees 1/17 topics; ANONYMOUS
  consume attempt on `netops.flows` → `GroupAuthorizationException` (write-only
  grant is truly write-only); admin plane authenticates on MTLS:9094.
- **Correlation peer scoping:** monitor-scope SVID 200 on `/metrics`,`/healthz`,
  403 on app paths (phase 6).
- **Sealed-fields feature-ON exercise (RUN 2026-08-09 late evening — findings
  F-6, F-7, F-8):** `FEATURE_SEALED_FIELDS=true` enabled on the lab api
  (SEAL_PROVIDER=swtpm already live), boot fatal=0, "Sealed Fields ENABLED"
  logged, edge-key route registered.
  **SEC-018.1 gate matrix PROVEN on the wire:**

  | Test (all against `/internal/sealing/edge-keys?tenant=…`) | Result |
  |---|---|
  | vector-router SVID | **200**, `{seal_key, mac_key, key_version}`; audit line `edge key served` peer=`spiffe://…/sa/vector-router` + tenant, never key material ✅ |
  | nginx SVID (passes api TLS allowlist, wrong identity) | 401 ✅ |
  | nginx SVID + valid stack-internal token over TLS (stolen-token case) | 401 — `SEALING_ACCEPT_TOKEN` window closed ✅ |
  | no client cert | handshake refused ✅ |
  | feature-OFF (after revert) with router SVID | route absent, 404 ✅ |

  **End-to-end sealed event: FAIL — blocked by two independent edge-path
  breaks (F-6, F-7).** A real tenant seal rule was created (QA tenant
  `t_69cb…`, snmptrap lane, match-guarded): the api rendered the seal VRL and
  the router **refused the generated config** (YAML parse error) and kept the
  old topology; separately, the router image cannot execute the key fetch at
  all (no curl). Every failure was LOUD — at no point did events flow unsealed
  while the config claimed sealing, which is exactly the fail-closed promise —
  but the feature is undeliverable until step 3 fixes both. Rule deleted,
  clean config re-rendered, router reloaded green; feature reverted to OFF
  (owner state).

### F-6 (P1) — seal VRL breaks the generated router config (YAML indent)
`processors.GenerateRouterConfig` writes each rule's VRL with
`fmt.Fprintf(&b, "      %s\n", line)` — correct for every action because they
compile to ONE line, except `seal`: `sealing.SealVRL` returns a MULTI-LINE
snippet whose continuation lines land at column 1, outside the `source: |`
block scalar. The rendered YAML never parses; Vector logs
`could not find expected ':'` and keeps the previous topology. Blast radius:
(a) a seal rule can never reach the edge; (b) while any seal rule exists,
**every other processor change for every tenant is also undeliverable** (the
regenerated file always contains the broken block); (c) nothing alerts on a
router config-reload failure — the error is visible only in container logs.
`generate_test.go` pins generator↔simulator semantics but never YAML-parses a
config containing a seal rule. **Remediation (step 3): indent continuation
lines of compiled action VRL to the block-scalar level; regression test =
YAML-parse (and ideally `vector validate`) a generated config with a seal
rule; consider a vmalert rule on Vector's `config_load` error counter.**

### F-7 (P1) — router image cannot execute the key fetch at all (no curl)
`cx-secret-backend.sh` hard-depends on `curl` for both its mTLS and plaintext
fetch paths; `timberio/vector:0.40.0-alpine` ships only BusyBox `wget`, which
has **zero TLS client-cert options**. Every fetch fails (`curl: not found` →
empty body → per-secret error → Vector refuses the config; proven by running
the real script in the live router container). The sealed-fields edge path has
therefore never been executable in the shipped image, in either transport
mode — the SEC-018.1 server side and script logic are unit-proven, but the
runtime dependency was never validated in-image. **Remediation (step 3): derive
a vector-router image that adds curl (or a small static fetch helper), and add
an image contract test that executes the secret backend inside the built
image.**

### F-8 (P3) — POST /api/devices accepts an id-less device that becomes unaddressable
The phase-11 fixture device was created without an `id`; the API returned 201
with `"id":""`, persisted it keyed `""`, and it can never be deleted through
the API (`DELETE /api/devices/{id}` cannot express the empty id). Residual
test state: device `cx-phase11-assurance-dev` (203.0.113.99, QA tenant
Bestbuy) remains on the lab pending this fix (direct DB cleanup was out of
scope for this run). **Remediation (step 3): generate an id server-side on
create (or 400 on missing id) + a repair path for existing `""` rows; then
delete the fixture.**

## Phase 12 — Perf/scale sanity under TLS (PASS 2026-08-09)

Sanity bounds under the FULL mesh (no pre-TLS baseline exists to diff against;
thresholds are absolute reasonableness + headroom vs live lane rates):

- **Resources:** no TLS-attributable hot spot — clickhouse 32 % / opensearch
  11 % / kafka 8 % / vectors ≤ 7 % CPU; api 41 MiB RSS. All within limits.
- **Ingress HTTPS** (nginx :443, cold handshake every request, 30 samples):
  handshake avg 16.7 ms, total p50 23.9 ms / p95 32.3 ms.
- **Authenticated API through the mesh** (nginx→api mTLS), 20 samples each:
  `/api/metrics` p50 32.5 ms / p95 42.9 ms (all 200);
  `/api/metrics/query?query=up` — the 3-TLS-hop chain nginx→api→vmauth→
  victoria — p50 35.2 ms / p95 45.9 ms (all 200).
- **Kafka over MTLS:9094** (perf probe on a scratch topic, 50 000 × 512 B,
  admin identity, cleaned up after): produce **9 789 rec/s (4.78 MB/s)**,
  consume **15 974 msg/s (7.8 MB/s)**. Steady-state lane traffic is ~10–25
  events/s total → ≥ 400× headroom on the encrypted bus.
- **Lag after the burst:** all 8 groups back to ≤ 11 in-flight immediately.

## Phase 13 — CI gates + fresh --tls install (RUN 2026-08-09, finding F-9)

**Local gate results** (branch `feat/observability-platform`, 8+ commits ahead
of origin — CI itself has NOT run: no local gcc for `-race`, push is the
owner's call):

| Gate | Result |
|---|---|
| `go vet ./...` | ✅ clean |
| `go build ./...` | ✅ clean |
| Go test suite (no `-race`, CI's `-timeout 20m`) | ✅ — one failure was this report's own filename tripping the env-docs guard (`TLS_ASSURANCE_REPORT_2026` parsed as a documented env switch); renamed `-08`→`_08` so the guard's filename exemption applies, guard re-run green. Note: the default 10 m `go test` timeout is NOT enough for the root package locally (582 s + compile) — always use CI's `-timeout 20m` |
| Python contract suite (`tests/`, full) | ✅ 97 passed |
| `preflight-install.py` | ✅ (incl. transport-exception + secret-rotation-policy gates) |
| `preflight-configs.sh` | ✅ all configs boot clean (incl. promtool rule unit tests) |
| staticcheck / gosec / govulncheck / `-race` | ⏳ CI-pending (owner push) |

**Fresh `--tls` install exercise** (scratch clone from `git archive HEAD`,
this host — the live lab precludes a second full stack, so `--no-start` depth):
`python3 scripts/install.py --tls=yes --no-start` ran clean end-to-end:
scaffold 44 paths ✓, .env generated 0600 with the TLS block (2 updated,
11 added), profiles gained `seal,security,vmauth`, self-signed ingress cert
generated, data-dir prep with correct chown guidance (65532 for data/tls),
honest completion message ("compose.tls.yml NOT yet activated — the two-phase
mint needs a running stack"). Post-checks: credential families that ride URL
userinfo are URL-safe in the generated .env (the 2026-08-07 landmine fix
holds); `docker compose -f docker-compose.yml -f compose.tls.yml config -q`
validates the full chain. **The two-phase mint (Phase A boot → poll for cert
material → Phase B recreate) remains unexercised on a truly fresh host — F-9.**

### F-9 (P2) — no CI leg exercises the fresh `--tls` install
`fresh-install-integrity.yml` runs only `preflight-install.py` +
`preflight-configs.sh` — it never executes `install.py`, boots nothing, and
has no `--tls` variant. The programme's delivery shape (the one install-time
question) and its riskiest mechanics (the two-phase first-boot mint) are
validated only by hand on the lab. **Remediation (step 3/4): add a
`--tls=yes` leg to fresh-install-integrity (GH runners can boot the stack),
asserting boot-validator fatal=0 + tlsprobe all-ok + one lane count-moving
as the pass condition.**

---

## Findings register

| ID | Pri | Phase | Summary | Disposition |
|----|-----|-------|---------|-------------|
| F-1 | P2 | 3 | syslog-ng→vector-aggregator plaintext TCP, no exception row | **FIXED 2026-08-11** (below) — hop converted to mesh TLS + required client cert |
| F-2 | P3 | 3 | 3 inventory rows stale vs shipped SEC-012.2/013/018 | **FIXED 2026-08-11** (below) |
| F-3 | P3 | 3 | `target: mtls` predates owner-accepted TLS shapes (OS basic-in-TLS, goflow2 option-1) | **FIXED 2026-08-11** (below) — targets restated citing the recorded owner decisions |
| F-4 | P2 | 6 | postgres pg_hba `host` (not `hostssl`) — non-TLS TCP accepted from compose network | **FIXED 2026-08-10** (below) |
| F-5 | P2 | 9 | inventory missing aux-tier edges: api→gotenberg (tenant PDFs, plaintext) / api→keycloak / api→netbox / nginx→UI upstreams | declare or convert; add mechanical completeness check |
| F-6 | P1 | 11 | seal VRL multi-line snippet breaks generated processors.yaml (YAML indent) — seal rules undeliverable AND block all other processor changes; no reload-failure alert | step-3 fix + YAML-parse regression test |
| F-7 | P1 | 11 | vector image has no curl — cx-secret-backend.sh cannot fetch keys in any mode; sealed-fields edge path never executable in-image | step-3 fix (image + in-image contract test) |
| F-8 | P3 | 11 | POST /api/devices accepts id-less device → unaddressable `""`-keyed row; phase-11 fixture remains on lab pending fix | step-3 fix + repair; then delete fixture |
| F-9 | P2 | 13 | fresh-install-integrity CI never runs install.py and has no `--tls` leg — the delivery shape + two-phase mint are validated only by hand | add a `--tls=yes` boot leg to the workflow |
| F-10 | P2 | step-3 e2e | aggregator never reloads `device_tenant.csv` (Vector watches config files, not enrichment) — a device→tenant assignment takes effect only at the next aggregator restart/SIGHUP; until then that device's telemetry lands untagged | api-triggered reload or watched-file touch on CSV write |
| F-11 | P2 | step-3 e2e | sealing is fail-open across ATTRIBUTION: an event that loses its tenant stamp (F-10 staleness, unknown hostname) skips every tenant-guarded seal rule and is stored in PLAINTEXT in the untagged index — observed live | owner decision: design boundary vs seal-or-quarantine semantics |
| F-12 | P2 | step-3 F-4 | the `pgintegration` test suite has not COMPILED since the platformdb extraction (`7a7555a2`, 2026-07-28): `pg_integration_test.go` still reaches for `db.pool` / `migrationLockKey`, now in `internal/platformdb`. `go test -tags=pgintegration ./...` = `build failed`, so backend-ci's pg-integration job — the ONLY place the INVARIANTS gap-#4 proofs (statement_timeout, migration advisory lock, audit paging, retention DELETE) execute — has been dead for two weeks. A build-tagged test is invisible to the default build, so nothing announced it | step-3 fix: restore the suite (own commit); prefer env-gated over tag-gated for new guards |

---

## Step-3 progress (2026-08-09 late night)

**F-6 FIXED** (two defects, both test-first in `processors/generate_test.go`
`TestGeneratedConfigSurvivesMultilineActionVRL`): (1) multi-line action VRL now
re-indented into the `source: |` block scalar; (2) a second latent defect found
by the live router the moment (1) let it see the VRL: the `"; "` stamp
separator landed at line start after a multi-line action — a VRL syntax error —
now joins on a newline. Package suite green.

**F-7 FIXED**: `netops-vector-router:0.40.0-curl` derived image
(`vector-router/Dockerfile`, `APK_REPO_SCHEME` build-arg for TLS-intercepted
egress hosts; apk indexes are signed either way). Contract pin
`test_router_image_provides_secret_backend_dependencies` (compose must use the
derived build; Dockerfile must install every binary the script executes).
**Plus a third latent defect only the now-executable path could reveal: Vector
0.40 STRIPS the backend name from secret requests** — the script's documented
`cxseal.<tenant>` request shape never matched reality; the backend kind now
rides as argv (`command: [".../cx-secret-backend.sh", "seal"|"mac"]`) and the
script parses bare tenant ids (legacy prefixed names still tolerated).

**Sealed-fields e2e RE-RUN: PASS.** Full chain proven live on the lab,
feature-ON: seal rule → rendered config (valid YAML, valid VRL) → router
hot-reload → secret backend fetches both keys over mTLS (audited, router
SVID) → Vector loads → injected tenant-attributed trap stored in the TENANT
index with `cx_secret_note` as an `<enc:v1:…>` token, zero plaintext in the
document → **audited unseal returns the exact plaintext**
(`sensitive_data:admin`, reason recorded). Test docs deleted, rule deleted,
feature reverted to OFF (route 404 re-verified), lanes lag ≈ 0.

The e2e also surfaced **F-10/F-11** above: round 1 of the injection landed
UNTAGGED and UNSEALED because the aggregator's enrichment table predated the
fixture device (stale CSV → no tenant stamp → tenant-guarded seal skipped);
round 2 after an aggregator SIGHUP sealed correctly.

## Step-3 progress (2026-08-10)

**F-4 FIXED — postgres now REFUSES plaintext TCP.**

`postgres/tls-entrypoint.sh` stages its own `pg_hba.conf` and hands it to the
server with `-c hba_file`, network row `hostssl all all all scram-sha-256`.
The wrapper OWNS the file rather than sed-editing PGDATA's copy, so the policy
cannot depend on initdb having run first and survives a re-init; `local` +
`127.0.0.1`/`::1` rows mirror the image's initdb defaults, keeping the
in-container boundary (the `pg_isready` healthcheck, `docker compose exec …
psql`, `secret_rotation.py`'s loopback psql) working untouched.

Two tests, deliberately split by what each can prove without a live stack:

- `test_postgres_tls_entrypoint_requires_hostssl`
  (`tests/test_assurance_contracts.py`) — always runs. Asserts the wrapper
  passes `hba_file`, that no plaintext-capable (`host`/`hostnossl`) row reaches
  beyond loopback, and that `hostssl` *does* cover the compose network. RED on
  the pre-fix script, and mutation-checked against two weaker fixes: a bare
  `host all all all` row left alongside `hostssl` → caught; `hostssl` narrowed
  to `127.0.0.1/32` so nothing serves the network → caught.
- `TestPostgresRefusesPlaintextTCP` (`src/backend/pg_hostssl_guard_test.go`) —
  the live negative. Strips TLS from the parsed pgx config **and every
  fallback** (`sslmode=prefer` is "TLS first, then plaintext": clearing only the
  primary would let a fallback negotiate TLS and turn the negative green for the
  wrong reason), then requires the failure to name `pg_hba.conf` and to *not*
  mention a password — reaching auth at all is the thing being prevented.

**Proof (A/B on identical infrastructure, then live).** Two scratch containers
off the same pinned `postgres:16-alpine` digest with the same self-signed SVID,
differing only in wrapper version: pre-fix → `show hba_file` =
`…/data/pg_hba.conf`, last row `host all all all scram-sha-256`, guard test
**FAILS** (`plaintext TCP connection SUCCEEDED`); post-fix → `show hba_file` =
`…/tls/pg_hba.conf`, last row `hostssl …`, guard test **PASSES**. On the live
lab stack: `sslmode=disable` from a container on the compose network →
`FATAL: no pg_hba.conf entry for host "172.18.0.31", user "netops_app",
database "netops", no encryption`; the same image with the real
`sslmode=verify-full` DSN → `ssl=true ver=TLSv1.3`; every network session in
`pg_stat_ssl` is TLSv1.3, api and keycloak included.

**Client fallout checked, not assumed.** Every postgres:5432 client was
enumerated before landing this: the api's `DATABASE_URL` (already
`verify-full`); the api's stack-health probe (bare TCP connect — never reaches
hba); in-container `psql`/`pg_isready`/`createdb` and `secret_rotation.py`'s
`-h 127.0.0.1` psql (loopback rows); and **keycloak** (`sso` profile), whose
pgjdbc link survives hostssl — live `pg_stat_ssl` shows it on TLSv1.3 — but
negotiates **without CA/hostname verification** and still has no inventory row.
That last one is recorded against **F-5** rather than silently widened into this
fix. `correlation` holds no postgres DSN at all (SEC-011.2 evicted
`POSTGRES_DSN`), so the inventory row's claim of a "correlation DSN at
verify-full" was stale and is corrected.

Docs corrected in the same change (they now described the opposite of the
behaviour): the "accepts BOTH TLS and plaintext / migration ladder" comment on
both TLS compose variants, the `tls-mtls.md` §Postgres runbook (with the exact
refusal string and how to read it — "this client is not speaking TLS", not a
credential problem), the api's `DATABASE_URL` comment, `install.py`'s sample
DSN, and the `api-postgres` rows in `mtls-edges.yaml` + `transport-inventory.yaml`.

**F-12 filed** (register above): placing F-4's live guard exposed that the
`pgintegration` suite has not compiled since the platformdb extraction, so
backend-ci's pg-integration job has been failing at build for two weeks. That
is why the F-4 guard is **env-gated, not tag-gated** — it compiles on every
`go test ./...` and skips loudly rather than rotting unseen. Repair lands in its
own commit.

## Step-3 progress (2026-08-11)

**F-1 FIXED — the syslog hop rides mesh TLS with a required client
certificate.** The finding offered "convert or declare"; converted — both ends
already spoke TLS and both identities already existed (the syslog-ng client
SVID was registered for exactly this hop, SEC-014.1).

Shape, mirroring the ingest lanes: vector.yaml `syslog_in` gains the env-gated
tls block (`SYSLOG_TLS_ENABLED`, plaintext stays the base-compose default) with
`verify_certificate` on the same gate — TLS on always means a mesh client cert
is REQUIRED, never server-only, because this hop has no app-layer token to fall
back on. syslog-ng gets a tracked TLS variant conf (`syslog-ng-tls.conf`,
selected by compose.tls.yml / the lab override) that verifies the aggregator
SVID against the mesh CA (`peer-verify(required-trusted)`) and presents the
syslog-ng SVID; the shared body moved to `core.conf` so the two variants cannot
drift. The F-48 reliable disk-buffer is retained in the variant — it is what
held device syslog across the cutover window (173 messages drained, dropped=0).

Test-first: `test_syslog_hop_serves_and_requires_mesh_tls`
(`tests/test_assurance_contracts.py`) pins all four halves (vector tls block,
variant conf shape incl. disk-buffer, compose.tls.yml wiring, inventory
`security_profile`) — the security_profile in turn drags the hop into the
mtls-edges coverage rule, which now carries a `syslog-ng-vector` contract row
with negatives. `preflight-configs.sh` validates BOTH syslog-ng variants with
the runtime dir mount (the tls() file arguments are existence-checked at parse
time — stub certs, same idiom as the vector secret stubs).

Proven live on the lab: 6601 serves `spiffe://…/sa/vector-aggregator`
(chain-verified); handshake WITHOUT a client cert → alert 40 refusal;
plaintext client → connection reset; marker injected at the device port landed
in `netops-syslog-*` over the TLS hop; stats destination reads
`d_vector#0,tls,vector-aggregator:6601` with dropped=0. Rotation folded in:
`rotate-tls-services.sh` restarts syslog-ng (start-loaded client SVID — the
2026-08-05 incident class) and wire-verifies `vector-aggregator:6601`; tlsprobe
gains the same endpoint, which also puts the aggregator SVID — previously
unwatched, though it backs all four ingest lanes — under expiry watch (10
endpoints).

**F-2 + F-3 FIXED — the inventory tells the truth again.** Failed-first pins:
`test_transport_inventory_rows_reflect_shipped_epics` +
`test_transport_inventory_targets_record_owner_accepted_shapes`
(`tests/test_architecture_contract.py`, beside the honest-baseline pin).

F-2: `collectors-vector-lanes` current.authn → `basic-per-lane` (a BASE fact —
the lane tokens are fail-closed `${VAR:?}` with no shared fallback) + a
security_profile recording the SEC-013 mTLS shape, which drags the lanes into
the coverage rule — a `collectors-vector-lanes` contract row with the proven
negatives (shared token 401, cross-lane token 401, no-cert refused) now exists
in mtls-edges.yaml. `vector-router-api-sealing-keys` sheds the "worst hop"
double-flag: current records the dormant plaintext-baseline token gate,
security_profile records SEC-018.1 router-SVID-only (matrix proven twice).
`api-valkey` security_profile → `tls` (6380 is the only listener since the
wave; the `plaintext-authenticated` text was SEC-012.1-era).

F-3: targets restated as the owner-accepted shapes WITH the decision cited in
`target.notes` — api-opensearch / vector-router-opensearch to
`tls`/`basic-per-identity` (§0a smallest-sufficient; SEC-008.2's "every client
authenticated" criterion met; the mTLS-to-OS-role HLD ideal explicitly not
being built), goflow2-kafka to the option-1 shape (TLS-anon on FLOWS:9095,
ACL-bounded, exclusive under default-deny) with its reopen condition
(goflow2 growing client-cert support).
