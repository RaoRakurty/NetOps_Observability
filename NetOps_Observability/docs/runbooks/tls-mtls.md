# Runbook — the TLS/mTLS mesh, as running (tracker #151)

> **This mesh is SHIPPED and enforced.** Since the enforce wave (2026-08-09)
> a TLS deployment has **no plaintext listeners left** on the in-scope
> intra-stack edges: stores, bus, ingest lanes, correlation and the sealing
> key path all ride TLS/mTLS, and the servers refuse plaintext rather than
> merely preferring TLS. Per-hop truth: `docs/security/transport-inventory.yaml`
> (34 edges) and `docs/security/mtls-edges.yaml`; wire-verified evidence:
> `docs/security/TLS_ASSURANCE_REPORT_2026_08.md` (13-phase assurance run).
>
> This document is the OPERATOR view: how a deployment gets the mesh, what
> the fail-closed gates look like when they fire, how rotation works, and how
> to triage. Deep per-store procedures live in `docs/runbooks/security/`.

## 1. The two variants — how a deployment gets the mesh

The stack ships a **two-variant doctrine**:

- **Base `docker-compose.yml` = plaintext default.** A fresh install has no
  CA, no seal provider and no certificates, and must boot without them. All
  `TLS_*`/`SEAL_*` knobs exist in the base file but are dormant.
- **`deployment/docker/compose.tls.yml` = the ONLY supported way to turn the
  mesh on.** It layers fail-closed store wrappers, mTLS listeners, the mTLS
  nginx config and the TLS collector variants over the base file via the
  `COMPOSE_FILE` chain. (The lab's `docker-compose.override.yml` mirrors it;
  keep the two in sync where they overlap.)

The installer owns activation — one question, or unattended:

```bash
cd NetOps_Observability
python3 scripts/install.py --tls=yes     # full mesh; --tls=no = declared-plaintext baseline
```

`--tls=yes` runs a **two-phase first boot**, because the CA's own state lives
in the platform store — a fail-closed postgres cannot start without certs
that only a running api can mint (the SEC-011 bootstrap-deadlock lesson):

- **Phase A** boots the plaintext baseline with the mint variables set
  (`TLS_INTERNAL_CA=true`, `SEAL_PROVIDER=swtpm`, `TLS_SVID_TTL=168h`,
  cert-dir paths; profiles gain `seal,security,vmauth`). The api's internal
  CA writes `data/tls/ca.pem` and one SVID per service under
  `data/tls/services/<svc>/`. The installer **blocks (≤300 s) on mint
  sentinel files** — a partial mint is a loud install FAILURE, never a
  half-enabled mesh.
- **Phase B** appends `compose.tls.yml` to the `COMPOSE_FILE` chain in `.env`
  and recreates the stack. From now on every plain `docker compose` command
  in that directory sees the TLS variant automatically.

A self-signed ingress certificate is generated for nginx if none exists
(`scripts/gen-dev-cert.sh`); production replaces the files under
`deployment/docker/nginx/certs/` in place.

**Identities:** every service holds a SPIFFE-style SVID
(`spiffe://netops/ns/default/sa/<service>` as URI SAN), minted at api boot
and re-issued by the CA's loop at TTL/2. One CA bundle (`data/tls/ca.pem`)
verifies everything; the nginx *ingress* cert is deliberately a public/dev
cert, not an SVID. The full identity registry lives in
`src/backend/internal/workloadid` (28 identities + exemptions).

## 2. Boot-time fail-closed gates — what refusing looks like

There is **no plaintext fallback anywhere**. Misconfiguration is a refusal to
start, by design (ADR-SEC-008). Three gate families, three signatures:

| Gate | Symptom | Meaning |
|---|---|---|
| **Store TLS wrappers** (`postgres/`, `clickhouse/`, `kafka/` `tls-entrypoint.sh`; `opensearch/security/apply-security.sh`) | container exits **78** (EX_CONFIG) immediately, log names the missing cert/key path | The TLS variant is active but the service's SVID material is absent/unreadable. Was phase A's mint completed? Is `data/tls` mounted and owned correctly (uid 65532)? |
| **Vector secret resolution** (`cx-secret-backend.sh`, sealed fields + quarantine) | `vector-router` exits **78**, log names an unresolvable `cxseal.<scope>` / `cxmac.<scope>` secret | The router could not fetch sealing keys from the api's edge-key endpoint. Key-custody triage: api up? `secrets-seal` (swtpm) healthy? Router SVID accepted? See `security/quarantine-operations.md` §7 and `security/secret-unseal-failure.md`. |
| **api boot validator** | api logs `security control not satisfied` findings and, in a production profile, refuses to start; every profile logs the summary line `security posture evaluated … fatal=N warn=N` | The running configuration violates the posture rules. Each finding names rule, component, observed vs required, and the remedy — read the finding, not the stack trace. Healthy TLS deployment = **fatal=0**. |

Live posture is queryable, not just a boot log:
`GET /admin/security/posture` (platform admin) and the
`netops_sec_posture_findings{severity=…}` gauge (alerted on by
`SecurityPostureFatalFindings`). The posture view distinguishes *declared*
state from *observed* (probe-backed) state and never assumes green.

Also fail-closed, unchanged from day one: `SEAL_PROVIDER=swtpm` with the
sidecar down ⇒ the vault cannot unseal ⇒ the api refuses to start;
`TLS_INTERNAL_CA=true` without a working seal provider ⇒ boot refusal (the
CA key must never exist in plaintext — ADR-SEC-007).

## 3. Rotation — the weekly sweep and the wire watchers

**The incident class this section exists for (2026-08-05):** the CA's reissue
loop keeps *disk* material fresh, but services that load certificates once at
start kept **serving** the copy they loaded — clickhouse and postgres served
expired certs for hours while the disk looked perfectly healthy, and the
first signal was every client failing at once. Rotation therefore has three
independent parts: re-issue (api), propagation (sweep), and wire observation
(prober + alerts). Never assume one implies the others.

### 3.1 Re-issue (automatic)

The api re-issues all SVIDs at TTL/2 (`TLS_SVID_TTL`, installer default
168 h) and hot-reloads its own (`CertReloader`). Disk under
`data/tls/services/` is always the current mint.

### 3.2 Propagation — `scripts/rotate-tls-services.sh` (cron Sun 04:30)

The weekly sweep closes the disk→wire gap using the cheapest mechanism each
service actually supports, then **verifies the wire**:

| Class | Services | Mechanism |
|---|---|---|
| Native reload (no restart) | kafka | dynamic per-listener keystore re-set (`kafka-configs --alter`, all three listeners, admin plane on MTLS:9094) |
| | postgres | re-stage + `pg_reload_conf()` |
| | clickhouse | re-stage + `SYSTEM RELOAD CONFIG` |
| | nginx | `nginx -s reload` |
| | vmauth | nothing — re-reads cert files automatically |
| Restart class (health-gated, one at a time) | correlation, opensearch, vector-router, vector-aggregator, **syslog-ng**, kafka-exporter, grafana, gnmic, opensearch-dashboards | `docker compose restart` — these load certs at start (the 2026-08-05 class); opensearch stays here until the security plugin's hot-reload flag is adopted |

Then it compares every mesh endpoint's **served** certificate expiry against
the on-disk mint (90-min tolerance) and **exits non-zero on any mismatch** —
a sweep that cannot prove the wire moved is as loud as the condition it
maintains against. It also refuses to run at all if the freshest disk cert
has <72 h left (`MIN_DISK_LEFT_H`): that means the api's reissue loop is
broken, and spreading stale material would just spread the problem.

```bash
scripts/rotate-tls-services.sh --check    # verify-only: wire==disk, 10 endpoints, no changes
scripts/rotate-tls-services.sh            # act + verify (what cron runs)
tail scripts/rotate-tls.log scripts/rotate-tls.heartbeat
```

The heartbeat file makes "the sweep stopped running" itself detectable.

### 3.3 Wire observation — tlsprobe + alerts

The api's served-cert prober (`internal/tlsprobe`, override with
`TLS_PROBE_ENDPOINTS`) dials **10 mesh endpoints** on an interval and records
what each one actually serves: postgres:5432 (STARTTLS), clickhouse:8443 +
9440, opensearch:9200, kafka:9093/9094/9095, correlation:8443, vmauth:8427,
vector-aggregator:6601 (the aggregator SVID that backs all four ingest lanes
plus the syslog hop). Gauges: `netops_tls_peer_cert_expiry_seconds`,
`netops_tls_peer_probe_ok`.

Alerts (`src/config/rules.yaml`, group `tls-posture`) and what to DO:

| Alert | Meaning | Action |
|---|---|---|
| `TLSServedCertExpiringSoon` (<24 h, warning) | an endpoint SERVES a cert about to expire — its loading service missed/needs propagation | run the sweep (or restart/reload just that service), then `--check` |
| `TLSServedCertExpiryCritical` (<6 h, critical) | clients of this endpoint WILL start failing | same, now |
| `TLSPeerProbeFailed` (20 m, warning) | the probe captures nothing — endpoint down, not serving TLS, or unreachable; its expiry is UNWATCHED while this fires | treat as an availability incident on that endpoint first |
| `TLSApiCertExpiringSoon` | the api's own served cert is old — the in-process reloader/reissue loop is sick | check api logs for the reissue loop before touching anything else |

### 3.4 CA root and KEK

The CA root is long-lived; rotation is the dual-root ceremony in
`security/rotate-workload-ca.md` (`TrustBundle` carries multiple roots). The
sealing KEK is trust domain 4 and separate (`security/secret-unseal-failure.md`,
ADR-SEC-007); the CA key is "just another sealed secret" to it.

## 4. Postgres refuses plaintext — the server enforces it (F-4)

`postgres/tls-entrypoint.sh` stages its own `pg_hba.conf` and hands it to the
server (`-c hba_file`) with **`hostssl`** — not `host` — as the network row,
because `host` matches non-SSL connections too. A client that is not speaking
TLS is refused **before** authentication. The operator-visible string:

```
FATAL: no pg_hba.conf entry for host "172.18.0.31", user "netops_app", database "netops", no encryption
```

Read `no encryption` as **"this client is not speaking TLS"** — it is never a
credential problem, and no password was sent. The fix is the client's DSN:

```
DATABASE_URL=postgres://app@postgres:5432/netops?sslmode=verify-full&sslrootcert=/data/tls/ca.pem
```

`verify-full` checks BOTH the chain and the hostname — do not use `require`
(no verification). In-container access (the `pg_isready` healthcheck,
`docker compose exec … psql`, `secret_rotation.py`'s loopback psql) rides the
`local`/`127.0.0.1` rows and is unaffected. Verify the live policy:

```bash
docker compose exec postgres psql -U "$DB_USER" -tAc "show hba_file"
docker compose exec postgres psql -U "$DB_USER" \
  -c "select usename, ssl, version from pg_stat_ssl join pg_stat_activity using (pid) where client_addr is not null"
```

Every network session should show TLSv1.3 — keycloak (sso profile) included.

## 5. Triage — symptom → diagnosis → action

| Symptom | Likely cause | Action |
|---|---|---|
| api refuses to start, log says `secret custody` / unseal | swtpm sidecar down or state damaged | `security/secret-unseal-failure.md` — do NOT unset `SEAL_PROVIDER` |
| api refuses to start with posture findings | config violates a fail-closed rule | read the finding's `remedy` field; fix the named control, never the validator |
| a store container exits 78 at start | TLS variant active, SVID material missing/unreadable | confirm the mint (`ls data/tls/services/<svc>/`), ownership (65532), then recreate |
| `vector-router` exits 78 naming `cxseal.*`/`cxmac.*` | sealing key fetch failing (custody or router identity) | `security/quarantine-operations.md` §7 |
| every client of ONE store starts failing at once | that store serves an expired cert (2026-08-05 class) — check `TLSServedCert*` alerts | reload/restart that service, then `rotate-tls-services.sh --check` |
| handshake refused with `certificate required` / `bad certificate` | caller has no client cert, or an identity not in the server's allowlist; the api counts these in `netops_tls_identity_rejected_total` | verify the caller presents the RIGHT SVID (`openssl s_client` + the workloadid registry), not just *a* cert |
| `sslmode=disable` (or any non-TLS pg client) fails with `no pg_hba.conf entry … no encryption` | working as intended (§4) | fix the client's DSN to `verify-full` |
| device syslog stops after a rotation | syslog-ng loads its client SVID at start (F-1 hop: TLS to vector-aggregator:6601 with a REQUIRED client cert) | the sweep restarts syslog-ng for exactly this reason; if it was skipped, `docker compose restart syslog-ng` — the disk-buffer holds messages across the gap |
| `up{instance="api:8080"} == 0`, all `netops_*` metrics dark | victoria's mTLS scrape client not configured while the api is mTLS-only | compose.tls.yml carries the victoria scrape variant (`vmscrape-mtls.yml` + the victoria client SVID); verify both halves are active |

## 6. Where the deep procedures live

- **Per-store server-side migrations** (how each store's TLS wrapper works,
  migration + rollback): `docs/runbooks/security/` —
  `postgres-tls-migration.md`, `clickhouse-tls-migration.md`,
  `kafka-tls-migration.md`, `opensearch-security-bootstrap.md`,
  `valkey-acl-migration.md`, `syslog-tls-onboarding.md`,
  `gnmi-certificate-onboarding.md`.
- **PKI lifecycle:** `security/bootstrap-pki.md` (sealing-before-CA ordering),
  `security/rotate-workload-ca.md`, `security/rotate-service-certificate.md`,
  `security/revoke-compromised-identity.md`,
  `security/ca-compromise-response.md`.
- **The enforce wave itself** (what flipped, and the rollback per step):
  `tls-enforce-wave.md`.
- **Quarantine (unattributable telemetry) operations:**
  `security/quarantine-operations.md`.
- **Decision records:** ADR-SEC-001…009 in `docs/adr/`.

## Validation status

- Full-mesh assurance run 2026-08-09 (13 phases): every in-scope edge
  encrypted or declared, 28/28 disk + 9/9 wire identities verified, negative
  matrix (no cert / wrong identity / stolen token / anonymous) refused,
  three consecutive rotations with zero lane interruption, ≥400× bus
  headroom under TLS. Findings F-1…F-12 fixed on this branch —
  `docs/security/TLS_ASSURANCE_REPORT_2026_08.md` is the evidence document.
- The fresh `--tls=yes` install path is exercised end-to-end by the blocking
  `tls-install-boot` CI job (fresh-install-integrity workflow).
