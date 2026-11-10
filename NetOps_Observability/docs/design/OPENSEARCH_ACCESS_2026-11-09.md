# OpenSearch access model for enterprise production

**Date:** 2026-11-09

**Status:** approved direction. Owner, 2026-11-09: "do what is necessary for
enterprise production networks, not just my lab".

**Owner decisions taken:**

- The admin certificate stays on disk at 0600 under `CORRELIX_UID`. There is no
  on-demand minting (decision 1 below, as recommended).

**Scope landed with this document:** PR A (admin key custody) and PR B (service
key custody), on branch `fix/opensearch-key-custody`. PRs C to G are later work
based on PR #162. Claims in the plan below were leads when it was written; where
implementation disproved one, the section "Corrections from implementation" at
the end of this document says so.

---

Repo root for all paths: `/home/rao/Projects/NetOps_Observability/NetOps_Observability/`. Nothing below used the admin certificate; all commands were read-only.

## Headline findings

1. **The 0644 admin key is deliberate configuration, not an accident — and it is on every TLS install.** `scripts/install.py:3049,3053` write `TLS_NGINX_KEY_MODE=0644` and `TLS_SERVICE_KEY_MODE=0644` into `.env` for every `--tls yes` install (customer installer included). `src/backend/tls_ca.go:119-130` mints every key 0600 (`WriteFileAtomic` chmods the temp file before writing, `internal/platformdb/atomicfile.go:47-76`), then `tls_ca.go:265-273` chmods the admin key to `TLS_SERVICE_KEY_MODE` and `tls_ca.go:292-308` does the same for all 26 registry SVIDs. Only `api.key` (`TLS_KEY_FILE`, read by the api itself) and `victoria/victoria.key` (no escape hatch by design, `tls_ca.go:238-252`) stay 0600. Live tree confirms: 27 `.key` files 0644, 2 at 0600 (listing below). Rotation does not change this: the same `provisionFromEnv` runs at boot and every TTL/2 (`tls_ca.go:354-374`), so the 13:43 rewrite was the boot re-mint after today's deploy; `rotate-tls-services.sh` never touches modes (it only re-stages/reloads, `scripts/rotate-tls-services.sh:15-24`).
2. **Why 0644:** cross-uid handoff. The api runs as `CORRELIX_UID` = the installer's uid (`docker-compose.yml:1600`, `install.py:1173-1174,1356`) and is non-root so cannot chown (`tls_ca.go:210-225,285-291`); `opensearch-security-init` (and `opensearch`) run as image `USER 1000` (`deployment/docker/opensearch/Dockerfile:85`). The widening is registry-WIDE although, per `docker compose config` + image inspection, only **opensearch, opensearch-security-init, kafka/kafka-init** read a key as a non-root uid; every other key holder runs as root or behind a root entrypoint wrapper (postgres/clickhouse stage the key as root, `compose.tls.yml:308-313,325-327`) and could read 0600. So ~23 of 26 service keys are world-readable for no reason, and on a host whose installer uid happens to be 1000 (this lab) even the three "needed" ones were readable at 0600.
3. **The admin cert is used habitually, not only for bootstrap.** Users: `apply-security.sh:109-115` (securityadmin — legitimately needs it), `scripts/backup.sh:677-694` (snapshot PUT), `scripts/host-hygiene.sh:147-148,197,260` (read + clear `read_only_allow_delete` via `_all/_settings`), `scripts/install.py:3052,3071` (mint target + sentinel only), and the docs corpus/runbooks that *teach* admin-cert reads to customers: `src/backend/ai/docs_corpus/deploy/manage-snapshots.md:195`, `docs/runbooks/storage-and-volume-operations.md:298`, `docs/runbooks/backup-restore.md:80`. `opensearch-security-init` also mounts the WHOLE `data/tls` (`docker-compose.yml:862`), not just the admin dir. In contrast `bootstrap-opensearch.sh:41-45`, `stack-watchdog.sh:938-992` and `support-bundle.sh:388-420` already refuse the admin cert and use `svc_bootstrap`/`svc_api` (though the latter two borrow the api's identity from `.env`, which is the next smell).
4. **Successful reads are not audited by anyone today.** `apply-security.sh:41-48` seeds `audit.yml`/`config.yml` from the plugin defaults; the default `audit.yml` disables `AUTHENTICATED` and `GRANTED_PRIVILEGES` and has `compliance.read_watched_fields: {}` (opensearch-project/security `config/audit.yml`, main — 2.16 image copy UNVERIFIED). So `security-auditlog-*` records failed auth/missing privileges/config changes, never a granted `_search` — for the admin cert or any identity. Store-level "who read syslog" is unanswerable on the current config; the only read audit is the api's own (`netops-audit-*`).
5. **Audit retention is wrong in two directions.** `apply-ism.sh:34-35` puts `security-auditlog-*` under `netops-retention` (`OPENSEARCH_LOG_RETENTION_DAYS`, default 14 — `apply-ism.sh:14`), i.e. the *intent* is 14 d, not the owner's 90 d. But `netops_bootstrap` has only settings/ISM-attach on that pattern (`roles.yml:217-225`), and ISM executes actions in the policy owner's security context, so the delete action should FAIL and the indices grow forever (owner memory 2026-10-18 says the same; not verifiable here without a privileged read — UNVERIFIED on the lab). No tracker row exists for it (grep of `docs/TRACKER.md` finds none).

## 1. Who writes the keys, why 644, sweep

Writer: the api's internal CA (`tls_ca.go:160-188` bootstrap, `:193-320` provision, `:354-374` re-issue loop; TTL = `TLS_SVID_TTL`=168h on the lab `.env`, re-mint ~84h). Installer config is the cause (`install.py:3041-3055`). Every TLS install (installer, `update.sh`, `deploy.sh`, 351/369 rotation work) inherits it; the rotation scripts are not at fault.

Sweep of `data/tls/**` and `data/secrets/**` (modes only, no contents):

| Path | Mode (owner) | Dir mode | Needed reader (effective uid) | Verdict |
|---|---|---|---|---|
| `data/tls/admin/admin.key` | 0644 (installer uid) | 0755 | `opensearch-security-init` uid 1000 (securityadmin) | DEFECT — super-admin key, world-readable |
| `data/tls/admin/{admin.crt,ca.pem}` | 0644 | 0755 | public material | ok |
| `data/tls/api.key` | 0600 | 0775 (`data/tls`) | api (own uid) | ok |
| `data/tls/nginx/nginx.key` | 0644 (`TLS_NGINX_KEY_MODE`) | 0755 | nginx — image runs root per inspect (`tls_ca.go:210-215` says uid 101; UNVERIFIED which applies with the TLS variant) | DEFECT (likely unneeded widening) |
| `data/tls/victoria/victoria.key` | 0600 | 0755 | victoria (root) | ok |
| `data/tls/services/opensearch/opensearch.key` | 0644 | 0775 | opensearch uid 1000 | NEEDED-widen → fix with 0640 + `group_add` |
| `data/tls/services/kafka/kafka.key` | 0644 | 0775 | kafka/kafka-init `appuser` (copies to /tmp/kafka-tls, `rotate-tls-services.sh:266`) | NEEDED-widen → 0640 + `group_add` |
| 22 other `data/tls/services/*/*.key` (api, cadvisor, clickhouse, cloud-ingest, correlation, frontend, gnmic, goflow2, gotenberg, grafana, kafka-exporter, keycloak, netbox, netbox-postgres, nginx, node-exporter, opensearch-dashboards, postgres, prober, redis, syslog-ng, vector-aggregator, vector-router, vmalert, vmauth) | 0644 | 0755/0775 | root or root wrapper, or not mounted at all (several registry rows are additive/dormant, `tls_ca.go:278-283`) | DEFECT — needless widening |
| `data/secrets/**/password`, `vmauth/auth.yml` | 0400 (root or CORRELIX_UID per reader) | 0700 / 0711 | one container each | CORRECT — this is the model (`install.py:2828-2835,2900-2906`) |
| `deployment/docker/.env` | 0600 | — | installer, host scripts | ok |
| `data/licence-signer/*.ed25519`, `data/api/api/licence-report-key.json` | 0600 | — | — | ok |

Directory exposure compounds it: `data` 0755, `data/tls` 0775, `data/tls/admin` 0755 — any local user can traverse.

## 2. What `admin_dn` bypasses; who needs it

OpenSearch: "Super admin certificates are regular client certificates that have elevated rights to perform administrative security tasks"; required for `securityadmin.sh` and the security REST API when `restapi.admin.enabled` is false (ours lists only `all_access`, `opensearch-security.yml:54`); "Only a superadmin can use the Reload Certificates API"; "You can't use node certificates as admin certificates"; `securityadmin.sh` "**overwrites** one or more portions of the `.opendistro_security` index… Run it with extreme care". The DN is honoured by `admin_dn` (`opensearch-security.yml:49`), not by the `all_access` mapping — the comment at `roles_mapping.yml:42-47` describes the wrong mechanism (doc fix). It bypasses every role/index check including system indices and `security-auditlog-*`; whether super-admin requests are themselves audited is UNVERIFIED (docs silent) — and irrelevant today because granted reads are not audited for anyone (finding 4).

| User | What it does | Minimum privilege | Recommended identity |
|---|---|---|---|
| `opensearch-security-init` (`apply-security.sh:109-115`) | `securityadmin -cd` writes the security index | super-admin by product design | **admin cert** (only legitimate consumer), bootstrap-time only, 0600, run as `CORRELIX_UID`, mount only `data/tls/admin` |
| reloadcerts (`opensearch-security.yml:34-43`, no caller wired; opensearch is restart-class `rotate-tls-services.sh:202`) | TLS hot reload | super-admin (docs) | future: admin cert from the sweep, or move to ≥2.19 file-watcher reload and remove the need (tracker 369 L2) |
| `scripts/backup.sh:677-694` | `PUT _snapshot/netops-fs/<snap>` indices `netops-*` | `cluster:admin/snapshot/create|get|status`, `cluster:admin/repository/get` (index-level check for create: UNVERIFIED → negative test) | new `svc_backup` → `netops_backup` (tracker 225 "backup identity") |
| `scripts/host-hygiene.sh:197,260` | GET/PUT `index.blocks.read_only_allow_delete` on `_all` | `indices:monitor/settings/get` + `indices:admin/settings/update` on explicit patterns (`netops-*`, `security-auditlog-*`, `.opendistro-ism-*`, `.opensearch-sap*`, `restored-*`, `probe-*`); `_all` must go (resolves to `.opendistro_security` → 403 for any non-admin). Note OpenSearch auto-releases the block once disk recovers (`opensearch-security.yml:68-76` tunes exactly that), so this is belt-and-braces | new `svc_hygiene` → `netops_hygiene` |
| humans/agents, docs corpus, `stack-watchdog.sh:942`, `support-bundle.sh:408` | health, `_cat/indices`, counts, snapshots, ISM state | monitor-class only: `cluster:monitor/health|state|nodes/stats`, `indices:monitor/*`, `indices:admin/get|mappings/get`, `cluster:admin/repository/get`, `cluster:admin/snapshot/get|status`, ISM explain — **no `read`/`search`** (`_count` executes as a search action → use `_stats/docs`) | new `svc_diag` → `netops_diag`; watchdog/support-bundle move off `svc_api` |
| `install.py:3052,3071` | mint target + sentinel | n/a | unchanged |

## 3. Target model (single box, low complexity)

- **Identities**: keep the OpenSearch-idiomatic shape already in place — one internal basic-auth user per function, password rendered by `install.py` into `data/secrets/opensearch/<id>/password` (root:0400, dir 0711; PR #162 generalises this as the `ServiceSecret` table), mounted/read as a file, sent via `curl --config -`/`-H @file`, never argv (pattern: `apply-ism.sh:44-55`, `support-bundle.sh:417-420`). Add `svc_backup`, `svc_hygiene`, `svc_diag`, `svc_auditretention`. Rotation = the existing `--rotate-secret` + `apply-security` re-run (idempotent, `apply-security.sh:12-14`).
- **Admin cert custody**: on disk but 0600 under `CORRELIX_UID`, dir 0700, consumed only by `opensearch-security-init` running as `CORRELIX_UID`, mounting only `data/tls/admin`. "Offline" custody is not honest here: the CA (sealed in swtpm + kv, `tls_ca.go:164-175`) can mint an admin cert at will, so the real break-glass is api-container/seal access, and the loop re-mints the cert every TTL/2 anyway. On-demand short-TTL minting is possible (api endpoint or CLI, with install tiering changes — `install.py:3804-3809` starts `opensearch-security-init` before the api) but is over-engineering for one box; offer it as an owner decision, not the plan.
- **Diagnostic reads**: long-lived `svc_diag` (not a per-request SVID — client-cert auth would require owning `config.yml` (`clientcert_auth_domain` is `http_enabled: false` by default) plus an issuance API; no gain on a single host). Who may use it: host root (`sudo`) — the file is root:0400, so sudo logging is the who/when. Scope: metadata only, no documents; raw `_source` (syslog with usernames, D7) is read only through the api, which applies tenant scope, `OperatorRestricted` (`docs/security/operator-visibility.md:23-36`) and `_source` stripping (`logs.go:305`, `logsecrets.SourceExcludes`); a raw store read would bypass all three. Alternative if the owner wants per-document triage: `search` with FLS (`fls: [timestamp, device, severity, program]`) — still no message/username fields. Provide one shared `scripts/lib/os-fetch.sh` (GET-only, TLS-vs-plaintext detection, credential from file, one syslog/host-log line per call) used by watchdog, support-bundle and a thin `scripts/osq.sh`; this replaces the three copies that exist now.
- **Audit of those reads**: own `audit.yml` (4th file in `apply-security.sh:48`): enable `GRANTED_PRIVILEGES` with `ignore_users` = the five high-volume app identities (`svc_api svc_router svc_correlation svc_dashboards svc_aggregator`) so every call by backup/hygiene/diag/bootstrap/admin DN is recorded at negligible volume. Keep `resolve_bulk_requests: false`.
- **Audit retention (belongs in this series, separate PR)**: `svc_auditretention` → `netops_audit_retention` (`indices:admin/delete`, `indices:monitor/*`, ISM managedindex on `security-auditlog-*` ONLY + `cluster:admin/opendistro/ism/*`) creates its own ISM policy `netops-audit-retention` (delete ≥ 90 d, ism_template priority above `netops-retention`); remove `security-auditlog-*` from `PATTERNS` (`apply-ism.sh:34-35`). "Kept 1 year" cannot be met by the current SM policy (`max_count` 3 on the same disk, tracker 225a) — honest position: 90 d online now, 1 y when the off-host repo exists. Reading audit logs needs its own role (`netops_audit_reader`) — nobody should read them with the delete identity.
- **Plaintext profile**: `DISABLE_SECURITY_PLUGIN: "true"` (`docker-compose.yml:808`) = no identities, no audit, everything on the compose network reads/writes everything. Honest position: declare it "no access model — lab/dev only" in docs and the posture UI; scripts keep their plaintext branches (`backup.sh:697-701`, `host-hygiene.sh:166-172`); do not build a second mechanism.
- **Industry comparison**: Elastic — "do not use the `elastic` superuser unless full access… is absolutely required… create users that have the minimum necessary roles"; OpenSearch — super admin "reserved for select users and… managed carefully", read-only roles for operators, admin certs separate from node certs. The plan matches both. Over-engineering deliberately rejected: per-tenant OpenSearch roles (design law, `roles.yml:5-9`), short-lived diag SVIDs, auditd on the key file, a retention service.

## 4. Tenant isolation (§3a)

These are platform identities. What keeps them from customers: secrets exist only as root:0400 host files and are never surfaced by any api route (the api's sole OpenSearch identity is `svc_api`, `compose.tls.yml:151-152`); tenant scoping stays in `oslog.TenantFilter`/`osTenantFilter` (`roles.yml:5-9`). A tenant admin has no route to them — but a diag identity with `search` WOULD be a cross-tenant and OperatorRestricted bypass, which is why `netops_diag` is metadata-only. Multi-tenant installs: per-tenant indices all match `netops-*`, so backup/hygiene correctly cover every tenant (platform functions); no per-tenant identity is needed. Required tests: no api route references any OS identity but `svc_api` (Go source sweep); route-isolation coverage unchanged (`route_isolation_coverage_test.go`); the negative matrix proves `svc_diag` cannot `_search` any `netops-*` index.

## 5. Migration

- Fresh install: `install.py` renders the new secret files → `apply-security.sh` env list (`:26-27`, heredoc `:71-106`) and `roles.yml`/`roles_mapping.yml` gain the identities → `securityadmin -cd` applies all (it needs the admin cert — the admin cert is minted in phase A by the plaintext api before phase B, `install.py:3064-3075,3478`; unchanged).
- Upgrade over a running stack: `update.sh`/`deploy.sh` must re-run `opensearch-security-init` (the "edit roles.yml changes nothing until securityadmin re-runs" rule, `roles.yml:67-70`). Deadlock checks: (a) `apply-security.sh` needs a VALID admin cert on disk — if the api has been down > TTL (168h) the cert is expired and the one-shot fails before the api tier starts (`install.py:3807-3809`); add `openssl x509 -checkend` to `apply-security.sh` with a named failure (§16.1) and document "start api first". (b) Key-mode flip ordering: `group_add` (or `user:`) must land and those services be recreated BEFORE `TLS_SERVICE_KEY_MODE` changes, because the api re-chmods every key at its next boot (`provisionFromEnv` at `tls_ca.go:182`) and opensearch/kafka would then fail to read 0600. (c) Healthcheck stays non-`-f` (`compose.tls.yml:294-299`); `opensearch-init` keeps its bounded wait (`tests/test_install_opensearch_bootstrap_bound.py`).
- Rollback: set the mode back in `.env` and restart the api (re-mint re-chmods); `securityadmin -cd` with the previous files restores the role model; data unaffected.
- Coordination: PR #162 (`fix/384-service-credentials`) edits `apply-security.sh`, `install.py` (ServiceSecret table), `bootstrap-jobs.yaml`, `compose.tls.yml`, `docker-compose.yml`, `test_upgrade_bootstraps.py` — PRs C–F below must be based on #162. PR #163 touches `apply-ism.sh` (templates) — PR F's `PATTERNS` edit rebases on it. PR A/B touch `tls_ca.go`, compose `user:`/mount lines and `TLS_ENV_VALUES`, which neither PR edits (UNVERIFIED hunk-level).

## 6. Tests

- **Unit (pytest, static)**: extend `tests/test_opensearch_role_privileges.py` — each new role's actions equal an agreed set; `netops_diag` has no `read`/`search`/`get`/`scroll` on any pattern; `netops_hygiene` only settings get/update; `netops_audit_retention` patterns == `["security-auditlog-*"]`; `netops_backup` only snapshot/repository verbs; one user ↔ one role; `apply-security.sh` env list == users in `roles_mapping.yml` (drift guard); `install.py` ServiceSecret rows exist for each; `TLS_ENV_VALUES` key modes have no "other" bits; compose: `opensearch-security-init` has `user: ${CORRELIX_UID}` and mounts only `data/tls/admin`; static sweep: no script/doc outside an allowlist (`apply-security.sh`, `install.py`, `tls_ca.go`) references `data/tls/admin`.
- **Go**: `serviceKeyMode` rejects modes with o+r unless `ALLOW_DEV_SECRETS`; admin key path never widened.
- **Custody test (all keys)**: walk `data/tls/**` + `data/secrets/**`; every `*.key` and secret file must have `mode & 0o007 == 0` and be 0600/0640/0400 per an explicit reader table; dirs no `o+rx`; run in install-boot CI against the real rendered tree and shipped as `install.py --verify-custody` for the watchdog.
- **Real-OpenSearch negative matrix** (new deploy-qualify block + install-boot CI): anonymous → 401; `svc_backup`: snapshot PUT 200, `_search` 403, `.opendistro_security` 403, index DELETE 403; `svc_hygiene`: settings PUT 200 on `netops-*`, snapshot 403, `_search` 403; `svc_diag`: health/`_cat/indices`/`_stats/docs` 200, `_search` 403, `security-auditlog-*` 403, snapshot PUT 403; `svc_auditretention`: DELETE `security-auditlog-<old>` 200, DELETE `netops-*` 403; `svc_bootstrap` unchanged.
- **Audit-log proof**: a `svc_diag` GET yields a `security-auditlog-*` document with that effective user; read back in CI with the admin cert (CI-only) or the new reader role.
- **Mutation targets**: restore `_all` in hygiene; add `search` to diag; widen audit-retention pattern; set mode 0644; mount whole `data/tls`; add a `data/tls/admin` reference to a script; put `security-auditlog-*` back in `PATTERNS` — each must fail exactly one named test.
- **Profiles**: plaintext — matrix asserts scripts take the plaintext branch and identities are unused; helm — `tests/test_helm_chart.py:269-270` deliberately does not stage roles; the chart's security job uses the CA secret as the admin cert (`bootstrap-jobs.yaml:244-246,262-266`) which cannot match `admin_dn` (UNVERIFIED) → file a tracker row, out of scope.

## 7. Ordered PRs

| # | PR | Files | Stage | Risk | Effort |
|---|---|---|---|---|---|
| A | **Quick custody fix (ship first)**: admin key stays 0600; security-init runs as `CORRELIX_UID`, mounts only `data/tls/admin` (`OS_ADMIN_CA=/certs/ca.pem` from `tls_ca.go:274`); `data/tls/admin` 0700 via `install.py:2402` private_modes; checkend pre-check in `apply-security.sh` | `tls_ca.go`, `docker-compose.yml:841-865`, `install.py`, `apply-security.sh`, tests | custody | Low (securityadmin as a non-1000 uid needs writable `/tmp` — UNVERIFIED → install-boot) | S |
| B | Service-key custody: `TLS_SERVICE_KEY_MODE`→0640 + `group_add: ["${CORRELIX_GID}"]` on opensearch/kafka/kafka-init; `serviceKeyMode` refuses o+r; nginx mode re-verified; custody test over all keys; migration ordering doc | `tls_ca.go`, `compose.tls.yml`, `install.py:3041-3055`, tests, `docs/runbooks/tls-mtls.md` | custody | Med (kafka `appuser` gid handling; dormant registry rows) | M |
| C | `svc_backup` (after #162): role+mapping+ServiceSecret row; `backup.sh` curl container with `--config -`; drop admin-cert path; runbook `backup-restore.md:80` | `roles.yml`, `roles_mapping.yml`, `apply-security.sh`, `install.py`, `backup.sh`, tests | identities | Med (snapshot create index-check UNVERIFIED) | M |
| D | `svc_hygiene`: role+mapping+row; `host-hygiene.sh` explicit patterns, no `_all` | same set + `host-hygiene.sh` | identities | Low | S |
| E | `svc_diag` + `scripts/lib/os-fetch.sh`; watchdog `_count`→`_stats/docs`; support-bundle and docs corpus/runbooks rewritten; static sweep test | `roles*.yml`, `install.py`, `stack-watchdog.sh`, `support-bundle.sh`, `docs_corpus/deploy/*.md`, runbooks | identities | Low | M |
| F | Owned `audit.yml` + `svc_auditretention` + 90 d ISM policy; `PATTERNS` edit (after #163); reader role | `apply-security.sh`, `audit.yml` (new), `roles*.yml`, `apply-ism.sh`, tests | audit | Med (securityadmin overwrites audit config; volume check) | M |
| G | Tracker/INVARIANTS rows: audit-retention gap, helm admin-cert wiring, 225 backup identity closed | docs | docs | — | S |

## Owner decisions (with recommendations)

1. Admin cert custody: on-disk 0600 under `CORRELIX_UID` (recommend) vs on-demand short-TTL mint (defer).
2. `svc_diag` scope: metadata-only, documents only via the api (recommend) vs FLS-limited `search`.
3. Audit "1 year kept": accept 90 d online + 1 y only once an off-host repo exists (recommend) vs raise `max_count` on disk-rich hosts.
4. Enable `GRANTED_PRIVILEGES` auditing for non-app identities (recommend yes).
5. Plaintext profile: declare "no access model, lab/dev only" in docs + posture UI (recommend yes).
6. Move to an OpenSearch ≥2.19 image for file-watcher cert reload, removing the last runtime admin-cert use (tracker 369 L2) — separate decision.
7. Helm chart admin-cert wiring — file and defer.

## UNVERIFIED items
2.16 image's default `audit.yml` matches upstream main; super-admin requests are audited; snapshot-create index-level check; securityadmin running as a non-1000 uid; nginx's effective uid under the TLS variant; current lab state of `security-auditlog-*` growth and ISM failure; exact hunk overlap with PRs #162/#163.

---

## Corrections from implementation (PRs A and B, 2026-11-09)

Each was checked on the pinned images, in the rendered compose for every
profile, and in a throwaway TLS bring-up with `CORRELIX_UID=1234`.

1. **securityadmin cannot run as a non-1000 uid on the stock image.** Its home
   `/usr/share/opensearch` is 0700 at 1000:1000, and `securityadmin.sh`,
   `hash.sh` and the default security config give others no access. As 1234:1234
   and as 1234:1000 every tool fails with "Permission denied". The plan's
   "needs a writable /tmp" was not the blocker (`/tmp` is 1777). The smallest
   correct alternative that keeps the 0600 decision: the slim image chmods its
   home 0750, and `opensearch-security-init` runs as `CORRELIX_UID:1000`. Group
   1000 opens the image's own files and is not the key's group. Proven with a
   real `securityadmin -cd` as uid 1234 against a TLS OpenSearch (exit 0, then
   anonymous 401, `svc_api` 200, a wrong password 401).
2. **Eight readers need more than 0600, not three.** Effective identities:
   opensearch 1000; kafka and kafka-init 1000 (appuser); nginx 101 with
   `cap_drop: ALL`; correlation 10001 with `cap_drop: ALL`; prober root but with
   `cap_drop: ALL` (+NET_RAW), so no DAC override; cloud-ingest 1000 (poller);
   redis, whose image starts as root and drops to 999 with
   `setpriv --clear-groups`, which also discards any `group_add`. Redis therefore
   runs as `999:1000` directly in the TLS variant. Every other reader is root
   with Docker's default capabilities (it reads a 0600 file of any owner), a root
   wrapper that stages the key (postgres, clickhouse, gotenberg-tls-init), or a
   row nothing mounts (11 dormant rows).
3. **nginx's effective uid is 101** under the TLS variant (`Dockerfile.nginx`
   `USER 101`, `cap_drop: ALL`), confirmed on the running lab container. Its key
   is 0640, read through `group_add`.
4. **nginx and victoria mounted the whole of `data/tls`,** as the security job
   did. Each now mounts its own directory plus `ca.pem`, with unchanged
   container paths. With `data/tls` at 0700, a reader that holds `CORRELIX_GID`
   cannot reach another reader's key.
5. **The helm chart mints nothing on disk.** Its keys are cert-manager Secrets
   mounted per pod, so `TLS_SERVICE_KEY_MODE` has no equivalent there, and PR B
   changes nothing in the chart. Its security job mounts the CA Secret as the
   admin certificate (`bootstrap-jobs.yaml`). That cannot match `admin_dn`, and it
   puts the CA's private key in a job pod. This falls under owner decision 7
   (file and defer) and is not fixed here.
6. **backup.sh would have lost its snapshot call** at 0600, because its curl
   container runs as uid 100. PR A runs it as the key's owner until PR C moves it
   to `svc_backup`. `host-hygiene.sh` reads the key on the host as the cron user,
   who is `CORRELIX_UID`, so it keeps working unchanged.
7. **A hand-run `docker compose up -d api` alone is the wrong upgrade order.** It
   recreates the api, which tightens every key at boot, while the readers still
   run without `group_add`. Nothing fails at once, because each reader holds its
   key in memory, but its next restart or certificate reload fails and the store
   stays down. The supported paths get the order right: `update.sh` and
   `install.py` recreate everything in one `compose up`, and `deploy.sh api`
   recreates any reader without `group_add` first. Recovery from the wrong order
   is `docker compose up -d` for all services. Proven: old-shape kafka and redis
   on the tightened tree do not come up.
8. **The installer's recursive chown of `data/tls` re-owned gotenberg's staged
   copies** (0400, owned by uid 1001) to the api's uid, and gotenberg could not
   read them until `gotenberg-tls-init` happened to re-run. Fixed in the
   installer: after the chown it hands the staged files back to 1001, failing the
   install if it cannot.
