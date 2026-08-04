# Correlix Security — Open Unknowns Register

Things this review did **not** establish. Recorded rather than guessed, because
inventing a finding is the failure mode the errata ledger exists to prevent.

Each has a **resolution method** — most are a code read or one read-only
command, not a decision.

| Status | Meaning |
|---|---|
| **BLOCKING** | A v1 item cannot be designed or executed until this is answered |
| **GATING** | Blocks a *deferred* phase only |
| **OPEN** | Should be answered; does not block v1 |
| **RESOLVED** | Answered during this review; kept for the audit trail |

---

## RESOLVED during this review

**U3 — Does goflow2 support Kafka TLS? → RESOLVED (owner decision #7).**
Verified two independent ways: the pinned binary's own flag list
(`netsampler/goflow2:v2.2.1@sha256:bc7aafd…`) and upstream
`transport/kafka/kafka.go` at tag `v2.2.1`.

| Capability | Answer |
|---|---|
| TLS to broker | **YES** — boolean `-transport.kafka.tls` |
| CA trust | **System cert pool only** — no CA-file flag (mount a private-CA bundle + `SSL_CERT_FILE`, the pattern already used for the api) |
| **Client cert / mTLS** | **NO** — no flag, no config field |
| Hostname verification | **Always on, not disableable** — `InsecureSkipVerify` does not appear in the source |
| SASL | `plain`, `scram-sha256`, `scram-sha512`; credentials via `KAFKA_SASL_USER`/`KAFKA_SASL_PASS` env only |
| TLS min version | **1.2, hardcoded** |
| Transports available | `file` and `kafka` **only** |

**Consequences.** (a) The premise "keeping goflow2 forces unauthenticated
Kafka" is **false** — SCRAM-SHA-512 over TLS works today. (b) **Decision D5
("mTLS, one credential system") must be amended**: goflow2 provably cannot
present a client certificate, so D5 needs an exception permitting SASL_SSL
where a client cannot do mTLS. (c) The owner's preferred option 1
(goflow2 → Vector → Kafka) is **not available** — goflow2 has no HTTP/TCP
transport, so it would mean returning to the stdout-scraping path that change
F-49 deliberately removed as lossy. **Recommended: option 2** (direct Kafka
with TLS + SCRAM + a `goflow2` principal ACL'd to produce `netops.flows` only).
Residual caveats: the SASL secret is an env var (same exposure class as
`CLICKHOUSE_PASSWORD` today), and TLS 1.3 cannot be forced from goflow2's side.

**U-CORR — Can a tenant caller cause a cross-tenant read? → RESOLVED: YES.**
Full chain verified in the evidence matrix §4. No longer an unknown; it is a
finding.

---

## BLOCKING (must be answered before the v1 item they gate)

**U1 — Does enabling Valkey `--requirepass` silently destroy RCA evidence?**
*Strong evidence it does.* `RedisAddr()` (`collectors/redis.go:46-54`) is a pure
env read — it never dials and never consults `REDIS_PASSWORD`, so it returns
non-empty regardless of auth state. The traceroute publisher
(`collectors/traceroute.go:169-181`) gates its file fallback on `RedisAddr() != ""`
and then `return`s unconditionally, so on an auth failure the measurement is
**dropped with no log and no metric** — and nine write sites discard errors
(`_ = redisSetEX(...)`). Read paths *do* fall back correctly.
**Resolution:** read the remaining write sites and confirm; then fix the
fallback and the health probes **before** enabling auth. This is why Valkey is
"v1-mandatory but strictly sequenced".

**U2 — What are the actual ClickHouse grants for `netops`?**
Inferred from `CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT: "1"` (`docker-compose.yml:914`),
zero `GRANT` statements in `init.sql`, and the fact that the same user executes
DDL and `CREATE USER`. **Not directly observed.** Resolution: `SHOW GRANTS FOR netops`
against a **non-production** instance. Gates the privilege-reduction item.

**U4 — Is the correlation service's platform scope genuinely required, and where?**
The engine's bus-consuming loop legitimately needs platform-wide correlation;
the request-serving reads do not. `CH.query` (`main.py:1832-1839`) is the only
read method and hardcodes `__all__`, conflating both. **Resolution: instrument,
do not guess** — add a `CH_CROSS_TENANT_READS` counter mirroring the existing
write counter, observe which call sites appear, then scope the rest. Guessing
this from a code read is exactly the trap the owner warned about.

**U5 — Which clients break when each datastore gains authentication?**
Enumerated per store, but not *tested*. Resolution: a staged rollout with the
health probes fixed first — four of five healthchecks authenticate with nothing
and would stay green through a botched cutover.

---

## GATING (deferred phases only)

**U6 — Kafka PEM keystore format and reload semantics** for `apache/kafka:4.1.1`
KRaft. Gates the deferred Kafka work.

**U7 — Can Vector's `http_server` source enforce a per-source client identity
allowlist**, or only TLS + Basic? Gates per-collector identity.

**U8 — Does vmauth verify client certificates**, or only terminate TLS? Gates
the VictoriaMetrics design shape (vmauth-in-front vs global `-httpAuth`).

**U9 — Does the hand-rolled Go RESP client support TLS?** `collectors/redis.go`
imports no `crypto/tls`. Gates Valkey TLS (separate from Valkey *auth*, which
is v1).

**U10 — Does the correlation service use OpenSearch at all?** Compose passes
`OPENSEARCH_URL` (`:973`); whether `main.py` reads it was not confirmed. Affects
the OpenSearch client inventory.

---

## OPEN (answer when convenient)

**U11 — VictoriaMetrics tenant-label leak.** `/metrics` exposes
`corr_tenant_writes_window{tenant_id="…"}` (`main.py:3424-3432`), scraped
unauthenticated. Whether a tenant-scoped user can query those series back is
untraced. Independent of the transport work: **customer names on an
unauthenticated endpoint**.

**U12 — Are there deployment overrides that segment the flat `netops` network?**
Only the single compose file plus the lab override were reviewed. If a
production deployment segments the bridge, the "any container can reach any
datastore" exposure narrows — but that must be *verified*, not assumed, and
network topology is not authentication regardless.

**U13 — Was the correlation replay leak ever exposed to real customer data,**
or is it lab-only so far? Determines whether this needs disclosure handling in
addition to a patch. **Only the owner can answer this.**

**U14 — Does `deployment/docker/goflow2/goflow2.yaml` still serve a purpose?**
It is not mounted (dead as config), but its `fields:` list is the flow schema
the ClickHouse/OpenSearch mappings are written against. Its `transport:` stanza
already drifts from the live command and should be deleted either way.

**U15 — Runtime confirmation for every IBD control.** The entire PKI is
"implemented but disabled"; nothing in it has run in this deployment. Every
claim about its behavior is code-reading. Resolution: enable in a lab profile
and observe before any claim is made externally.
