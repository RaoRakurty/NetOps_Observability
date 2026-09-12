# ADR-SEC-005 — Kafka authentication: mTLS vs SASL_SSL (SCRAM)

- **Status:** **Accepted (owner, 2026-08-04).** Decision: **mTLS, using the same
  internal CA that mints every other workload identity** (ADR-SEC-003). This
  settles HLD §11 open decision #3. The SASL_SSL/SCRAM analysis is retained in
  full below because the deferred option must stay auditable — if a client
  proves intractable (see U4), the fallback path is already reasoned through.
- **Owner rationale (overhead, not purity):** SASL/SCRAM would introduce a
  **second credential store** to generate, seal, distribute, rotate and audit —
  the same class of object that produced the shared-`INGEST_TOKEN` problem this
  programme exists to remove. mTLS reuses certificates the platform **already
  mints and already auto-rotates at TTL/2**
  (`src/backend/tls_ca.go:159-165`). One credential system, not two.
- **Implementation state:** **nothing implemented.** Kafka runs
  `PLAINTEXT` with **no authentication and no ACLs**
  (`deployment/docker/docker-compose.yml:207-210`:
  `KAFKA_LISTENERS: "PLAINTEXT://0.0.0.0:9092,CONTROLLER://0.0.0.0:9093"`,
  `KAFKA_ADVERTISED_LISTENERS: "PLAINTEXT://kafka:9092"`,
  `KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: "PLAINTEXT:PLAINTEXT,CONTROLLER:PLAINTEXT"`).
- **Relates to:** HLD §7 (Kafka rows, all P0/P1), §9 phase 3, §11.3;
  ADR-SEC-003 (workload identity); ADR-SEC-004 (native authz per component);
  `docs/runbooks/security/kafka-tls-migration.md`.

---

## Context

Kafka is the spine: single-node KRaft (service `kafka`, profile `embedded-bus`),
and every client resolves it through `BROKER_URLS`
(`docker-compose.yml:393,431,481,739,972`), which also supports pointing at an
external Kafka-compatible broker. Today it authenticates nobody. Anyone with
network reach can produce to any topic, consume every tenant's telemetry, or
join any consumer group. HLD scores the resulting threats T3, T4 and T5 all
**HIGH**.

**The client population is heterogeneous, and this is the crux of the
decision.** Verified:

| Client | Runtime / library | Notes |
|---|---|---|
| `vector-aggregator`, `vector-router` | Vector (Rust, librdkafka) | `kafka` sinks/sources at `deployment/docker/vector/vector.yaml:990,1001,1009,1017,1031` with `bootstrap_servers: "${BROKER_URLS:-kafka:9092}"`. Supports both TLS and SASL. |
| `goflow2` | Go (`netsampler/goflow2:v2.2.1`) | Native `kafka://` transport, `deployment/docker/goflow2/goflow2.yaml:50-52` (`type: kafka`, `brokers: kafka:9092`). Third-party image — its TLS/SASL surface is whatever the upstream exposes, not something we can extend. |
| `correlation` | Python `aiokafka==0.11.0` (`src/correlation/requirements.txt:7`) | Supports SSL and SASL/SCRAM; certificate handling means files + an `ssl_context`. |
| `kafka-exporter` | third-party image (`docker-compose.yml:739`, `--kafka.server=${BROKER_URLS:-kafka:9092}`) | Metrics scraper; must also authenticate once anonymous access is closed. |
| **Go API** | **not a Kafka client at all** | `src/backend/bus_producer.go` is explicit: *"The Go backend is stdlib-only with NO Kafka client (allowlist §6)"* — it produces over Vector's HTTP bus-bridge (`bus_in`, :8692) and Vector forwards to the topic. |

That last row is load-bearing in both directions. It **removes** the largest
objection to mTLS (we would otherwise need a certificate-capable Kafka client in
Go, which the dependency allowlist in root `CLAUDE.md` §6 does not permit), and
it **adds** a constraint: the api→bus hop is HTTP to Vector, so securing Kafka
does *not* secure that hop — it is a separate ingest-lane problem (HLD §7,
`collectors/ingest_auth.go`, the shared `INGEST_TOKEN`).

Whatever is chosen must also carry **authorization**, not just authentication.
Kafka ACLs are principal-based, and the principal's form differs between the two
options — which is precisely why this cannot be deferred as "an ops detail".

## Decision (ACCEPTED — owner, 2026-08-04)

**Use `SSL` (mutual TLS) as the Kafka authentication mechanism, issued by the
same internal CA as every other workload identity, with topic and consumer-group
ACLs bound to the SPIFFE identity carried in each client certificate, and
`allow.everyone.if.no.acl.found=false` as the terminal state.**

1. **Authentication:** mutual TLS on a dedicated `SSL` listener. Client
   principal derives from the certificate; ACLs are written against it.
2. **Identity source:** the workload trust domain from ADR-SEC-003 —
   `spiffe://correlix.workload/ns/<ns>/sa/<service>` — so Kafka principals are
   the *same* identities used by every other component. **No second credential
   store.** This is the primary argument for mTLS over SCRAM.
3. **Authorization:** a least-privilege ACL matrix, one entry per client, scoped
   to the topics it genuinely owns. Indicative (authoritative matrix belongs in
   the LLD): `goflow2` produces `netops.flows` and consumes nothing;
   `vector-aggregator` produces the lanes it owns (`netops.syslog`,
   `netops.metrics`, applog/cloud lanes) and consumes nothing; `vector-router`
   consumes those topics into its own group; `correlation` consumes only, in its
   own group; `kafka-exporter` gets describe/metadata rights only.
4. **Terminal state:** the `PLAINTEXT` listener is **removed**, and
   `allow.everyone.if.no.acl.found=false`. A migration that stops at "TLS is
   available" has achieved nothing (HLD §9 phase 3 completion criteria).
5. **Dual listener is the migration mechanism, and it expires.** `PLAINTEXT` and
   `SSL` listeners coexist only during cutover, with a declared exception
   carrying an owner and a date (ADR-SEC-001 extension #1).
6. **Per-client SCRAM fallback is a declared, expiring exception — never a
   parallel design.** If a specific client (most plausibly `goflow2`, U4) cannot
   be made to work with certificates, it may be granted SASL_SSL/SCRAM as a
   **named, owned, time-boxed exception** in the transport-policy table
   (ADR-SEC-001), with its ACL principal in `User:<scram-user>` form. It must not
   become a second standing mechanism by default. The ACL matrix, the
   dual-listener migration and the terminal state are identical either way.
   **Switching mechanism is cheap only before ACLs are written**, because
   principals differ — so the mechanism per client must be settled during the
   observe phase (migration step 3), not after.

### The cost this decision accepts, stated plainly

The cost of mTLS does not land on code we control. It lands on **goflow2** (a
third-party image whose Kafka TLS configuration surface we do not own), on
**Vector's** librdkafka TLS settings, on **aiokafka's** `ssl_context` plumbing
in the correlation service, and on **kafka-exporter**. Each needs a certificate
file, a key file with correct permissions, a CA bundle, and a rotation trigger —
and each rotates on its own restart semantics, none of which have the Go
`CertReloader` hot-swap (`src/backend/tlsconfig/reload.go`).

SCRAM would trade that for a static username/password per client: trivially
portable, supported by every client listed above, rotatable without touching
PKI. The owner's judgement is that this trade is **worse overall**, because the
"simpler" option is simpler only at install time — it is permanently more
expensive to *operate*, since a second credential store means a second sealing
path, a second rotation schedule, a second audit trail, and a second way to
leave a stale secret in production. The mTLS cost is paid once per client, in
configuration; the SCRAM cost recurs forever, in operations.

**Mitigation for the accepted cost:** rather than forcing 24 h certificate
churn on clients that only read certificates at startup, those peers get a
longer, **declared** leaf TTL under the policy object (see U3) — an explicit
exception with an owner, not a silent divergence.

## Alternatives considered

| Alternative | Assessment |
|---|---|
| **mTLS (`SSL` listener)** — **CHOSEN (owner, 2026-08-04)** | **Pro:** one identity system; certificates expire by themselves (24 h leaves, ADR-SEC-003) so a leaked credential self-heals; principals are SPIFFE IDs that match ACLs elsewhere; no new secret store. **Con:** every non-Go client needs certificate plumbing and a rotation trigger; goflow2's TLS surface is upstream-controlled; short TTLs are hostile to clients that only read certificates at startup (see U3). |
| **SASL_SSL with SCRAM-SHA-512** | **Pro:** simplest possible client config (user + password + CA); universally supported; rotation is a broker-side operation with no PKI; tolerant of clients that cannot reload certificates. **Con:** a second credential store to seal, distribute, rotate and audit — exactly the class of thing that produced the `INGEST_TOKEN` problem; credentials never expire on their own; the principal is a name, not an attested identity; and it diverges from the identity model every *other* component uses (ADR-SEC-003, ADR-SEC-004). |
| **SASL_SSL with OAUTHBEARER** (token from Keycloak) | Attractive on paper — reuses the identity provider already in the stack (profile `sso`). Rejected for now: it makes Kafka availability depend on Keycloak availability, `aiokafka`/goflow2 support is uneven, and it introduces token-refresh failure modes on the data spine. Revisit if a k8s/OIDC-native deployment becomes primary. |
| **SASL_PLAIN over TLS** | Rejected: plaintext credentials inside the TLS session, no per-message binding, and no advantage over SCRAM. |
| **Delegation tokens** | Kafka-native, short-lived, but require an initial SASL/SCRAM or mTLS authentication to obtain — a layer on top of one of the above, not an alternative to them. |
| **TLS encryption only, no client authentication** | **Rejected outright.** This is the ADR-SEC-004 anti-goal in miniature: it encrypts anonymous access. T3/T4/T5 are unchanged. |
| **Network isolation only** (broker unreachable outside the compose network) | Already partly true and it is *necessary*, not *sufficient*: it does not separate the six clients from each other, so a compromise of any collector still yields full bus read/write (T3). |
| **Both mechanisms enabled permanently** (mTLS for services, SCRAM for awkward clients) | Pragmatic, and the likely real-world outcome if one client proves intractable. Rejected as a *design* because "both forever" means neither is ever fully enforced; permitted only as a declared, expiring exception per client (ADR-SEC-001). |

## Consequences

**Accepted path (mTLS)**
- **The event bus stops being the hole in the "everything over TLS" claim.**
  Kafka is the one hop every telemetry record crosses; leaving it plaintext
  would make the customer-facing statement false at its most important point.
- One identity fabric end to end; Kafka principals look like every other
  principal in the platform, and there is exactly one thing to rotate.
- Credential compromise self-limits at the leaf TTL.
- Four non-Go clients acquire a certificate lifecycle, and the *weakest* of them
  sets the practical leaf TTL for the whole bus (U3).
- goflow2 becomes a supply-chain dependency for a security control — if the
  pinned image's Kafka TLS support is inadequate, the options are pin-bump,
  replace, or grant it a standing exception.

**Rejected path (SCRAM) — retained for auditability**
- Migration would have been materially faster and lower-risk; every client
  supports it today.
- But a new secret store enters the platform: per-client SCRAM credentials that
  must be sealed (`internal/vault`), distributed, rotated on a schedule and
  audited — with no natural expiry to catch a missed rotation.
- Kafka's authorization model would diverge from the rest of the stack, so "who
  is this principal" gets two answers.
- **Revisit trigger:** if U4 shows the pinned goflow2 image cannot do client
  certificates and no acceptable alternative exists, SCRAM returns as a
  per-client exception (decision 6) — not as the stack-wide mechanism.

**In both cases**
- **Phase 3 is the highest-risk phase in the roadmap** (HLD §9): the bus is the
  spine, and a botched cutover drops telemetry. Per-client cutover with consumer-
  lag monitoring is mandatory, not advisory.
- Broker restarts are required for listener changes; single-node KRaft means a
  restart is a brief total bus outage, absorbed by Vector's disk buffers
  (`vector/vector.yaml:47`, the `buffer:` blocks on the Kafka sinks) — those
  buffers are the safety margin and their capacity must be checked *before* the
  cutover, not after.

## Security implications

- **Mitigates T3** (collector compromise ⇒ full bus access), **T4** (topic
  injection — writing into another lane), **T5** (unauthorized consumption of
  tenant telemetry). All three are currently scored HIGH.
- **Authentication without ACLs is half a control.** With authentication on and
  `allow.everyone.if.no.acl.found=true`, every authenticated client still gets
  everything — T4 and T5 survive. The completion criterion must be the ACL
  matrix plus the flag flipped to `false`.
- **Kafka authorization is not tenant isolation.** Topics are shared across
  tenants; tenant scoping lives downstream at the data layer (ClickHouse row
  policies, PG RLS, per-tenant OpenSearch indices). Nothing in this ADR changes
  or weakens that, and no ACL may be presented as a tenant control (HLD §4).
- **Consumer groups need ACLs too.** Read access without group scoping lets one
  client steal another's group and silently divert partitions — a data-loss
  vector, not just a confidentiality one.
- **The api→Vector bus-bridge hop is out of scope here and still plaintext with
  a shared token.** Securing Kafka while `bus_in` accepts a shared
  `INGEST_TOKEN` over HTTP leaves the *easier* path into the bus wide open. The
  two must be sequenced together or the mitigation is illusory.

## Operational implications

- **Certificate/credential distribution to four non-Go containers** is the bulk
  of the work: mount paths, file ownership, `0600` keys, and a restart or reload
  trigger per client.
- **Rotation must not drop messages.** Vector's disk buffers tolerate a short
  broker gap; a client that restarts to pick up a certificate must be verified
  to resume from its committed offsets without duplication or loss.
- **Monitoring:** authentication failures, ACL denials per principal, and
  consumer lag per group must be visible *before* the cutover begins — a denial
  that is invisible looks exactly like a data-loss bug.
- **External brokers.** `BROKER_URLS` supports pointing at a managed
  Kafka-compatible broker (`docker-compose.yml:186-188`), where the customer
  dictates the mechanism — often SASL_SSL. The client configuration surface must
  therefore be able to express **both** mechanisms even if we standardize on one
  internally. This is an argument for making the mechanism a per-peer policy
  value (ADR-SEC-001) rather than a hardcoded assumption.
- **Runbook:** `docs/runbooks/security/kafka-tls-migration.md` (outline; entirely
  pending implementation).

## Migration implications

Sequence (detail in the runbook; risk narrative in HLD §9 phase 3):

1. Add a second listener (`SSL` or `SASL_SSL`) alongside `PLAINTEXT`; both
   advertised. No client changes yet.
2. Move clients one at a time, verifying produce/consume and lag after each.
   Order by blast radius: `kafka-exporter` (metrics only) → `goflow2` → the
   Vector lanes → `correlation`.
3. Write ACLs in **permissive/observe** posture first (authorizer logging on,
   `allow.everyone.if.no.acl.found=true`) and read the denials that *would* have
   happened. Do not narrow until the log is quiet.
4. Flip `allow.everyone.if.no.acl.found=false`.
5. Remove the `PLAINTEXT` listener and delete its declared exception.

**Irreversibility notes:** steps 1–3 are reversible by reverting compose and
restarting the broker. Step 4 is reversible but will cause immediate denials for
anything missed. Step 5 is reversible only by re-adding the listener and
restarting — which is a full (brief) bus outage.

## Unresolved questions

- **RESOLVED (owner, 2026-08-04):** mTLS with the internal CA. HLD §11.3 is
  closed. SCRAM survives only as a per-client, expiring exception (decision 6).
- **U2 — Do we support both mechanisms** to accommodate external managed brokers,
  or standardize internally and treat external brokers as a separate policy?
- **U3 — Leaf TTL for Kafka clients.** 24 h suits Go services with hot reload;
  clients that read certificates only at startup would restart daily. Either a
  longer declared TTL for those peers or a reload mechanism per client — unsolved
  and it materially affects whether mTLS is operable.
- **U4 — goflow2's actual TLS/SASL capability at the pinned version**
  (`v2.2.1`, digest-pinned). Must be verified against the image before the
  decision is ratified; it is the client most likely to force the answer.
- **U5 — Broker-side certificate.** Who issues the Kafka *server* certificate and
  who rotates it? The API's `internalca` currently mints only `api` and `nginx`
  (`src/backend/tls_ca.go:145-155`), and the broker's lifecycle is not
  API-controlled (ADR-SEC-003 U5).
- **U6 — KRaft controller listener.** The controller listener is also
  `PLAINTEXT` (`docker-compose.yml:207,210`). Single-node makes it low risk
  today; a multi-node bus makes it a real one, and it is not addressed above.
- **U7 — Sequencing with the ingest lanes.** Securing Kafka without securing the
  `bus_in` HTTP bridge and the shared `INGEST_TOKEN` leaves an easier path in.
  Which goes first, or do they ship together?
