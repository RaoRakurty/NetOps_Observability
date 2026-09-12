# ADR-SEC-004 — Native TLS + native authorization per component; service mesh deferred

- **Status:** **Accepted (owner, 2026-08-04)** — **partially implemented,
  formalizing.** Decision: **native TLS, no service mesh.**
  The native-TLS half is *already the implemented architecture*
  (`docs/design/tls-architecture.md` phases 1–4 ✅, `src/backend/tlsconfig`,
  `src/backend/backend_client.go`), and a mesh has never been adopted. What is
  **new** here is (a) the explicit, recorded *deferral* of a mesh with named
  re-evaluation triggers, and (b) the **anti-goal** that a mesh must never be
  used to make an insecure datastore or broker configuration look secure.
- **Implementation state:** native TLS built and **dormant** (no `TLS_*` in the
  live `deployment/docker/.env`); native authorization partially present
  (ClickHouse row policies ✅, PG FORCE-RLS ✅) and partially absent (Kafka has no
  ACLs, OpenSearch has no security plugin at all).
- **Relates to:** HLD §1.3, §8, §10; ADR-SEC-003 (workload identity);
  ADR-SEC-005 (Kafka); ADR-SEC-008 (fail-closed).

---

## Context

The industry-default answer to "secure service-to-service traffic" is a service
mesh: Istio or Linkerd sidecars, or Istio ambient. It is the right answer for a
large fleet of homogeneous HTTP/gRPC microservices on Kubernetes. Correlix is
not that, in four verifiable ways.

**1. There is no Kubernetes.** No manifests, Helm charts or kustomize overlays
exist anywhere in the repository — verified by searching for `Chart.yaml`,
`kustomization.yaml` and `kind: Deployment`, all of which return nothing. The
substrate is Docker Compose (`deployment/docker/docker-compose.yml`, 18
services). HLD §1.3 makes the same finding and notes that #114 (k8s packaging)
is unstarted. A mesh cannot be adopted on a substrate that does not exist.

**2. Half the peers will never be in a mesh.** Correlix's security perimeter
starts at customer devices (HLD §4 boundary ①): routers sending syslog to
`syslog-ng` on UDP/TCP 514 (`deployment/docker/syslog-ng/syslog-ng.conf:84-85`),
flow exporters sending NetFlow/IPFIX/sFlow over UDP to goflow2, SNMP agents and
trap senders, gNMI targets dialled by gnmic
(`deployment/docker/gnmic/gnmic.yaml`). A Cisco router will not run an Envoy
sidecar. Whatever secures those is not a mesh.

**3. Mesh authorization cannot reach the controls that actually matter here.**
Correlix's authorization primitives are data-model-aware, not path-aware:

| Control | Where it lives | Could a mesh express it? |
|---|---|---|
| ClickHouse `ROW POLICY` per tenant, converged on every API start | `src/backend/clickhouse_policies.go` (idempotent, self-healing; guarded by `clickhouse_policies_test.go:65-69`, `ch_convergence_test.go:96`, `cloud_costs_test.go:79-84`) | No — row-level, inside the database |
| Postgres FORCE-RLS + `withTenant` | `src/backend/db.go` and the `tenant_iso` policy migrations | No |
| Per-tenant OpenSearch indices + `osTenantFilter` | backend query layer | No |
| Kafka topic ACLs (target state) | broker | No — L7 path rules cannot express "may produce to `netops.flows` only" |
| Tenant scoping from the principal | `principalTenant(claims)` throughout the API | No |

**4. The real failure mode is not "traffic was sniffed".** It is *"the datastore
accepts anonymous connections."* OpenSearch runs with
`DISABLE_SECURITY_PLUGIN: "true"` (`docker-compose.yml:538`) holding every
tenant's logs; Kafka runs `PLAINTEXT` with no authentication
(`docker-compose.yml:207-210`); VictoriaMetrics and Valkey are unauthenticated;
Postgres is `sslmode=disable`. **A mesh in front of an unauthenticated
OpenSearch encrypts the anonymity — it does not remove it.** That single
sentence is the whole argument.

Meanwhile the native path is already built and tested: `tlsconfig` as the single
policy chokepoint, `backend_client.go` as one hardened mTLS transport wired into
14 internal-backend call sites (`tls-architecture.md` §6 phase 3), identity
allowlists, federation binding, expiry metrics, hot reload.

## Decision

**Use native TLS and native authorization per component, on a common
workload-identity fabric (ADR-SEC-003). Defer service-mesh adoption. Record an
explicit anti-goal against using a mesh as a substitute for component-level
authentication.**

1. **Every hop is secured by the component's own TLS and the component's own
   authorization model**: Kafka TLS + topic ACLs; OpenSearch HTTPS + security
   plugin roles; ClickHouse TLS + users + the existing row policies; Postgres
   `verify-full` + per-service roles + RLS; Valkey TLS + ACL users;
   VictoriaMetrics behind `vmauth`; nginx→api mTLS; api→correlation mTLS.
   (The full source→destination matrix is HLD §7 and is not duplicated here.)
2. **Identity is common across all of them** — the SPIFFE URI SAN from
   ADR-SEC-003 — so "who is calling" has one answer regardless of which
   component's authorization engine is asking.
3. **Anti-goal, stated normatively:** *a service mesh must never be used to make
   an insecure Kafka, datastore, or ingest configuration look secure.* Any future
   mesh adoption is **additive** to component-native authentication and
   authorization; it may never be presented as a replacement for it, and no
   compliance claim may rest on mesh encryption over an anonymous backend.
   (HLD §8, "Explicit anti-goal".)
4. **A mesh is re-evaluated only when all of these hold**: (a) a Kubernetes
   substrate exists and is the primary deployment target (#114); (b) generic
   HTTP/gRPC service-to-service traffic is a large enough share of connections to
   justify the sidecar/ztunnel cost; (c) component-native authn/authz is
   *already* in place, so the mesh adds defence in depth rather than a veneer.
   Ambient mode is the preferred form if that day comes (no per-pod sidecar,
   lower overhead), for the same L4 traffic only.
5. **cert-manager, if and when Kubernetes arrives, manages certificate
   *resources* only** — the identity model and the authorization model are
   unchanged by it (ADR-SEC-003 decision 6).
6. **Overhead is a first-class criterion (owner, 2026-08-04).** A mesh would add
   a control plane, a sidecar or ztunnel per node, an injection webhook, an
   upgrade choreography and a second policy language — for a stack of ~18
   Compose services whose *actual* exposure is anonymous datastores. Native TLS
   adds **configuration**, not **components**. When two options give a comparable
   security outcome, the one that ships no new daemon wins.

## Alternatives considered

| Alternative | Verdict | Why |
|---|---|---|
| **Sidecar mesh (Istio / Linkerd) now** | **Rejected** | No k8s substrate to run it on; cannot secure any device peer; would encrypt rather than fix anonymous datastores; large operational surface (control plane, sidecar injection, upgrade choreography) for a product that ships single-node appliance installs. |
| **Ambient mesh (Istio ambient) now** | **Rejected** | Same substrate and device objections. Lower overhead than sidecars, which makes it the preferred *future* form, not a present option. |
| **Mesh as the sole control, skipping component authz** | **Rejected, emphatically** | Cannot express Kafka ACLs, ClickHouse row policies, OpenSearch roles or tenant scoping. Would leave the CRITICAL findings (T13 plaintext credentials, T14 unauthorized DB access) untouched while creating the appearance of a fix. This is the anti-goal. |
| **Mesh for intra-stack + native for devices (hybrid)** | **Deferred** | Defensible in a k8s world. Today it means running a mesh control plane to secure ~10 Compose services while still building every native control anyway — all the cost, none of the simplification. |
| **"Put everything behind nginx"** | **Rejected** | nginx is an ingress terminator, not a service-to-service authenticator. It does not touch api→ClickHouse, vector→Kafka, or any device path. Explicitly rejected in HLD §10. |
| **Network-layer only (mgmt VRF, IPsec, ACLs, firewalling)** | **Rejected as sufficient; retained as necessary** | It is the *only* control available for NetFlow/sFlow/syslog-UDP/SNMPv2c (HLD §6.6) and belongs in deployment guidance. It authenticates a network location, not a workload, and cannot express tenant or topic scope. |
| **WireGuard/IPsec overlay between containers** | **Rejected** | Encrypts links, authenticates hosts, gives no workload identity and no component authorization; adds a second key lifecycle with none of the SPIFFE integration already built. |
| **SPIFFE/SPIRE without a mesh** | **Chosen in spirit** — see ADR-SEC-003 | This *is* the decision: SPIFFE identity semantics, own issuer, native TLS. The only deferral is SPIRE the runtime, not SPIFFE the model. |

## Consequences

**Positive**
- **The customer-facing claim is delivered end-to-end and is checkable.**
  "Every Correlix component talks to every other over TLS, authenticated by a
  per-service certificate" is provable hop by hop — by the transport-policy
  table (ADR-SEC-001), by the boot validator (ADR-SEC-008), and by pointing a
  packet capture at any inter-container link. With a mesh the same claim would
  be true of the sidecar hop while the datastore behind it still accepted
  anonymous connections.
- No new control plane, no sidecars, no orchestrator dependency; works on
  Compose today and in an air-gapped appliance. The runtime cost is a TLS
  handshake per connection, not a proxy process per service.
- The controls land where the risk actually is — at the datastore and broker
  authentication surfaces that are currently anonymous.
- Reuses machinery that is already implemented and tested rather than building
  a parallel one.
- Keeps `tlsconfig` as a single auditable chokepoint: there is exactly one place
  in the Go codebase where a `*tls.Config` can be constructed, and it structurally
  cannot skip verification.

**Negative**
- **Per-component work does not amortize.** Six datastores, one broker, four
  ingest lanes and several collectors each need their own TLS configuration,
  their own credential, their own authorization model and their own runbook.
  A mesh would have given one mechanism for the intra-stack subset.
- **Heterogeneous configuration surface.** Kafka's `ssl.*` properties, OpenSearch's
  security-plugin YAML, ClickHouse's XML, Postgres's `pg_hba.conf`, Valkey's
  ACL file, Vector's TOML/YAML `tls:` blocks, nginx's `proxy_ssl_*` — seven
  idioms, seven failure modes, seven ways to get it subtly wrong.
- **No automatic mTLS for new services.** A mesh gives encryption to a workload
  by deploying it; here, a new service is plaintext until someone wires it. The
  production validator (ADR-SEC-008) is the compensating control — it must fail
  a build that adds an unpoliced hop.
- **Non-Go clients carry the cost.** goflow2, Vector, syslog-ng, gnmic and the
  Python correlation service each need certificates on disk and a per-client TLS
  configuration (this is also the main cost argument in ADR-SEC-005).

## Security implications

- **Addresses the CRITICAL findings directly**: T13 (plaintext credentials —
  including per-tenant sealing keys fetched over `http://api:8080`,
  `deployment/docker/vector-router/cx-secret-backend.sh:24,55`) and T14
  (unauthenticated OpenSearch/VictoriaMetrics/Valkey). A mesh would have
  addressed neither.
- **Preserves the tenant boundary where it belongs.** Transport is never the
  tenant boundary (HLD §4); ClickHouse row policies and PG RLS stay
  database-enforced and stay guarded by the tests that already exist
  (`clickhouse_policies_test.go:65-69`).
- **Defence in depth is *not* weakened by deferring the mesh**, because the mesh
  layer being deferred is the one that duplicates transport encryption — the
  layers that are unique (component authn, ACLs, row policies) are exactly the
  ones this decision builds.
- **The anti-goal is a real risk, not a rhetorical one.** The most likely future
  failure is someone adopting a mesh on k8s, seeing "mTLS: STRICT" in a
  dashboard, and concluding the platform is secure while OpenSearch still runs
  with the security plugin disabled. Recording it as an anti-goal is what makes
  that reviewable.

## Operational implications

- **Certificate distribution is the operational spine.** Every component needs
  the right leaf, the right key permissions and the right bundle — on Compose
  that is shared volumes and mount discipline (the `TLS_NGINX_CERT_DIR` pattern,
  `src/backend/tls_ca.go:150-155`).
- **Rotation must be per-component and non-disruptive.** Go services hot-reload
  (`tlsconfig/reload.go`); nginx needs a reload; some datastores need a restart.
  That heterogeneity is the reason the rotation runbooks are per-component
  (`docs/runbooks/security/rotate-service-certificate.md` and the per-store
  migration runbooks).
- **Debuggability changes.** With a mesh, `istioctl` answers "why was this
  rejected". Here the answer lives in seven different logs, which is why the
  identity-rejection and handshake-error metrics already implemented
  (`src/backend/tls_server.go`, `netops_tls_identity_rejected_total`) must be
  extended per component rather than treated as an API-only feature.
- **Compose and k8s must not diverge in identity semantics.** The logical
  identity ↔ Compose cert file ↔ future k8s ServiceAccount mapping is an LLD
  deliverable (HLD §6.2) precisely so that a later mesh/cert-manager adoption is
  a substrate change, not a redesign.

## Migration implications

- **No migration is required to adopt this ADR** — it ratifies the existing
  direction. The work it authorizes is the per-component enablement in HLD §9
  phases 1–5.
- **Ordering matters and is fixed by risk**: nginx→api (edge, contained) →
  PKI foundation → Kafka (the spine; highest data-loss risk) → datastores →
  device lanes.
- **Every hop migrates via the accept-set** (ADR-SEC-001): dual listener or dual
  accept, verify traffic on the secure member, then narrow and remove the
  plaintext listener. Migration listeners must carry an expiry.
- **If Kubernetes lands later**, nothing in this ADR must be undone: the identity
  strings survive (ADR-SEC-003), the component authorization survives, and a
  mesh — if adopted — is layered on top as defence in depth.

## Unresolved questions

- **U1 — What exactly triggers mesh re-evaluation?** "Kubernetes exists" is
  necessary, not sufficient. Needs a stated threshold (service count? multi-
  cluster? a customer requirement?).
- **U2 — Do we ever want a mesh for the *device-facing* tier?** Almost certainly
  not, but a site-gateway/collector-at-customer-premises design (HLD §4 boundary
  ②) could change that calculus.
- **U3 — Who owns the per-component TLS configuration** in a Compose install —
  the installer (`scripts/install.py`), a generated override file, or the
  operator by hand? Unspecified, and it determines whether ADR-SEC-008's
  validator can even see the configuration it must judge.
- **U4 — Is `vmauth` an accepted new component?** HLD §7 assumes it in front of
  VictoriaMetrics; it is an additional service that does not exist in compose
  today.
- **U5 — Connection-reuse behaviour under native TLS on high-fan-out
  collection.** Zabbix documents ~1 s per encrypted check without session
  caching; ours is unmeasured (HLD §11, standing risks). A mesh would have
  amortized handshakes via long-lived pooled connections — native clients must
  be verified to do the same.
