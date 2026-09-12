# ADR-SEC-003 — Workload identity: keep `internalca`, stay SPIRE-compatible, adopt cert-manager only under Kubernetes

- **Status:** **Accepted (owner, 2026-08-04)** — **partially implemented,
  formalizing.** Decision: **keep the existing in-process internal CA.**
  **No SPIRE, no Vault PKI, no cert-manager in v1.** The decision to mint
  SPIFFE-format workload identities from an own, stdlib internal CA is *already
  made and already in the code* (`src/backend/internalca/ca.go`,
  `src/backend/tls_ca.go`, `docs/design/tls-architecture.md` phases 2–5 marked
  ✅); this ADR ratifies it and states the SPIRE-compatibility constraint that
  keeps a later swap cheap. Still open within the accepted direction: the
  namespace/trust-domain migration and the per-service identity inventory beyond
  api+nginx (see "Migration implications" and U1/U2).
- **Owner rationale:** **zero new operational components.** The CA already
  self-bootstraps on boot, already emits SPIFFE URI SANs, and already re-issues
  at TTL/2 with hot reload and no restart. SPIRE remains a later drop-in
  precisely because the identity *strings* — not the issuer — are the contract.
- **Implementation state:** **built, wired into `main.go`, and switched off.**
  No `TLS_*` variable is set in the live `deployment/docker/.env` (HLD §1.1).
  Two identities are minted today — `api` and `nginx` — and no others.
- **Relates to:** HLD §6.2, §8; ADR-SEC-002 (trust domains); ADR-SEC-005 (Kafka
  clients need identities); ADR-SEC-006 (device identities are a *separate*
  domain); `docs/design/tls-architecture.md`; `docs/runbooks/tls-mtls.md`.

---

## Context

**The workload-identity platform is not a green field — it exists and it works.**
Verified in code:

| Capability | Evidence |
|---|---|
| Stdlib ECDSA P-256 internal CA, load-or-create, 10-year root | `src/backend/internalca/ca.go:41` (`Generate`), `:78` (`FromPEM`); `src/backend/tls_ca.go:33` (`caValidity`) |
| Leaf issuance with a **SPIFFE URI SAN** | `internalca/ca.go:141` (`Issue`), `:152` (rejects a SPIFFE ID with no scheme), `:181` (`URIs: []*url.URL{uri}`) |
| SPIFFE ID construction | `tls_ca.go:91-93` — `"spiffe://" + m.trustDomain + "/ns/default/sa/" + svc` |
| Boot self-bootstrap of the mesh | `tls_ca.go:140-156` — writes the CA bundle (`TLS_CLIENT_CA_FILE`), the API server SVID (`TLS_CERT_FILE`/`TLS_KEY_FILE`, `:145-149`), and the nginx client SVID (`TLS_NGINX_CERT_DIR`, `:150-155`) |
| Automatic re-issue at ~TTL/2, hot-reloaded without restart | `tls_ca.go:159-165` (`startReissueLoop`) + `tlsconfig/reload.go` (`CertReloader`) |
| CA private key sealed at rest under the platform DEK | `tls_ca.go:31` — `caKeyField = "tls.ca.key"`; `src/backend/internal/vault` |
| Identity-based authorization, not just chain validity | `tlsconfig/verify.go` (`PeerPolicy`, DNS + URI/SPIFFE SAN allowlist) |
| Trust-domain ↔ anchoring-root binding (anti-impersonation across federated domains) | `tlsconfig/federation.go` (`FederationTrust`); `tls-architecture.md` §7 phase 5 |
| Structural refusal to skip verification | `tlsconfig/config.go` — `ClientConfig` requires explicit `RootCAs` + non-empty `ServerName`; no `InsecureSkipVerify` knob exists (`tls-architecture.md` §0 rows 5–6) |

So the question is *not* "what should we build". It is **"do we keep this, or
replace it with SPIRE / Vault PKI / cert-manager, and what must stay true so
that replacing it later is cheap?"**

Three constraints shape the answer:

1. **The deployment substrate is Docker Compose.** No Kubernetes manifests,
   Helm charts or kustomize overlays exist anywhere in the repository (verified
   by search: no `Chart.yaml`, no `kustomization.yaml`, no `kind: Deployment`).
   HLD §1.3 states the same and notes #114 (k8s packaging) is unstarted. SPIRE's
   and cert-manager's operational models both assume an orchestrator.
2. **The dependency rule is strict.** Root `CLAUDE.md` §6 permits only an
   explicit allowlist of third-party Go modules; SPIRE's workload API client and
   cert-manager's client libraries are neither on it nor trivially justifiable
   under the "stdlib genuinely cannot" gate — the stdlib demonstrably *can*, and
   already does.
3. **The product ships as an appliance in some deployments.** An offline,
   air-gapped install cannot depend on a control plane it does not have.

Against that, the honest weakness of the status quo: **the CA root is in-process
on the most internet-adjacent service**, only two identities are actually minted,
and the whole thing is dormant.

## Decision

**Keep the own `internalca`/`tls_ca.go` issuer as the workload-identity platform
for the Compose substrate. Constrain it to remain SPIRE-compatible so that SPIRE
becomes a drop-in later without changing a single identity string. Adopt
cert-manager only when a Kubernetes substrate exists, and only for certificate
*resources* — never for the identity model.**

Concretely:

1. **Identity format is fixed and SPIRE-shaped** (HLD §6.2):
   ```
   spiffe://correlix.workload/ns/<namespace>/sa/<service>
   ```
   with namespaces `ingress`, `app`, `ingestion`, `streaming`, `storage`,
   `identity`, `ops`. The `/ns/<ns>/sa/<svc>` path is exactly SPIRE's Kubernetes
   workload-registration shape, which is what makes the swap cheap.
2. **The identity string is the stable contract; the issuer is an
   implementation detail.** Anything that consumes identity — `PeerPolicy`
   allowlists, Kafka ACL principals (ADR-SEC-005), OpenSearch role mappings,
   ClickHouse users — binds to the SPIFFE URI, never to a certificate serial,
   fingerprint, DN, or file path.
3. **Every workload gets its own identity. No wildcards, no shared identities.**
   One identity per service *role*, SANs carrying both the URI SAN (identity)
   and the DNS names actually dialled, hostname verification mandatory. This is
   a restatement of HLD §6.2's rules and of root `CLAUDE.md` §3's zero-trust law,
   and it is what makes the current single `INGEST_TOKEN` (six clients, one
   secret) unacceptable as an identity mechanism.
4. **Short TTL is the revocation strategy.** 24 h leaves, renewal at TTL/2, no
   CRL and no OCSP (`tls-architecture.md` §0 row 4). Revocation = refuse to
   re-issue (ADR-SEC-006 and
   `docs/runbooks/security/revoke-compromised-identity.md` carry the honest
   limits of this).
5. **The issuer must be swappable behind the same seam it already has.**
   `tls_ca.go` is the only minting site and `tlsconfig` is the only place a
   `*tls.Config` can be constructed. A future `SPIREWorkloadSource` supplies
   certs to the same `CertReloader` seam that files supply today.
6. **cert-manager: adopt later, k8s only, for certificate resources.** It
   manages `Certificate`/`Issuer` objects and writes Secrets; the SPIFFE identity
   strings and the `PeerPolicy` authorization model are unchanged by it. It is
   not an identity platform and must not be treated as one.
7. **SPIRE: explicitly not in v1, kept as a first-class future option.** Adopt
   when (a) a Kubernetes substrate exists, (b) node attestation is worth the
   operational surface, and (c) the identity strings need no change — which
   (1)–(2) guarantee.
8. **Overhead ceiling (owner constraint, 2026-08-04):** the workload-identity
   platform must add **no new service, no new control plane and no new
   third-party dependency** in v1. Every option that fails that test (SPIRE
   server+agents, Vault, cert-manager+k8s, step-ca) is deferred regardless of its
   technical merit — those merits are recorded in "Alternatives considered" so a
   future revisit starts from the analysis rather than repeating it.

## Alternatives considered

| Alternative | Why rejected (now) |
|---|---|
| **SPIRE today** | Requires an orchestrator for node/workload attestation; adds a control plane (server + agent per node + a datastore) to a product that ships single-node appliance installs; brings Go dependencies outside the `CLAUDE.md` §6 allowlist. Its real advantage — *attested* identity rather than file-based identity — is genuinely superior and is why the identity format is constrained to stay compatible. Deferred, not dismissed. |
| **HashiCorp Vault PKI** | A real option **for customers who already run Vault**, and the HLD lists it as such (§8). Rejected as the default: it adds a hard runtime dependency an air-gapped appliance may not have, and it moves the CA out of the fail-closed boot path into a network call. |
| **cert-manager now** | There is no Kubernetes to run it on. Adopting it would mean building the k8s substrate first (#114, unstarted) purely to obtain certificate issuance we already have. |
| **step-ca / smallstep** | Closest external equivalent to what `internalca` already does, with ACME and provisioner support we would not use on Compose. Adds a service and an operational dependency for parity, not capability. |
| **Public/enterprise CA for workloads** | Rejected in ADR-SEC-002: cross-domain minting, long-lived certificates, and CRL/OCSP semantics that contradict the short-TTL model. |
| **Static long-lived per-service certificates, hand-generated** | Makes revocation the hard problem and rotation an outage. Directly contradicts `tls-architecture.md` §0 row 4. |
| **Shared credentials / one wildcard certificate** | Today's `INGEST_TOKEN` failure mode, generalized: no attribution, no rotation, one theft = full impersonation. Explicitly forbidden (HLD §10, `CLAUDE.md` §3a). |
| **JWT/SVID over plain TLS instead of mTLS** (bearer workload identity) | Bearer tokens are replayable and require an issuer online on every hop; mTLS binds identity to the connection. Also would not satisfy Kafka/ClickHouse/OpenSearch native authn, which want a certificate or a user, not a token. |

## Consequences

**Positive**
- **Delivers the customer-facing claim with the least possible machinery.**
  "Every Correlix component authenticates to every other with a short-lived,
  per-service certificate issued by a private CA that rotates itself" is true
  once the existing code is switched on — no new service to install, monitor,
  upgrade or explain in a security review.
- Zero new dependencies, zero new services, works offline, already tested
  end-to-end (`internalca/ca_test.go`, `tlsconfig/*_test.go`).
- The *hard* parts of a workload-identity platform — issuance, SPIFFE SANs,
  hot rotation, identity-based authorization, federation binding — are done.
  Phase 0 of the roadmap is genuinely "turn it on", not "build it".
- SPIRE remains a drop-in because the identity strings, not the issuer, are the
  contract.

**Negative**
- **We own a CA.** Ceremony, custody, rotation, compromise response and expiry
  monitoring are ours, permanently.
- **The root is in-process today.** Mitigated by ADR-SEC-002's offline-root
  recommendation; until that lands, the highest-value transport key lives with
  the API process.
- **Only two identities exist.** Every additional workload (vector-aggregator,
  vector-router, goflow2, correlation, syslog-ng, each collector, each datastore
  client) needs a minting path, a distribution path into its container, and an
  allowlist entry. That is the bulk of the remaining work and it is not small.
- **Non-Go workloads need certificates on disk.** goflow2, Vector, syslog-ng,
  gnmic and the Python correlation service cannot call a Go issuer; they consume
  files. That constrains distribution to the shared-volume pattern already used
  for `TLS_NGINX_CERT_DIR` (`tls_ca.go:150-155`), with its file-permission
  implications.

## Security implications

- **Mitigates HLD T12** (service impersonation — nothing authenticates services
  today), **T3** (collector compromise ⇒ full bus access, because one
  `INGEST_TOKEN` serves six clients), and **T9** (stale/leaked credentials, via
  24 h TTLs).
- **`PeerPolicy` is the part that matters most and is easiest to under-use.** A
  valid certificate proves "issued by our CA"; only the allowlist proves "*this*
  peer may call *this* endpoint". Every mTLS listener must set an allowlist —
  chain validity alone would let any workload impersonate any other's *access*,
  even with distinct identities.
- **Certificate files are secrets.** `tls_ca.go` writes keys `0600` and certs
  `0644` (`tls_ca.go:95-96`); any shared-volume distribution to other containers
  must preserve that and must not widen the mount to services that do not need
  the key.
- **Federation binding must be reachable.** `TLS_FEDERATED_BUNDLES` is absent
  from `deployment/docker/docker-compose.yml` (verified — the `TLS_*` block at
  `:1455-1472` does not declare it), so the anti-impersonation binding cannot be
  turned on through the supported surface. This is a security defect, not a
  packaging nit.
- **Identity ≠ tenant.** A workload SVID authenticates a *service*; it grants no
  tenant scope whatsoever. Tenant authorization stays at the data layer
  (HLD §4, root `CLAUDE.md` §3a).

## Operational implications

- **Boot fails closed** on a broken or missing certificate when TLS is
  configured (`tls-architecture.md` §5, `buildTLSServer`/`bootstrapInternalCA`).
  That is correct and it means a bad certificate rollout is an outage —
  see ADR-SEC-008 for the availability tradeoff stated in full.
- **Rotation is already non-disruptive for Go services** (modtime-poll
  `CertReloader`), but **nginx needs a reload** to pick up its re-issued client
  SVID (`tls_ca.go:159-161` says so explicitly). Any rotation runbook must
  include the nginx reload or the mesh breaks at TTL/2, not at expiry.
- **Expiry is observable** via `netops_tls_cert_expiry_seconds`
  (`src/backend/tls_server.go`) and `/admin/readyz` asserts cert validity with a
  5-minute margin (`tls-architecture.md` §6 phase 4). Alerting on it is not
  optional once TLS is enforced.
- **Per-service certificate distribution is an ops design problem**, not a Go
  problem: which container mounts which path, read-only, with what ownership.

## Migration implications

**The identity strings in code today do not match the HLD's target, and this is
the single riskiest detail in this ADR.**

| | Emitted today | HLD target |
|---|---|---|
| Trust domain | `netops` (`docker-compose.yml:1463` default; `tls_ca.go:91-93`) | `correlix.workload` |
| Namespace | `default`, hardcoded (`tls_ca.go:92`) | `ingress`/`app`/`ingestion`/`streaming`/`storage`/`identity`/`ops` |
| Example | `spiffe://netops/ns/default/sa/nginx` (this exact string is in `docs/runbooks/tls-mtls.md` step 2) | `spiffe://correlix.workload/ns/ingress/sa/nginx` |

Consequences of that gap:

1. **The HLD's claim that this is "already the format `tls_ca.go:91-93` emits"
   is true of the *shape* but not of the *values*.** Namespaces are not derivable
   from anything in `tls_ca.go` today — the namespace is a literal.
2. **Changing the trust domain or namespace invalidates every allowlist at
   once**, because `TLS_CLIENT_ALLOWED_URIS` matches exact URIs. The migration
   must be: allowlist *both* strings → issue under the new string → verify →
   drop the old string. Never a rename in place.
3. **Any deployment that already enabled the mesh** (following
   `docs/runbooks/tls-mtls.md`) has `spiffe://netops/...` baked into its nginx
   allowlist and its issued files. The dual-allowlist window is what protects
   them.
4. **Recommendation:** make the namespace a per-service parameter of
   `issueService` before minting identities for anything beyond api and nginx —
   changing it later multiplies the migration by the number of services.

Otherwise the migration is additive: existing services keep working while new
identities are minted, because the accept-set model (ADR-SEC-001) permits both
plaintext and mTLS during the window.

## Unresolved questions

- **U1 — When does the namespace/trust-domain migration happen?** Before any new
  identity is minted (cheap, recommended) or after (expensive)? Not decided.
- **U2 — Who mints identities for non-Go workloads, and how are they
  distributed?** The `TLS_NGINX_CERT_DIR` pattern generalizes, but the mount
  matrix (which container sees which key) is unspecified.
- **U3 — Does the API remain the issuer?** It is today. An issuer inside the
  most exposed service is uncomfortable; a separate minting sidecar would follow
  the `secrets-seal` precedent (`docker-compose.yml:1683-1693`, profile `seal`).
- **RESOLVED (owner, 2026-08-04):** issuer = the existing in-process
  `internalca`; SPIRE / Vault PKI / cert-manager are all out of v1.
- **U4 — What is the SPIRE adoption trigger?** "When k8s exists" is not a
  criterion. Node count? Multi-cluster? Customer requirement? Unchanged by the
  v1 decision — it defines when the deferral ends.
- **U5 — Are datastores workloads or peers?** ClickHouse/OpenSearch/Kafka each
  need a *server* identity as well as accepting client identities; who mints a
  server SVID for a container the API does not control the lifecycle of?
- **U6 — Leaf TTL for non-reloading consumers.** 24 h is fine for Go services
  with `CertReloader`; syslog-ng, goflow2 and gnmic may need a reload or restart
  per rotation, which argues for a longer TTL for those specific peers — an
  explicit, declared exception rather than a silent one.
