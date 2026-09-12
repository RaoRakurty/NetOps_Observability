# ADR-SEC-002 — Five separate PKI trust domains, and an offline root

- **Status:** **Accepted (owner, 2026-08-04)** — **partially implemented,
  formalizing.**
  **v1 = TWO trust domains: public ingress (separate chain) + ONE workload
  domain.** The **device** and **operator** domains are designed here in full and
  **deferred with the device lanes to Phase 2** (ADR-SEC-006). The
  **secret-encryption root** is ratified as a separate custody authority that
  already exists in code (`src/backend/internal/vault`), and the **backup**
  authority is designed but not built. **No offline-root ceremony in v1** — the
  in-process root is retained; the offline root is documented below as a future
  option with its tradeoff stated.
  The public-edge ↔ internal-mesh split is *already an accepted and implemented
  decision* (`docs/design/tls-architecture.md` §1: "Two trust domains, never
  shared"; enforced in code by `tlsconfig`'s explicit-roots-only trust model,
  `src/backend/tlsconfig/trust.go`) — v1 therefore ratifies what exists rather
  than introducing a new PKI topology.
- **Implementation state:** both v1 domains exist in some form (public edge via
  nginx; a single internal CA via `src/backend/internalca` + `src/backend/tls_ca.go`,
  **dormant** — no `TLS_*` variable is set in the live `deployment/docker/.env`).
  The device domain does not exist. The secret-encryption root exists but is not
  documented as a trust *domain* (`src/backend/internal/vault`). The backup
  domain does not exist at all (HLD §5, T20).
- **Product outcome:** two domains are the minimum that lets Correlix say
  *"browser-facing certificates and internal service certificates are separate
  chains — a public-CA mis-issuance cannot forge an internal service"* while
  adding **zero new operational components**. That is the whole overhead budget
  for v1.
- **Relates to:** HLD §6.1, ADR-SEC-003 (workload identity), ADR-SEC-006 (device
  identity), ADR-SEC-007 (sealing provider), `docs/design/secret-custody.md`.

---

## Context

Correlix has **one** internal certificate authority today. `src/backend/tls_ca.go`
load-or-creates a single ECDSA P-256 root (`internalca.Generate`,
`internalca/ca.go:41`) with a 10-year validity (`tls_ca.go:33` — `caValidity`),
and mints every internal leaf from it: the API server SVID
(`tls_ca.go:145-149`) and the nginx client SVID (`tls_ca.go:150-155`). That
single root is also the only thing that would sign a *device* certificate if a
device lane were built tomorrow, because there is no other issuer in the repo.

The current design doc already names the first and most important separation and
gives the reason: a public-CA compromise must not be able to forge an internal
service identity, and internal mTLS therefore trusts **only** the private CA,
never the OS trust pool (`tls-architecture.md` §1 and §2, "Mis-issued public cert
used internally"). `tlsconfig.ClientConfig` makes this structural rather than
advisory — it *requires* an explicit `RootCAs` and a non-empty `ServerName`, and
exposes no `InsecureSkipVerify` knob at all (`tls-architecture.md` §0 rows 5–6).

What the existing design does **not** separate:

- **Devices from workloads.** The target architecture binds a syslog sender's
  tenancy to its certificate (HLD §6.2, §7 device→syslog-ng row). If the same CA
  signs both, then a stolen or mis-issued device certificate — held by a customer
  router in an untrusted estate (HLD §4 boundary ①) — chains to the same root
  that authenticates `api`, `correlation` and Kafka. That is a full-stack
  impersonation path originating in the least-trusted zone.
- **Key-encryption custody from transport PKI.** The Vault's root KEK
  (`docs/design/secret-custody.md` §3) is not a CA and must not be modelled as
  one, but it *is* a separate root of trust with its own compromise story. Today
  the CA private key is itself a Vault-sealed secret (`tls_ca.go:31` —
  `caKeyField = "tls.ca.key"`, platform DEK), so the dependency runs
  transport-PKI → sealing-root, and it must not be allowed to run the other way.
- **Backups.** There is no backup encryption authority. `scripts/backup.sh`
  produces a tarball; HLD threat T20 ("backup theft") is scored **HIGH** with no
  target control in place.

And a structural defect compounds all of it: enabling `TLS_INTERNAL_CA=true`
without a seal provider stores the CA private key **in plaintext**. The code says
so in its own header comment (`src/backend/tls_ca.go:22-24`). A single root
holding every identity in the product, on disk, unsealed, is the worst possible
combination of "one domain" and "no custody" — see ADR-SEC-007.

## Decision

**Target architecture: five deliberately separate trust domains. No key in any
domain may sign, unwrap, or authenticate for another. v1 builds domains 1, 2 and
4; domains 3 and 5 are designed here and deferred.**

| # | Domain | Authority | What it signs / protects | Anchors | **v1?** |
|---|---|---|---|---|---|
| 1 | **Public ingress** | Public or enterprise CA (ACME / internal enterprise PKI) | The nginx server certificate presented to browsers and API clients | Browser/OS trust stores | **✅ v1** (exists) |
| 2 | **Workload** (`correlix.workload`) | Correlix internal CA (in-process in v1 — ADR-SEC-003) | Every intra-stack service SVID: api, nginx, correlation, vector, collectors, broker, datastores | Internal bundle only, never the OS pool | **✅ v1** (exists, dormant) |
| 3 | **Device** (`correlix.device`) | Correlix device intermediate | Device / remote-vantage / site-gateway certificates for secure syslog (RFC 5425), gNMI, vantage ingest | Its own bundle, loaded only by the collection tier | **Phase 2** — designed, not built (ADR-SEC-006) |
| 4 | **Secret-encryption root** | TPM/swtpm-sealed KEK → per-tenant DEKs (`internal/vault`) | Reversible secrets at rest, incl. the workload CA's own private key | Not a transport CA; never presented on the wire | **✅ v1** (exists — ADR-SEC-007) |
| 5 | **Backup** | Separate backup-encryption authority | Snapshots, exports, off-host copies | Keys distinct from every live service credential | **Deferred** — designed, not built (HLD §11.6) |

**Why v1 stops at two transport domains.** A device domain only earns its keep
when device certificates are actually issued, and v1 issues none: the v1 answer
for devices is protocol-native security where it exists (SNMPv3 `authPriv`),
honest labeling (`transport_authenticated=false`) and network segmentation
(ADR-SEC-006). Creating a second transport CA that signs nothing would add a
rotation, expiry-monitoring and custody burden for zero delivered control. The
domain separation is written down now precisely so that Phase 2 creates it at
its target values with **no migration** — greenfield, exactly as
"Migration implications" §3 describes.

**Supporting decisions:**

1. **Domain 2 and domain 3 are rooted separately, and both are *intermediates*
   under an offline root** (recommendation — see §"Offline root" below). A
   compromise of the online device intermediate must not be able to mint a
   workload identity, and vice versa.
2. **Domain 1 never touches domains 2/3.** Internal verification uses an explicit
   root bundle; the OS pool is never consulted for internal peers. This is
   already true in code and this ADR ratifies it, not introduces it.
3. **Domain 4 must survive a total transport-PKI compromise.** Concretely: an
   attacker who steals the workload CA key gains service impersonation but
   **not** the ability to decrypt any tenant secret, because the KEK is sealed
   under a different custodian (`secret-custody.md` §2, §3).
4. **Domain 5 must survive a total live-stack compromise.** Backup keys are not
   derived from, wrapped by, or recoverable from the running platform's
   credentials. (Corollary: the disaster-recovery runbook must not depend on the
   platform being alive — see `docs/runbooks/security/restore-encrypted-backup.md`.)
5. **Federation stays domain-aware.** `tlsconfig.FederationTrust`
   (`src/backend/tlsconfig/federation.go`) already binds a peer's SPIFFE trust
   domain to the CA root that anchored its verified chain — a peer chaining to
   domain B's root cannot present a domain-A SVID (`tls-architecture.md` §7,
   phase 5). Multi-domain separation therefore has a *working enforcement
   mechanism* already; this ADR extends who is enrolled in it, not how it works.
   **Blocking defect:** `TLS_FEDERATED_BUNDLES` is implemented in Go but is
   **absent from `deployment/docker/docker-compose.yml`** (verified: the `TLS_*`
   block at `docker-compose.yml:1455-1472` does not declare it), so the
   mechanism is unreachable through the supported configuration surface.

### Offline root — DEFERRED in v1 (owner decision, 2026-08-04)

**Decision: v1 keeps the in-process root** that `src/backend/tls_ca.go` already
load-or-creates, sealed under the platform DEK (ADR-SEC-007 makes that sealing
mandatory, which is the control that makes an in-process root tolerable).
**No air-gapped ceremony ships in v1.**

**The future option, retained in full so a later revisit does not re-derive it:**
an air-gapped root (10-year, manual ceremony) signing only the workload and
device intermediates; intermediates online, short-lived, rotatable without a
customer-visible event. **Its argument:** the in-process root means the
highest-value key in the transport PKI lives in the memory and on the disk of
the most internet-adjacent service, and a compromise of that service is a
compromise of every internal identity. HLD §11.2 and the brief's constraint 4
both flag this. **Its cost, stated honestly:** a documented manual ceremony, an
offline storage procedure, two-person control, and an appliance/air-gapped
deployment story for customers who have neither an HSM nor a safe — plus a
re-issuance event for every workload leaf when it is introduced.

**Why deferring is defensible rather than merely cheap:** v1's blast radius for
a stolen workload CA key is bounded by (a) mandatory sealing — the key is not
readable from a disk image or a backup without this host's TPM
(`docs/design/secret-custody.md` §2), (b) 24 h leaf TTLs, and (c) an internal-only
trust domain that no browser and no public client ever anchors to. The
in-process root is not *good*; it is *contained*, and containment is
proportionate for v1's threat model. Revisit when Correlix runs multi-node, when
a customer's security review demands it, or at the first k8s deployment —
whichever comes first.

**Compensating control required in v1:** the CA key must never exist unsealed.
That is not advisory — it is ADR-SEC-007's boot refusal, and it is the hard
prerequisite for this deferral being acceptable at all.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| **One CA for everything** (public + workload + device) | Cross-domain minting. A compromise of any issuing surface forges every identity in the product; a device certificate in a customer's rack becomes a service credential. HLD §10 lists this explicitly as rejected. |
| **Two domains only** (public + internal), i.e. today's design | **CHOSEN FOR v1.** Correct exactly as long as no device holds a Correlix-issued certificate — which is v1's device answer (ADR-SEC-006). The moment a customer router holds one, the untrusted zone (HLD §4 boundary ①) would share a root with the application zone, and that is the trigger for creating domain 3 in Phase 2. |
| **Three domains, folding backup keys into the secret-encryption root** | Tempting — one custodian, one ceremony. Rejected because the failure modes are opposite: the sealing root is deliberately bound to *this host's* TPM (`secret-custody.md` §2 — "unrecoverable without the TPM"), while a backup must be restorable *precisely when this host is gone*. Sharing them makes the backup either unrestorable or the TPM binding meaningless. |
| **A separate operator/break-glass intermediate as a sixth domain** | The HLD §6.1 diagram does show an `Operator Intermediate` for break-glass and admin automation. It is **not adopted as a distinct domain here** because operator access today is human OIDC/JWT plus the nginx `auth_request` gate, not client certificates — there is no operator certificate to issue. Recorded as unresolved question U2 rather than silently dropped; see the "Conflict noted" box below. |
| **Public CA for internal services too** (one enterprise PKI) | Any mis-issuance anywhere in the enterprise or WebPKI becomes an internal service identity. Also forces long-lived certificates and CRL/OCSP, contradicting the short-TTL revocation model already chosen (`tls-architecture.md` §0 row 4). |
| **Per-tenant CAs** | Sounds like stronger isolation; is not. Transport identity is never the tenant boundary (HLD §4) — tenancy is enforced at the data layer. Per-tenant CAs would multiply ceremonies and rotation surface for zero isolation gain, and would tempt exactly the mistake this design forbids. |
| **Keep the in-process root; skip the offline ceremony** | **CHOSEN FOR v1** (owner, 2026-08-04), *conditional on mandatory sealing*. The root lives on the API host with a 10-year validity and no recovery story short of re-issuing every identity in the deployment — that cost is accepted for v1 because the identities are internal-only, short-lived, and the key is unreadable without the host's sealing custodian. It remains the weakest point in the v1 PKI and is the first thing to revisit (see "Offline root" above). |

> **Conflict noted (HLD §6.1).** The section is titled "Trust domains (five,
> deliberately separate)" but its diagram contains **six** authorities: offline
> root → workload intermediate, device intermediate, **operator intermediate**,
> plus the public chain, the secret-encryption root and the backup authority.
> This ADR adopts the **five** named in the brief and in the HLD prose
> (public / workload / device / secret-encryption / backup) and treats the
> operator intermediate as an open question (U2). The HLD should be reconciled.

## Consequences

**Positive (v1)**
- **Supports the customer-facing claim directly.** "Correlix uses a separate
  private CA for internal service-to-service TLS; your browser-facing
  certificate chain is independent of it, and a mis-issuance in either cannot
  affect the other" is a true, demonstrable statement on day one of v1 — with no
  new component to operate.
- **Zero added operational surface in v1.** Two domains means one internal CA
  (already built, already self-bootstrapping, already auto-rotating at TTL/2)
  plus whatever public certificate the customer already has for nginx.
- The federation binding already implemented (`tlsconfig/federation.go`) gives
  the separation teeth rather than leaving it as a naming convention, and it
  scales to the deferred domains without redesign.

**Positive (target, once domains 3 and 5 land)**
- Blast radius is bounded by design: device-domain compromise ⇒ device
  impersonation only; workload-domain compromise ⇒ no secret decryption; live-
  stack compromise ⇒ backups still confidential.
- Rotation becomes per-domain and therefore survivable: rotating the device
  intermediate does not touch a single intra-stack connection.

**Negative**
- **v1's in-process root is the accepted weak point.** A root compromise means
  re-issuing every internal identity, and there is no offline recovery anchor.
  Contained by mandatory sealing + short leaf TTLs + internal-only trust, not
  eliminated.
- **Deferring domain 3 means the device story stays honest-but-unauthenticated
  in v1.** The exception rows in the transport-policy table (ADR-SEC-001) will
  visibly show that, which is the intent — but it does mean the "everything is
  TLS" claim must be stated precisely: *every Correlix component*, not *every
  packet from every router*.
- **Up to five lifecycles at target**: five sets of keys, rotations, expiries,
  runbooks and alerting thresholds where there is one today (and that one is
  off). v1 pays one of the five.
- **A manual ceremony enters the product if the offline root is ever adopted.**
  Offline roots cannot be automated by definition; the ceremony must be
  documented, rehearsed and auditable
  (`docs/runbooks/security/bootstrap-pki.md` carries the outline already).
- **More trust-store distribution** as domains are added. Every consumer must
  receive the right bundle and only that bundle. Trust-store drift becomes a
  monitored condition (HLD T19) — bundle version + age metric + drift alert.
- Lab and production diverge more than they do today, which is a testing
  liability the deployment profile must manage rather than hide.

## Security implications

- **Directly mitigates HLD T2** (device impersonation), **T11** (CA compromise),
  **T12** (service impersonation) and **T20** (backup theft) — the four threats
  whose exposure is driven by having one authority or none.
- **Removes the cross-domain minting path** that would otherwise be created the
  day device certificates ship.
- **Does not, by itself, fix custody.** A five-domain PKI whose workload CA key
  sits in plaintext on disk (`tls_ca.go:22-24`) is not safer than a one-domain
  PKI that is sealed. ADR-SEC-007's boot refusal is a **hard prerequisite** for
  this ADR to deliver anything.
- **Domain confusion is the new bug class.** A leaf verified against the wrong
  bundle, or a bundle file that accidentally concatenates two domains' roots, is
  a silent collapse of the separation. The mitigation is the existing
  `FederationTrust` invariant (trust-domain of the SPIFFE ID must equal the
  trust-domain whose root anchored the chain) applied to *every* internal
  verifier, plus a test that fails if a device root ever appears in the workload
  bundle.

## Operational implications

- **New runbooks required** (outlines shipped alongside this ADR):
  `bootstrap-pki.md`, `rotate-workload-ca.md`, `rotate-device-ca.md`,
  `ca-compromise-response.md`, `restore-encrypted-backup.md`.
- **Expiry monitoring must be per-domain.** The existing
  `netops_tls_cert_expiry_seconds` gauge (`src/backend/tls_server.go`) covers the
  serving leaf; intermediates and roots need their own gauges or an expired
  intermediate becomes a total outage with no warning (HLD T18).
- **`TLS_FEDERATED_BUNDLES` must be added to compose** before any multi-domain
  claim is operable. Until then the separation is design-only.
- **The offline root implies a custody procedure the customer owns**: where the
  root lives, who can access it, two-person control, and how a ceremony is
  witnessed and logged. That is a documentation and possibly a contractual
  deliverable, not just an engineering one.

## Migration implications

1. **Nothing breaks on adoption day** — today's single dormant CA becomes the
   *workload* domain by renaming intent, not by re-issuing anything.
2. **The trust-domain string changes.** Code today emits
   `spiffe://<TLS_TRUST_DOMAIN>/ns/default/sa/<svc>` with the compose default
   `netops` (`tls_ca.go:91-93`; `docker-compose.yml:1463`), and the existing
   runbook allowlists `spiffe://netops/ns/default/sa/nginx`
   (`docs/runbooks/tls-mtls.md` step 2). The HLD targets
   `correlix.workload`. **Changing the trust domain invalidates every configured
   allowlist simultaneously** — it must be a dual-bundle, dual-allowlist window,
   not a rename. See ADR-SEC-003 for the identity-string migration in full.
3. **Device domain is greenfield** — it can be created at its target values with
   no migration at all, which is an argument for creating it *before* any device
   certificate ships.
4. **Backup domain is greenfield and currently absent.** HLD §11.6 asks build-now
   vs defer; unanswered.
5. **Introducing the offline root is a re-issuance event** for every workload
   leaf (they must chain to the new intermediate). The dual-root window
   (`TrustBundle` carries multiple roots — `tls-architecture.md` §4) is the
   mechanism; the overlap must exceed the longest leaf TTL.

## Unresolved questions

- **RESOLVED (owner, 2026-08-04):** v1 = two transport domains (public ingress +
  one workload); device and operator domains deferred to Phase 2; no offline-root
  ceremony in v1.
- **U1 — Where would the offline root physically live** *if* adopted later? HSM,
  air-gapped laptop, or customer-supplied enterprise PKI? Different answers for
  SaaS vs appliance vs air-gapped deployments. HLD §11.2 remains open; the
  question is now Phase-2+, not v1-blocking.
- **U2 — Is there an operator/break-glass trust domain?** The HLD diagram says
  yes; the prose says five. **Deferred with the device domain.** Resolve before
  any operator client certificate is contemplated — today operator access is
  human OIDC/JWT plus the nginx `auth_request` gate, so nothing is blocked.
- **U3 — Build the backup domain now or defer?** HLD §11.6, still open. T20 is
  scored HIGH, which argues for "soon"; it is orthogonal to the transport work
  and can proceed on its own track
  (`docs/runbooks/security/restore-encrypted-backup.md`).
- **U4 — Do customers get to bring their own CA** for the workload domain (some
  enterprises will insist)? If yes, the identity format and the federation
  binding both have to tolerate an externally-controlled issuer.
- **U5 — Intermediate lifetimes and root lifetime.** `caValidity` is 10y today
  (`tls_ca.go:33`) for a root that is also the issuer. Split values (root 10y,
  intermediate 1y) are implied but not specified anywhere.
- **U6 — Cross-signing during root rotation** — accept dual roots only (current
  `TrustBundle` model) or also cross-sign? Cross-signing shortens the overlap
  window but adds ceremony complexity.
