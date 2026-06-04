# Transport Security (TLS / mTLS) Architecture — #18

> Status: **phases 1–4 done; phase 5 (1/3 — SPIFFE federation) done** (2026-06-04).
> Centralized `tlsconfig` package, opt-in API HTTPS/mTLS, internal CA + Vault-sealed
> custody, backend client TLS, metrics/audit/readiness/re-issue, and multi-region
> SPIFFE federation have landed. Remaining phase-5 (live SPIRE, HSM/TPM) is future.
> Pairs with: `secret-custody.md` (#17 — TLS keys become a Vault tenant in phase
> 2), `postgres-rls.md` (#15), SAML cert auto-rotation (#30).

This document is the design + threat model + phased plan for production-grade
transport security. It treats **TLS as an identity + trust system**, not merely
encryption: who a peer *is* (and whether it is *allowed*) matters as much as
confidentiality. Everything is stdlib (`crypto/tls`, `crypto/x509`) per the
zero-dependency rule.

---

## 0. Review of the requirements + gaps we hardened

The driving spec was strong. Gaps / enhancements we added:

| # | Gap in a naive reading | Hardening we adopted |
|---|---|---|
| 1 | "No TLS < 1.2" but cipher list unspecified | TLS 1.3-first; 1.2 restricted to **ECDHE + AEAD only** (PFS; no CBC, no static-RSA kx, no RC4/3DES). 1.3 suites are non-configurable/strong in Go. |
| 2 | Renegotiation unaddressed | `Renegotiation: RenegotiateNever` (kills the CVE-2009-3555 class). Go servers don't renegotiate anyway; we make it explicit on clients too. |
| 3 | "Certificate rotation" | Rotation **without restart or dropped connections** via `GetCertificate`/`GetClientCertificate` resolving a hot-swappable `CertReloader` (modtime poll — no fsnotify dep). |
| 4 | Revocation "considerations" | **Short-lived certs + fast rotation is the primary revocation strategy** (SPIFFE model), not CR/OCSP. CRL/OCSP are brittle at scale (soft-fail) — documented as a fallback, not the mechanism. |
| 5 | Trust roots | **Explicit roots only** for internal mTLS — never the OS pool, so a mis-issued public-CA cert is never accepted internally. `InsecureSkipVerify` is structurally impossible to set through the package. |
| 6 | Hostname validation "always" | `ClientConfig` **requires** a non-empty `ServerName` and an explicit `RootCAs` — a caller literally cannot build a client that skips hostname verification. |
| 7 | Identity model thin on authZ | `PeerPolicy` least-privilege allowlist (DNS + URI/SPIFFE SAN) layered on top of chain verification — authn (valid cert) ≠ authz (allowed counterparty). |
| 8 | 0-RTT / replay | TLS 1.3 early-data (0-RTT) is **not enabled** (Go stdlib server default) — it has replay semantics unsuitable for state-changing APIs. Documented; do not enable for the API. |
| 9 | Session resumption across instances | Default per-process ticket keys. For HA resumption either share rotating ticket keys via the #17 Vault or accept full handshakes. Documented (don't hand-roll static ticket keys). |
| 10 | Secure cookies | Tie `SECURE_COOKIES=true` to TLS being terminated end-to-end (already a flag; see `auth.go`/OSD gate). |
| 11 | Key protection | Private keys 0600 on disk today; **sealed via the #17 Vault in phase 2** (the SealingProvider seam already exists). HSM/TPM is the same seam later. |
| 12 | Fail modes | **Fail closed everywhere**: a configured-but-broken cert/CA aborts boot (matches `assertRLSCapable` + the Vault). Never silently downgrade. |

---

## 1. Trust model & boundaries

```
                       ┌────────────────────────── trust domain: prod ──────────────────────────┐
   Internet            │                                                                          │
   ───────▶  nginx (ingress TLS terminator, HSTS)  ──TLS/mTLS──▶  API  ──mTLS──▶  OpenSearch      │
            public CA cert (Let's Encrypt/ACM)      internal CA      │            ClickHouse       │
                                                                     │            VictoriaMetrics  │
   humans  → OIDC/JWT (not client certs)                            └──mTLS──▶  correlation svc    │
   services→ mTLS (internal CA SVIDs)                                                              │
   APIclients→ API tokens (#23), optionally pinned over mTLS         pgx → Postgres (TLS, verify-full)
                       └──────────────────────────────────────────────────────────────────────────┘
```

- **Two trust domains, never shared:** the **public** edge (browser ↔ nginx, a
  public/ACME CA) and the **internal** mesh (service ↔ service, a *private* CA).
  A public-CA compromise cannot forge an internal service identity, and vice
  versa. **Dev / stage / prod each get their own internal CA** — a stage cert is
  worthless in prod.
- **Identity matrix:** humans authenticate with OIDC/JWT (#22) — *not* client
  certs (poor UX, hard rotation); **services** authenticate with **mTLS** carrying
  a SPIFFE-style URI SAN (`spiffe://<trust-domain>/ns/<ns>/sa/<svc>`); **API
  clients** use bearer tokens (#23) and MAY additionally be pinned over mTLS.
- **Least privilege:** chain verification proves "from our CA"; `PeerPolicy`
  proves "*this* allowed peer" (e.g. only the `api` SVID may call the collector).

## 2. Threat model (abridged)

| Threat | Mitigation |
|---|---|
| Passive network sniffing | TLS 1.3/1.2 AEAD everywhere; PFS so a future key leak doesn't decrypt past traffic |
| Active MITM / downgrade | Explicit roots + hostname/SAN verify; 1.2 floor (no SSLv3/1.0/1.1); no renegotiation; HSTS at edge |
| Mis-issued public cert used internally | Internal mTLS trusts ONLY the private CA, never the system pool |
| Stolen service key | Short-lived certs + fast rotation; key sealed by #17 Vault (phase 2); per-service keys (no shared static creds) |
| Compromised service calling peers it shouldn't | `PeerPolicy` identity allowlist (least privilege) |
| Replay of early data | 0-RTT disabled |
| Cert expiry outage | `netops_tls_cert_expiry_seconds` gauge + alert; hot reload so rotation is non-disruptive |
| Operator disables verification "to debug" | Not possible through `tlsconfig` — no `InsecureSkipVerify` knob; client needs explicit roots + ServerName |
| Resource exhaustion (handshake flood) | `ReadHeaderTimeout`, connection/Body limits, fail-fast handshake deadlines; LB/ratelimit at edge |

## 3. Go package structure (landed)

`src/backend/tlsconfig/` — the single policy chokepoint:
- `policy.go` — version floor, cipher/curve policy, `baseConfig()`.
- `trust.go` — `TrustBundle` (explicit roots, hot-reload, fail-closed).
- `reload.go` — `CertReloader` (hot cert rotation, modtime poll, leaf parse).
- `verify.go` — `PeerPolicy` (DNS/URI SAN least-privilege allowlist).
- `config.go` — `ServerConfig` / `ClientConfig` builders (the only way to get a
  `*tls.Config`).

`src/backend/tls_server.go` — opt-in API HTTPS/mTLS wiring (`buildTLSServer`),
HSTS, cert-expiry `/metrics`, reloader watch. Dormant unless `TLS_CERT_FILE` set.

## 4. Certificate lifecycle

- **Issuance:** internal CA (phase 2 — `step-ca`/cert-manager/SPIRE, or a small
  stdlib issuer) mints short-lived (hours–days) SVIDs with a SPIFFE URI SAN.
- **Distribution:** cert+key written to a path each service watches; key sealed
  by the #17 Vault at rest.
- **Rotation:** issuer rewrites the files atomically; `CertReloader` picks them up
  on the next poll — **zero downtime, no restart**. CA rotation: publish the new
  root into the `TrustBundle` (carry both), reload, retire the old root.
- **Expiry handling:** `netops_tls_cert_expiry_seconds` gauge; alert well before
  zero; rotation is routine, not an incident.
- **Revocation:** short TTLs make CRL/OCSP largely unnecessary; revoke by refusing
  to re-issue. (CRL/OCSP-staple is a documented future option, soft-fail caveats.)

## 5. Failure handling

Fail **closed** and **loud**, never silent-downgrade: a configured-but-broken
cert/CA aborts boot (`log.Fatalf`); a runtime reload error keeps the last good
cert and logs (serving a still-valid cert beats dropping the listener); a trust
or identity violation rejects the connection and is audit-logged.

## 6. Implementation phases

| Phase | Scope | Status |
|---|---|---|
| **1** | Centralized `tlsconfig` package (secure server/client builders, trust, reload, mTLS identity) + opt-in API HTTPS/mTLS + HSTS + expiry metric + tests | ✅ **done** |
| **2** | Internal CA (`internalca`) issuing short-lived SPIFFE SVIDs; CA key **sealed via the #17 Vault**; boot self-bootstrap of API+nginx SVIDs + trust bundle (`tls_ca.go`); nginx↔API mTLS runbook | ✅ **done** (CA+seal+bootstrap unit-tested end to end; swtpm seal/unseal **live-validated**; nginx hop = runbook `docs/runbooks/tls-mtls.md`) |
| **3** | API→backends client TLS — `tlsconfig.HTTPTransport` + `backend_client.go` (one shared hardened transport, explicit mesh-CA roots, optional backend mTLS, fail-closed) wired into all 7 internal-backend call sites; external clients (copilot/jwks/netbox) stay public-CA; Postgres `sslmode=verify-full` guidance | ✅ **done** (round-trip + fail-closed tested) |
| **4** | Handshake-error + identity-reject metrics; `PeerPolicy.OnReject` trust-failure audit; `/admin/readyz` asserts cert validity (5m margin); periodic SVID re-issue loop (~TTL/2, hot-reloaded) | ✅ **done** (OnReject + margin + re-issue tested) |
| **5** | **Multi-region SPIFFE federation** — `tlsconfig.FederationTrust` binds a peer's SPIFFE **trust domain** to the CA root that anchored its verified chain (closes a federation-impersonation gap: a peer chaining to domain B's root can no longer present a domain-A SVID); structured `parseSpiffeID`; `TLS_FEDERATED_BUNDLES` wiring on the mTLS server **and** the outbound-backend transport; dormant by default | ✅ **done (1/3)** (binding-impersonation proof + table/regression tested) |
| **5 (remaining)** | Live SPIRE Workload-API SVID source; HSM/TPM via the #17 SealingProvider (PKCS#11 needs cgo/3rd-party — out of the stdlib scope; swtpm covers the TPM path) | future |

## 7. Operational guidance (phase 1)

Enable API HTTPS:
```
TLS_CERT_FILE=/certs/api.crt TLS_KEY_FILE=/certs/api.key
```
Enable mTLS (require + verify client certs, least-privilege identities):
```
TLS_CLIENT_CA_FILE=/certs/internal-ca.pem
TLS_CLIENT_ALLOWED_URIS=spiffe://netops/ns/default/sa/nginx
TLS_RELOAD_INTERVAL=30s
```
Dormant by default (unset → plaintext on the internal port; nginx terminates
ingress TLS). Watch `netops_tls_cert_expiry_seconds`.

### Multi-region SPIFFE federation (phase 5)

When the mesh spans more than one trust domain (regions, or a federated partner),
list each foreign domain's CA root:
```
TLS_FEDERATED_BUNDLES=netops-west=/certs/west-ca.pem,partner=/certs/partner-ca.pem
```
Each listed root is added to **both** the chain-building pool **and** the
`FederationTrust` registry (the invariant *anchorable ⊇ registered*), and the
verifier then enforces that a peer's SPIFFE-ID trust domain equals the trust
domain whose root anchored its chain — so a peer authenticated under `netops-west`
cannot impersonate a local `netops` identity. Applies to the mTLS ingress
(`TLS_CLIENT_CA_FILE`) and the outbound-backend transport. A mismatch is rejected,
audit-logged via `OnReject`, and counted in `netops_tls_identity_rejected_total`.
Roots are keyed on whole-cert DER (unforgeable); each region exports its CA bundle
and operators wire peers' roots in. Unset → no federation (single-domain default
unchanged). The **local** trust domain (`TLS_TRUST_DOMAIN`, default `netops`) is
auto-registered to the local CA when federation is enabled, so turning it on never
rejects the platform's own same-domain peers — you only list *foreign* domains.
**Out of scope here:** running a live SPIRE deployment and HSM-backed keys (the
`PeerPolicy` URI seam + #17 SealingProvider are ready for both). Foreign-root
rotation currently needs a restart (matches the boot-time trust-bundle load);
`FederationTrust.Reload()` is wired for a future SIGHUP/watch.

## 8. Migration strategy

1. Land the package + opt-in serving (no behavior change). ✅
2. Turn on API HTTPS behind nginx (re-encrypt) in stage; verify; then prod.
3. Introduce the internal CA; enable nginx↔API mTLS; then API→backend mTLS one
   backend at a time (each backend must speak TLS first — partly ops, not Go).
4. Seal keys via the Vault (#17 phase 2). Adopt SPIRE when the mesh grows.

## 9. Assumptions, tradeoffs, risks

- **Assumption:** nginx remains the public ingress terminator; the Go API's TLS is
  for internal/re-encrypt + deployments without nginx. (The package supports the
  API being the direct edge too.)
- **Tradeoff:** modtime-poll reload (not inotify) trades sub-second freshness for
  zero dependencies — fine for cert rotation cadence.
- **Risk:** backend TLS (phase 3) depends on each datastore speaking TLS, which is
  deployment config outside Go; the client side is ready and fails closed.
- **Risk:** swtpm (#17) is not a hardware root of trust — see secret-custody.md.
