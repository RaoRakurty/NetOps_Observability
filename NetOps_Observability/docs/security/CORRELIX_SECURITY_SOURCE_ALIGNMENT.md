# Alignment: owner's TLS-Cloudnative design ↔ the shipped security corpus

**Purpose.** The owner supplied an independent transport-security design
("Correlix Security Architecture: A Zabbix-Inspired Encryption Design",
2026-08-04). This note records where it agrees with the HLD/LLD/backlog/ADRs
already in `docs/security/`, where it goes further, and the **three places it
diverges from a decision we took** — so no divergence is silent.

No design change is made here. The owner's instruction was to confirm alignment.

---

## 1. Agreement — the substance is the same design

| Owner's document | Our corpus | Status |
|---|---|---|
| Separate cryptographic domains (public ingress · workload · device · secret-encryption root) | HLD §6.1 — same four, plus a fifth (backup) which the owner's acceptance list also implies ("backups encrypted with keys separate from live service credentials") | **Agree** |
| SPIFFE-style workload identities per service | HLD §6.2, ADR-SEC-003 | **Agree** (naming caveat in §3) |
| Production validator that **rejects** rather than warns, with a concrete error list | HLD §6.4, LLD §A, SEC-002 — including the same "name the exact control" error contract | **Agree — strongly.** The owner's sample output is almost line-for-line our validator spec |
| Dependency-first delivery: profiles → PKI → public/management plane → event plane → storage plane → device plane → rotation | HLD §9 phases 0–8 | **Agree**, same ordering and same rationale |
| Acceptance proves *behavior*, not configuration (wrong-SAN rejected, unauthorized Kafka principal, unenrolled syslog sender, renewal without telemetry loss, dual-root rotation) | LLD §6.26, V1 scope §9 | **Agree** |
| `transport_authenticated=false` labeling for the legacy syslog lane | LLD §6.15, claims doc §5 | **Agree** — and note: this field **does not exist yet** (errata E7). It is new work, not an existing control |
| Legacy lanes bound to a management interface + source allowlists, never all interfaces | LLD §6.15/§6.18 | **Agree** |
| Short-lived certs, atomic replacement, overlapping trust bundles, per-service reload hooks, expiry alerts, tested revocation | LLD §6.3/§6.6, runbooks | **Agree** |
| Gap list: Kafka PLAINTEXT, OpenSearch security disabled, Valkey nopass, VM unauthenticated, PG non-TLS, gNMI skip-verify/insecure, sealing dormant, shared Vector Basic credential | Evidence matrix §1–§3 | **Agree — independently verified**, same findings, now with file:line and a classification per control |

**Verdict: no architectural conflict.** Two independently written designs
reached the same structure, which is the strongest signal either of them is
right.

---

## 2. Where the owner's document goes further than v1 (already deferred, not contradicted)

- **Device PKI as a first-class component** (device intermediate, cert→inventory→tenant mapping, enrollment/rotation). Ours is designed in full (LLD §6.15/§6.16/§6.17, ADR-SEC-006) but **deferred to Phase 2** by owner decision #2 — because we cannot put certificates on customer hardware on our schedule. The owner's document and that decision are compatible: it describes the target, decision #2 sets when.
- **Kafka TLS + ACLs as a delivery stage.** Ours is **separately gated** (owner decision #6). Same content, later gate.
- **Hardware TPM/HSM/KMS for production sealing.** Ours keeps swtpm for v1 with `REQUIRE_SEAL` enforced, and lists external KMS/HSM as a commercial capability (V1 scope §6). Direction identical; v1 stops earlier.
- **Backup/snapshot encryption with separate keys.** Explicitly out of v1 (owner decision #1), documented as a known gap with posture visibility. The owner's acceptance bullet is the eventual target.

---

## 3. Divergences that need to be visible

### D-A. Who issues certificates (the one real architectural difference)

The owner's document says issuance should move **out of the API process** into
a dedicated `pki-controller`, on the grounds that *"an API compromise should not
automatically provide access to the root or intermediate signing capability for
every service"* — and suggests the API-bootstrap remain a **lab** mode while
production uses a separate issuer.

Our v1 decision (**D2**, HLD §11.0) keeps the **existing in-process CA** with
mandatory sealing, choosing operational simplicity: the machinery exists,
auto-rotates, and adds no new component.

**Both are defensible; they optimize different things.** The owner's document is
right about the blast radius — and the correlation-service findings sharpen it:
this codebase has already demonstrated one process holding more authority than
it needs. The mitigations now in place are (a) the CA key is sealed or boot is
refused (shipped 2026-08-04, `tls_ca.go` seal gate), and (b) the identity
allowlist is non-empty so a stolen leaf cannot impersonate arbitrarily.

**Recorded as an open decision, not silently resolved.** If production
deployments face a compliance regime or a real multi-tenant hosting model,
splitting the issuer is the correct next step and the design is unchanged by it.

### D-B. SPIFFE identity strings

The owner's document uses `spiffe://correlix/ns/platform/sa/nginx`. The code
**actually emits** `spiffe://netops/ns/default/sa/<svc>` — trust domain from
`TLS_TRUST_DOMAIN` (compose default `netops`), namespace a hardcoded literal
`default` (errata E12). `docs/runbooks/tls-mtls.md:33` allowlists that exact
string.

Our recommendation stands: **keep `netops` in v1.** The string carries no
security value, and changing it invalidates every allowlist simultaneously — an
outage-class change for a cosmetic gain. The namespaced form is the documented
target for when identities must distinguish tiers.

### D-C. What the owner's document could not know

It was written before the 2026-08-04 investigation and therefore does not cover:

- the **correlation service** findings — unauthenticated, cross-tenant-capable,
  and the source of a **live cross-tenant leak** via `/api/correlations/{id}/replay`
  (fixed, commit `7ea62e1d`);
- **four further cross-tenant leaks** in the VictoriaMetrics lane (fixed,
  commit `53829a55`);
- the **shared ClickHouse superuser** with `access_management=1`, which lets
  application services drop their own row policies;
- the verified **goflow2 capability** answer: TLS yes, SASL/SCRAM yes,
  **mTLS no** — which amends the "mTLS everywhere" position (owner decision #7,
  now reflected in ADR-SEC-005).

These do not contradict the document; they add findings to it and reorder the
work — authorization defects now precede transport encryption, because an
encrypted channel to an unauthorized reader is not a fix.

---

## 4. One place the owner's document is sharper than ours was

> *"This is one of the most important differences between a secure feature and a
> secure product: Correlix already possesses many security features, but a
> production profile must make unsafe deployment impossible by accident."*

That sentence is a better statement of the problem than anything in our HLD's
executive summary, and it is exactly what the evidence matrix measured: **18
controls contradicted by evidence, 5 built but switched off.** The feature/product
distinction is now the organizing idea of the V1 scope document.

Its acceptance bullet *"a packet capture between every internal tier must show
no readable telemetry, credentials, queries, or tenant information"* is also a
stronger test than our config-level assertions, and is adopted into the LLD's
acceptance criteria as the end-state proof for the internal-TLS claim.
