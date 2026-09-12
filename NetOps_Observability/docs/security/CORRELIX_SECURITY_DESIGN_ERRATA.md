# Correlix Security Design — Errata Ledger

**Purpose (owner decision #8):** *"No document is authoritative merely because
it was generated first."* This ledger records every claim in the security
design corpus that turned out to be wrong, why it was wrong, what replaced it,
and — crucially — the **test or process change that prevents the same class of
error recurring**.

It is deliberately public and deliberately unflattering. A security design that
hides its own error rate cannot be trusted to have found the code's.

**Provenance of these findings:** the HLD was written first; the LLD, the
implementation backlog and the ADR set were then written *against* it by
separate reviewers whose instructions included contradicting it. Every entry
below was found that way — not by the original author re-reading their own work.
That is the process lesson: **first-draft security documents are hypotheses.**

---

## How to read the ledger

| Field | Meaning |
|---|---|
| Original claim | What the first version asserted |
| Why wrong | The evidence that disproved it |
| Corrected claim | What is true |
| Affected docs | Where the correction was applied |
| Implementation consequence | What would have gone wrong had we built from the error |
| Prevention | The test, check or rule that stops recurrence |

Severity: **S1** would have caused an insecure or broken implementation ·
**S2** would have caused wasted or misdirected work · **S3** cosmetic.

---

## E1 — False drift claim (S2)

- **Original:** `docs/UPGRADE.md` and `docs/STREAMING.md` were listed as stale
  for referencing Redpanda.
- **Why wrong:** `UPGRADE.md:61-70` is a legitimate *migration note* for
  existing installs; `STREAMING.md:8` explicitly *records the removal*. Both
  are correct history.
- **Corrected:** retracted. Real drift found instead: `ARCHITECTURE.md:14,56-58,78`
  presents Telegraf as the SNMP collector (it is `profiles: [legacy]`, not
  running — the Go collector is real), and `scripts/preflight-configs.sh:18`
  names a CI workflow (`config-preflight.yml`) that does not exist; the actual
  caller is `.github/workflows/fresh-install-integrity.yml:44`.
- **Affected:** HLD §3.
- **Consequence:** would have "fixed" correct documentation, destroying real
  migration history.
- **Prevention:** a drift claim must quote the surrounding lines, not just match
  a keyword. Historical/migration sections are legitimate references.

## E2 — Impossible phase dependency (S1)

- **Original:** HLD §9 Phase 1 (nginx→API mTLS) listed **"Deps: 0"**.
- **Why wrong:** enabling that hop enables `TLS_INTERNAL_CA`, which by the
  HLD's own §1.1 writes a **plaintext CA private key** unless a seal provider
  is configured (`tls_ca.go:23-24`).
- **Corrected:** Phase 1 depends on the PKI + seal-gate items.
- **Affected:** HLD §9, backlog dependency graph.
- **Consequence:** the first "security improvement" would have written an
  unprotected CA key to disk — a net security *regression*.
- **Prevention:** every phase's dependency list must be derived from the
  enabling code path, not from narrative order. The validator's seal check runs
  before any CA bootstrap.

## E3 — Highest-priority item had no phase (S1)

- **Original:** SEC-018 (secret-sealing enforcement, covering the plaintext
  sealing-key hop rated P0 ⚠⚠) appeared in the epic list but **in no phase**.
- **Why wrong:** omission during roadmap assembly.
- **Corrected:** placed in Phase 4 and marked as the item v1 cannot ship without.
- **Affected:** HLD §9, backlog.
- **Consequence:** the sharpest identified gap could have been scheduled into
  nothing.
- **Prevention:** a roadmap-completeness check — every epic must appear in
  exactly one phase; the docs test (§ below) asserts it.

## E4 — Policy store had no owner (S2)

- **Original:** the transport-policy object was adopted and schematised, but no
  epic owned building its **store**; it was implicit in the UI epic.
- **Corrected:** assigned explicitly; the store is tenant-scoped RLS-backed
  state and belongs with the policy model, not the UI.
- **Prevention:** every design object must name the epic that builds it.

## E5 — Backup encryption scoped but unowned (S2)

- **Original:** backup encryption was in scope (§2) and rated HIGH (T20) with
  **no epic**.
- **Corrected:** owner decision #1 — **explicitly out of v1**, documented as a
  known deferred gap with posture-page visibility and a "no silent unencrypted
  destination" requirement.
- **Prevention:** anything in the threat model rated HIGH must map to an epic
  *or* an explicit deferral decision.

## E6 — Valkey surface understated (S1)

- **Original:** treated as a cache with an availability-only impact.
- **Why wrong:** it carries **RCA evidence** — probe paths, LLDP/BGP-LS
  topology, interface maps. Publishers **discard write errors** (`_ = redisSetEX(...)`),
  so an auth failure would be silent; and `RedisAddr()` returns non-empty even
  with a bad password, so the intended file-fallback never triggers.
- **Corrected:** integrity finding, not just confidentiality; the silent-failure
  and fallback defects must be fixed alongside enabling authentication.
- **Consequence:** enabling auth without fixing the discard would have silently
  stopped evidence writes — a data-loss bug introduced by a security change.
- **Prevention:** before securing any dependency, check what the client does
  with its errors.

## E7 — Claimed a control that does not exist (S1)

- **Original:** "the SNMP trap path **already does this**" for a
  `transport_authenticated` stamp.
- **Why wrong:** **`transport_authenticated` does not exist anywhere in the
  codebase.** The real field is `Authenticated bool \`json:"authenticated"\``
  (`collectors/snmptrap.go:60`) and it exists on the **trap lane only**.
- **Corrected:** a stack-wide labeling stamp is **new work**.
- **Consequence:** the honest-labeling commitment in the claims document would
  have rested on a control that was never built — making a *published customer
  claim* false.
- **Prevention:** the evidence matrix requires a file path + symbol for every
  "implemented" classification; claims may not cite a control absent from it.

## E8 — Correlation finding understated (S1)

- **Original:** "the correlation service exposes an unauthenticated HTTP
  surface."
- **Why wrong:** it is unauthenticated **and cross-tenant-capable**:
  `src/correlation/main.py:1837` queries ClickHouse with
  `tenant_scope="__all__"`, deliberately bypassing the row policy.
- **Corrected:** raised to a critical finding requiring authentication **and** a
  tenant-scoping review; owner decision #5 governs the investigation.
- **Consequence:** would have been scheduled as "add TLS to an internal hop"
  when the actual risk is unauthenticated access to a cross-tenant-capable
  client.
- **Prevention:** for every unauthenticated surface, trace what its *credentials
  can reach*, not just what the surface is.

## E9 — Non-existent data path in the design (S2)

- **Original:** an `api → Kafka` row in the component matrix.
- **Why wrong:** the Go API has **no Kafka client** (`bus_producer.go:17-23`) —
  it POSTs to the Vector bus bridge.
- **Corrected:** removed; the ACL matrix has no `api` row.
- **Prevention:** matrix rows must cite the client code that makes the
  connection.

## E10 — Decision inconsistency (S3)

- **Original:** `goflow2 → Kafka` offered "mTLS **or SASL_SSL**", contradicting
  decision D5 (one credential system).
- **Corrected:** mTLS; goflow2's actual TLS capability is a tracked unknown
  (owner decision #7 requires verification, not assumption).

## E11 — Client count wrong, and the reason was the finding (S2)

- **Original:** "one `INGEST_TOKEN` shared by 6 clients."
- **Why wrong:** tracked compose has 4 clients + 1 verifier. The 6th
  (`cloud-ingest`) exists only in a **gitignored override**.
- **Corrected:** 4+1 tracked; and the discovery is itself a finding — a real
  Kafka producer holding the shared token and host cloud credentials is
  **invisible to the tracked configuration**, therefore invisible to review, CI
  and the validator.
- **Prevention:** the validator must operate on the *effective merged*
  configuration, not the tracked file.

## E12 — SPIFFE claim shape-true, value-false (S1)

- **Original:** the target ID `spiffe://correlix.workload/ns/<ns>/sa/<svc>` was
  described as "already the format `tls_ca.go:91-93` emits".
- **Why wrong:** the code emits `spiffe://netops/ns/default/sa/<svc>` — trust
  domain from `TLS_TRUST_DOMAIN` (compose default `netops`), and the namespace
  a **hardcoded literal `default`**. `docs/runbooks/tls-mtls.md:33` allowlists
  that exact string.
- **Corrected:** the target is a **migration**, not a description. Recommended:
  keep `netops` in v1 — the string carries no security value and changing it
  invalidates every allowlist simultaneously.
- **Consequence:** an allowlist written to the aspirational string would have
  rejected every real certificate — a total-outage-class error.
- **Prevention:** identity strings in any design must be copied from code
  output, never from intent.

## E13 — Line-number citation drift (S3)

- **Original:** `tls_ca.go:22-24`; `snmptrap.go:64`.
- **Corrected:** `:23-24` and `:60`.
- **Prevention:** the docs test re-resolves cited symbols, not just paths.

---

## Additional defects found in code during verification

Not errata (these are code findings, not document errors), recorded here
because they were discovered by the same adversarial passes:

| Finding | Evidence | Why it matters |
|---|---|---|
| `writeTLSMetrics` emits nothing when no leaf is loaded | `tls_server.go` | The TLS metrics vanish exactly when something is wrong — the monitoring blind spot coincides with the failure |
| `PeerPolicy` with an empty allowlist accepts **any** CA-signed cert | `tlsconfig/verify.go:62-64` | Authentication without authorization; a valid-but-unrelated workload would be accepted |
| `initBackendTransport()` runs **before** CA bootstrap | `main.go` | First-boot ordering hazard |
| `REQUIRE_SEAL` uses strict-equality parsing | `internal/vault/secrets.go` | `TRUE`/`1`/`yes` would silently not enable it |
| 4–10 Kafka topics exist **only by auto-creation** | vector configs vs compose | A typo creates a topic instead of failing |
| nginx has **no rate limiting** | `nginx/default.conf` | The example config says so explicitly |
| `read_only` / `tmpfs` used **nowhere**; `no-new-privileges` on 7 of 32 services | compose | Container hardening is inconsistent |
| `clickhouse/users.d/tenant-scope.xml` referenced but **missing** | compose vs filesystem | A tenant-scoping config file that does not exist |

---

## Prevention measures adopted (owner decision #8)

1. **Evidence classification is mandatory.** Every control is
   verified-implemented / implemented-but-disabled / partially-implemented /
   documented-only / proposed / unknown / contradicted-by-evidence — with a
   file path and symbol for anything claimed implemented.
2. **Nine review passes** before a security document is treated as
   authoritative: repository evidence · HLD/LLD consistency · dependency graph
   validation · implementation feasibility · threat model · operational ·
   testability · **adversarial (goal: disprove the design)** · unresolved
   unknowns.
3. **Documentation tests** (specified in the LLD test matrix): cited file paths
   must resolve; every epic must appear in exactly one phase; no control marked
   implemented without an evidence-matrix row; ADR status must not contradict
   the backlog.
4. **The ledger is updated, never rewritten.** Corrections are appended with
   their original claim intact.
