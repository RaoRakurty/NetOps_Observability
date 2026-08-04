# ADR-SEC-008 — Production fails closed at boot; lab is the only escape hatch

- **Status:** **Accepted (owner, 2026-08-04).** Decision: **production refuses to
  boot on any item in the violation list below**, the **lab profile is the
  explicit escape hatch**, and every refusal must produce a **clear, actionable
  error message** naming the cause, the fix, and the lab override. This settles
  HLD §11 open decision #4.
- **Implementation state:** **the mechanism exists; the policy does not.** The
  codebase already fails closed on individual conditions —
  `src/backend/main.go` `log.Fatalf`s on secret custody (`:271`), sealed fields
  (`:279`), backend TLS (`:285`), the store backend (`:253`) and auth (`:247`),
  and `db.go`'s `assertRLSCapable` is the established precedent. What is missing
  is a **deployment profile**, a **consolidated violation list**, and a
  **validator that runs the same rules at install, at boot and in CI.**
- **Owner rationale:** a security posture that depends on remembering to set
  variables is not a posture. The stack today has every `TLS_*` and `SEAL_*` knob
  wired into compose (`deployment/docker/docker-compose.yml:1448-1472`) and
  **none of them set in the live `.env`** — which is precisely how "built" became
  "off" with nothing to report it. The validator is the cheapest possible fix:
  no new component, one boot check.
- **Relates to:** HLD §6.4, §6.5, §9 phase 0, §11.4; ADR-SEC-001 (policy
  violations are what it validates); ADR-SEC-007 (the sealing rules are two
  entries on the list); `scripts/preflight-configs.sh`,
  `scripts/preflight-install.py`.

---

## Context

**Correlix's security controls are almost all opt-in, and the live deployment
opts out of every one of them.** That is not an accusation — it is the verified
state (HLD §1.1): the internal CA, the mTLS listener, the backend mTLS client,
the SPIFFE federation binding and the envelope sealing layer are all built,
wired into `main.go`, and dormant, because no `TLS_*` or `SEAL_*` variable is set.

The pattern that produces this is well understood and is not unique to us:
a security feature that is *available* and *not required* will, at scale, be
absent. The compensating control is to make the insecure configuration
**impossible to run**, not merely discouraged.

Three things make this practical here rather than aspirational:

1. **The repo already fails closed, per-subsystem, and it works.**
   `docs/design/tls-architecture.md` §5 states the rule — "fail **closed** and
   **loud**, never silent-downgrade: a configured-but-broken cert/CA aborts
   boot" — and `main.go` implements it at `:247`, `:253`, `:271`, `:279`, `:285`.
   `assertRLSCapable` in `db.go` refuses to start against a Postgres role that
   could bypass RLS. Nobody has argued these are wrong.
2. **A validation hook already exists at every point the check needs to run.**
   `scripts/preflight-configs.sh` performs fresh-load validation of every
   config-driven service in throwaway containers and is already wired into
   `.github/workflows/config-preflight.yml` (CI gate), the optional pre-push
   hook, and `install.py` before `docker compose up`. Its header documents
   exactly the failure class this ADR generalizes: *"a committed config that the
   running service tolerates in memory but that FAILS a fresh load — so a restart
   or a clean install silently brings up a broken pipeline."* The security
   analogue is a stack that silently brings up an *insecure* pipeline.
3. **The HLD already specifies the profiles** (§6.5): lab / development /
   staging / production, with enforcement severity ranging from `warn` to
   **`fail closed at boot`**.

> **Documentation conflict found.** The HLD refers three times to "the §4.4
> violation list" (`CORRELIX_CLOUD_NATIVE_SECURITY_HLD.md:363,448,594`) but the
> HLD's own §4 is "Trust boundaries" and has **no subsection 4.4** — the
> reference points at the originating brief, not at any section a reader of the
> HLD can find. **This ADR therefore enumerates the list explicitly** (below),
> derived from the HLD's verified findings and its §6.5 profile table, and the
> HLD's dangling cross-reference should be repointed here.

## Decision

**1. Introduce an explicit deployment profile** — `lab` | `development` |
`staging` | `production` — as a first-class, declared configuration value.
Default must be **safe**, not convenient: an unset profile is treated as
`production` (see U1 for the counter-argument, which is real).

**2. In `production`, the API refuses to boot on any violation below.** In
`staging`, violations fail unless covered by a declared, unexpired exception. In
`development`, they warn. In `lab`, they are permitted and announced loudly at
boot.

### The production violation list (v1)

Derived from HLD §1.1 (verified gaps), §6.5 (profile table) and the ADRs in this
series. Every entry is a boot-time refusal in production.

| # | Violation | Rationale / evidence | ADR |
|---|---|---|---|
| V1 | `TLS_INTERNAL_CA=true` with no working seal provider | CA private key written in plaintext — `src/backend/tls_ca.go:22-24` | SEC-007 |
| V2 | No sealing provider configured at all (`REQUIRE_SEAL` unmet) | Every "sealed" secret stored in the clear; `SEAL_PROVIDER` defaults empty (`docker-compose.yml:1448`) | SEC-007 |
| V3 | Any datastore URL using `http://` rather than `https://` | `OPENSEARCH_URL`/`CLICKHOUSE_URL` are `http://` today (`docker-compose.yml:973-974,1119-1120`) | SEC-004 |
| V4 | OpenSearch security plugin disabled | `DISABLE_SECURITY_PLUGIN: "true"` (`docker-compose.yml:538`) — no authentication over every tenant's logs | SEC-004 |
| V5 | Kafka listener without TLS + authentication, or `allow.everyone.if.no.acl.found=true` | `KAFKA_LISTENERS: "PLAINTEXT://…"` (`docker-compose.yml:207-210`) | SEC-005 |
| V6 | Postgres DSN with `sslmode` weaker than `verify-full` | `verify-full` checks chain **and** hostname; `require` verifies nothing (`docs/runbooks/tls-mtls.md`, Postgres) | SEC-004 |
| V7 | Valkey or VictoriaMetrics reachable without authentication | Both unauthenticated today (HLD §1.1, T14 CRITICAL) | SEC-004 |
| V8 | nginx→api plaintext, or the plaintext `:8000` listener still published alongside TLS | Downgrade surface (HLD T17) | SEC-004 |
| V9 | Correlation service exposing an unauthenticated HTTP surface | HLD §1.1, §7 (api→correlation, authn "none ⚠") | SEC-004 |
| V10 | A shared credential used by more than one client (today's single `INGEST_TOKEN`, six clients) | HLD T3/T9; `CLAUDE.md` §3a and HLD §2 invariant "the shared ingest token is eliminated" | SEC-003 |
| V11 | Any peer whose transport policy has `accept ⊇ plaintext` **without** a well-formed, unexpired exception (owner, reason, ticket, expiry) | ADR-SEC-001 extension #1 | SEC-001 |
| V12 | An exception that has **expired** | Otherwise "temporary" is permanent (HLD §10, "permanent plaintext migration listeners") | SEC-001 |
| V13 | Hostname verification disabled anywhere — `skip-verify`/`insecure` in a collector config | `gnmic.yaml:13` global `skip-verify: true`, `:30,35,40,45,50` `insecure: true` | SEC-006 |
| V14 | `ALLOW_DEV_SECRETS=true` or any dev-only bypass set | e.g. it gates LDAP `InsecureSkipVerify` (`src/backend/internal/ldap/ldap.go:311-317`) | SEC-004 |
| V15 | A certificate that is expired, or expires within the renewal margin, at boot | `/admin/readyz` already asserts validity with a 5-minute margin (`tls-architecture.md` §6 phase 4) | SEC-003 |
| V16 | SNMPv3 trap path accepting unknown senders (fail-open) once trap enforcement ships | Verified fail-open (`transport-encryption-2026-08-04.md` §2.3) | SEC-006 |

**3. The same rules run in three places, from one implementation.**
(a) at install (`scripts/preflight-install.py` / `install.py`), (b) at API boot,
(c) in CI. HLD §9 phase 0's completion criterion is exactly this: *an insecure
production config **fails** the validator in CI.* A rule that exists only as
prose is not a rule (HLD §6.4: "production checks must be executable, not
prose").

**4. Lab is the only escape hatch, and it is loud.** `DEPLOYMENT_PROFILE=lab`
permits every violation above, logs each permitted violation individually at
boot, and marks the deployment's posture as unenforced wherever posture is
displayed. There is **no per-rule "just this once" override in production** —
that is what the exception mechanism (V11/V12) is for, and exceptions expire.

**5. Warn-only mode is permitted *before* approval, and only before.**
HLD §12 permits the validator to ship in warn-only mode ahead of the
implementation boundary being lifted. Warn-only must be a **transitional
setting with a removal date**, not a fourth profile — otherwise it becomes the
permanent default and the ADR achieves nothing.

**6. Error messages are part of the contract.** Every refusal states: what is
wrong, why it matters, the exact fix, and the lab override. A fatal that says
`backend TLS: bad certificate` will be misdiagnosed; the required shape is the
one in ADR-SEC-007 decision 3. Poor error text converts a safety feature into an
outage with no path out of it.

## Alternatives considered

| Alternative | Why rejected |
|---|---|
| **Warn loudly, start anyway** | This is effectively today's behaviour for the config that matters, and today's outcome is a stack with every control off. Warnings in a boot log are read once, at install, by someone who is already busy. Retained *only* as the pre-approval transitional mode (decision 5). |
| **Degrade gracefully** (disable the affected feature, keep serving) | The affected feature *is* the security control; "degrading" means running insecurely with extra steps. It also produces the worst possible state: a deployment that believes it is protected. Explicitly contrary to `tls-architecture.md` §5 and root `CLAUDE.md` §14. |
| **Refuse at install time only** (`install.py` gate, no boot check) | Catches the initial deployment and nothing after it. Configuration drifts: an operator edits `.env` and restarts, an upgrade changes a default, a compose override is added. The boot check is the only one that sees the *running* configuration. Install-time validation is kept as an *additional* gate, not a replacement. |
| **CI-only enforcement** | Validates the repo, not the deployment. Customer `.env` files never pass through our CI. Kept as a third gate for the same rules. |
| **Per-rule environment overrides** (`ALLOW_PLAINTEXT_KAFKA=true`, etc.) | Every override becomes a permanent production setting within a quarter, individually justified and collectively fatal. The exception mechanism (owner + expiry + audit) delivers the same flexibility with an expiry date attached. |
| **A runtime health-check/alert instead of a boot refusal** | Better than nothing and it should also exist. But an alert on a running insecure stack competes with every other alert, and the window between "insecure" and "someone acts" is unbounded. The boot refusal makes the window zero. |
| **Make the *installer* generate a secure config and trust it thereafter** | Necessary and planned, but insufficient: it does not survive manual edits, upgrades, or a compose override file. Generation and validation are complementary. |
| **Fail closed in staging too, with no exception mechanism** | Rejected as too rigid: staging exists partly to exercise migrations, and migrations legitimately pass through accept-set states that include plaintext. Staging therefore fails on *undeclared* violations only (HLD §6.5). |
| **Default profile = `development` when unset** | Safer for developer ergonomics, and it is the real counter-argument to decision 1 (see U1). Rejected as the *default default*: an unset variable in a customer deployment must not silently select the permissive mode. |

## Consequences

**Positive**
- **This is what makes the customer-facing claim true rather than aspirational.**
  "Every Correlix component communicates over TLS" becomes a property the
  software *enforces on itself at every boot* — the strongest form of the claim
  available, and one that a customer's security reviewer can verify by
  deliberately breaking a setting and watching the stack refuse to start.
- **Configuration drift becomes impossible to sustain.** A deployment cannot
  quietly regress: the next restart surfaces it.
- **The gap between "built" and "enforced" closes permanently.** The single most
  expensive finding in the whole inventory was that distinction, and this is the
  mechanism that removes it.
- One implementation, three enforcement points, no new component.

**Negative — stated honestly, because this is the tradeoff the owner accepted**
- **A misconfigured upgrade takes the stack down instead of silently degrading.**
  That is the point, and it is a real availability cost. A customer who removes
  the `seal` profile during maintenance, or whose certificate expires
  unnoticed, gets an outage rather than a warning. HLD §11.4 states this
  precisely: *"a misconfigured upgrade takes the stack down rather than silently
  degrading — which is the point, but it is an availability tradeoff the owner
  must accept."*
- **Mean-time-to-recovery depends entirely on error-message quality.** A refusal
  the operator cannot diagnose in minutes is worse than the insecurity it
  prevented. Decision 6 is not polish.
- **Certificate expiry becomes an outage class** (HLD T18, "n/a → will become MED
  once enabled). Mitigated by the existing expiry gauge
  (`netops_tls_cert_expiry_seconds`), the TTL/2 re-issue loop
  (`src/backend/tls_ca.go:159-165`) and V15's renewal-margin check — but the risk
  is created by this decision and must be owned by it.
- **Boot-time dependencies multiply.** The sealing sidecar, the datastores' TLS
  listeners and the certificate files all become start-order-critical. Startup
  races will look identical to genuine violations unless the validator
  distinguishes "not ready yet" from "misconfigured" (U4).
- **Lab/production divergence grows**, so more defects will be lab-invisible.
  Staging is the compensating control and must actually run the production
  profile minus declared exceptions.

## Security implications

- **Converts every other ADR in this series from a design into a guarantee.**
  ADRs 001–007 describe controls; this one is why they are on.
- **Directly addresses HLD T17** (insecure fallback / downgrade — plaintext
  `:8000` published beside `:443`) and removes the "silent plaintext fallback"
  that HLD §2 lists as a non-negotiable invariant.
- **V11/V12 are the anti-rubber-stamp control.** Without expiry enforcement, the
  exception mechanism degrades into a permanent allowlist — the exact failure
  `transport-encryption-2026-08-04.md` §7 R5 predicts.
- **New denial-of-service consideration:** anything that can cause a validator
  rule to trip can stop the platform. Rules must therefore depend only on local
  configuration and locally-verifiable state — **never** on a remote service's
  availability, or an attacker who can disrupt a dependency can prevent boot.
- **The validator must not log secrets** while explaining a violation. Root
  `CLAUDE.md` §8 (sanitize all logs) applies to the error text in decision 6.

## Operational implications

- **The install path must produce a passing configuration by default.**
  `python3 scripts/install.py` cannot leave an operator with a stack that refuses
  to start; generation and validation ship together or the feature is a support
  incident.
- **Upgrade procedure changes:** validate the *new* configuration before
  restarting, not after. A pre-restart dry-run of the validator (`--check` mode)
  is required, and it must be runnable without touching the live stack.
- **Any script implementing this obeys `scripts/CLAUDE.md`**: `set -euo
  pipefail`, explicit PATH, quoted expansions, bounded external calls, and
  **never** `|| true` around a security check (§16.1 — swallowing the error is
  the exact defect the whole rule exists to prevent). A validator that exits 0
  because a command was not found is worse than no validator.
- **Runbooks must state which procedures can trip a boot refusal.** Every
  runbook in `docs/runbooks/security/` carries a SAFETY WARNINGS section for this
  reason; the ones that can lock out an operator or stop the stack are marked
  explicitly.
- **Break-glass must remain possible.** If a production deployment cannot boot
  and the fix requires the platform, that is a deadlock. `DEPLOYMENT_PROFILE=lab`
  is the documented escape, and using it must be auditable after the fact.

## Migration implications

1. **Phase 0 of the roadmap** (HLD §9) — no dependencies, additive, and permitted
   before the §12 approval boundary *in warn-only mode*.
2. **Ship warn-only first, with a removal date.** Run it against real
   deployments, collect the violations, fix them, and only then flip to
   enforcing. Flipping first would take every existing deployment down at once —
   all sixteen violations are currently true.
3. **The profile must be introduced before the rules bite**, or there is no way
   to express "this is a lab".
4. **Each rule turns on as its corresponding control ships.** V5 (Kafka) cannot
   be enforced before ADR-SEC-005 is implemented; V13 (gNMI) waits on Phase 2.
   The list is the target; the enabled subset grows with the roadmap, and the
   validator must report which rules are active so nobody mistakes an unenforced
   rule for a passing one.
5. **Existing deployments need a migration window** with the violation report
   available before enforcement — the same widen/verify/narrow discipline the
   accept-set uses (ADR-SEC-001).

## Unresolved questions

- **RESOLVED (owner, 2026-08-04):** production fails closed at boot on the
  violation list; lab is the escape hatch; error messages must be actionable.
- **U1 — What is the default when the profile is unset?** This ADR chooses
  `production` (safe default). The counter-argument is real: a developer running
  `docker compose up` on a laptop hits sixteen refusals immediately. Options:
  default `production` + a very clear first-run message; or detect a lab-shaped
  install. Needs a decision before implementation.
- **U2 — Is `REQUIRE_SEAL` a separate variable or derived from the profile?**
  Shared with ADR-SEC-007 U1. Two ways to express one rule is one too many.
- **U3 — Who may set `DEPLOYMENT_PROFILE=lab`, and is it auditable?** If it is a
  plain env var, anyone with host access silently disables every rule. That may
  be acceptable (host access is already game over) but it should be a conscious
  choice, and the posture display must show it.
- **U4 — How does the validator distinguish "dependency not ready yet" from
  "misconfigured"?** A datastore still starting up looks like a datastore with no
  TLS. Needs bounded retries with a clear timeout, not an immediate fatal.
- **U5 — Does the validator run continuously or only at boot?** Configuration can
  change under a running process (a rotated file, an edited compose override).
  A periodic re-check with an alert — not a re-refusal — is the likely answer,
  but it is unspecified.
- **U6 — Where does the exception store live** so the validator can read it at
  boot? If exceptions live in Postgres and Postgres is one of the things being
  validated, the ordering is circular. Likely a file-based declaration validated
  against the database later; unresolved.
- **U7 — Should V15 (certificate expiring within the renewal margin) refuse to
  boot, or start and alert?** Refusing turns a recoverable near-miss into an
  outage; starting risks expiry mid-flight. The renewal loop makes the second
  option defensible, and this ADR's choice of refusal is the more conservative
  one — worth revisiting with real data.
