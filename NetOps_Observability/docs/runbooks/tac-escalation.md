# Runbook — TAC escalation pack

**What it is.** When an RCA is not confirmed and the incident has to go to the
vendor, Correlix classifies the issue, builds the read-only command list an
expert would want for that issue class on that platform, runs it over the SSH
gateway, and packages the outputs with the incident's own evidence into a
redacted zip and a pre-filled case description.

Design of record: `docs/design/TAC_ESCALATION_2026-09-05.md`.
Engine: `src/backend/internal/tac`. Knowledge (data): `src/backend/ai/tac`
(schema in `src/backend/ai/tac/README.md`).
HTTP adapter: `src/backend/protocol_diagnostics.go`, inside `TAC-ROUTES-BEGIN/END`.

---

## 1. The operator flow

Investigate → Troubleshooting → an incident → **Escalate to TAC**.

| Step | What it does | What "honest" looks like |
|---|---|---|
| Classify | Scores the incident's evidence — RCA hypotheses, alerts, matched protocol signatures, the selected Iris skill, log lines — against the closed issue-class taxonomy | Nothing matched is an ANSWER: the `generic` class, and the screen says Correlix did not classify it |
| Plan | Builds baseline + class deep-dive + topology context for the device's CLI dialect | Intents the dialect does not bind are listed as unbound; a platform with no authored plan runs NOTHING and offers the paste path |
| Collect | Runs the plan read-only over the SSH gateway | Every per-command failure is recorded against that command; a partial capture still bundles |
| Bundle | Zips MANIFEST, the problem statement, per-command outputs, evidence, topology, device facts, SHA256SUMS | Every output is redacted; the manifest names every gap |
| Case | Pre-fills the vendor/ITSM case form | A connector that cannot create says so; portal text always works |

---

## 2. Turning live collection on

Collection is **dormant by default**. It shares one flag and one identity with
the protocol-diagnostics collector, deliberately: one read-only account, one
host-key custody, one thing to audit.

```
FEATURE_PROTOCOL_DIAG_COLLECT=true
PROTOCOL_DIAG_SSH_USER=<least-privilege read-only account>
PROTOCOL_DIAG_SSH_PASSWORD=…      # or PROTOCOL_DIAG_SSH_KEY
PROTOCOL_DIAG_SSH_PORT=22         # optional
```

With the flag off, `POST …/tac/collect` answers **503** with the sentence the UI
shows verbatim — the plan, the bundle and the case text still work, and the
operator pastes the outputs in. That is a supported path, not a degraded one.

**The account must be read-only.** Three independent guards stand between a plan
file and a device (the loader's read-only grammar, the run-time closed table, the
runner's re-validation), but the account is the one that matters if all three are
ever wrong.

**Privilege matters on some platforms.** Arista EOS answers
`show running-config` and `show environment all` only at privilege 15; at a lower
level they exit non-zero and the collection records the failure against those two
commands and continues. That is correct behaviour, not a bug to work around by
raising the account's privilege — decide deliberately.

---

## 3. Where the bundles live

```
<DATA_DIR>/tac/<tenant>/<incident>/correlix-tac-<ref>-<host>-<class>.zip
```

Directories are `0700`, files `0600`. Retention prunes on every write: at most 10
bundles per incident, nothing older than 30 days. There is no cross-tenant
listing method on the store, by design.

A bundle filename carries no tenant id — the file is meant to leave the
operator's hands.

---

## 4. When something is wrong

### "The escalation catalog is not available on this build" (503 everywhere)

The embedded taxonomy or a plan file failed to load. This cannot happen from a
deployment condition — the data is embedded and `internal/tac`'s own tests parse
it in CI — so it means a data change shipped without the test running.

```bash
cd src/backend && go test ./internal/tac/ -run TestDefaultCatalogLoads -v
```
The error names the file, the line and the field.

### Collection returns 503 with the paste sentence

Expected when `FEATURE_PROTOCOL_DIAG_COLLECT` is off or no read-only account is
provisioned. Check the api log at boot:
```
protocol-diag: live collect transport wired (read-only SSH)
```
Absent → the flag is off or `buildProtocolDiagCollector` refused (it logs why).

### Collection returns 409

Another collection is running against that device. This is a REFUSAL, not a
queue: two operators cannot multiply SSH sessions on a router that is already
having a bad day. Wait, or cancel the running one (`{"cancel": true}`).

### Every command fails with an SSH handshake error

The read-only account no longer authenticates. Verify by hand from the api host:
```bash
ssh -o PreferredAuthentications=password <user>@<device> 'show version'
```
This is the same failure mode config capture would have — if TAC collection
cannot authenticate, config backup on that device almost certainly cannot either.

### A step says "needs your explicit approval"

The vendor's own documentation says that command is not routine — SR OS's
`admin tech-support` is a core dump Nokia says needs their authorisation, Huawei's
`display diagnostic-information` loads the control plane and writes a file. It is
bound, it is shown with the vendor's caveat, and it runs only when the operator
approves that specific intent (`consent: [<intent>]` on the plan request). It is
never in a baseline.

### A command is refused as "not in the TAC escalation command plan"

The run-time closed table rejected a string the plan could not have produced.
That means either a caller reached the runner outside the plan path, or a plan
file changed without the gate being rebuilt. Both are bugs; do not widen the
table to make the symptom go away.

### The problem statement says "this is Correlix's deterministic evidence summary"

Iris either was not configured, failed, or wrote something that broke the
evidence-only rule (an uncited claim, or a citation to an id that is not in the
bundle). The deterministic statement is a complete artifact — the bundle is fine
to send. The `problem_statement.rejected` field in MANIFEST.json says which.

---

## 5. Extending the knowledge (it is data)

- The taxonomy and the plans are **machine-merged** from
  `ai/tac/research/<vendor>.yaml`. Edit the research file (or the merge script),
  never `classes.yaml`/`plans/*.yaml` by hand: a hand edit is reverted by the
  next merge, and `--check` fails in CI meanwhile. The ONE exception is
  promoting a binding to `verified: capture` after a real run — the merge
  preserves that, and a test pins it.
- A new issue class, a new intent, a new per-dialect command: edit
  `ai/tac/classes.yaml` / `ai/tac/plans/<dialect>.yaml` per
  `ai/tac/README.md`, then `go test ./internal/tac/`.
- Vendor research lands in `ai/tac/research/<vendor>.yaml` and is merged by
  `python3 scripts/tac-merge-research.py` (idempotent; `--check` is the CI mode).
  The script refuses unknown fields and unsafe commands and DROPS detection cues
  that name ids this repository does not contain.
- A command Correlix has actually run on a platform is `verified: capture`;
  everything else is `verified: doc_claimed` and is displayed as "documented,
  not verified". When in doubt it is `doc_claimed`.

## 6. What W1 does NOT do

- No case is created by an API. `POST …/tac/case` returns a pre-filled form for a
  human, and the portal-text connector hands back paste-ready text. ServiceNow,
  Jira, email-with-attachment, Cisco (CXD + Smart Bonding) and Juniper are W2,
  built against `internal/tac/caseopener.go`.
- No unknown-output backlog is tracked yet; the Knowledge page says so rather
  than showing a zero.
- An escalation lives in the api process. A restart loses the in-flight state
  (never a bundle, which is on disk) and the state endpoint says so.
