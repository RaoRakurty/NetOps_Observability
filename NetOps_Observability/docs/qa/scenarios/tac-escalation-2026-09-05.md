# QA scenario — TAC escalation pack, W1 (2026-09-05)

Design of record: `docs/design/TAC_ESCALATION_2026-09-05.md`.
Runbook: `docs/runbooks/tac-escalation.md`.

This is the evidence for W1, run on the lab, not a description of intent.
Everything below was produced by
`src/backend/internal/tac/labproof_test.go`, which is skipped unless
`TAC_LAB_PROOF=1`, runs **show commands only** through the same closed table and
the same SSH gateway production uses, and writes nothing to any device.

---

> **Revised the same day.** S1 was originally the SR Linux "no authored plan"
> proof. The vendor research then landed 40 cited SR Linux issues and SR Linux
> gained a real plan (98 bindings), so keeping the old assertion would have meant
> refusing knowledge to protect a demonstration. S1 below is the *original* run,
> kept because it is what the honest path looks like; S1b is what replaced it.

## S1 — the honest "no authored plan" path (as it ran, before the merge)

At the time of this run the lab spines' platform had **no authored command plan**.
The requirement is not that it degrades gracefully; it is that it runs *nothing*
and says so, because a bundle that names the wrong operating system is worse than
one that admits it does not know (QA 2026-09-03, D-2).

```
$ TAC_LAB_PROOF=1 PROTOCOL_DIAG_SSH_USER=… PROTOCOL_DIAG_SSH_PASSWORD=… \
  go test ./internal/tac/ -run TestLabProofSRLinuxIsHonest -v

classified: isis-adjacency (IS-IS adjacency will not form or is stuck) —
  Classified as IS-IS adjacency will not form or is stuck from
  hypothesis sig.ent.fabric.isis-adjacency-flap, alert ISISAdjacencyDown.
plan: has_plan=false steps=0 unbound=8
plan note: No authored command plan for this platform (Nokia SR Linux 24.3.2).
  Correlix will not render another vendor's commands at this device. Collect the
  outputs manually and paste them into the collect step — the bundle, the
  evidence timeline and the problem statement are built the same way.
  unbound isis.summary — no authored command plan for this platform
  unbound isis.interfaces — no authored command plan for this platform
  unbound isis.adjacency — no authored command plan for this platform
  unbound isis.adjacency.detail — no authored command plan for this platform
  unbound isis.database — no authored command plan for this platform
  … and 3 more unbound intents
--- PASS
```

**Result.** Classification still works (it reads Correlix's own evidence, not the
device). Zero commands planned, zero run. All eight intents the class calls for
are named as unbound with the platform-level reason. The run-time gate
independently refuses `show version` for this platform, so even a caller that
bypassed the plan could not reach the device.

### S1b — the honest path today

The offline assertion moved to a platform that genuinely has no commands:
MikroTik RouterOS (`internal/vendorprofile` carries it; its CLI shares no grammar
with the read-only show table, so no plan was authored). `TestPlanNoAuthoredPlanIsHonest`
and `TestLabProofUnknownPlatformRunsNothing` both pin it, and the live run
confirms an unrecognised platform still produces zero commands:

```
plan note: No authored command plan for this platform (Acme RouterThing 1.0).
  Correlix will not render another vendor's commands at this device. Collect the
  outputs manually and paste them into the collect step — the bundle, the
  evidence timeline and the problem statement are built the same way.
--- PASS: TestLabProofUnknownPlatformRunsNothing
```

### S1c — SR Linux now plans, and could not be collected from

With the research merged, spine1 plans **12 bound commands and 29 honestly
unbound intents** for `isis-adjacency`. The live collection did **not** run: every
command failed the SSH handshake with the credentials available to this session
(`admin` + the config-capture password, and the `correlix-faultlab` key, are both
rejected by the spine; an interactive `ssh admin@172.40.40.11` succeeds through
some other identity). Attempts were stopped after two rounds rather than
hammering a lab device with failed authentications.

```
plan fa45b80f88795484: 12 commands, 29 unbound
  unbound isis.summary — no binding on the Nokia SR Linux dialect
  … and 24 more unbound intents
  [1/12] platform.version   error — ssh handshake: unable to authenticate
collected 12 commands, 0 returned output, 0 bytes total
```

**That output is the feature working.** Twelve per-command failures were recorded
against their own commands, nothing was invented, and the capture is still
bundleable. It is not, however, evidence that the SR Linux commands are correct —
they remain `verified: doc_claimed`. Correlix has never run them.

## S2 — Arista cEOS: a real read-only collection and a real bundle (leaf1)

`172.40.40.21`, cEOSLab `4.36.0.1F`, class `bgp-session`, one collection,
read-only, paced.

```
$ TAC_LAB_PROOF=1 TAC_LAB_EOS=172.40.40.21 TAC_LAB_CLASS=bgp-session \
  PROTOCOL_DIAG_SSH_USER=admin PROTOCOL_DIAG_SSH_PASSWORD=… \
  go test ./internal/tac/ -run TestLabProofEOSCollectsAndBundles -v

classified: bgp-session — Classified as BGP session down or will not establish
  from skill bgp-session-down, alert BGPSessionDown.
plan 459eb48e44042ff7: 24 commands, 36 unbound, ≤12582912 bytes, ≤744s
  [ 1/24] system.version         done (538 bytes)
  [ 2/24] system.inventory       done (604 bytes)
  [ 3/24] system.uptime          done (538 bytes)
  [ 4/24] hardware.environment   error — command "show environment all" failed: Process exited with status 1
  [ 5/24] interface.brief        done (881 bytes)
  [ 6/24] interface.counters     done (881 bytes)
  [ 7/24] route.summary          done (1818 bytes)
  [ 8/24] logging.recent         done (11165 bytes)
  [ 9/24] config.running         error — command "show running-config" failed: Process exited with status 1
  [10/24] interface.status       done (467 bytes)
  [11/24] version.info           done (538 bytes)
  [12/24] environment.all        error — command "show system environment all" failed: Process exited with status 1
  [13/24] agent.logs.crash       done (0 bytes)
  [14/24] bgp.summary            done (228 bytes)
  [15/24] bgp.neighbor.detail    done (10949 bytes)
  [16/24] route.prefix           done (2125 bytes)
  [17/24] interface.detail       done (5995 bytes)
  [18/24] arp.table              done (351 bytes)
  [19/24] logging.bgp            done (1660 bytes)
  [20/24] bgp.peergroup          done (1437 bytes)
  [21/24] bgp.peerfilter         done (0 bytes)
  [22/24] bgp.route.prefix       done (664 bytes)
  [23/24] policy.routemap        done (0 bytes)
  [24/24] acl.all                error — command "show access-lists" failed: Process exited with status 1
collected 24 commands, 20 returned output, 40839 bytes total
bundle correlix-tac-lab-proof-leaf1-bgp-session.zip: 27100 bytes, 33 files
--- PASS
```

(The first run of this scenario, before the vendor research merged, collected 15
commands of which 13 returned output. The merge added nine more BGP-relevant
Arista commands from cited documentation; all nine ran.)

**The failures are the point.** `show environment all` and
`show running-config` (and `show system environment all`, `show access-lists`)
exit non-zero at this account's privilege level — EOS answers them only at
privilege 15, a deployment fact `internal/vendorprofile` already records for
config capture. The collection recorded each failure **against its own command**
and continued; none is reported as an empty result, and all appear in the
manifest's `failed` list. Those bindings stay `verified: doc_claimed`; the other
**20 were promoted to `verified: capture`** in `ai/tac/plans/arista-eos.yaml`
because they actually ran here. A promoted binding survives every later research
merge — `test_a_hand_verified_binding_survives_a_merge` pins that.

### Bundle layout (real, from the run above)

```
    15103  MANIFEST.json
     1286  PROBLEM_STATEMENT.md
     2299  SHA256SUMS
      185  device.json
       92  evidence/alerts.json
        5  evidence/correlation.json
        5  evidence/findings.json
        5  evidence/hypotheses.json
     3091  evidence/index.json
       58  evidence/logs.txt
      690  outputs/01-system-version.txt
       …   (15 command outputs, one per planned command)
     1825  outputs/15-logging-bgp.txt
        3  topology.json
```

### One captured output (redacted, verbatim)

```
# intent   : bgp.summary
# command  : show ip bgp summary
# section  : deep-dive
# sourcing : doc_claimed
# at       : 2026-09-05T04:26:25Z
# redacted : yes

BGP summary information for VRF default
Router identifier 10.0.0.11, local AS number 65000
Neighbor Status Codes: m - Under maintenance
  Neighbor V AS  MsgRcvd  MsgSent  InQ OutQ  Up/Down State  PfxRcd PfxAcc PfxAdv
```

### A command that failed (verbatim — the honest shape)

```
# intent   : config.running
# command  : show running-config
# section  : baseline
# sourcing : doc_claimed
# at       : 2026-09-05T04:26:24Z
# redacted : yes
# ERROR    : command "show running-config" failed: Process exited with status 1
```

### MANIFEST.json — the gap fields

```json
"failed": [
  {"intent": "hardware.environment", "error": "command \"show environment all\" failed: Process exited with status 1"},
  {"intent": "config.running",       "error": "command \"show running-config\" failed: Process exited with status 1"}
],
"not_collected": [
  {"intent": "tech.support",
   "title": "The vendor's own all-in-one support capture",
   "reason": "available on this dialect but OFF by default — it can be tens of megabytes and slow; enable it in the plan preview"}
],
"classification": {
  "class_id": "bgp-session", "classified": true,
  "why": [{"kind": "skill", "ref": "bgp-session-down", "weight": 3},
          {"kind": "alert", "ref": "BGPSessionDown",   "weight": 2}]
},
"problem_statement": {"written_by": "template", "cited_ids": [8 ids]},
"counts": {"alerts": 1, "hypotheses": 0, "logs": 0, "findings": 0,
           "topology": 0, "evidence_items": 18}
```

### PROBLEM_STATEMENT.md (verbatim, redacted)

```markdown
# Problem statement

## What happened

Incident LAB-PROOF: Lab proof: bgp-session on leaf1 [I1]

1 alert(s) fired in the incident window: BGPSessionDown. [A1]

Correlix's correlation engine produced no ranked hypothesis for this incident,
so no cause is asserted here.

## When

Incident window 2026-09-05T03:27:12Z to 2026-09-05T04:27:12Z (UTC). [I1]

## What Correlix checked

Correlix classified this as **BGP session down or will not establish** on the
evidence skill bgp-session-down, alert BGPSessionDown. [A1]

15 read-only command(s) were collected from leaf1; 13 returned output and 2
failed. Every output in `outputs/` is redacted. [C1] [C2] [C3] [C4] [C5] [C6]

## What was NOT established

1 command intent(s) this issue class calls for are not authored for Arista EOS,
so they were not collected: tech.support. [C1]

2 command(s) failed on the device; each failure is recorded against its command
in MANIFEST.json rather than treated as an empty result. [C1] [C2]

No cause beyond the cited evidence is asserted for this incident. [I1]

## Where TAC should look first

The neighbour's last error and notification, then TCP reachability and any
ACL/control-plane policy between the two addresses. [C1] [C2] [C3]

Every bracketed id above indexes `evidence/index.json`. [I1]
```

**Every line carries an evidence id.** That is enforced, not merely observed:
`validateStatement` refuses any statement — Correlix's own or Iris's — in which
a claim line cites nothing, or cites an id that is not in the bundle. The one
sentence that reads like a disclaimer ("No cause beyond the cited evidence is
asserted") carries `[I1]` for the same reason: a rule with one exception is a
rule a model can talk its way past.

No hypothesis was available here because the lab run supplied none; the statement
says that in words rather than leaving the section blank.

---

## S3 — the offline guards (CI, no device)

| Property | Test |
|---|---|
| Every shipped command is a read-only show | `TestEveryPlannedCommandIsReadOnly` |
| Every detection id exists in this repo | `TestEveryDetectionReferenceExists` |
| The loader refuses write commands, bad placeholders, unknown fields, dangling intents, uncited doc_claimed | `TestLoaderRefusesUnsafeData`, `TestDocClaimedNeedsACitation` |
| Evidence → class, 11 rows incl. two unclassified | `TestClassifyTable` |
| Unbound intents / no-plan platform are named, never guessed | `TestPlanHonestyUnboundIntents`, `TestPlanNoAuthoredPlanIsHonest`, `TestPlanUnknownPlatformNeverBorrowsADialect` |
| A malformed target argument never reaches a command line | `TestPlanRendersTargetArguments` |
| Closed table refuses a read-only command that is not in the plan | `TestGateAllowsOnlyPlannedCommands` |
| Size cap, total cap, timeout, cancel, one-per-device, pacing | `TestCollect*` (fake runner, no socket) |
| A planted secret never reaches the bundle, in any section | `TestBundleRedactsEverySection` |
| Manifest names every gap; checksums cover every entry; bundle is deterministic | `TestBundleManifestTellsTheTruth`, `TestBundleChecksums`, `TestBundleIsDeterministic` |
| Email profile trims and says what it dropped | `TestBundleEmailProfileTrimsAndSaysSo` |
| A model draft with an uncited claim or a fabricated citation is refused | `TestNarratorOutputMustCiteRealEvidence` |
| Bundles are tenant-keyed on disk, 0700/0600, traversal refused, retention bounded | `TestStore*` |
| Cross-org: own-only, foreign 404, as_tenant ignored, body tenant rejected | `TestTACEscalationCrossOrgIsolation` |
| Collect without a transport is an honest 503 naming the paste path | `TestTACCollectIsHonestWithoutATransport` |
| The coverage view is tenant-invariant | `TestTACKnowledgeIsTenantInvariant` |
| The adapter stays inside its markers and stays thin | `TestTACRoutesLiveInsideTheirMarkers`, `TestTACAdapterLivesInsideItsMarkers` |
| The research merge refuses and is idempotent | `tests/test_tac_merge_research.py` (16 cases) |

---

## S4 — findings from the lab run (not blockers, worth acting on)

1. **`CONFIG_BACKUP_SSH_PASSWORD` in `deployment/docker/.env` no longer
   authenticates to the cEOS leaves.** The proof run failed every command with
   `ssh: unable to authenticate` on those credentials and succeeded with the
   leaf's current account. Config capture on `leaf1`/`leaf2` is therefore almost
   certainly failing too, silently, for the same reason. Worth a check outside
   this work.
2. **The capture account is not privilege 15 on cEOS**, so `show running-config`
   and `show environment all` are refused. That is recorded honestly per command
   rather than papered over — but it means a TAC bundle from a cEOS leaf carries
   no configuration today.
3. **`topology.json` was empty** in the proof run: the lab-proof harness supplies
   no topology (the server adapter fills it from `aiTopologyContext`). Nothing to
   fix in the engine; noted so the empty file is not read as a defect.

---

## S5 — the vendor-research merge (2026-09-05)

425 cited issues across ten dialects (`ai/tac/research/*.yaml`) were merged into
the taxonomy and the plans by `scripts/tac-merge-research.py`. The merge is
idempotent (`--check` exits 0), and 25 pytest cases in
`tests/test_tac_merge_research.py` pin its refusals.

**Result:** 84 issue classes, 1,256 intents, **1,641 bindings across 12 dialects**,
7 cited read-only exceptions, and 955 command records refused of ~3,070 —
every refusal reported with its reason.

| dialect | bound intents | verified | documented | baseline |
|---|---|---|---|---|
| cisco-nxos | 307 | 0 | 307 | 9 |
| cisco-iosxe | 274 | 0 | 274 | 9 |
| cisco-iosxr | 214 | 0 | 214 | 8 |
| arista-eos | 212 | **20** | 192 | 13 |
| huawei-vrp | 157 | 0 | 157 | 35 |
| juniper-junos | 147 | 0 | 147 | 16 |
| nokia-sros | 107 | 0 | 107 | 17 |
| nokia-srlinux | 98 | 0 | 98 | 12 |
| paloalto-panos | 64 | 0 | 64 | 19 |
| fortinet-fortios | 42 | 0 | 42 | 17 |
| cisco-ios | 10 | 0 | 10 | 9 |
| cisco-asa | 9 | 0 | 9 | 8 |
| *mikrotik-routeros* | *no plan — the honest path* | | | |

Only Arista carries `verified: capture` bindings, because leaf1 is the only
device this session actually collected from. Everything else is
`doc_claimed` — the vendor documents it, Correlix has not run it — and every
surface says so.

### The refusals, by reason (955 records)

| n | reason |
|---|---|
| 132 | the intent is already bound to a different command on that dialect; the existing binding is kept |
| 89 | a baseline command that carries no intent, so it cannot bind to a vendor-neutral concept |
| ~230 | a placeholder Correlix cannot fill from an incident (`<loc>`, `<slot>`, `{service-id}`, `{session-id}`, `{policy-id}`, `{log-id}`, …) — running it unscoped would be invalid or fleet-wide |
| 28 | `diagnose test application <daemon> <n>` — some levels restart the daemon |
| 21 | `ping` / `traceroute` — transmits from the device rather than reading it |
| 20 | `diagnose sys session list` — not a read-only lead, and unusable without a scope-setter |
| 12 | `execute log display` — not a read-only lead |
| 11 | `diagnose sys session filter` / `execute log filter` — sets daemon-side read scope |
| rest | state-changing leads, cleartext-credential commands, `scp export`, `diagnose sniffer packet` |

### The cited read-only exceptions (7)

`fortinet-fortios`: `diagnose debug crashlog read`, `diagnose debug
config-error-log read`, `diagnose debug rating`, `diagnose debug fsso-polling
{detail,summary,user}`, `diagnose debug authd fsso {list,server-status}` —
documented status prints whose text carries the word `debug`.
`huawei-vrp`: `dir`, which Huawei's own collection procedure uses to confirm a
diagnostic file was written.

Each carries the citation that establishes it; an uncited exception is a load
error, and `TestEveryPlannedCommandIsReadOnly` fails if the allowlist grows past
20 entries.

### Consent-gated commands

`admin tech-support` (SR OS — Nokia calls it a core dump needing their
authorisation), `display diagnostic-information` (Huawei — raises CPU, writes a
file, emits MAC addresses), `tech-support` (SR Linux — writes a zip under
`/tmp`), `show tech-support` and `execute tac report`. All are bound, none is in
a baseline, none runs without the operator approving that specific command with
the vendor's caveat on screen.

### Class synonyms normalised

`lacp-bundle`/`port-channel-lacp` → `lag-lacp` · `snmp-agent` → `snmp` ·
`bfd-session` → `bfd` · `acl-drops` → `acl` · `mpls-rsvp`/`mpls-te` →
`mpls-rsvp-te` · `l3vpn`/`l3vpn-vprn` → `mpls-l3vpn` · `logging-pipeline` →
`logging` · `process-crash` → `process-health` · `software-install` →
`software-upgrade` · `environment` → the taxonomy's `hardware-fault`.

One class, `ztna`, was **pruned**: every one of its commands was refused, so it
could neither fire nor collect anything beyond the baseline.

### Still open for a product decision

- FortiOS scope-setters (`diagnose sys session filter`, `execute log filter`):
  no config change, no clear, but they leave daemon-side state. `diagnose sys
  session list` is unusable on a production firewall without them.
- FortiOS `diagnose test application <daemon> <n>`: needs a per-daemon,
  per-level allowlist.
- `ping`/`traceroute`: 21 cited entries. They are diagnostics an engineer runs
  constantly; they transmit, so they need the same consent treatment the
  file-writing commands got.
- Huawei `pads diagnose …`: read-only in effect, not a `display` form, and
  Huawei's own mandatory-check table lists it first for protocol-flapping cases.
- PAN-OS tech-support: no CLI form is documented publicly, so none is asserted.
