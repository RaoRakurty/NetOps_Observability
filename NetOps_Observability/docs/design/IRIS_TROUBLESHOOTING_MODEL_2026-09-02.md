# Iris troubleshooting model — NetClaw as the reference, built in-house (2026-09-02)

**Owner decision (2026-09-02):** "Use NetClaw as reference and build Iris intelligence
based on that model — that is exactly how I want Iris to troubleshoot. Bring the idea
and develop in-house." Knowledge source: the owner's own troubleshooting documentation
(20 years of field experience), consumed and organized by Fable into the skills layer.

This is the design of record. It extends `IRIS_ENHANCEMENT_ROADMAP_2026-08-28.md`
(Phase A is the foundation and is landing now) and `correlix-ai-hld.md` §10. Fable
designs and grades; Opus subagents build.

---

## 1. What NetClaw's model IS (from the pinned source, 4933254)

NetClaw is an OpenClaw agent. Its troubleshooting model, distilled:

| NetClaw element | What it does |
|---|---|
| **Skills as markdown** | Method lives in `SKILL.md`-style files injected into the prompt — when to use, which tools, what to look for. 191 skills; the network ones are `pyats-troubleshoot`, `pyats-health-check`, `pyats-routing`, `pyats-network`, `pyats-topology`, `pyats-security`, `pyats-junos-*`, `protocol-participation`, `gtrace-path-analysis`. |
| **"Never guess device state. Run a show command first. Always."** | Live device state is the first evidence, not the last. |
| **Structured output** | Every show command is parsed (Genie, 100+ parsers) into JSON before the model sees it. The model reasons over fields, not raw text. |
| **Iterative loop with skill chaining** | Collect → evaluate severity → decide (drill deeper / escalate / propose) → next skill. Chains e.g. `pyats-routing → protocol-participation → gtrace-path-analysis`. |
| **Parallel multi-device collection** | pyATS pCall across the fleet, failure-isolated ("one device timeout must not block others"), results aggregated by severity. |
| **Intent cross-reference** | Live state vs NetBox/Nautobot: IP_DRIFT, MISSING_INTERFACE, UNDOCUMENTED_LINK, CABLE_MISMATCH. |
| **Proactive flags** | Non-FULL OSPF, BGP IDLE/ACTIVE, CPU >90 %, CVE match, SoT mismatch — flagged without being asked. |
| **Gated writes** | Changes only behind a ServiceNow CR: baseline → apply → verify → close or roll back. Destructive verbs refused outright. |
| **Audit (GAIT)** | Every turn recorded: prompt → tool calls → artifacts. |
| **Memory** | Daily logs + long-term structured memory; "never carry assumptions between sessions — verify current state". |

The one property we do NOT adopt: **the model chooses tools dynamically with an open
action space** (113 MCP servers, ~1 000 operations). CLAUDE.md §15 (LLM07/LLM08) and the
HLD's load-bearing invariant — *the model cannot reach the action subsystem* — rule that
out. Everything else is adoptable, and most of it maps onto something already built.

## 2. What we already have (do not duplicate)

| NetClaw element | Correlix today |
|---|---|
| Skills as markdown | `ai/skills/<name>/SKILL.md` — strict dialect, 14 skills, loader validates every tool/arg/next= against the real registry (Phase A, landing 2026-09-02). |
| Show-first | `internal/protocoldiag`: 15-issue catalog, closed per-vendor CommandTable, read-only guard, **live SSH runner wired** (`FEATURE_PROTOCOL_DIAG_COLLECT`, 2026-09-02). `run_protocol_diagnostic` is a skill tool. |
| Structured output | protocoldiag **signatures** (fail-closed verdict/cause/remediation) + the three deterministic **verify-module parsers** (iface_deep, bgp_edge, recent_change). No general parser library yet — this is the biggest gap. |
| Proactive flags | The **correlation engine** — symptom rules for adjacency changes, link state, config change, etc. This is the product; Iris starts from its verdict (`get_rca_verdict`, the osi-bisection skill's first rule). |
| Intent cross-reference | Config drift (`configdrift`), topology graph, seam ownership. No IPAM/SoT connector. |
| Gated writes | HLD P6 — separate subsystem, not built, model has no path to it. Unchanged. |
| Audit | Tool audit (arg names only), AI ask audit, pcap/config `sensitive` audits. |
| Memory | Feedback store (verdict feedback). No investigation memory. |

## 3. The in-house model: five additions, in build order

Each keeps the invariant: **the skill (server-owned data) and deterministic rules
choose what runs; the model narrates and may only pick among authored options.**

### 3.1 Bounded investigation loop (skill chaining) — Phase A2
Today: one gather round → narrate. Target: NetClaw's iterate-and-chain, closed.

- `MaxInvestigationRounds = 4`, `MaxSkillToolCalls` per round unchanged (6), total
  tool budget per turn capped (≤ 16), wall-clock budget per turn (§9).
- After each round the **next skill** is chosen by, in priority order:
  1. **Deterministic rules** authored in the skill's `decisions:` — extend the dialect
     so a `next=` line may carry a machine condition on gathered evidence, e.g.
     `next=interface-down when signature=bgp-hold-timer-expired` or
     `next=optics-degraded when metric:if_crc rising`. Conditions come from a closed
     vocabulary (signature id fired, lane/tool state, metric anomaly kind, verdict tier).
  2. **Model-proposed, closed choice:** if no rule fires, the model may name ONE
     of the skill's declared `next=` targets (and only those). The server validates
     the name against the skill's own list, re-gates every tool of the next skill
     through the Policy Engine, and audits the choice as `model_selected`.
  3. Stop: no rule fired and the model proposes nothing / proposes a verdict.
- Evidence accumulates across rounds (deduped by citation id, re-capped); the final
  narrative cites the whole bundle; the answer carries the **chain** as provenance
  (`skills: [bgp-session-down, interface-down]`) so the UI can show the path taken.
- Isolation: entity binding resolved once per turn under the caller's tenant; a
  later skill cannot widen scope.

#### A2 — shipped (2026-09-02)

`ai/skill_chain.go` + `ai/skill_run.go`. Bounds: `MaxInvestigationRounds = 4`,
`MaxSkillToolCalls = 6` per round, `MaxChainToolCalls = 16` per turn,
`SkillTurnBudget = 45s` wall-clock (a context deadline installed before the
first tool; an earlier caller deadline wins) with `skillRoundReserve = 8s` kept
back so the turn can always narrate what it has. Every budget that cuts the
investigation short is DISCLOSED as a collection note and lifted into
`missing_evidence`. Evidence accumulates across rounds deduped by citation id
and re-capped at `skillEvidenceMaxChars`. Entities are resolved ONCE per turn,
before round 1; a later hop reuses that binding and can never re-resolve from
model text. `Answer.Skill` stays the LAST hop; `Answer.Chain` (`chain`) carries
every hop — `{name, layer, version, selected, round, reason}` — and every tool
audit entry gains `round` + `selected`, with one `next_skill` entry per
selection (`rule_selected` / `model_selected` / `model_selected_invalid`; a
refused name is never logged).

**Condition grammar (the closed vocabulary).** A `next=` line may carry ONE
machine condition as the first word after `when`; if that word contains an `=`
it MUST parse, so a mistyped key fails the loader (and CI) rather than becoming
a rule that silently never fires. Everything after the condition is the human
reason (auto-generated from the condition when omitted). A `when` clause with no
`=` in its first word stays a free-text human reason: it is shown to the
operator and offered to the model as a closed choice, but fires no rule.

```
decisions:
  - next=<skill> when <key>=<value> [human reason]
```

| key | value vocabulary | fires when |
|---|---|---|
| `signature` | a protocol-diagnostic signature id, or `none` | that signature fired this turn; `none` = `run_protocol_diagnostic` RAN and no signature matched (never true on a turn that ran no diagnostic) |
| `tool:<name>` | `ok` · `not_found` · `not_wired` · `denied` · `error` | that tool's outcome this turn. `<name>` must be on the skill tool allowlist AND in this skill's own `tools:` list |
| `evidence:kind` | `app` `device` `doc` `finding` `flow` `integration` `knowledge` `log` `metric` `navigation` `ticket` `topology` | an evidence item of that kind was gathered |
| `verdict:tier` | `confirmed` `suspected` `candidate` `undetermined` | the RCA engine's verdict tier |
| `verdict:phrase` | a token `[a-z][a-z0-9_-]{1,31}` | the ENGINE's own operator phrase/title contains that word (hyphenated compounds also contribute their parts) |
| `note` | a token `[a-z][a-z0-9_-]{1,31}` | a server-authored collection note contains that token |

Facts are SERVER-derived only: tool outcomes and evidence kinds are observed by
the runner, and `signature` / `verdict:*` arrive as `ToolResult.Signals` that the
TOOL declares (bounded, re-validated against the same vocabulary). A tool cannot
assert a kind, an outcome or a note; the model cannot assert anything. Rules are
evaluated in authored order; the first that holds wins.

**Model path (b).** When no rule fires, one small routing turn per round gets
this round's evidence plus the skill's own `next=` menu and must end with
`NEXT: <name>` or `NEXT: none`. The name is validated against that skill's
declared, unvisited targets; anything else (a tool name, another real skill it
does not hand off to, an invention) is refused and audited. The directive is
stripped from any text that could reach an operator.

**Authored conditions in the corpus.** `bgp-session-down` → `interface-down` on
`verdict:phrase=link` and on `signature=bgp-idle-unreachable`;
`ospf-adjacency` → `interface-down` on `signature=ospf-flap-l1` and
`verdict:phrase=link`; `isis-adjacency` → `interface-down` on
`verdict:phrase=link`; every diagnostic-bearing skill → `log-confirmation` on
`signature=none`; `bgp-session-down` → `bgp-prefix-missing` on
`signature=bgp-nothing-advertised`; `osi-bisection` routes to the layer skill by
`verdict:phrase` in bisection order; `interface-down`/`app-edge-5xx` →
`optics-degraded` on `evidence:kind=metric`; `security-exposure-context` →
`osi-bisection` on `verdict:tier=confirmed`.

### 3.2 Show-first state battery + deterministic parser library — Phase A3
NetClaw's "run a show command first" and Genie, in-house and closed.

- Extend the protocoldiag **CommandTable** with a per-vendor **state battery**:
  interfaces (state/errors/optics DDM), IGP neighbours, BGP summary, routes for a
  prefix, ARP/MAC for an address, CPU/memory/environment, recent log buffer. All
  read-only `show`/`display`, all in the closed table, all rendered per dialect
  (Cisco IOS/IOS-XE/NX-OS/IOS-XR, Junos, Nokia SR OS, Arista EOS, Huawei VRP).
- A Go **parser library** `internal/showparse`: one deterministic parser per
  (command, dialect) → a typed struct; unparseable ⇒ `Skipped` (inconclusive),
  never a fabricated field. Table-driven tests with real captured outputs per
  vendor (the verify-module parsers move here; protocoldiag signatures consume
  typed fields where available and fall back to regex). This is the Genie
  equivalent and the single largest piece of work — scope it to what the skills
  actually name, not to all of Genie.
- New skill tool `get_device_state(device_id, area=interfaces|igp|bgp|routes|platform|logs, target=…)`
  returning typed evidence lines. Skills gather it FIRST ("never guess state").
- Parallel collection: `SSHCommandRunner` fan-out across the devices a skill names
  (a case's affected set), per-device timeout, failure-isolated, bounded
  concurrency (≤ 8), one-in-flight-per-device kept.

#### A3 backend — shipped; `ai` tool pending (2026-09-02)

`internal/protocoldiag/statebattery.go` + `fanout.go` + `typedbridge.go` and the
new `internal/showparse` package. The `get_device_state` skill tool is NOT here —
`ai/` is owned by another agent this wave — so the backend exports a clean package
API and the tool is a thin call over it (`StateBattery.Battery`'s doc comment
carries the worked call sequence).

**State battery.** A SECOND closed table beside the 15-issue catalog's, never a
widening of it: `matchTemplate` now takes a `tokenGrammar`, so the battery can add
`{addr}` and Huawei's `vpn-instance` qualifier without loosening the catalog by a
token (`TestStateBattery_CatalogTableUnaffected`). 14 specs across 7 areas
(`interfaces` · `igp` · `bgp` · `routes` · `l2` · `platform` · `logs`) × 8
dialects = 103 authored (spec, dialect) templates; 578 rendered forms are proven
read-only AND admitted by their own table, and `show running-config` is refused on
every dialect. Dialects are **vendorprofile profile ids** (`cisco/ios`,
`cisco/ios_xe`, `cisco/nx-os`, `cisco/ios_xr`, `juniper/junos`, `nokia/sros`,
`arista/eos`, `huawei/vrp`) — one vendor vocabulary, asserted against the registry.
Two rules differ from the catalog on purpose: **no dialect fallback** (an unbound
platform gets no command, never a Cisco one) and **required arguments**
(`show mac address-table address` with no address is omitted, never rendered as a
dangling keyword). Log reads are bounded by a CONSTANT 200 lines where the dialect
has the keyword, by `MaxOutputBytes` where it does not.

**`internal/showparse`.** 77 (command, dialect) parsers over 14 command concepts,
92.8 % covered. `Parse(cmdID, dialect, raw) (Result, error)` errors only on a
contract violation (empty id, over-cap input); everything else — unknown command,
unsupported dialect, unreadable text — is `Skipped` + `Reason`. Every optional
field is a POINTER: absent means absent, and the tests assert the nils as hard as
the values (IOS reports no last-flap ⇒ `LastFlap == nil`). Three distinctions the
library refuses to collapse: Cisco's OSPF **dead time** vs NX-OS's **up time**;
Cisco's fused `State/PfxRcd` column vs Arista's split one (a naive reader calls
Arista's *Idle, 0 prefixes* "Established"); and "the device says there is no such
route" vs "we could not read the answer". Bounded input, no nested quantifier
anywhere, adversarial-input test over all 77 bindings.

**Fan-out.** `BatteryCollector.RunBattery(ctx, devices, area, target)` — ≤ 8 in
flight (constant, `WithConcurrency` can only narrow), per-device and whole-run
deadlines, ≤ 64 devices (the rest REPORTED as `not_run`), devices deduped by id so
one run never schedules a router twice. One device's error / hang / unassessed
platform is its own status and note and changes nothing for the others; a
cancelled run still returns one honest state per device. Every capture goes
through `RedactOutput` BEFORE it is stored and BEFORE it is parsed, so nothing
unredacted reaches a typed row. `NewSSHBatteryRunner` is the live wiring (same
policy layer as `NewSSHCommandRunner`, over the battery's table).

**Signature bridge.** `bgp-idle-unreachable` and `bgp-tcp-blocked` now read
`BGPPeer.State` where the capture parses and fall back to their regexes where it
does not — three-valued, so a typed refusal does NOT hand the regex a second
chance. Every pre-existing signature test is unchanged and green.

**Deliberately left skipping-only / not done.** No parser for: ARP on IOS-XR,
Junos and VRP; `if-brief` on VRP and SR OS; IS-IS on NX-OS, EOS and VRP;
`platform-env` on any dialect; `platform-cpu` on EOS and SR OS; `route-prefix` on
SR OS and VRP; `platform-uptime` on SR OS and VRP; `platform-memory` on the Cisco
family and SR OS. Those commands still RUN and their output is honest raw
evidence — `TestStateBattery_ParserCoverage` lists the gap every build.
`internal/verify`'s three parsers were **left untouched** (they parse different
commands — `show interfaces` fleet-wide, `show bgp all summary`, `show system
commit` — against a different evidence vocabulary, so delegating could not have
kept their tests byte-identical); the duplication is tracked for the
registry-consolidation follow-up, tracker 216.

### 3.3 Knowledge ingestion — the owner's documents become skills — continuous
The owner's troubleshooting documentation is the knowledge source, NetClaw only the
model. Process (Fable does the distillation; the loader is the gate):

1. Owner places documents (any format: md, txt, docx, pdf, notes, scanned runbooks)
   under `docs/knowledge/inbox/` (gitignored if the material is private — decide per
   drop). One topic per file is ideal but not required.
2. Fable reads each and produces, per distinct method: a `SKILL.md` in the strict
   dialect (`when_to_use`, `symptom_kinds`, `tools`, `gather`, `look_for`,
   `decisions`, prose body in the owner's method), **citing the source document
   and section** in a `source:` frontmatter line. Where a document says "run X and
   look for Y", X becomes a CommandTable entry per dialect and Y becomes a
   signature or a parser field. Where it says "if A then check B", it becomes a
   `next=` decision with a machine condition (§3.1).
3. The loader rejects any skill naming a tool, argument, entity or next-skill that
   does not exist — a document cannot make Iris claim a capability we lack.
4. Owner reviews the SKILL.md files (readable by a network engineer without Go).
   Review = read the prose and the decisions; the gather lines are the "commands".
5. Golden evals: each ingested skill ships with ≥ 1 question→skill selection case
   and ≥ 1 evidence→verdict case (fake tools) in `ai/skill_*_test.go`.

Target after ingestion: skills organised by the bisection layers already in the
loader (physical · l2 · igp · bgp · path_seam · application · security · logs) plus
any new layer the documents justify (e.g. `wan_sdwan`, `dns`, `qos`, `mcast`,
`vpn_tunnel`) — the layer set is data (`skillLayerOrder`), extend it deliberately.

### 3.4 Proactive checks and intent cross-reference — Phase A4
- Map NetClaw's heartbeat list onto the engine: non-FULL OSPF / non-UP IS-IS
  (igpmon), BGP IDLE/ACTIVE (bgp watch), CPU/memory thresholds, config change in
  window (verify `recent_change`), CVE match (Project 3 findings). Where a rule is
  missing, add a symptom rule — the engine flags, Iris narrates.
- Intent cross-reference: seam/topology graph and config drift are the SoT we own.
  IPAM/NetBox connector is a Project 2 integration item, not an Iris item.

### 3.5 Investigation memory — Phase B
Per-tenant, per-entity memory of prior conclusions ("this peer flapped on 2026-08-30,
cause was hold-timer/optic"), read-only to the model, surfaced as evidence with a
citation, never as a rule. Verify current state first (NetClaw's own rule). Builds on
the feedback store; tenant-keyed; no cross-tenant recall.

**Not in scope, by decision:** open tool choice by the model; device writes (P6 stays
separate and human-gated); running NetClaw or OpenClaw; MCP as a trust boundary.

## 4. Acceptance (per phase)
- A2: chain of ≥ 2 skills on a BGP-down-because-link-down fixture, deterministic
  path, model-selected path audited, budgets enforced, isolation test.
- A3: ≥ 20 (command, dialect) parsers with captured-output tests, 0 fabricated fields
  (skip-on-unparseable proven), state battery renders on all five dialects, parallel
  collection failure-isolated under -race in CI.
- Ingestion: every owner document → ≥ 1 skill with source citation, loader green,
  owner sign-off on the prose, golden evals green.
- All: CLAUDE.md §3a isolation test, §15 checks (citation verifier, escaped
  rendering), gate green.
