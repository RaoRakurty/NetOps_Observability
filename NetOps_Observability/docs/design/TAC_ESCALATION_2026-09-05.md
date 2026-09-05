# TAC escalation pack — design of record (2026-09-05)

**Owner's goal (verbatim intent):** when a NOC admin opens Correlix the logs are already
correlated and an RCA is offered. If the RCA is not confirmed and the admin must escalate
to the vendor's TAC, Correlix makes that easy: it detects the type of issue, builds the
list of commands an expert engineer / TAC would want for that issue class (in addition to
the standard outputs every TAC asks for), executes them read-only over SSH, zips the
result, and when the admin opens the case, Correlix opens it and attaches the logs.

This replaces the Protocol Diagnostics bench on the Investigate → Troubleshooting page.
The issue/command catalogue becomes Iris's knowledge surface (what it knows per vendor).

## 1. The flow (one screen, incident-first)
1. **Verdict** (exists): the incident's RCA, confidence, evidence classes, causality path.
2. **Escalate to TAC** (new, one action). Correlix:
   a. **Classifies** the issue from the evidence it already has — the RCA hypotheses,
      the alerts, the Iris skill signature match, the protocol state battery — into a
      closed **issue-class taxonomy** (§2). It says which class and why, and lets the admin
      override.
   b. **Builds the command plan** for that class on that device's vendor dialect (§3):
      the vendor **baseline** set + the **class deep-dive** set + **connected topology**
      context from Correlix's own model (neighbours, links, the seam). The plan is shown
      before anything runs, with the estimated size/time and what will be redacted.
   c. **Collects** read-only over the SSH gateway (existing `protocoldiag` runner + registry
      CommandTable): closed grammar (registry commands only, never `debug`/`clear`/config),
      per-command timeout, output size cap, pacing, one collection per device at a time,
      the NOC's `ssh readonly` policy honoured; Nokia SR Linux and every dialect without an
      authored command set report honestly ("no authored plan for this platform") and fall
      back to paste.
   d. **Bundles**: zip with `MANIFEST.json`, per-command outputs, the incident's evidence
      timeline (correlation objects, alerts, logs excerpts, findings), Correlix's
      **problem statement** written by Iris under the evidence-only rule (what happened,
      when, what was checked, what was ruled out, what TAC should look at first),
      topology snippet, device facts; **redacted** by the existing TAC redactor
      (secrets, communities, keys; tenant ids kept); SHA256SUMS.
   e. **Opens the case** through a **CaseOpener** connector (§4) with the bundle attached
      and the problem statement as the description, records the case id on the incident,
      and shows the link. With no connector configured: download + a pre-filled case text
      to paste into the vendor portal / email.
3. **Feedback → Iris memory**: the escalation (class, plan, what TAC found) is an
   investigation Iris recalls; TAC's answer, when recorded, becomes a signature candidate.

## 2. Issue-class taxonomy (closed, versioned; `ai/tac/classes.yaml`)
`ospf-adjacency`, `ospf-database` (LSA churn / corruption), `ospf-flapping-link`,
`isis-adjacency`, `isis-lsp`, `bgp-session`, `bgp-route-missing`, `bgp-instability`,
`interface-errors`, `link-flap`, `optics`, `hardware-fault`, `high-cpu`, `high-memory`,
`mlag-vpc-peer`, `evpn-vxlan`, `qos-drops`, `mpls-ldp`, `config-change`, `generic`.
Each class carries: detection rules (which evidence/alert/signature names map to it),
the deep-dive command intent list (vendor-neutral intents, e.g. `ospf.interfaces`,
`ospf.neighbors.detail`, `ospf.database.detail`, `fib.prefix`, `logging.recent`), and
the "what TAC looks at first" note. Adding a class is data, reviewed like a skill.

## 3. Command plans (data, per vendor dialect; `ai/tac/plans/<dialect>.yaml`)
- **Baseline** (every class): version, inventory/platform, running-config, recent logs,
  environment/health, `show tech-support` (size-capped; optional toggle because it can
  be tens of MB and slow), interface counters summary.
- **Intent → command** bindings per dialect (IOS/IOS-XE, IOS-XR, NX-OS, EOS, Junos,
  SR Linux, SR OS, FortiOS, PAN-OS, Huawei VRP): the registry `CommandTable` already
  binds many intents; unbound intents are listed honestly in the plan ("no binding on
  this dialect") — never invented.
- Example, `ospf-adjacency` on IOS-XE: `show ip ospf interface`, `show ip ospf neighbor`,
  `show ip ospf neighbor detail`, `show ip ospf database`, `show ip ospf database router
  <rid>`, `show ip route ospf`, `show ip cef <prefix>`, `show interfaces <if>`, `show
  logging | include OSPF`, plus baseline.
- **Learning**: plans are extended from owner runbooks (skills ingestion) and from
  collected outputs the parsers do not recognise (backlog → parser/ binding work).

## 4. CaseOpener connectors (`internal/tac/`; interface in core, implementations pluggable)
Corrected 2026-09-05 from `TAC_CASE_OPENING_RESEARCH_2026-09-05.md` (cited per vendor):
- **Tier 1 (W2): ITSM first** — ServiceNow (incident + `/api/now/attachment/file`, 1 GB
  platform cap) and Jira (issue + attachment, Cloud 1 GB default / Data Center 10 MB) via the
  existing `internal/ticketing` adapters (per-tenant config, write-only secrets, SSRF
  validation) which lack only `AttachFile`; then **email with attachment** (≤ 14 MB profile;
  covers five of seven vendors, fully serves Arista) and **portal text** (pre-filled case
  description + bundle download) for every vendor.
- **Tier 2: Cisco** — the Support Case API v3 is READ-ONLY and PSS-partner scoped; create =
  **Smart Bonding** (`push/call`, staging env available), attach = **CXD** (one `PUT`, Basic
  auth with SR number + token from SCM, no size limit) — CXD attach-first, then Smart
  Bonding create (its response carries the CXD host/token). Then **Juniper** (`/createsr`,
  S3-token `/attachfile` (Beta), status poll 90 d + `publishSR` webhook; `contactEmail`
  must be a named human).
- **Tier 3: portal text only** — Fortinet (FortiCare API is asset/licensing only), Palo
  Alto (CSP key is licensing; TSF mandatory `.tar/.zip/.tgz`), Nokia (no case API in NSP),
  Huawei enterprise (only Cloud OSM has an API). Never promise an API here.
- **Credentials:** bring-your-own, per tenant, opt-in, sealed; vendor APIs behind a pinned
  host allowlist; gate = `requirePerm` + tenant filter (a tenant's own case), NOT platform
  admin. No shared Correlix identity (Arista domain-matched accounts, Juniper named human).
- **Bundle profiles:** `full` (API paths) and `email` (≤ 14 MB: clears Cisco 20 MB,
  ServiceNow 18 MiB, Exchange defaults) plus link-only; no chunking (no ITSM documents
  resumable upload).
- **Human-approved always:** case creation is a click by a person with the pre-filled form
  (severity, contract/serial, contact, problem statement); never an autonomous engine output.
  Every action audited; case id/URL recorded on the incident; status polled where the
  API allows.

## 5. What leaves the page
The issue × command matrix, the free-form device picker + collect/analyse bench, and the
"Analyze against signatures" button as a manual step (analysis happens inside classify).
They move to **Iris → Knowledge** (coverage per vendor, signatures, plans, ingestion).

## 6. Build order
W1 (now): taxonomy + plans for the six protocol classes on IOS-XE/EOS/NX-OS/Junos + baseline
for all dialects; classify from RCA/alerts/signatures; plan preview; read-only collect
through the existing runner; bundle with problem statement; download + portal-text case
mode; the page rebuilt around it; Iris → Knowledge view; tests + scenario proof on the lab.
W2: ServiceNow/Jira case opening with attachment; Cisco Support Case API; feedback loop.
W3: remaining classes (hardware, EVPN, MLAG, QoS, MPLS), learning from unknown outputs.

## 7. Command policy — OUTPUT ONLY (owner decision, 2026-09-05)

The owner's rule, verbatim:

> "Rules in executing commands, any command changing the config should be blocked
> or not even known to Correlix. Any command trying to restart or reboot should be
> unknown to Correlix. TAC usually need outputs to understand what is going on,
> not that we have to execute something and change."
>
> "Ping and traceroute are good examples, should be allowed."
>
> "Any commands that is touching at daemon level block them."

**"Not even known" is the operative half.** Refusing a command at merge time still
leaves it sitting in the research corpus, which is knowledge Correlix carries. So
the vocabulary is *purged*, and only the COUNT survives.

### The three families (`src/backend/ai/tac/forbidden.yaml`)

| Family | What it covers |
|---|---|
| `config` | enters configuration mode, or changes configuration/state that outlives the session — `configure`/`conf t`/`system-view`/`edit`/`set`/`delete`/`undo`/`commit`/`write`/`copy`/`save`/`install`/`upgrade`/`format`/`erase`, FortiOS `execute …`, Junos `request system software`, **and state-clearing**: `clear …`, Huawei `reset …` |
| `restart` | `reload`/`reboot`/`restart`/`halt`/`shutdown`/`power-off`, `request system reboot\|halt\|power-off`, `execute reboot\|shutdown\|restore\|factoryreset\|formatlogdisk`, `admin reboot`, `tools system reboot` |
| `daemon` | anything addressing a named daemon/process — FortiOS `diagnose test application <daemon> <level>` (**all** levels) and `diagnose sys kill`, Huawei `pads diagnose` and the `diagnose` view, Junos `restart <process>` / `request system process`, `kill`, per-process `debug`, EOS `agent … terminate`, NX-OS `system internal … restart`, SR OS `admin … restart`, SR Linux `tools system app-management` |

Matching is on **command tokens**, never substrings: a rule's tokens must be the
command's LEADING tokens. `show reload cause`, `show system processes` and
`show ip bgp` therefore stay allowed by construction — no rule may begin with
`show`/`display`/`get`/`info`, and the loader refuses one that does. `except:`
lists the documented output-only leaves of an action branch (`execute ping`,
`admin show …`, `request license info`).

### Enforced in four places, none of them redundant

1. **Ingestion** — `scripts/tac-merge-research.py` refuses a forbidden record at
   the door and reports **only a count per family**; the command text is never
   printed, written or kept.
2. **Purge** — `scripts/tac-purge-forbidden.py` removes forbidden records from
   `classes.yaml`, `plans/*.yaml` **and `research/*.yaml`**, and keeps the census
   (counts per family and per dialect) in `forbidden.yaml`. `--check` is the CI
   mode and fails if anything forbidden is present.
3. **Load** — `internal/tac` refuses a plan file carrying a forbidden command:
   the api does not boot with one.
4. **Gate** — `internal/tac.Gate` re-applies the policy to the RENDERED string at
   the moment it would go on a wire, so a hand-edited plan file still cannot reach
   a device. This is the layer that makes the rule structural rather than
   procedural, and `internal/tac/forbidden_test.go` proves it with a deliberately
   tampered table.

### What IS allowed

- **Bounded ping and traceroute** (`internal/protocoldiag/probe.go`), not consent
  gated. They are not reads, so they get their own grammar rather than a hole in
  the read-only one: count/repeat ≤ 5, size ≤ 1500, timeout ≤ 5 s, traceroute
  TTL/max-hops ≤ 30, probes ≤ 3; `flood`/`-f`/`sweep`/`rapid`/`pattern`/
  `interval`/`continuous` refused by name; a probe with no destination refused
  (a bare `ping` opens an interactive dialog on several platforms). `df-bit` is
  allowed — with size ≤ 1500 and count ≤ 5 it cannot be a flood, and the DF probe
  is the standard path-MTU test every vendor's TAC asks for.
- **FortiOS session-scoped setters** — `diagnose sys session filter …` and
  `execute log filter …`. They change no configuration and clear nothing: they
  narrow what a READ prints, and the scope dies with the CLI session. They are
  admitted only from `forbidden.yaml`'s `session_scoped:` list, only WITH the
  documented teardown (`… clear` / `… reset`), and the collector runs that
  teardown immediately afterwards — including after a failure or a cancellation.
- **PAN-OS tech-support** has no read-only CLI form (`scp/tftp export` pushes a
  file to a third-party host, which is a different trust model). It stays
  unbound: the plan shows the intent as unbound rather than inventing a command,
  and the operator generates the bundle from the PAN-OS GUI or the XML API
  (`type=export&category=tech-support`) with their own key. Correlix does not hold
  a PAN-OS API key for this, and will not guess one.

### What the operator sees

Iris → Knowledge states the policy and the census: **"Excluded by policy: N
(config · restart · daemon)"**, per build and per dialect. Counts only — a
command in one of the three families is not knowledge Correlix holds, and the
coverage page is knowledge.
