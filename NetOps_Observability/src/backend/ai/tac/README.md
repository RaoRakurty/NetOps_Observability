# `ai/tac` — the TAC escalation pack's knowledge, as data

Design of record: `docs/design/TAC_ESCALATION_2026-09-05.md`.
Loader + engine: `src/backend/internal/tac` (Go). **Nothing in this directory is
code.** Everything here is reviewed data: a closed issue-class taxonomy, a
vendor-neutral intent vocabulary, and one command-plan file per CLI dialect.

Four files matter:

| File | What it holds |
|------|---------------|
| `classes.yaml` | the intent vocabulary + the issue-class taxonomy with its detection rules |
| `forbidden.yaml` | the OUTPUT-ONLY command policy (owner, 2026-09-05): the vocabulary Correlix refuses to learn, plus the two session-scoped setters that are exempt and the exclusion census |
| `plans/<dialect>.yaml` | one dialect's baseline plan and its intent → command bindings |
| `research/<vendor>.yaml` | raw vendor-documentation research, merged into the two above by `scripts/tac-merge-research.py` |

> **Rule zero.** Every id this data references — alert name, hypothesis template
> id, signature id, skill id, catalog issue id — must ALREADY EXIST in the repo.
> The loader fails closed on an unknown reference. Never invent a name; grep for
> it (§ "Where the referenced ids live" below).

---

## 1. `classes.yaml`

```yaml
schema_version: 1
version: correlix-tac-classes-2026-09-05   # bump on any change; stamped into every bundle MANIFEST

intents:                       # THE CLOSED INTENT VOCABULARY (see §2)
  - id: ospf.neighbors.detail
    area: ospf                 # closed enum, §2
    title: OSPF neighbours, detailed
    note: the exact neighbour state word is the tell   # optional, one line

classes:
  - id: ospf-adjacency         # slug: ^[a-z][a-z0-9]*(-[a-z0-9]+)*$
    title: OSPF adjacency will not form or is stuck
    protocol: ospf             # closed enum, §3
    summary: >
      One line an operator reads on the escalate screen.
    tac_first_look: >
      What the vendor's TAC engineer opens first, in one or two sentences.
    detect:                    # ALL keys optional; at least one must be present
      alerts:      [OSPFAdjacencyDown, OSPFAdjacencyFlapping]
      hypotheses:  [sig.ent.access.ospf-adjacency-flap]
      signatures:  [ospf-exstart-mtu, ospf-exstart-only, ospf-init-oneway]
      skills:      [ospf-adjacency]
      issues:      [ospf-neighbor-stuck, ospf-adjacency-nonform]
      log_regex:   ['(?i)OSPF-5-ADJCHG']     # RE2 only; anchored where possible
    intents:                   # the DEEP-DIVE set, in the order TAC wants it
      - ospf.interfaces
      - ospf.neighbors.detail
      - ospf.database
      - route.ospf
      - interface.detail
      - logging.recent
    sources:                   # citations, see §5
      - title: Troubleshoot OSPF Neighbor Problems
        url: https://www.cisco.com/...
        retrieved: 2026-09-05
```

### Field rules

- `id` — kebab slug, unique, stable. **Renaming a class breaks recorded
  escalations; add a new one instead.**
- `protocol` — closed enum (§3). It only groups the class in the UI; detection
  never keys on it.
- `detect` — the evidence → class map. Every list entry is a REAL id:
  - `alerts` → an `alert:` name in `src/config/rules.yaml` **or**
    `src/config/rules-scale-slo.yaml`.
  - `hypotheses` → a `template_id` in `src/correlation/catalog.py`
    (`sig.ent.<domain>.<name>`).
  - `signatures` → a signature `ID:` in
    `src/backend/internal/protocoldiag/analyze.go`.
  - `skills` → a directory under `src/backend/ai/skills/`.
  - `issues` → an issue `ID:` in `src/backend/internal/protocoldiag/catalog.go`.
  - `log_regex` → Go RE2, compiled at load; a pattern that fails to compile is
    a load error. Keep them cheap — no nested quantifiers.
- `intents` — ids that MUST appear in the top-level `intents:` vocabulary. They
  are vendor-neutral: an intent that no dialect binds is shown honestly as
  "no binding on this dialect", never dropped and never guessed.
- `generic` is the mandatory fallback class (no `detect`, baseline only). It is
  what an unclassifiable incident escalates as.

### Scoring (how `Classify` picks)

Each matched reference adds a weight: `signatures` 5, `hypotheses` 4,
`skills` 3, `issues` 3, `alerts` 2, `log_regex` 1. Highest total wins;
ties break on the class id (deterministic). Every class that scored > 0 is
returned as an *alternative* with its own `why`, and the operator may override
to ANY class. Score 0 everywhere → `generic`, said out loud.

**Adding a class is a data change**, reviewed like a skill. The list is open to
additions from research; the *grammar* and the read-only rules are not.

---

## 2. Intent vocabulary

An intent is a vendor-neutral command CONCEPT: `<area>.<object>[.<qualifier>]`.

- id grammar: `^[a-z][a-z0-9-]*(\.[a-z0-9][a-z0-9_-]*){1,3}$` — an area, an
  object, and up to two qualifiers. Segments after the area may use `_` as a word
  separator (`bgp.neighbors.reset_reason`); a single-segment id is not an intent,
  because it names no object.
- `area` (the first segment) is a **closed enum**:
  `system`, `interface`, `optics`, `route`, `fib`, `arp`, `l2`, `stp`,
  `ospf`, `isis`, `bgp`, `mpls`, `overlay`, `mlag`, `qos`, `hardware`,
  `logging`, `config`, `tech`, `platform`
- Adding an AREA is a code change (the `intentAreas` set in
  `internal/tac/tac.go`). Adding an INTENT inside an existing area is a data
  change — add it to `intents:` with a title, then bind it per dialect.

Examples in use: `system.version`, `system.inventory`, `system.uptime`,
`interface.brief`, `interface.detail`, `interface.counters`, `optics.detail`,
`route.summary`, `route.ospf`, `route.bgp`, `fib.prefix`, `ospf.interfaces`,
`ospf.neighbors`, `ospf.neighbors.detail`, `ospf.database`,
`ospf.database.router`, `isis.adjacency`, `isis.adjacency.detail`,
`isis.database`, `isis.interfaces`, `bgp.summary`, `bgp.neighbor.detail`,
`bgp.neighbor.received`, `bgp.neighbor.advertised`, `bgp.prefix`,
`bgp.dampening`, `logging.recent`, `logging.ospf`, `logging.isis`,
`logging.bgp`, `config.running`, `tech.support`, `hardware.environment`.
The shipped vocabulary is `classes.yaml`'s own `intents:` block — that list is
the authority, not this paragraph.

### Argument placeholders

A binding's command may carry ONLY these placeholders, and only where the
operator has supplied the value (an empty value collapses the token away):

| Placeholder | Filled from |
|---|---|
| `{if}` | the incident's interface |
| `{peer}` | the BGP/IGP neighbour address |
| `{prefix}` | the prefix under investigation |
| `{vrf-scope}` | the VRF/routing-instance qualifier, rendered per dialect |
| `{rid}` | a router / system id |
| `{area}` | an OSPF area id |
| `{vlan}` | a VLAN id |
| `{vni}` | a VXLAN VNI |

A vendor's own name for one of these concepts is folded onto the token by
`scripts/tac-merge-research.py` (`<network-instance>` → `{vrf-scope}`,
`<port-id>` → `{if}`, …). A placeholder that is NOT one of these is a value
Correlix has no source for — an IOS-XR `<loc>`, a slot, an NPU id, a session id —
and the binding is REFUSED rather than rendered unscoped, which would be either
invalid or fleet-wide.

Any other `{...}` token is treated as a LITERAL, so a typo fails closed (the
command simply never matches the closed table) rather than opening a wildcard.
This mirrors `internal/protocoldiag/commandtable.go`, deliberately.

---

## 3. Closed enums

```
protocol:  bgp | ospf | isis | interface | l2 | overlay | mpls | qos
           | hardware | system | config | generic
severity_hint (optional on a class): page | warning | info
```

Dialect slugs (file name = slug). A slug is the `internal/vendorprofile`
profile id — `<vendor>/<platform>` — with `/` → `-` and `_`/`-` removed inside
the platform segment:

| slug | profile id | display |
|---|---|---|
| `cisco-iosxe` | `cisco/ios_xe` | Cisco IOS-XE |
| `cisco-ios` | `cisco/ios` | Cisco IOS |
| `cisco-iosxr` | `cisco/ios_xr` | Cisco IOS-XR |
| `cisco-nxos` | `cisco/nx-os` | Cisco NX-OS |
| `cisco-asa` | `cisco/asa` | Cisco ASA |
| `arista-eos` | `arista/eos` | Arista EOS |
| `juniper-junos` | `juniper/junos` | Juniper Junos |
| `nokia-sros` | `nokia/sros` | Nokia SR OS |
| `nokia-srlinux` | `nokia/srlinux` | Nokia SR Linux |
| `huawei-vrp` | `huawei/vrp` | Huawei VRP |
| `fortinet-fortios` | `fortinet/fortios` | Fortinet FortiOS |
| `paloalto-panos` | `paloalto/pan-os` | Palo Alto PAN-OS |
| `mikrotik-routeros` | `mikrotik/routeros` | MikroTik RouterOS |

A dialect with no plan file is not an error — it is the **honest** path: the
plan says "no authored command set for this platform", offers the paste
fallback, and lists every intent as unbound.

---

## 4. `plans/<dialect>.yaml`

```yaml
schema_version: 1
dialect: cisco-iosxe
profile: cisco/ios_xe          # must match the slug's profile id (§3)
display: Cisco IOS-XE
version: correlix-tac-plan-cisco-iosxe-2026-09-05

# The dialect's DEFAULT citation set. A doc_claimed binding that names no
# `sources` of its own inherits these, so "where did this command come from"
# is always answerable without repeating one URL under two hundred bindings.
sources:
  - title: Cisco IOS XE Command References
    url: https://www.cisco.com/…
    retrieved: 2026-09-05

baseline:                      # every class gets this, in this order
  - system.version
  - system.inventory
  - platform.environment
  - interface.brief
  - logging.recent
  - config.running

optional:                      # opt-in, off by default (big/slow captures)
  - tech.support

bindings:
  system.version:
    command: show version
    verified: capture          # capture | doc_claimed   (see below)
    sources:
      - title: Cisco IOS Command Reference — show version
        url: https://www.cisco.com/...
        retrieved: 2026-09-05
  ospf.database.router:
    command: show ip ospf database router {rid}
    verified: doc_claimed
  tech.support:
    command: show tech-support
    verified: capture
    max_bytes: 4194304         # optional per-command override, clamped to the package ceiling
    timeout_s: 120             # optional, clamped to the package ceiling
```

### Field rules

- `command` — a single command line. It MUST pass
  `protocoldiag.ValidateReadOnly`: lead token in `show|display|get|info`, pipe
  segments are display filters only, no `;` `&` `|` chaining, no redirection,
  no substitution, no `debug` / `clear` / `configure` / `request` / `test` /
  `monitor` / `start shell`. **The loader refuses the file otherwise** — this
  is the safety boundary, and there is no override flag.
- `verified`
  - `capture` — we have run this exact command shape on this platform (lab
    capture, fixture, or a recorded collection) and it returned what we expect.
  - `doc_claimed` — taken from the vendor's published documentation but never
    executed here. **Shown to the operator as "documented, not verified"** in
    the plan preview, and stamped that way in the bundle MANIFEST.
  There is no third value. Unsure → `doc_claimed`.
  A binding is promoted to `capture` only when the command has ACTUALLY been run
  on that platform and the run is recorded — the Arista EOS plan's 13 `capture`
  bindings cite `docs/qa/scenarios/tac-escalation-2026-09-05.md`.
- `max_bytes` / `timeout_s` — optional per-command bounds. They can only
  NARROW: a value above the package ceiling is clamped, never honoured.
- `consent: true` + `consent_note` — the command is one the VENDOR'S OWN
  documentation says is not routine: SR OS `admin tech-support` is a core dump
  Nokia says needs their authorisation; Huawei `display diagnostic-information`
  measurably loads the control plane and writes a file; SR Linux `tech-support`
  writes a zip under `/tmp`. Such a binding is NEVER in a baseline, never runs by
  default, and the plan preview shows the vendor's caveat verbatim beside a
  consent control. `consent: true` without a note is a load error — the operator
  is being asked to approve something, so they are told what.
- `read_only_exception: <cited reason>` — the per-dialect DOCUMENTED-STATUS-READ
  allowlist. The read-only grammar judges a command by its lead token, and some
  vendors spell a pure status print with a token that reads like an action
  (FortiOS `diagnose debug crashlog read` prints a stored crash log). Naming the
  exception admits THAT command and nothing else: no prefixes, no wildcards, and
  every structural rule (no chaining, no redirection, display-only filters,
  closed placeholders) still applies. An exception with no `sources` is a load
  error, and `internal/tac`'s own test fails if the shipped allowlist grows past
  20 entries — it is a footnote to the grammar, not a second grammar.
- An intent present in `bindings` but absent from `classes.yaml`'s `intents:`
  is a load error (dangling binding).
- An intent a class asks for and this dialect does not bind is **not** an
  error: it renders as an unbound line in the plan preview.

---

## 4a. `forbidden.yaml` — the output-only command policy

**Owner decision, 2026-09-05, verbatim:**

> "Rules in executing commands, any command changing the config should be blocked
> or not even known to Correlix. Any command trying to restart or reboot should be
> unknown to Correlix. TAC usually need outputs to understand what is going on,
> not that we have to execute something and change."
> · "Ping and traceroute are good examples, should be allowed."
> · "Any commands that is touching at daemon level block them."

`forbidden.yaml` is that rule as DATA. Three families — `config`, `restart`,
`daemon` — with per-dialect rules and a cross-vendor `common:` block:

```yaml
common:
  - {family: 'restart', tokens: 'reload', why: 'reloads the device'}
dialects:
  - dialect: fortinet-fortios
    sources: [...]                      # a per-vendor rule MUST cite the vendor
    rules:
      - family: config
        tokens: execute                 # the FortiOS ACTION branch
        why: '…only the documented output-only leaves are exempt'
        except:                         # …and here they are, by name
          - execute ping
          - execute traceroute
          - execute log display
```

### How a rule matches

On **command tokens**, never on substrings. A rule's `tokens` must be the
command's LEADING tokens, so `reload` refuses `reload in 5` and leaves
`show reload cause` alone. `show` / `display` / `get` / `info` commands are
therefore safe by construction — **no rule may begin with a read verb, and the
loader refuses one that does.** A longer rule wins over a shorter one
(`execute reboot` beats `execute`); a DIALECT rule beats a `common:` rule of the
same length; an unrecognised dialect still gets every common rule.

### Where it is enforced (four places, none redundant)

| Where | What it does |
|---|---|
| `scripts/tac-merge-research.py` | refuses a forbidden record AT THE DOOR and reports **only a count per family** — the command text is never printed, written or kept |
| `scripts/tac-purge-forbidden.py` | removes forbidden records from `classes.yaml`, `plans/*.yaml` **and `research/*.yaml`**, and rewrites the `census:` block. `--check` is the CI mode |
| `internal/tac` loader | a plan carrying a forbidden command fails the load: the api does not boot with one |
| `internal/tac.Gate` | re-applies the policy to the RENDERED string as it would go on a wire, so a hand-edited plan file still cannot reach a device |

### `census:` — the count is known, the command is not

The purge writes what it excluded, per family and per dialect, and nothing else.
It is CUMULATIVE (a purge removes the commands, so a per-run count would fall
back to zero and claim the policy excluded nothing). Iris → Knowledge renders it
as "excluded by policy: N (config · restart · daemon)".

### `session_scoped:` — the one exemption

FortiOS `diagnose sys session filter …` and `execute log filter …` narrow what a
READ prints. They change no configuration, clear nothing, and the scope dies with
the CLI session, so the owner's rule does not bite. They are admitted ONLY from
this list, ONLY with the documented teardown, and a binding that uses one MUST
carry it:

```yaml
  session.filter:
    command: diagnose sys session filter dport 179
    verified: doc_claimed
    teardown: diagnose sys session filter clear     # required; the loader checks it
```

The collector runs the teardown right after the read — including after a failure
and after a cancellation — so a Correlix collection never leaves scope behind on
someone's firewall.

### Bounded probes — `ping` and `traceroute`

Allowed, NOT consent-gated, because the owner said so. They are not reads, so
they pass their own grammar (`internal/protocoldiag/probe.go`) rather than a hole
in the read-only one:

| Bound | Value |
|---|---|
| `count` · `repeat` · `-c` | ≤ 5 |
| `size` · `packet-size` · `datalen` · `-s` | ≤ 1500 |
| `timeout` · `wait-time` · `-w` | ≤ 5 s |
| `ttl` · `max-hops` · `hop-limit` · `-m` | ≤ 30 |
| `probe` · `probes` · `queries` · `-q` | ≤ 3 |

`flood`, `-f`, `sweep`, `rapid`, `pattern`, `interval`, `-i`, `continuous` are
refused **by name**. A probe with NO destination is refused — a bare `ping` opens
an interactive dialog on several platforms and would hang the session. `df-bit` /
`do-not-fragment` IS allowed: with the size capped at 1500 and the count at 5 it
cannot be a flood, and the DF probe is the standard path-MTU test. A bare number
(`ping 10.0.0.1 100`) is refused, because whether it is a count or a size cannot
be told from the string.

### PAN-OS tech-support

There is no read-only CLI form: `scp/tftp export tech-support` pushes a file to a
third-party host, which is a different trust model from a read. The intent stays
**unbound** — the plan says so rather than inventing a command — and the operator
generates the bundle from the PAN-OS GUI, or through the XML API
(`type=export&category=tech-support`) with their own key.

---

## 5. Citations (`sources`)

Allowed on a class, on a plan file (as the dialect's default set), on a single
binding, and on every research issue.

```yaml
sources:
  - title: <the page's own title, verbatim>
    url:   https://…            # https only; vendor/official docs preferred
    retrieved: YYYY-MM-DD
```

Citations are carried into the bundle MANIFEST so a TAC engineer can see where
a command came from. A `doc_claimed` binding must resolve to at least one source — its own, or the
plan file's top-level `sources`. The loader refuses the file otherwise.

---

## 6. `research/<vendor>.yaml` — the research hand-off

One file per vendor. It is INPUT: `scripts/tac-merge-research.py` merges it into
`classes.yaml` + `plans/*.yaml`. Nothing reads it at runtime.

The research files predate this document and use the research brief's schema.
That is the INPUT OF RECORD; the merge script reads it and translates.

```yaml
vendor: cisco-iosxe            # a DIALECT slug (the plan file it targets)

sources:                       # the file's citation set
  - title: "Quick Start Guide — Data Collection for Routing & Platform Issues"
    url: https://www.cisco.com/…

tac_baseline:                  # "what this vendor's TAC always asks for"
  commands:
    - {cmd: "show version", intent: system.version}
    - {cmd: "show tech-support", intent: tech.support, writes_file: false}
  notes: >-
    Prose about how the vendor wants the bundle collected.
  sources: [https://www.cisco.com/…]

issues:                        # 30–55 per vendor
  - id: ospfv2-neighbor-stuck-exstart-exchange
    class: ospf-adjacency      # an EXISTING class id …
    proposed_class: true       # … or this, when the concept is outside §2
    title: "OSPFv2 neighbor stuck in EXSTART/EXCHANGE (MTU mismatch)"
    symptoms: ["adjacency never reaches FULL"]
    log_signatures: ["%OSPF-5-ADJCHG"]     # verbatim; ESCAPED into detect.log_regex
    likely_causes: ["MTU mismatch — the most common cause"]
    commands:
      - {cmd: "show ip ospf neighbor detail", intent: ospf.neighbors.detail}
      - {cmd: "show ip ospf interface <if>", intent: ospf.interface.mtu, params: [if]}
    tac_first_look: >-
      What the vendor's own guide says to open first.
    sources: [https://www.cisco.com/…]
```

### What the merge script does (`scripts/tac-merge-research.py`)

Stdlib-only, **idempotent** (running it twice changes nothing), and it REFUSES
rather than guesses:

1. Rejects unknown top-level or per-record fields (typo = refusal, not silence).
2. Normalises placeholders: `<x>` → `{x}` through the alias table, folding each
   vendor's own name for a concept onto the token Correlix can fill. A
   placeholder with no alias is a value Correlix has no source for, and the
   record is refused rather than rendered unscoped.
3. Applies the read-only grammar, the cited documented-status-read allowlist, and
   an explicit refusal list (§7 below). Nothing that fails lands, in any form.
4. Normalises the ten cross-vendor CLASS SYNONYMS onto one canonical id each
   (`lacp-bundle`/`port-channel-lacp` → `lag-lacp`, `snmp-agent` → `snmp`,
   `l3vpn`/`l3vpn-vprn` → `mpls-l3vpn`, `environment` → the taxonomy's
   `hardware-fault`, …).
5. Escapes every `log_signatures` line into a literal `detect.log_regex` pattern
   — a vendor log line is matched as itself, never as an accidental wildcard.
6. Merges: new classes appended (only when the issue marks `proposed_class`),
   new intents appended to the vocabulary, new bindings added per dialect. An
   EXISTING binding is never silently overwritten — a conflicting command is
   reported and the existing binding kept, so a lab-verified `capture` binding
   survives every later merge.
7. Never adds a detection rule to the `generic` fallback class, and prunes a
   class whose every command was refused (it could neither fire nor collect).
8. Keeps every `sources` entry, deduplicated by URL.
9. Prints a per-file report: issues merged, intents and bindings added, consent
   bindings, cited exceptions, conflicts, and every refusal grouped by reason.

### What it refuses, and why (§7)

| Refusal | Reason |
|---|---|
| `ping`, `traceroute` | transmits from the device; W1's collector reads state, and an active probe needs its own consent path |
| `test authentication … password`, `diagnose test authserver` | takes a cleartext credential on the command line |
| `scp export …`, `tftp export …` | pushes a file to an arbitrary external host instead of returning output over Correlix's own channel |
| `diagnose sniffer packet` | a live capture with an operator-supplied BPF; belongs behind the Packet Capture module's closed BPF grammar |
| a placeholder with no alias | Correlix has no value for it, so the command could only run unscoped |
| a probe outside the bounds (`ping … repeat 100`, `… flood`, `… sweep`) | it is a packet generator, not a question |

Everything in the `config` / `restart` / `daemon` families (§4a) is handled
EARLIER and differently: the record is EXCLUDED, counted by family, and **never
named** — not in the report, not in the data, not in the research corpus.

Run it as `python3 scripts/tac-merge-research.py [--check]`. `--check` is the CI
mode: it exits non-zero if a merge would change anything, so the checked-in
taxonomy is always the merged one.

---

## 7. Where the referenced ids live

| Reference | Grep |
|---|---|
| alert name | `grep -n 'alert:' src/config/rules.yaml src/config/rules-scale-slo.yaml` |
| hypothesis template | `grep -o 'sig\.ent\.[a-z0-9.-]*' src/correlation/catalog.py \| sort -u` |
| protocoldiag signature | `grep -n 'ID: "' src/backend/internal/protocoldiag/analyze.go` |
| protocoldiag issue | `grep -n 'ID: "' src/backend/internal/protocoldiag/catalog.go` |
| Iris skill | `ls src/backend/ai/skills` |
| dialect / profile id | `ls src/backend/internal/vendorprofile/profiles` |

---

## 8. Non-negotiables

- **Output only, always** (owner, 2026-09-05). No `debug`, no `clear`, no
  `configure`, no `request`, no `reload`, no shell, and nothing that addresses a
  daemon — and not merely refused: **not carried**. §4a is the vocabulary; the
  merge, the purge, the loader and the gate are the four places it is enforced.
  The two things that are NOT reads and are still allowed are a bounded
  ping/traceroute and the two documented FortiOS session-scoped setters, each
  with its teardown.
- **No invented commands.** `doc_claimed` is the honest label for "the vendor
  documents it, we have not run it". Guessing is worse than an unbound intent.
- **No invented ids.** See rule zero.
- **Honest gaps.** A dialect with no plan, an intent with no binding, a class
  with no detection hit — every one of those is DISPLAYED, never hidden and
  never papered over with a fallback that pretends.

---

## 9. The YAML subset these files may use

There is no YAML module on the dependency allowlist (CLAUDE.md §6), so both
readers — `internal/tac/yamlmin.go` (Go, the runtime) and
`scripts/tac-merge-research.py` (Python, the merge) — implement the SAME small
subset. Stay inside it:

- block mappings `key: value` and `key:` + an indented block
- block sequences `- scalar` and `- key: value`
- **space** indentation only (a tab in the indent is an error)
- quoted scalars `'single'` (with `''` to escape a quote) and `"double"`
- block scalars `key: |` (literal) and `key: >` (folded)
- flow sequences `key: [a, b, c]` and flow mappings `- {title: x, url: y}`
- `#` comments, at the start of a line or after whitespace

**Refused, with the line number:** anchors, aliases, tags, multiple documents,
merge keys, complex keys, and flow collections nested inside flow collections.
A parser that silently ignored these would turn a typo into missing data; both
of ours fail the load instead.
