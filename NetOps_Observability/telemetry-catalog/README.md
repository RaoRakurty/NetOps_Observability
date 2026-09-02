# Telemetry Catalog — the load-bearing replacement for MIB templates

A source-agnostic, **validated-fidelity** catalog of how this product collects and
normalizes telemetry across vendors/platforms/versions. The governing principle:

> **Validated fidelity is the product truth — not vendor documentation.**
> A path that exists in a vendor model but doesn't actually stream is *worse* than
> no path: it reads as covered and fails silently. So no row is "supported" until
> a captured fixture proves it normalizes correctly.

## The three catalogs + shared identity

| File | Role |
|------|------|
| `identity.yaml` | **Shared identity model** — canonical entity keys (device, ifName, vrf, peer, …) + the raw per-vendor aliases that reconcile to them, so metrics + events + flows join on the same identity. |
| `collection.yaml` | **Collection catalog** — `(vendor, platform, os_version, signal_family, method, path/OID/API, mode, interval)` → **fidelity_status**, last_validated, fixture, cost. |
| `normalization.yaml` | **Normalization catalog** — raw → canonical `device_*` (path match, enum map, unit, label set, **owner transport**, dedup key). Applied by `normalize.py` (code-owned, tested) — NOT buried in gnmic YAML. |
| `events.yaml` | **Event/parser catalog** — syslog/trap grammars → canonical event schema, AND (since A3) the EXECUTABLE rule table the correlation engine's parser runs. |

## Fidelity ladder (collection.yaml `fidelity_status`)

`doc_claimed` → `lab_validated` → `live_validated` → `degraded` → `failed`

- **doc_claimed** — a reference says it exists; untested. *Candidate, not supported.*
- **lab_validated** — a captured fixture replays to correct canonical output in CI.
- **live_validated** — confirmed flowing end-to-end on the live lab.
- **degraded** — works in some conditions, fails in others (must carry `issue_ref`).
- **failed** — claimed by docs but proven not to work (must carry `issue_ref`).

Only `lab_validated` / `live_validated` may be advertised as supported.
**See the `arista/ceos … device_bgp_peer_state … degraded` row** (`ceos-bgp-gnmi-issue.md`)
— established BGP not delivered under a persistent multi-target subscription. That
row is exactly why this catalog exists.

### What the ladder does NOT say: correlation delivery

`fidelity_status` grades ONE thing — whether the (vendor, platform, signal-family)
row's path collects the correct canonical value. It says nothing about which
*consumer* receives it. Until now that distinction was invisible, because every
gNMI row had exactly one destination: VictoriaMetrics.

As of 2026-09-02 gnmic can also produce canonical MetricEvents to the correlation
bus (`netops.metrics`) — `deployment/docker/gnmic/gnmic-correlation.yaml`, gated
by `ENABLE_GNMI_CORRELATION` / `GNMIC_CONFIG_FILE` and **off in every shipped
profile**. That lane is CONFIGURED AND FIXTURE-PROVEN, **not live-attested**: no
deployment has yet been observed turning a gNMI sample into a `corr_signals` row.

So **no row's `fidelity_status` was promoted, and no `delivery:` column was
added.** Adding a `delivery: victoria | victoria+correlation` attestation column
here would be a claim about a path this catalog has not seen work, which is
exactly the failure mode the ladder exists to prevent (the cEOS BGP row above).
The column lands when a live run shows the signal, together with the rows it
actually covers — which, given the ownership gate, will be the gNMI-OWNED
families only (BGP session state / FSM transitions, Nokia SRL memory), not the
interface or CPU/temperature rows that SNMP owns.

Status meanwhile: `docs/TEST_REPORT_metric-trap-lane.md` and `docs/INGESTION.md`.

## Tooling

```bash
cd telemetry-catalog
python3 catalog.py          # invariant check (fidelity ladder, owner collisions, fixtures exist)
python3 conformance.py      # replay validated fixtures through normalize.py, assert canonical output
python3 -m pytest -q        # invariants + conformance + explicit canonical anchors
```

`conformance.py` is the gNMI analogue of LibreNMS `.snmprec` replay: capture real
subscribe streams (`fixtures/*.jsonl`), replay through the engine, assert the
contract. This is how a `doc_claimed` row earns promotion to `lab_validated`, and
the regression guard that keeps the catalog honest.

## Phasing

- **Phase 1 (done)** — schema + harness + 3 validated families: interfaces (oper/admin status), BGP peer-state, memory.
- **Phase 2 (done)** — event/parser catalog (`events.yaml` + `parse_events.py`): BGP/OSPF adjchange + link-state syslog grammars → canonical event schema, sharing the identity model. Each event family declares `correlates_with` + `join_on` so events ⨝ metrics on the same identity (a BGP adjchange event joins `device_bgp_peer_state` on `(device, peer)`). It is the authoritative spec for the correlation engine's `src/correlation/producers.py`. Firewall fw_event schema (PAN/FortiOS) lands with Phase 3.
- **Phase 3** — import P1–P5 research rows as `doc_claimed` candidates (OSPF/ISIS/BFD/MPLS/LDP/IPsec/QoS/SD-WAN/firewall).
- **Phase 4** — validate vendor-by-vendor; promote rows to `lab_validated`.

### Event catalog tooling
```bash
python3 -m pytest test_events.py -q      # grammar parsing + the correlation invariant
python3 -m pytest test_bake_rules.py -q  # the rule table + its bake
python3 -m pytest test_trap_rules_a9.py -q   # the trap rows, replayed through the producer
python3 bake_rules.py                    # regenerate src/correlation/parser_rules.py
python3 bake_rules.py --check            # CI drift guard (exit 1 if stale)
python3 coverage_matrix.py               # regenerate docs/design/telemetry-coverage-matrix.md
python3 coverage_matrix.py --check       # CI drift guard for that artifact
```
`catalog.py` also validates the event catalog: every event family must declare a
`join_on` of canonical identity keys it actually produces. An event whose paired
metric is a not-yet-built Phase-3 family is printed as a tracked forward-reference,
not a failure.

---

## A3 — the catalog IS the parser

Until A3, `events.yaml` was a **spec** that `src/correlation/producers.py`
mirrored by hand: one `if` branch per family, one copy of every regex on each
side, and nothing that could tell you when the two disagreed. (They did — see
*The one declared divergence* below.) Now the catalog **is** the parser:

```
events.yaml  rules[]            ← the single source of truth
      |
      |  bake_rules.py                (validate → compile → generate)
      v
src/correlation/parser_rules.py       GENERATED, checked in, drift-guarded
      |
      +--> producers.classify()       runtime: raw event → Signal
      +--> parse_events.parse_event() conformance: raw event → canonical event
```

**Why a bake and not a runtime read.** The correlation image copies
`src/correlation/` only (`deployment/docker/Dockerfile.correlation`);
`telemetry-catalog/` is a repo artifact and is not shipped. A runtime YAML read
would resolve to the real rules in tests and to *nothing* in production. So the
table is compiled at development time into a checked-in module, and CI proves
the two agree (`bake_rules.py --check`, plus `test_bake_rules.py` here and
`test_parser_interpreter_a3.py` in the engine).

**Adding a symptom is a ROW plus a fixture**, never a code branch.

### Rule row schema

| Field | Meaning |
|-------|---------|
| `rule_id` | Stable id — the Prometheus label and the provenance stamp on every signal. Fixed set: no device string can widen it. |
| `lane` | `syslog` \| `trap` \| `port` \| `catalog`. The first three are producer lanes and are baked into the image; `catalog` is conformance-only (a family the canonical schema covers and no correlation lane consumes yet — the NGFW rows). |
| `source` | The wire `Source` stamped on the Signal: `syslog` \| `trap`. |
| `kind` | The emitted Signal kind (∈ `producers.EMITTED_KINDS` for syslog/trap). |
| `entity_type` | `device` \| `interface` \| `device_or_interface` — the declared scope. |
| `family` | The event family it implements → fidelity ladder + canonical `event_type`. `null` = a grammar with no family; it stamps fidelity `code` and the conformance reader skips it. |
| `vendors` | The vendor grammars the rule targets (documentation + audit). |
| `markers` | UPPER-CASE classification-token literals the guard tests — **the ingest pre-filter is derived from these** (`producers._CP_GUARD_MARKERS`). |
| `pattern_src` | The message regex the guard tests, as source text; the screen's other half. Must occur as a live `re` node of the row's own `guard` — the bake refuses it otherwise. |
| `severity` | A fixed severity, when the rule has one. |
| `state` / `state_re` | The fixed state / the regex it derives state with (provenance + digest metadata). |
| `generic` | The unclassified severity-floor safety net (#80 §4), counted apart from typed rules in the promotion rate. |
| `fidelity_status` | **A9** — this ROW's own rung on the ladder, for a rule whose symptom is already a family but whose grammar is evidenced differently from the family's other rules (a TRAP twin of a syslog symptom is exactly that). It WINS over the family lookup, and it is a CATALOG claim, so it never enters `rules_hash`. |
| `shadow` | **A8** — evaluated and COUNTED (`corr_parser_shadow_hits_total{rule_id}`), emits nothing, falls through. How a candidate grammar earns promotion on real traffic before it is allowed to produce evidence. |
| `guard` | The boolean tree that decides whether the rule fires. |
| `extract` | Named field extractions — **lazy and memoized**, so a row can carry a grammar only the conformance reader needs without taxing ingest. |
| `emit` | `kind`, `metric`, `modality`, `entity{type,id,when,else}`, `severity`, `native_id`, `content_tag`, `tokens`, `attrs`. |

**Guard nodes** — `{all: […]}` `{any: […]}` `{not: n}` `{always: b}`
`{contains: [FIELD, "LIT"]}` `{re: [FIELD, "pat", FLAGS]}` `{eq|ne: [FIELD, v]}`
`{equals_any|not_in: [FIELD, [...]]}` `{truthy: FIELD}` `{var_true: name}`
`{severity_floor: syslog|trap}`.

**FIELD** is a lane haystack or `$var` (an extraction, run lazily):

| Lane | Haystacks |
|------|-----------|
| `syslog`, `catalog` | `msg`, `msg_u`, `tag`, `ctoken`, `ctoken_msg_u` |
| `port` | `pctoken`, `msg` |
| `trap` | `oid`, `name`, `etype` |

**Extraction specs** — `{const: v}` `{field: F}` `{var: n}` `{lane: n}`
`{ev: [k1, k2]}` (raw event keys, first truthy) `{re: [[F, pat, group, flags], …]}`
(first alternative) `{findall: [F, pat, flags]}` `{nth: [listvar, i]}`
`{vb: [oid…]}` / `{vbname: [substr…]}` (SNMP varbinds)
`{pick: {find: […], reject: […]}}` `{alt: [spec, …]}` `{bool: guard}`
`{case: [{when: guard, value: template}]}` `{template: "…"}` `{severity_num: true}`
`{scan: {target, target_order, order, field, default, target_scope,
target_fallthrough}}` — the state primitive. Any spec also takes `lower: true`
and `slice: N`.

**Templates** are `{var}` and `{var|default}`. A token whose vars are all empty
is **dropped**, never rendered as a stub; `local: true` qualifies a
DEVICE-LOCAL name as `<device>:<name>` (tracker 168 — a bare `Gi0/5` welded
every switch in the estate into one RCA object).

### The one declared divergence

`bgp_adjacency_change` declares `new state (\w+)` as its transition target with
`target_scope: catalog`. The conformance reader honours it (a flap *into*
Established is an `up`); the executable rule does not, because consulting it
would re-classify every "old state X new state Y" line already stored. The
defect is **recorded in the row** rather than hidden in a second grammar, and
`test_parser_interpreter_a3.py` pins the list of such divergences at exactly
one, so a new one cannot appear quietly.

## Relationship to the runtime

The gnmic canonical lane (`deployment/docker/gnmic/gnmic.yaml`) is a *derived
runtime applier* of these same rules. `scripts/audit_metric_contract.py` already
checks the gnmic lane against the emitted contract; the catalog is the authoritative
spec it must agree with. Capturing fixtures: `gnmic ... subscribe --format event`.


---

## A9 — the trap-coverage audit, and the coverage matrix

A9 asked of every syslog symptom the parser types: *does a standard or vendor
trap carry the same symptom, and if so does it produce the same evidence?*
Before it, the trap lane typed three families and swept everything else into the
generic `device_alarm`, so an OSPF adjacency loss reported by
`ospfNbrStateChange` and the same loss reported by `%OSPF-5-ADJCHG` were two
different kinds — the trap could not corroborate the syslog line.

**The contract a promoted trap rule signs.** It emits the SAME `kind`, entity
shape and `state` vocabulary as its syslog counterpart, so the engine sees one
symptom and two observers (the modality stays `control_plane`; only the `Source`
and the observer's collection path differ). It never invents a kind: a kind no
signature template names is inert evidence. `src/correlation/
test_trap_syslog_parity_a9.py` is the pairing table that pins it, driven by
`fixtures/trap_events.jsonl` — each fixture carries the trap AND the syslog line
for the same symptom.

**The anti-fabrication rule.** A guard may test an OID only when that OID
resolves in the vendored MIB index (`make mib-index`, generated by pysmi from
real MIB modules). A symptom whose MIB is not vendored is matched on the
MIB-decoded `event_type` instead, so vendoring the module later makes it
classify with no rule edit. `test_trap_rules_a9.py` enforces both halves.

**The artifact.** `coverage_matrix.py` generates
`docs/design/telemetry-coverage-matrix.md` — symptom × source (syslog / trap /
metric episode) × vendor × fidelity — from these rows plus the metric-episode
lane reconstructed from the collector's RCA allowlist and `metric_identity`.
It is the answer to "what does Correlix recognize?", it is drift-guarded, and
the two Go/engine tables it mirrors are re-derived and compared in
`test_coverage_matrix.py`.
