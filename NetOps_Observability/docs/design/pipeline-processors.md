# Pipeline Processors & the Sensitive Data Scanner

**Status: shipped.** Tenant-scoped, ordered, versioned log processing that runs
against incoming telemetry **before it is stored**, plus a free Sensitive Data
Scanner built on the same engine.

- UI: **Administration ▸ Data Collection ▸ Pipeline Processors**
- API: `/api/pipeline/processors` (`administration:admin`, tenant-scoped)
- Code: `src/backend/processors/` (domain) · `src/backend/pipeline_processors.go`
  (HTTP + config writer) · `src/frontend/src/tabs/ProcessorsAdmin.tsx` (UI)
- Migrations: 0032 (table) · 0033 (framework) · 0034 (type CHECK removal)

---

## 1. What it does, in one paragraph

By default the platform stores every event exactly as it arrives — processors
are **optional**. When a tenant declares one, it runs at ingest against that
tenant's events only, in a declared order, and can redact, mask, hash, tag,
remove a field, or drop the event. Changes take effect on the live pipeline in
about a minute with no restart, and a bad configuration can never take the lane
down: the runtime keeps the previous topology if a generated config fails to
load.

## 2. Architecture — "Go owns the model, Vector executes"

```
Go Pipeline Engine  (source of truth)
  ├─ Processor model        rule.go
  ├─ Matcher registry       registry.go   ─┐ one definition per plugin:
  ├─ Action registry        registry.go   ─┤ validate + compile + evaluate
  ├─ Managed-rule catalog   managed.go     │
  ├─ Simulator (dry run)    simulate.go   ─┘ (compiler and preview read the
  └─ Compiler → VRL         generate.go      SAME definition twice)
                    │
                    ▼   data/api/processors/router/processors.yaml
        vector-router  --config … --watch-config
                    │   per lane: <lane>_rules_apply → <lane>_rules (drop filter)
                    ▼
             OpenSearch · ClickHouse
```

Why the engine compiles to Vector instead of processing in Go: the backend has
**no Kafka client by design** (CLAUDE.md §6), so an inline Go stage would mean a
new service and a new dependency. Compiling to the executor already in the path
costs neither, and inherits hot reload plus fail-safe rollback.

**The anti-drift invariant.** Every matcher and action defines its validation,
its VRL compilation *and* its Go evaluation in one registry entry. The compiler
and the dry-run simulator both dispatch through it, so "what the preview showed"
and "what the pipeline does" are one definition read twice. `TestFieldAllCompilesAsASweep`
and `TestEveryRegisteredPluginCompilesAndEvaluates` pin that.

## 3. Processor model

| Field | Meaning |
|---|---|
| `name` | operator-facing label ("Redact customer emails") |
| `lane` | `applogs` · `syslog` · `snmptrap` · `cloudlogs` · `flows` |
| `type` | the action (§4) |
| `field` | target dot-path (`message`, `user.email`), or `*` = every string |
| `keys` | field NAMES to redact (key-scoped actions) |
| `pattern` / `pattern_kind` | `builtin` (managed rule id) · `literal` · `regex` |
| `replacement` | token written by redact/mask/tag (default `***`) |
| `keep_last` | mask tail length (default 4) |
| `match` | optional guard (§5) |
| `order` | execution priority, ascending |
| `enabled` · `version` · `source` | lifecycle; `source` = `custom` \| `managed` |

**Execution order** is total: `order` → `created_at` → `id`. The same rule set
always compiles byte-identically, which is what lets the writer skip a rewrite
when nothing changed (so `--watch-config` never sees a phantom reload).

## 4. Actions

| Action | Effect | Example |
|---|---|---|
| `redact_pattern` | replace pattern matches inside a field (or every field) | `jsmith@corp.com` → `[EMAIL]` |
| `redact_field` | replace the whole value | `hostname` → `[HOST]` |
| `redact_keys` | replace values of fields **named** like a secret | `"password":"hunter2"` → `"password":"[REDACTED]"` |
| `mask` | keep the last N characters | `4111111111111111` → `************1111` |
| `hash` | stable 16-char SHA-256 digest — unreadable but still **joinable** | `alice` → `2bd806c97f0e00af` |
| `tag` | **detect only**: stamp `cx_sensitive[]`, change nothing | adds `["PCI"]` |
| `drop_field` | delete the field | `password` gone |
| `drop_event` | drop the whole event (guard required) | `level=debug` discarded |

Two notes that matter operationally:

- **`hash` preserves correlation.** Redaction destroys the ability to ask "all
  events from this user"; hashing keeps it while storing nothing readable.
- **`tag` is how you roll out safely.** Run detectors in tag mode first, look at
  where `cx_sensitive` appears, *then* decide what to redact. Nothing is
  destroyed while you learn.

**`drop_event` requires a match condition** — an unguarded drop would discard an
entire lane. Dropped events are counted, never routed to the dead-letter index:
a deliberate drop is not a pipeline failure.

## 5. Matchers

| Matcher | Meaning | Example |
|---|---|---|
| `equals` | exact value | `severity == "critical"` |
| `attribute` | exact value, operator vocabulary | `service == "authentication"` |
| `contains` | substring | `message contains "LOGGINGHOST"` |
| `prefix` | starts-with | `hostname` starts with `homedepot` |
| `regex` | RE2 pattern | `parser_id` matches `^ios_style\.v[0-9]+$` |

Matchers read **JSON paths**, so `fields.vlan` and `request.headers.authorization`
work. Omitting the match applies the processor to every event in the lane.

## 6. Sensitive Data Scanner — the managed rules

16 curated detectors ship free. They are **read-only and versioned**; a tenant
clones one to get an editable processor of their own. Cloning produces an
ordinary processor that runs through the same engine — there is no second
execution path.

| Rule | Category | Catches | Scope |
|---|---|---|---|
| `email` | pii | `jsmith@corp.com` | content |
| `ipv4` | pii | `10.70.245.12` | content |
| `ipv6` | pii | `2001:db8::1` | content |
| `mac` | pii | `AA:C1:AB:E2:57:01` | content |
| `us_ssn` | pii | `123-45-6789` | content |
| `phone_e164` | pii | `+1 415 555 0132` | content |
| `credit_card` | financial | `4111 1111 1111 1111` | content (Luhn pending) |
| `iban` | financial | `DE89370400440532013000` | content (mod-97 pending) |
| `jwt` | secret | `eyJhbGci….eyJzdWI….sig` | content |
| `aws_access_key` | secret | `AKIAIOSFODNN7EXAMPLE` | content |
| `private_key` | secret | `-----BEGIN RSA PRIVATE KEY-----` | content |
| `snmp_community` | secret | `community=public` | content |
| `secret_in_text` | secret | `password=hunter2` in a message | content |
| `password_field` | secret | fields **named** `password`, `api_key`, `token`, … | **key** |
| `bearer_token` | auth | `Bearer sk-live-9f8e…` | content |
| `basic_auth_url` | auth | `https://user:pass@host` | content |

### Content scope vs key scope — the distinction that makes them work

A **content** detector matches the *value*. A **key** detector matches the
*field name*. This is not a nicety: in a real application log the secret is
`"password": "hunter2"`, and the value `hunter2` on its own matches no pattern
in existence. Only key-scoped redaction catches it. (This was found by running
the detectors against live documents — the earlier value-only `password_field`
silently did nothing, which is exactly what "the managed rules don't match
anything" looked like from the UI.)

### `*` — scan every field

Content detectors default to `field: *`, a recursive sweep of every string in
the event. Also not a nicety: in this platform's own traps the MAC lives in
nested `fields.mac` and the address in `host` — **never** in `message`. A
detector pointed only at `message` finds nothing.

The sweep **preserves pipeline-owned fields** (`tenant_id`, `tenant_seg`,
`tenant_attribution`, `log_index_base`, `ts`, `ts_source`, `ts_invalid`,
`timestamp`, `topic`) by saving and restoring them around the sweep, so a
content rule can never rewrite tenancy, time or index routing.

## 7. Worked examples

**A. Redact emails everywhere in syslog**

```json
{ "name": "Redact emails", "lane": "syslog", "type": "redact_pattern",
  "field": "*", "pattern_kind": "builtin", "pattern": "email",
  "replacement": "[EMAIL]", "order": 10 }
```
```
before  message: "%SYS-6-…: admin jsmith@homedepot.com from 10.70.245.12"
after   message: "%SYS-6-…: admin [EMAIL] from 10.70.245.12"
```

**B. Redact secret-named fields (key scope)**

```json
{ "name": "Secret fields", "lane": "applogs", "type": "redact_keys",
  "keys": ["password","api_key","authorization","token"],
  "replacement": "[REDACTED]", "order": 20 }
```
```
before  {"password": "hunter2", "headers": {"authorization": "Bearer x"}}
after   {"password": "[REDACTED]", "headers": {"authorization": "[REDACTED]"}}
```
Reaches one level into `fields`, `body`, `headers`, `attributes`, `labels`,
`params` — the containers real telemetry nests payload under.

**C. Mask a card, keep the last four**

```json
{ "lane": "applogs", "type": "mask", "field": "card", "keep_last": 4, "order": 30 }
```
```
before  card: "4111111111111111"      after  card: "************1111"
```

**D. Hash a username so it stays joinable**

```json
{ "lane": "applogs", "type": "hash", "field": "user", "order": 40 }
```
```
before  user: "alice"      after  user: "2bd806c97f0e00af"   (stable across events)
```

**E. Tag first, redact later (safe rollout)**

```json
{ "lane": "applogs", "type": "tag", "field": "*",
  "pattern_kind": "builtin", "pattern": "credit_card", "replacement": "PCI", "order": 5 }
```
```
before  message: "card=4111 1111 1111 1111"
after   message: "card=4111 1111 1111 1111"   ← unchanged, by design
        cx_sensitive: ["PCI"]
```

**F. Drop debug noise from one service**

```json
{ "lane": "applogs", "type": "drop_event", "order": 90,
  "match": { "field": "level", "op": "equals", "value": "debug" } }
```

**G. Conditional redaction (matcher + action)**

```json
{ "lane": "syslog", "type": "redact_field", "field": "user", "replacement": "[USER]",
  "match": { "field": "parser_id", "op": "regex", "value": "^ios_style\\.v[0-9]+$" } }
```

## 8. Dry run

`POST /api/pipeline/processors/preview` (the wizard's step 4) runs the tenant's
**saved** chain, in order, through the same engine — never a parallel preview
implementation. It reports the original event, the shaped event, which
processors fired (by display name and managed-rule name), and whether the event
would be **dropped**. Nothing is stored and the pipeline is untouched.

## 9. Ordering, versioning, metrics

- **Order** — ascending `order`, ties by age then id. Deterministic.
- **Versions** — every save appends an immutable snapshot (`processor_versions`).
  Rollback writes the old config **forward** as a new version: an audit trail you
  can rewind is not an audit trail. Retention is bounded (50/processor).
- **Metrics** — each processor that fires appends its id to `cx_applied`, and a
  `log_to_metric` transform turns that into a per-processor counter on the
  router's existing Prometheus exporter. No per-event execution-log row, which
  at ingest volume would cost more than the processing itself.

## 10. Security posture

- **Tenant isolation** — every action compiles with a tenant guard from the
  server-stamped owner; storage is FORCE-RLS; cross-tenant ids return 404.
  A processor can never touch another tenant's events.
- **No free-form VRL.** Rules are structured. User input reaches the generated
  config only as an escaped string literal or a validated RE2 pattern.
- **Custom regex is allowed** because both engines are RE2-family — linear time,
  no backtracking — so catastrophic backtracking is structurally impossible. The
  bar is compile-correctness, length (256) and capture-group count (9).
- **Protected fields** cannot be targeted, and sweeps restore them.
- **Findings never carry the raw secret** (the detector interface returns a
  redacted sample).

## 11. Verification

`processors/reallogs_test.go` is the acceptance suite. Its fixtures are **actual
documents** captured from the running stack (`netops-syslog-*`,
`netops-applogs-*`, `netops-snmptrap-*`) seeded with sensitive values. It asserts
every managed rule removes its target and writes its token, every action behaves
on a real document, every matcher fires and misses correctly, and a full ordered
chain leaks nothing.

The generated config is additionally **boot-validated against the real Vector
binary** (`scripts/preflight-configs.sh`, and by hand for every action). That
check has caught four production bugs unit tests could not:

1. VRL 0.40 has no `repeat()` — the first mask implementation would have failed
   to load the entire lane's config.
2. RE2 has no lookaround — a negative-lookahead SSN pattern panicked at init.
3. Vector interpolates `$` in config files — a regex end-anchor or a `$1`
   capture reference would have taken every tenant's processors down.
4. A whole-event sweep compiled to the single-field form (`.*`), which is
   invalid VRL, while the simulator previewed it correctly — the exact
   compile/simulate drift the registry exists to prevent.

## 12. Known limitations (deliberate)

- **Correlation signals are not shaped.** Processors run in the router, the
  terminal writer for stored data. The correlation engine consumes the Kafka
  topics *upstream*, so `corr_signals` derived from raw telemetry are unshaped.
- **Checksum validation is declared, not implemented.** `credit_card` (Luhn) and
  `iban` (mod-97) carry a `checksum` marker and report < 1.0 confidence through
  the detector interface; the validator itself is future work. Regex-shape
  matching is the current behavior, chosen deliberately: for a redactor a false
  positive costs one masked string, a false negative leaks a card number.
- **Key-scoped redaction reaches one level** into the known containers, not
  arbitrary depth (VRL cannot express unbounded key recursion).
- **Metrics-only and probe lanes** never traverse a storage hook, so they are
  out of scope by construction.

## 13. Extending the engine

Adding a matcher or action is **one `Register` call** in `registry.go` — the
validator, the compiler, the simulator, the API catalog and the UI wizard all
pick it up automatically (the wizard renders from `/catalog`, the engine's
self-description). Future SDS detectors that cannot run at the edge (ML,
cross-field correlation) implement `SensitiveDataDetector` and return `""` from
`CompileVRL`; the engine then knows to evaluate them service-side without any
caller learning the difference.
