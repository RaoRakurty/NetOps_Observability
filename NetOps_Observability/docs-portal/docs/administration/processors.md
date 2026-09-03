---
title: Create a pipeline processor
sidebar_label: Processors
description: Build a rule that masks, drops, hashes or tags a field before it is stored, and preview it against a real event first.
page_type: task
sidebar_position: 10
---

# Create a pipeline processor

A processor shapes telemetry on its way in. It runs at the edge, before the event reaches storage, so a value a processor removes is never written anywhere. Use one to keep a secret out of an index, to cut a noisy field, or to detect sensitive data without changing anything while you decide what to do about it.

## Before you begin

- **Permission:** `administration:admin`. Processors are per-tenant data. The list, the preview and every write are filtered to your tenant, another tenant's processor id answers `404`, and the owning tenant is stamped from your token rather than from the request body.
- **Flag:** `FEATURE_PROCESSORS`, default `true`. It is reported by `GET /api/features`. The routes are served whether or not it is set, because the rules persist regardless; the flag does not disable the API.
- Console path: **Administration → Data Collection → Processors**. The panel is titled **Pipeline processors**.
- Have a real event to preview against. A preview with an invented event proves nothing.

## What a processor is made of

| Field | What it holds |
| --- | --- |
| `lane` | Which stream the rule runs on: `applogs`, `syslog`, `snmptrap`, `cloudlogs`, `security` or `flows`. |
| `type` | The action to take. |
| `field` | The dotted path the action targets, or `*` for every string in the event. |
| `pattern`, `pattern_kind` | The pattern for pattern actions. `pattern_kind` is `builtin`, `literal` or `regex`. |
| `replacement` | The token written in place of a match. Defaults to `***`. |
| `keys` | The key names a key-scoped redaction targets. |
| `match` | An optional condition, as `{field, op, value}`. |
| `order` | Where the rule sits in the chain. A new rule runs last. |
| `enabled` | Defaults to `true` when omitted. |
| `version` | Increments on every saved edit. |

Ten actions are registered. The catalog at `GET /api/pipeline/processors/catalog` is the engine describing itself, so the wizard always offers exactly what the engine implements.

| Action | Label in the console | What it does |
| --- | --- | --- |
| `redact_field` | Redact field | Replaces the field's value with the replacement token. |
| `redact_pattern` | Redact pattern | Replaces every match of the pattern inside the field. |
| `redact_keys` | Redact by field name | Replaces values by key name rather than by content. |
| `mask` | Mask | Masks the value, keeping the trailing characters you ask for. |
| `drop_field` | Remove field | Removes the field entirely. |
| `set_field` | Set field | Writes a fixed value. |
| `hash` | Hash | Replaces the value with a stable digest. |
| `tag` | Tag (detect only) | Records that the pattern matched and leaves the value alone. |
| `drop_event` | Drop event | Discards the whole event. |
| `seal` | Seal (reversible) | Encrypts the value under the tenant's key. See [Review sensitive-data access](/administration/sensitive-data-access). |

Five matchers are registered: `equals`, `contains`, `prefix`, `regex` and `attribute`.

**A drop must be guarded.** A `drop_event` rule without a `match` condition is refused, because an unguarded drop would discard the whole lane.

**Custom patterns are accepted and validated.** A pattern is at most 256 characters, printable, and holds at most 9 capture groups. A single quote is refused outright. Both the preview engine and the edge engine are RE2-family, which evaluate in linear time, so catastrophic backtracking is structurally impossible and a hand-written pattern cannot stall the pipeline.

A tenant holds at most 200 processors. Replacement tokens are at most 64 characters, printable, and on one line.

## Steps

### Write and preview a rule

1. Open **Administration → Data Collection → Processors**.
2. Create a processor and pick the **lane**, the **action** and the **field**.
3. For a pattern action, choose a managed detector or write your own pattern.
4. For a `drop_event`, add the **match** condition it requires.
5. Preview it against a real event before saving. The preview posts to `POST /api/pipeline/processors/preview` with the lane, the event and the unsaved draft, and returns:

   | Field | Meaning |
   | --- | --- |
   | `original` | The event as you supplied it. |
   | `event` | The event after the whole chain ran. |
   | `applied` | Which rules actually changed something. |
   | `dropped` | Whether the event was discarded. |

   The draft is included in the chain, so you see what the rule you are writing does rather than only what the saved rules do. The sample is stamped with your tenant the way the router's enrichment stamps a real event, so the tenant guard behaves as it will in production.
6. Save. The rule takes effect at the edge within about a minute, with no restart.

Every matcher and every action defines its validation and both of its evaluators in one place, the processor registry. The compiler that generates the edge configuration and the simulator behind the preview both dispatch through the same registry entries, so what the preview showed and what the pipeline does cannot drift apart.

One nuance is worth knowing. Key-scoped redaction recurses to any depth in the preview, while at the edge it reaches the top level plus one level inside `fields`, `body`, `headers`, `attributes`, `labels` and `params`. Those are the shapes real telemetry nests payload under. A key buried deeper than that is redacted in the preview and not at the edge.

### Roll a rule back

Every save appends an immutable version, and the history holds the newest 50 per processor.

1. Open the processor's version history, or `GET /api/pipeline/processors/{id}/versions`.
2. Roll back with `POST /api/pipeline/processors/{id}/versions/{n}`.

A rollback does not rewind the chain. It writes the old configuration forward as a new version, because an audit trail you can rewrite is not an audit trail.

The generation step is fail-safe in two places. If the edge configuration cannot be generated, the API returns before writing anything and the last known-good configuration stays live. If a generated configuration fails to load, the edge keeps its previous topology rather than dropping the lane.

## The sensitive-data scanner

Sixteen curated detectors ship with the product. They are read-only: you enable one, or clone it into a processor you own, and you cannot edit the shipped pattern. Each carries its own version, which bumps when its pattern changes.

| Id | Category | Detects |
| --- | --- | --- |
| `aws_access_key` | secret | AWS access key ids |
| `basic_auth_url` | auth | A user and password embedded in a URL |
| `bearer_token` | auth | Authorization bearer tokens |
| `credit_card` | financial | 13 to 16 digit card numbers, Luhn-checked |
| `email` | pii | Email addresses |
| `iban` | financial | International bank account numbers, mod-97 checked |
| `ipv4` | pii | Dotted-quad addresses |
| `ipv6` | pii | IPv6 addresses |
| `jwt` | secret | JSON web tokens |
| `mac` | pii | MAC addresses |
| `password_field` | secret | A secret held as the value of a named key |
| `phone_e164` | pii | Phone numbers in E.164 shape |
| `private_key` | secret | Private key blocks |
| `secret_in_text` | secret | A secret assignment in free text |
| `snmp_community` | secret | SNMP community strings |
| `us_ssn` | pii | US social security numbers, area-checked |

Three of the actions matter most when rolling detection out.

- **`tag` detects and changes nothing else.** It leaves the matched value exactly as it was and appends the replacement token to a `cx_sensitive` array on the event. Start here: you learn where sensitive data actually is, on real traffic, with no risk of destroying a field an operator needs.
- **`hash` replaces the value with a stable digest.** It is the first 16 hexadecimal characters of a SHA-256 of the value. The same input always yields the same token, so events from one subject still join together after hashing. The digest is unsalted and truncated, so treat it as unreadable-but-joinable rather than as irreversible: a low-entropy value such as an email address or a phone number can be recovered by anyone who can guess candidates and hash them.
- **`redact_keys` works by key name.** This is what `password_field` compiles to.

### Why `password_field` is key-scoped

A real application log carries the secret as the value of a named field, as in `"password": "hunter2"`. The value on its own matches no secret pattern, so a content detector sees nothing. `password_field` therefore matches on the key name instead, case-insensitively, over this set: `password`, `passwd`, `pwd`, `secret`, `api_key`, `apikey`, `access_token`, `refresh_token`, `token`, `authorization`, `auth`, `credentials`, `private_key`, `client_secret`. Its free-text companion is `secret_in_text`, which catches the assignment shape in a message body.

### The `*` field

Setting `field` to `*` sweeps every string in the event, recursively. It is accepted only for `redact_pattern` and `tag`, and a `seal` refuses it outright.

The sweep preserves the pipeline's own fields, which are never rewritten and can never be targeted by any processor: `tenant_id`, `tenant_seg`, `tenant_attribution`, `log_index_base`, `ts`, `ts_source`, `ts_invalid`, `timestamp` and `topic`. Rewriting one of those could re-route another tenant's documents or corrupt the time axis. The protection applies to those names at the top level of the event.

## Result

`GET /api/pipeline/processors` returns your tenant's rules and a count:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/pipeline/processors
```

```json
{"count":0,"rules":[]}
```

A count of `0` with an empty `rules` array is a genuine empty list: this tenant has no processors. If the list cannot be loaded at all, the console says "Pipeline processors could not be loaded" and the meta line reads unavailable, rather than reporting zero processors. Those are different facts and the page never collapses them.

After a save, the next event on that lane arrives shaped. A `tag` rule adds `cx_sensitive` to the stored document without altering the value, which is how you confirm the detector fires before you switch it to `hash` or a redaction.

## Related

- [Review sensitive-data access](/administration/sensitive-data-access) for the reversible `seal` action and its reveal trail.
- [Check telemetry parser coverage](/administration/telemetry-coverage) for what the parser does with the events after shaping.
- [Explore logs](/explore/logs) to confirm the shaped document.
- [Feature flags](/reference/feature-flags) for `FEATURE_PROCESSORS` and its default.
