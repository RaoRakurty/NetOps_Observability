# First-party RUM — the experience-event lane end to end

**Status:** shipped 2026-09-06 (tracker 254). Design of record:
[`DEM_2026-09-05.md`](DEM_2026-09-05.md) §M.3 / §M.5 (Tier 4) / §M.8.
Route reference: [`dem-api.md`](dem-api.md). Privacy posture:
[`dem-privacy.md`](dem-privacy.md).

Until this row, `ExperienceEvent`, `ExperienceSession` and `BusinessEvent` were
validated CONTRACTS with an `EventSink` seam and no producer, so no storage lane
existed (Phase P: infrastructure follows a requirement). This is the
requirement, and this is the lane.

---

## 1. The path a beacon takes

```
browser  ──POST /api/dem/events──▶  api        (validates, stamps the owner
 (correlix-rum.js, one <script>)                 from the credential, bounds
                                                 the batch, refuses a direct
                                                 identifier)
                                        │
                                        ▼  internal/dem/expbus — BOUNDED queue,
                                           backpressure, retry + full jitter
                                        │
                              bus bridge (vector-aggregator :8692)
                                        │
                                        ▼
                              Kafka  netops.experience
                                        │
                                        ▼  vector-router  experience_split
                                           (record_type → two branches)
                          ┌─────────────┴─────────────┐
                          ▼                           ▼
             netops.experience_events      netops.business_events
                (ClickHouse, 30 d)           (ClickHouse, 400 d)
                     STRICT row policy           STRICT row policy
```

Nothing in that path is new infrastructure: it is the same aggregator bus
bridge every Go producer uses, the same router tier that lands flows and
security findings, and the same ClickHouse the correlation engine already
queries. What is new is one topic, one router lane, two tables and one producer.

## 2. Why two tables and two horizons

Experience events are high-volume, pseudonymous user behaviour; business events
are low-volume and are the **denominator of "what did this outage cost"**, which
is a question asked months later. One table would force the impact denominator
to expire with the beacons. Retention knobs:
`CH_EXPERIENCE_EVENT_RETENTION_DAYS` (default 30) and
`CH_BUSINESS_EVENT_RETENTION_DAYS` (default 400).

The 30-day default is a **privacy** decision, not a cost one — the same
reasoning as the wireless per-client tier.

## 3. Row policies are STRICT

`experience_events` and `business_events` use `StrictRowPolicyDDL`, not the
lenient telemetry policy: an untagged row is platform-only and is **never**
shared into every tenant's view. That is why the router aborts a record whose
`tenant_id` is empty into the dead letter rather than writing it — an untagged
row in a strict-policy table is invisible to everyone, which is a silent loss.

The api stamps `tenant_id` from the caller's credential before publishing, and
the router never derives or defaults it. There is exactly one place a row's
owner is decided.

## 4. The credential

Mint a **tenant-bound** API key with the single scope `ingest:experience`:

```bash
curl -sS -X POST https://correlix.example.com/api/apikeys \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"label":"checkout-rum","tenant_id":"<tenant>","scopes":["ingest:experience"]}'
```

What that key can do: `POST /api/dem/events` and `POST /api/dem/business-events`,
for its own tenant. **What it cannot do: read anything at all.** A key whose
scopes are exclusively `ingest:*` derives the zero-permission `ingest` role
(`roleFromScopes` → `rbac.RoleIngest`), so every RBAC-gated handler in the
product refuses it. That property is what makes the key safe to put in a page
served to the public — and it is pinned by
`TestDEMIngestKeyGrantsNoReadAtAll`.

> A platform-realm key carrying the scope is **refused**: the events are stamped
> with the key's tenant, and a key with no concrete tenant has no owner to
> stamp.

> **Known gap (2026-09-06):** the admin UI's API-key scope picker does not yet
> offer `ingest:experience` as a chip. Mint it through the API above.

## 5. Installing the snippet

`src/frontend/public/correlix-rum.js` is served from the deployment at
`/correlix-rum.js`; copy it to your own app's static assets or point at it
directly.

```html
<script src="https://correlix.example.com/correlix-rum.js"
        data-endpoint="https://correlix.example.com"
        data-key="<the ingest:experience key>"
        data-app="checkout"
        data-environment="production"
        data-release="2026.09.06"
        defer></script>
```

**Cross-origin.** Your app and Correlix are usually different origins, so add
your app's origin to `CORS_ALLOWED_ORIGINS`. Correlix reflects only explicitly
allowlisted origins — never a wildcard — so a missing entry fails loudly in the
browser console rather than half-working.

Manual events:

```js
window.correlixRum.track({ type: "journey_step", journey_id: "jny-…",
                           step_id: "pay", success: true, duration_ms: 812 });
window.correlixRum.business({ business_event_type: "purchase",
                              success: true, value: 42.5, currency: "USD" });
```

## 6. What the snippet deliberately does not collect

- No cookies, no `localStorage`, no form fields, no query strings.
- No DOM, no session replay, no page content.
- No full user-agent string — the browser **family** only, because that is what
  a cohort comparison needs and the full string is a fingerprint.
- Path segments that look like identifiers are collapsed (`/orders/1f9c/pay` →
  `/orders/:id/pay`), so an order number never becomes a label.
- `Do Not Track` and `Global Privacy Control` are honoured: with either set the
  snippet collects nothing and says so on the console once.

`user_ref` is optional and must be a **pseudonymous, per-tenant** reference that
*you* hash before handing it over. The API **refuses** anything that looks like a
direct identifier (an `@`, a phone prefix) rather than silently hashing it —
quietly repairing a caller's mistake teaches the caller that sending real
identifiers is fine. The refusal names the field and says what to do instead.

## 7. Backpressure, and why a 202 would be a lie

The api's queue is bounded in batches **and** in events. A full queue answers
**503 with `Retry-After`**, and the snippet puts the batch back and retries on
the next flush. A 202 for events with nowhere to go would make the lane look
healthy while a tenant's evidence disappeared — the "healthy process, dead data
path" failure this stack has already met twice.

Offsets on `netops.experience` commit only after ClickHouse acknowledges (the
router tier's global `acknowledgements`), so a ClickHouse outage back-pressures
into the retained topic rather than discarding a user's bad minute.

A batch that exhausts its bounded retry envelope is **dropped loudly**: counted
in `dem_experience_*` / `expbus` metrics and logged with its size, because "we
lost 300 of a tenant's beacons" is a fact an operator must be able to find.

## 8. Operating it

| Question | Where to look |
|---|---|
| Is the lane draining? | `netops-router-experience` consumer-group membership (the `RouterConsumerDead` page rule covers it automatically) |
| Are beacons arriving? | `dem_experience_events_ingested_total` |
| Is a producer being throttled? | `dem_experience_ingest_refused_total` (backpressure) vs `..._rejected_total` (malformed — it will never arrive) |
| Did we lose any? | `events_dropped_total` on the expbus snapshot, plus the log line naming the batch size |
| Is anything stored? | `SELECT count() FROM netops.experience_events WHERE tenant_id = …` |

`ingest_refused` and `ingest_rejected` are counted separately on purpose:
refused is backpressure a producer can retry through, rejected is data that will
never arrive. Treating them as one number hides which is happening.
