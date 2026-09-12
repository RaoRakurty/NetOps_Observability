# DEM privacy, data classification and authorization

Status: **as-built, 2026-09-05.** Source: `provenance.go`, `event.go`,
`investigator.go`, `store.go`, `pg.go`, `http.go` in
`src/backend/internal/dem/experience`; `probe_handlers.go`'s `demAuthz`;
migration `0044_dem_experience.sql`.

Digital Experience is the first Correlix domain that will hold data **about
people** rather than about devices. The classification model, the refusal to
pseudonymise a caller's mistake, the separation of a replay reference from
everything else, and the AI packet's redaction all exist for that reason, and
all of them are enforced in code rather than in a policy document.

Owner authority: `docs/design/DEM_2026-09-05.md` §M.8 and the owner's Phase L.

---

## 1. The eight data classes

Every object in this package carries `provenance.data_class`. The vocabulary is
closed and **ordered**, least to most sensitive, and the order is load-bearing:
`DataClassRank` and the AI packet redactor read it directly.

| Rank | Class | What it is | Example in DEM |
|---|---|---|---|
| 0 | `public` | Publishable without restriction. | A public ASN, a public resolver address in a path trace. |
| 1 | `internal` | Correlix's own operational data about itself. | A source-health state, a policy version. |
| 2 | `customer_metadata` | Facts about a tenant's estate that identify no person. | Every synthetic result, path degradation, journey outcome and change event produced today. |
| 3 | `pseudonymous_user` | A reference that stands for a person but is not that person's identifier. | `ExperienceEvent.user_ref`, `ExperienceSession.user_ref` — a per-tenant salted digest. |
| 4 | `pii` | A direct or directly-linkable personal identifier. | Nothing in DEM may carry this today; the class exists so a producer that would can be refused. |
| 5 | `regulated` | Data under a specific regime (health, payment, jurisdictional). | Reserved. |
| 6 | `credential` | An authentication factor. | Reserved. |
| 7 | `secret` | A key, token or other secret material. | Reserved. |

Two rules follow from the ordering, and both fail **closed**:

- **An unknown class ranks above every known one.** `DataClassRank` returns
  `len(vocabulary)` for anything it does not recognise. A class nobody declared
  is a class whose handling rules are unknown, so the answer to "is this safe to
  send out" is no. `TestPseudonymousUserReferencesAreEnforced` pins that
  `MayLeaveThePlatform("something_new")` is false.
- **Validation refuses an object whose class it does not recognise**, rather
  than defaulting it. An object that cannot state how it must be handled is not
  admissible.

### 1.1 Two classifications, kept apart on purpose

The `pathgraph` contract carries its own four-value `data_class`
(`live` / `synthetic` / `replay` / `lab`), which describes **how a measurement
was produced**. The eight classes above describe **how a value must be
handled**. They answer different questions and are separate fields for exactly
that reason: a `live` measurement can legitimately carry a `pseudonymous_user`
value, and collapsing the two is how a PII rule ends up applied to the wrong
column — or, worse, not applied to the right one.

Both survive into the AI packet: `PacketEvidence` carries `observation`
(observed / inferred / unknown / simulated), and the redactor reads
`data_class`.

---

## 2. `MayLeaveThePlatform`

```go
func MayLeaveThePlatform(c string) bool {
    return DataClassRank(c) <= dataClassRank[DataClassPseudonymousUser]
}
```

One function, one rule: **everything at or above `pii` is withheld from any
outbound prompt or exported bundle.** A pseudonymous user reference is admitted
only because it is, by construction, not a person's identifier — withholding it
would make every AI answer thin for no privacy benefit.

This is CLAUDE.md §15 LLM06 (sensitive information disclosure) reduced to a
single predicate that has exactly one caller in this package, `BuildPacket`, so
there is no second place a future edit could get it wrong.

---

## 3. Pseudonymous user references, and why a direct identifier is refused

`ExperienceEvent.user_ref` and `ExperienceSession.user_ref` are **pseudonymous
references** — a per-tenant salted digest, never a username, an email address or
a raw internal id. This is the same discipline
`DEM_DATA_MODEL_2026-09-05.md` §5 already requires of a wireless client id, and
for the same reason: an identifier that becomes a metric label or an event key
is the one place a value is impossible to redact after the fact.

`requirePseudonymous` checks for the shapes a raw identifier has and
**refuses** the record:

> `user_ref` must be a pseudonymous reference, not a direct identifier — hash it
> per tenant before sending it

**The refusal is the design.** Silently hashing the caller's value would be
easier and would be wrong three times over:

1. It teaches the producer that sending real identifiers is acceptable, so the
   next field they add will carry one too.
2. The identifier has already crossed the wire and already reached a log line,
   a proxy and a request body. Hashing at the receiver does not un-send it.
3. A value the platform silently transformed cannot be joined by the producer,
   so the producer will "fix" it by sending something else identifying.

The check is deliberately crude — it looks for markers, not for every possible
identifier — because its job is to make the *contract* unambiguous at the
boundary, not to be a PII detector. The contract is: pseudonymise before you
send.

Three further rules make the classification honest rather than decorative, all
pinned by `TestPseudonymousUserReferencesAreEnforced`:

- An event carrying a `user_ref` and declaring **no** class is classified
  `pseudonymous_user`, default-closed. Never `internal`.
- An event carrying a `user_ref` and declaring a class **below**
  `pseudonymous_user` is **refused**, not silently upgraded. Quietly rewriting a
  security classification would hide the fact that a producer is mislabelling
  its data, which is the thing an operator most needs to know.
- An `ExperienceSession` declaring no class is classified `pseudonymous_user`.

None of these can fire in production yet: nothing produces an
`ExperienceEvent`, an `ExperienceSession` or a `BusinessEvent` in this slice
(see [`dem-domain-model.md`](dem-domain-model.md) §11). The rules ship with the
shapes so that the first producer meets them rather than being retrofitted onto
them, which is what breaks a privacy model.

---

## 4. Replay references are kept separate

`ExperienceSession.ReplayRef` is a **pointer** to a session replay held
elsewhere, never the replay itself. It is its own field, apart from every other
session attribute, on purpose: replay access is role-controlled and audited, and
a reference is what an access check can be attached to. A replay embedded in a
session object could not be withheld from a caller who is allowed the session.

The same discipline applies to `SyntheticRun.ArtifactRef` (a screenshot or HAR
held by whatever stores artifacts) and `SyntheticRun.SessionRef`. Neither
carries content. A run record stays small, and a screenshot never lands in a
JSON API response.

**No session replay is recorded, stored or served in this slice.** There is no
recorder, no store and no route. `ReplayRef` is a contract, and the roadmap
([`dem-roadmap.md`](dem-roadmap.md) §3.6) states what building one would
require.

---

## 5. What the AI packet withholds, and how the redaction is surfaced

`BuildPacket(incident, health)` projects a **graded** incident into a closed
briefing. It is pure and it is bounded.

### 5.1 What is dropped

| Dropped | Rule |
|---|---|
| Any evidence item whose class fails `MayLeaveThePlatform` | Counted in `withheld` and reported. |
| Evidence beyond `MaxPacketEvidence` (40) | Reported. |
| Hypotheses beyond `MaxPacketHypotheses` (8) | Reported. |
| Changes beyond `MaxPacketChanges` (12) | Truncated silently — a change list is already ranked, and the tail is the least relevant by construction. |
| Everything on `EvidenceItem` that is not in `PacketEvidence` | `PacketEvidence` is a deliberately **reduced** projection: id, kind, stance, summary, entity, independence group, observer, reliability, observed-at, observation mode, and the two hypothesis-id lists. Raw values, baselines, detail text, producer ids and the full provenance never reach the model. |

### 5.2 How the redaction is surfaced

`Packet.Redacted[]` carries a sentence per reduction, for example:

> 2 evidence items were withheld because their data classification does not
> permit leaving the platform

The list is part of the answer's honesty. **An operator must be able to see that
the model was given less than the incident holds**, rather than wondering why
the answer is thin. `TestPacketWithholdsWhatMayNotLeaveAndSaysSo` pins both
halves: the PII-classified item is absent from the packet, and `Redacted` is
non-empty.

`IncidentResponse.evidence_packet_available` tells the UI whether a briefing
could be built from this incident at all. It is false when every item is above
the class that may leave — which is a real state, and one the UI must render as
"the investigator cannot be used on this incident" rather than as a broken
button.

### 5.3 What comes back, and what is refused

`ValidateInvestigation(answer, packet)` returns a **cleaned** answer or an
error, never a partially-accepted one:

| Rule | Behaviour |
|---|---|
| Empty answer | Rejected. |
| Confidence outside 0..1 | Rejected. |
| An evidence id not in `packet.evidence_ids` | **The whole answer is rejected**, with `ErrUnknownEvidence`. Not just the citation: a model that invented one reference has demonstrated it will invent another. |
| A hypothesis id not in the packet | Rejected the same way. |
| A model-claimed `CONFIRMED` state | **Downgraded to `SUSPECTED`** and `downgraded: true` is recorded and shown. Confirmation is a property of the evidence and is decided by `Hypothesis.Grade`, not by a sentence. |
| A recommended action not in `packet.allowed_actions` | Dropped, and `downgraded` is set. |
| Answer length | Clipped at `MaxAnswerBytes` (8000). |
| Attribution | `AttributionLine` — "AI-assisted analysis based on Correlix evidence" — is **stamped by the validator, never by the model**, and the caller is required to render it. |

The direction of the pipeline is the deepest of these rules and is enforced by
construction: telemetry → evidence → hypotheses → confidence → **then** the AI
explanation. There is no path in which a model guess is made first and evidence
is then sought to support it, because `BuildPacket` only accepts an
already-graded incident.

### 5.4 Gating

The investigator needs **two** switches, not one:
`FEATURE_COPILOT` (the platform copilot flag) **and**
`FEATURE_DEM_AI_INVESTIGATOR`. A feature that can send evidence to a model gets
its own switch. When either is off, `AIAvailability` carries
`available: false` and a sentence, so the UI renders a disabled panel with the
reason rather than hiding the feature — a hidden feature is indistinguishable
from a missing one.

No provider call lives in this package. LLM04 (cost and denial of service) is
therefore bounded here by the packet caps above; the request bound, the output
token cap and the audit trail belong to the orchestrator in `ai/*` and are
covered by CLAUDE.md §15.

---

## 6. Authorization on every route

All eight routes are gated by `s.demAuthz` (`probe_handlers.go`), which maps the
module's two gates onto the platform's permission model:

```
dem.GateRead  → requirePerm("infrastructure", LevelRead)
dem.GateWrite → requirePerm("infrastructure", LevelWrite)
```

An unknown gate is a wiring bug, and the safe answer to a gate that cannot be
mapped is refusal: `demAuthz` writes `403` rather than falling through.

### 6.1 Why `requirePerm(infrastructure, …)` and not a platform gate

CLAUDE.md §3a rule 3 requires the gate to match what the data **is**. Experience
journeys, change events, targets and scores are **per-tenant operator data about
the tenant's own services**. They are not platform-global plumbing the way an
auth provider, an LLM key or a notification channel is.

A platform gate here would be wrong in both directions:

- `requirePlatformAdmin` would **lock a tenant admin out of their own
  journeys**, which they declared and which describe their own workflows.
- `requireCrossTenant` would hand a cross-tenant principal every tenant's
  experience data at once, which is exactly the fleet-wide read this module
  refuses.

The same reasoning already governs `internal/dem`'s target catalogue
(`DEM_PLUMBING_2026-09-05.md` §3), and using a different gate for the causality
layer above it would have created a surface where an operator can see a
journey's health but not the targets it is built from.

`requirePerm` is followed — **inside** the handler, never as the gate — by
`principalTenant(claims)`, and the platform tenant is deliberately mapped to
"scopeless" so that the module's own refusal fires rather than a shared bucket
being read.

### 6.2 One concrete tenant, or nothing

`API.scoped` refuses a caller who resolves to no tenant, to `*`, or to a
cross-tenant principal:

> select a tenant to see its digital experience (it is per-tenant data;
> cross-tenant access is refused)

There is no wildcard read path. `as_tenant` narrowing is handled upstream by
`principalTenant`; a cross-tenant principal is never served the fleet.

### 6.3 Isolation at the storage layer

CLAUDE.md §3a rule 4 says the store enforces it, not the handler.

| Backend | How |
|---|---|
| Postgres | Migration `0044` puts `ENABLE` + **`FORCE ROW LEVEL SECURITY`** and the `tenant_iso` policy on both `dem_journeys` and `dem_change_events`. `pg.go` runs **every** statement inside `WithTenant`, so the policy always has its `app.tenant_id` GUC. The scoped reads carry no Go-side `WHERE tenant_id = …`: enforcement is RLS's job, and a redundant predicate would let a future edit remove the real enforcement while keeping the tests green. |
| File store | Rows are a tenant-keyed map, so a lookup for tenant A cannot walk tenant B's bucket. `concreteTenant` refuses `""` and `*` **at the store**, so no future caller can reintroduce a wildcard. A scopeless read returns nothing, which is the same answer an empty RLS GUC gives on the Postgres twin. |
| VictoriaMetrics | `dem.TenantFilter` emits `extra_filters[]={tenant="…"}` on every query and a match-nothing sentinel when it cannot. There is no code path that issues an unfiltered query. |
| The `Store` interface | Has **no** cross-tenant method. There is no `ListAll` on it at all. |

The `Store` interface deliberately omits a fleet-wide read even though
`internal/dem.Catalogue` has one (`ListAll`, used only by the prober's work-queue
projector and unreachable from any handler). The causality layer has no
equivalent need, so it has no equivalent method.

### 6.4 404, never 403, for a foreign id

Every item route answers `404` for an id that belongs to another tenant, an id
that does not exist, and an id whose *shape* is wrong. All three are
indistinguishable to the caller, which is the point: **an id is never confirmed
to exist.**

- `ValidJourneyID` / `validIncidentID` check the shape **before** the store is
  touched, so a path-traversal-shaped id never reaches a key lookup.
- `GetJourney` on another tenant's id returns `ErrNotFound`, which the handler
  turns into `404`.
- On Postgres, RLS has already hidden the row, so `pgx.ErrNoRows` and "absent"
  are the same condition — the code comments say so explicitly.
- An unparseable incident id is a `404` rather than a `400`, because a `400`
  would confirm that a well-formed id from another tenant is "the right shape".

`src/backend/dem_experience_isolation_test.go` asserts this end to end against
the real router and the real gate mapping: own-only list, cross-tenant
get/put/delete → 404, `as_tenant` into another org ignored.

### 6.5 Ownership is stamped from the token

Neither write route can express a tenant. `journeyWire` and `changeWire` have
**no tenant field at all** — a tenant in the body is not merely ignored, it
cannot be written. `TenantID` comes from `principalTenant(claims)`.

Both decoders call `DisallowUnknownFields` behind a 64 KiB
`http.MaxBytesReader`, so a typo'd field fails loudly rather than being silently
dropped. `actor` on a change event defaults to the authenticated subject, and
`producer` on its provenance is always the authenticated subject regardless of
what the body said.

---

## 7. What is logged, and what is not

`LogWarn` is called in exactly one place in this module: when the metrics store
does not answer, carrying the error text and the window label. No evidence
summary, no user reference, no cohort and no change payload is logged.
`probe_handlers.go` logs an error when the file store fails to load, carrying
only the error.

`ChangeEvent.Before` and `ChangeEvent.After` are bounded at 2000 bytes each
**because a change record is a pointer to a diff, not a copy of a
configuration**. An unbounded before/after is how a credential ends up in a
change feed, and from there into a log line, an export and an AI prompt. The
bound is a refusal at the boundary, not a truncation.

---

## 8. Retention

DEM adds no new retention regime. Its two persisted objects land in Postgres,
which the platform's retention map records as **unbounded**, and its series land
in VictoriaMetrics under the platform-wide `VICTORIA_RETENTION` (30 days in the
current lab profile). See
[`data-retention-map.md`](data-retention-map.md) for the whole-platform view.

| What | Store | Retention | Knob |
|---|---|---|---|
| `dem_journeys` | Postgres | Unbounded. A journey is a declaration; it lives until an operator deletes it. | none |
| `dem_change_events` | Postgres | Unbounded in the Postgres backend. **The file backend keeps the newest 2000 per tenant** (`changeRetention`) and drops the oldest, which is the right end to lose: a change from last month cannot be the cause of an incident inside the 90-minute lookback. | none / `changeRetention` |
| `dem_*` series | VictoriaMetrics | Platform retention, 30 days in the lab profile. | `VICTORIA_RETENTION` |
| Derived evidence, hypotheses, incidents, scores | — | **Not retained at all.** They exist for the duration of the request that computes them. | — |
| `ExperienceEvent` / `ExperienceSession` / `BusinessEvent` | — | Nothing is stored. When the `netops.experience` lane is built, retention becomes a ClickHouse TTL and **must be set per data class**: `pseudonymous_user` data should not inherit the `customer_metadata` horizon by default. | future |

The last row is the one that needs a decision before the lane ships. Retention
by class is the §M.8 requirement, and the class is already on every object; what
does not exist yet is a store that can apply a different TTL per class.
[`dem-roadmap.md`](dem-roadmap.md) §5 carries it as an open item.

Deriving rather than storing has a privacy consequence worth stating plainly:
because no incident, hypothesis or evidence item is written down, **there is no
DEM analysis corpus to subject-access, export or erase.** The underlying
measurements and change records are the record, and they are already covered by
the platform's retention and export paths.

---

## 9. What this slice does not do

Stated so nobody assumes otherwise:

- **No sensitive-data-access audit hook is wired.** §M.8 names the existing
  Sensitive-data-access module as the control for replay and user-level data.
  Nothing in this slice reaches that class of data, so nothing calls it. The
  hook must be added in the same change that adds the first producer of
  `pseudonymous_user` data.
- **No per-class retention exists**, because no store holds a class above
  `customer_metadata`.
- **No PII detector exists.** `requirePseudonymous` enforces a contract at the
  boundary; it is not a scanner, and it is not represented as one.
- **No consent, residency or subject-access surface exists** for experience
  data. Those become required when the RUM producer ships and are listed in
  [`dem-roadmap.md`](dem-roadmap.md) §5 as open owner decisions, alongside the
  endpoint-agent privacy posture that §M.11 already carries.

---

## Related

- [`dem-domain-model.md`](dem-domain-model.md) — the objects and their validation.
- [`dem-architecture.md`](dem-architecture.md) — storage decisions and what adding the event lane would take.
- [`dem-api.md`](dem-api.md) — the routes, their gates and the 404 rule in practice.
- [`data-retention-map.md`](data-retention-map.md) — the whole-platform retention picture.
- [`opaque-identity-model.md`](opaque-identity-model.md) — the platform's identifier discipline.
