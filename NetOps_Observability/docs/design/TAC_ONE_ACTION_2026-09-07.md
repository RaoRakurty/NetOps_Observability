# TAC escalation — the ONE ACTION (owner decisions, 2026-09-07)

Extends `TAC_ESCALATION_2026-09-05.md` (the engine) and `TAC_CAPTURES_2026-09-06.md`
(what the customer sees). Neither is superseded; this records what the owner asked
for on 2026-09-06/07 and how it was built.

**The goal, verbatim:**

> "We are just trying to close that initial time lag, so ease of collecting data
> and open the case with one or two clicks, that's the goal. … we pre-gather
> common commands especially things like show tech-support which is good enough
> to open a case initially and later vendor TAC engineer might ask more detail in
> which NOC admin will work with vendor TAC closely."

ITSM auto-ticketing from the RCA already exists and is **not** this page.

---

## 1. Tech-support first

Every dialect's default capture **leads** with the vendor's own first-ask
collection. It is authored in one table (`FIRST_ASK` in
`scripts/tac-merge-research.py`), rendered into `ai/tac/plans/*.yaml` as
`first_ask:` + `first_ask_note:`, and the loader refuses a plan that has neither.

| Dialect | First ask | Ceiling | Deadline |
|---|---|---|---|
| cisco-ios, cisco-iosxe | `show tech-support` | 32 MiB | 10 min |
| cisco-nxos | `show tech-support details` | 64 MiB | 15 min |
| cisco-asa | `show tech-support` | 16 MiB | 5 min |
| arista-eos | `show tech-support` | 32 MiB | 10 min |
| juniper-junos | `request support information` | 32 MiB | 10 min |
| fortinet-fortios | `execute tac report` | 16 MiB | 10 min |

**The size and time budgets are part of the fact.** Cisco's own reference says
`show tech-support` "can generate a very large amount of output"; the Nexus guide
warns the SSH timeout must exceed the generation time or the capture is
truncated. So a `first_ask` binding without both is a load error.

### Five dialects have none, and say why

| Dialect | Why, in one line |
|---|---|
| cisco-iosxr | the unscoped `show tech-support` writes a `.tgz` to the router's own hard disk instead of streaming |
| nokia-sros | `admin tech-support` writes an archive to compact flash; Nokia's own reference calls it a system core dump |
| nokia-srlinux | the bare `tech-support` (**not** `tools system tech-support`) writes a zip under `/tmp` |
| paloalto-panos | the file is generated on the device and downloaded; no read-only CLI form appears on any page we hold |
| huawei-vrp | Huawei warns `display diagnostic-information` markedly raises CPU and emits personal data — it stays opt-in |

Each note cites the vendor page. `admin tech-support`, `tech-support` and
`tools system tech-support` are refused **by name** in the `config` family of
`ai/tac/forbidden.yaml`: a file written on a customer's router is a change, and
the output-only rule does not negotiate about changes. `execute tac report` moved
the other way — Fortinet documents it purely as output, so it is a cited
output-only leaf of the `execute` branch.

### Two things this needed at the wire

**A cited read-only exception has to reach the device.** Junos and FortiOS spell
their documented READ as something the read-only grammar cannot recognise by lead
token. `protocoldiag.ReadOnlyExemptGate` is an optional seam that
`internal/tac.Gate` answers only for a rendering of an authored binding carrying a
CITED `read_only_exception`, with the output-only policy applied first and the
closed table still applied separately. This also fixed a latent gap: every
FortiOS `diagnose debug … read` baseline command loaded, planned and gated, then
was refused at the wire.

**A first-ask collection is streamed, never buffered.**
`protocoldiag.StreamingGateway`/`StreamingRunner` plus a `RedactingWriter` that
applies the identical per-line rules in a stream (PEM state carried across write
boundaries). The collector writes redacted bytes straight into a spill file the
bundle copies into the zip without reading back. Peak live heap for a 50 MB
output is bounded and tested. The redactor gained an anchor prefilter — a byte
scan, with a per-rule structural test that it cannot miss a rule — taking the
pass from 1 MB/s to 10 MB/s.

---

## 2. One or two clicks

```
Escalate ──▶ (collect, watched)  ──▶ Prepare ──▶ [ ONE CONFIRMATION SCREEN ] ──▶ Open case
   click 1                            automatic                                    click 2
```

`escalate` and `prepare` have **no path to a vendor**. `confirm` is the only call
that can cause a case to exist, and it needs a stored proposal and a named human.
The claim "Correlix never opens a case on its own" is therefore true by
construction, and a test asserts a recording connector saw zero submits through
both earlier steps.

### The route ladder, and every rung explains itself

1. the operator's explicit choice for this case
2. the tenant's configured route for this device's vendor — **honoured even when
   the named connector is unconfigured**, then refused by name; silently
   rerouting a deliberate setting would teach an operator that the setting does
   nothing
3. the vendor's own configured native path that can create
4. the vendor's configured mailbox
5. portal text — always available, never a failure

### The screen arrives complete

serial + model from the **device record** (learned from `show version` on the
probe's own SSH rung, or from a collection's own output) · contract + account id
+ contact from the **tenant's routing record** · title from the class and the
hostname · description from the problem statement. Anything the vendor demands
and Correlix does not have is a NAMED blocker with the vendor's own reason and
the settings page that fixes it, and `confirm` re-applies those blockers to the
form the operator actually submitted.

### Dry run

Authenticate against the configured endpoint with the stored credential (a real,
read-only call), then build the payload, run every validation the vendor's schema
and the required-field table impose, and show the exact request(s) with secrets
redacted. It creates nothing — structurally: the connector half calls Probe and
the vendor packages' `Validate`, and has no branch that reaches CreateCase.

---

## 3. The case comes back

`{connector, case_id, case_url, opened_at, status}` on the incident, refreshed on
a **severity-tiered** schedule (owner: *"For an emergency case, refresh should be
more often"*):

| Tier | First leg | Then |
|---|---|---|
| Sev 1 / P1 / S1 / Critical | every 2 min for 4 h | every 5 min |
| Sev 2 / P2 | every 5 min for 24 h | every 15 min |
| Sev 3–4 | every 15 min for 24 h | hourly |

Closed stops it; reopened resumes it (derived every read, never latched). A
failed read backs off with per-case deterministic jitter. A tenant over a
vendor's published limit (Juniper 1000/h; Correlix spends at most half) degrades
one ladder step and **says so on the chip**. Manual "Refresh now" has a 60-second
per-case floor. An unrecognised severity tiers **down**, never up.

**A failed read is never a stale green.** The chip reads
`695123456 · status unknown since 09:41 — the vendor returned 503`. An
email-opened case has no number at send time and reads `opened by email · number
pending` until the mailbox connector's reply read lifts the real one out of the
vendor's subject line — that path can learn a NUMBER and can never learn a
STATUS, and the connector declares those separately.

---

## 4. Tenant settings (Administration → Ticket delivery)

A **separate record** from the credential store, because a contract number is not
a secret and rotates on a different clock: the named human a vendor calls back,
the route per vendor, the preferred capture per dialect, and the support
contracts — per vendor, and **per device serial** where a vendor entitles per
chassis. Per-tenant data, so the gate is `requirePerm` + the store's own tenant
filter, never `requirePlatformAdmin`.

---

## 5. What is proven, and what is not

`internal/ticketing/caseconn_e2e_test.go` and `caseconn_dryrun_test.go` drive the
REAL connector code end to end against contract fakes built from the vendors'
documented shapes, and `tests/test_tac_case_connector_selftest.py` runs them from
the platform suite with a floor on how many cases must run.

**No vendor site is contacted.** What is proven is that the request Correlix
builds is the request the documentation describes, that the documented answers
parse, and that the documented failures — a wrong secret, an entitlement refusal,
a rate limit — become the named outcomes the confirmation screen and the case
chip are built to show. Entitlement itself is evaluated by the vendor at create
time. Every vendor path in this pack is `doc_claimed` until a real case proves
otherwise, and the field-level authority is
[`TAC_CASE_FIELDS_2026-09-07.md`](TAC_CASE_FIELDS_2026-09-07.md).

One boundary CI cannot cross, and it is a feature: the Cisco Smart Bonding token
host is pinned to Cisco's own, so no local fake can stand in for it. The OAuth
exchange is proven at the client and the refusal at the connector; both halves
are asserted and neither is skipped.
