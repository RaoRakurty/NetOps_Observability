# TAC case-opening connectors — operator runbook

**Scope.** How a tenant enables each connector in the TAC escalation pack: the
credential the CUSTOMER must own, the size limits that bite, where a test
instance exists, and the human-approval rule that governs every create.

**Design of record:** `docs/design/TAC_ESCALATION_2026-09-05.md` §4.
**Vendor facts and citations:** `docs/design/TAC_CASE_OPENING_RESEARCH_2026-09-05.md`.
Every endpoint, field name and limit below comes from that research; where a
vendor publishes nothing, this runbook says so rather than guessing.

---

## 0. The two rules that apply to every connector

1. **Bring your own credentials, per tenant, opt-in.** No vendor permits a
   shared Correlix-owned support identity — Arista domain-matches portal
   accounts to the customer, Juniper issues `appId`/`customerSourceID` per
   customer and demands a named human contact, Cisco entitles on the customer's
   own CCO-ID. Credentials are stored per tenant, write-only (never returned on
   read, a blank value on update keeps the stored one), and never logged.
   A tenant can never see or use another tenant's connector configuration.
2. **A case is opened by a person, never by an engine.** `CreateCase` refuses
   without a recorded approver (`ErrNotApproved`). No correlation rule, alert or
   auto-remediation may call it. Every create, attach, poll and credential change
   is audited with the tenant, incident, device, case id and the bundle's SHA256.

---

## 1. Capability matrix (what Correlix can actually do)

| Connector | Tier | Create | Attach | Poll | Max attachment | What the customer must own |
|---|---|---|---|---|---|---|
| `servicenow` | 1 | ✅ | ✅ | ✅ | 1024 MB (instance property) | instance + a user with write access to `incident` (e.g. `itil`) |
| `jira` | 1 | ✅ | ✅ | ✅ | Cloud 1 GB / DC 10 MB (instance property) | Cloud: account email + API token · DC: a PAT |
| `email-arista` | 1 | ✅ | ✅ | ❌ | ~14 MB | an SMTP relay that supports TLS |
| `email-cisco` | 1 | ❌ attach-only | ✅ | ❌ | ~14 MB (20 MB mailbox ÷ base64) | an SMTP relay + an existing SR number |
| `cisco-cxd` | 2 | ❌ attach-only | ✅ | ❌ | **no vendor limit** | SR number + the per-case upload token from SCM |
| `cisco-smart-bonding` | 2 | ✅ | ✅ (via CXD) | ✅ | no vendor limit | a completed Smart Bonding onboarding project |
| `juniper` | 2 | ✅ | ✅ | ✅ | no documented cap | Juniper onboarding (`appId`, `customerSourceID`, `userId`) |
| `portal-fortinet` · `portal-paloalto` · `portal-nokia` · `portal-huawei` | 3 | ❌ | ❌ | ❌ | n/a | nothing — Correlix pre-fills the portal text and hands over the bundle |

A Tier-3 vendor is **registered on purpose**: an absent vendor is
indistinguishable from a broken one, whereas a portal-only row tells the
operator the portal URL and exactly which fields it will ask for.

---

## 2. ServiceNow

**Credential the customer must own.** An instance and a service account with
permission to write the target table. ServiceNow's own docs name `itil` as the
example role for attaching to `incident`. Basic auth is the default; OAuth2 and
mutual TLS are also supported by the platform.

**Where the bundle goes.**
`POST /api/now/attachment/file?table_name=incident&table_sys_id=<sys_id>&file_name=<name>`
with the **raw bytes** in the body and the file's real `Content-Type`
(`application/zip` for a bundle). Not multipart, not base64.

**Size.** The ceiling is the instance property `com.glide.attachment.max_size`,
default **1024 MB**. Set `servicenow.max_attach_bytes` if your instance changed
it. There is **no chunked or resumable upload** — a bundle above the ceiling is
refused with an honest error naming the smaller profile; it is never silently
split.

> The **inbound email** path is a different, far stricter ceiling:
> `glide.email.inbound.max_total_attachment_size_bytes` = **18 MiB total**,
> 30 attachments. That is why the email bundle profile is capped at ~14 MB.

**Test instance.** A free Personal Developer Instance (PDI). It is **reclaimed
after 10 days idle**, so do a connector smoke test on a PDI you have touched
recently.

**Rate limits.** ServiceNow publishes no default limit and returns `429` with
`Retry-After`; the connector reads that header at runtime.

---

## 3. Jira

**Credential the customer must own.**
*Cloud*: the Atlassian account email plus an **API token** (password Basic was
disabled on 2019-06-03). *Data Center*: a **Personal Access Token** used as a
bearer.

**Where the bundle goes.** `POST /rest/api/3/issue/{key}/attachments` on Cloud,
`/rest/api/2/…` on Data Center, `multipart/form-data`, form field name **`file`**,
header **`X-Atlassian-Token: no-check`** (Data Center's docs spell it `nocheck`).
Without that header Jira refuses the upload.

**Size.** Set `jira.deployment` to `cloud` or `datacenter`; the documented
defaults are **1 GB** and **10 MB** respectively (both are instance properties
with a 2 GB hard maximum). Override with `jira.max_attach_bytes` when the
instance was tuned. A Data Center default of 10 MB will reject most
`show tech-support` bundles — raise the property or use the email/link path.

**Test instance.** A free Atlassian developer instance (5 users) at
`go.atlassian.com/cloud-dev`.

**Rate limits.** Jira Cloud enforces **20 writes per 2 seconds per issue** —
exactly the create-then-attach-then-retry pattern. The connector honours
`Retry-After` and backs off with jitter.

---

## 4. Email (Arista, and attach-to-existing for Cisco)

**Credential the customer must own.** An SMTP relay that supports **TLS**, plus
a sender address and, for the vendors that need a human on the case, a
`reply_to` that is a real person.

**TLS is required, not preferred.** If the relay offers neither implicit TLS
(port 465, `tls_on_connect: true`) nor STARTTLS, the send is refused. An
evidence bundle is customer network data and does not leave in the clear. This
is deliberately stricter than the alert-notification email channel, whose
STARTTLS is opportunistic because a late alert is worse than an unencrypted one.

**The closed mailbox table.** Only vendors whose case mailbox is published
appear, and the addresses are **not tenant-configurable**:

| Vendor | Mailbox | Mode | Subject rule |
|---|---|---|---|
| Arista | `support@arista.com` | opens a case, and attaches to one | the case **Ref. ID** in the subject auto-attaches; priority is stated in the subject or body, default **P3** |
| Cisco | `attach@cisco.com` | attach to an existing SR only | the subject must carry **`SR xxxxxxxxx`** (9 digits) |

Arista also wants the problem description, a **compressed `show tech-support`**,
network diagrams, and a name + contact.

**Size — the 14 MB number.** Base64 costs ~37% (RFC 2045). The binding ceilings
are Cisco's 20 MB mailbox, ServiceNow's 18 MiB inbound cap and the Exchange
Online default. **14,000,000 raw bytes** encodes to ~19.2 MB and clears all
three without per-customer tuning. The connector also reads the receiving MTA's
advertised `SIZE` at EHLO and refuses before DATA, and treats a `552` reply as a
first-class "degrade to link-only" outcome rather than a retryable error.

**Not implemented — Nokia reply-to-case.** Nokia's own guide says a reply to the
case email works and must not alter the Subject line, but the per-case reply
address is never published. Correlix cannot compose that mail without the
operator pasting the address, so Nokia is a Tier-3 portal connector instead of
an email one. Do not add it to the table without a published address.

---

## 5. Cisco — CXD first, Smart Bonding second

### 5a. CXD (attach to an existing SR) — start here

**Credential the customer must own.** An open SR and its **per-case upload
token**, copied from **Support Case Manager** (`mycase.cloudapps.cisco.com`).
The token is valid **72 days** and is refreshable.

Correlix **never persists the token**. It is supplied per attach, used
immediately, and dropped; it appears in no log and no audit row.

**Where the bundle goes.** `PUT https://cxd.cisco.com/home/<file>`, Basic auth
with the **SR number as the user and the token as the password**.

**Size.** Cisco documents **no size limit at all** — the only path in the whole
study that swallows a full `show tech-support` without negotiation. Correlix
still applies its own 8 GiB runaway guard.

**Host pinning.** `cxd.cisco.com` is pinned. Even a create response naming a
different upload host is refused rather than followed.

### 5b. Smart Bonding (open an SR)

> The design's original claim that the **Support Case API v3** opens cases is
> **wrong**: v3 is **GET-only** and scoped to PSS partners. It is useful for
> status, not for creation. Creation is Smart Bonding.

**Credential the customer must own.**
- A completed **Smart Bonding self-onboarding project** (analysis →
  implementation → test → go-live), which issues the `customerSourceID` and the
  OAuth client credentials.
- The customer's **CCO-ID**, required on every case.
- Entitlement at create: a **serial number** (hardware) **or** a **contract ID +
  PID** (software). Correlix validates this locally before calling, so an
  unentitled case fails with a message you can act on rather than a round-trip.

**Staging.** Cisco offers a test environment but does **not publish its
hostname** — it comes from your onboarding project. Set `cisco.staging_host`;
Correlix requires it to be a `cisco.com` host and adds it to the pinned
allowlist for that tenant only. Blank means production (`sb.xylem.cisco.com`).

**`cisco.field_map` — why the connector refuses until you fill it in.**
Cisco does not publish the `push/call` **request schema** on its public pages.
Correlix will not guess field names for a request that files a real support case
against a real contract, so it requires a binding from each canonical field to
the field name **your onboarding project issued**:

```
synopsis · description · severity · contact_email · contact_name
cco_id · serial_number · contract_id · pid
```

Until every one is bound, `ValidateConfig` and `CreateCase` return
**"vendor onboarding not complete"** naming the unbound fields. That is a
deliberate fail-closed state, not a bug. CXD attach is unaffected and works
without any of this.

**Closing the loop.** A successful create returns the CXD host and token as
`Field80` / `Field81`; Correlix carries them straight into the attach, so no
second credential prompt is needed.

**Status.** Smart Bonding is a **pull** model (`pull/call`). There is no webhook.

**Severity.** Cisco's published S1–S4 vocabulary is shown; the operator picks.

---

## 6. Juniper — Service Case API (Beta)

**Credential the customer must own.**
- Onboarding via `https://onboarding-form-app.juniper.net`, which issues
  **`appId`** and **`customerSourceID`**.
- A **`userId`** that is a registered Customer Service Portal user.
- An **`accountID`**.
- Either OAuth2 `client_id`/`client_secret` (scopes `css-api-scope`,
  `css-phase2-scope`) **or** an API key.
- A **`contactEmail` that is a real named person, not an alias.** Correlix
  enforces this: `noc@`, `support@`, `netops@`, `no-reply@` and similar shared
  mailboxes are refused before the call, because Juniper rejects them.

**Where the bundle goes.** Three steps: `POST /getfileuploadtoken` returns
short-lived **AWS STS credentials**; the client `PUT`s the object to S3 signed
with SigV4; `POST /attachfile` registers it by `documentPath` + `sizeInBytes`.
The STS credentials are per-upload and are never persisted or logged.

**Size.** No documented byte cap (`sizeInBytes` is unvalidated). Text caps ARE
documented and enforced locally: `problemDescription` ≤ **15000**,
`synopsis` ≤ **250**.

**Mandatory fields.** `softwareVersion` has been mandatory **since 2024-05-16**.
`networkOutage` applies to P1 technical SRs only and is omitted unless set.
Every request carries a `customerUniqueTransactionID` — Juniper treats a repeat
as an update, not a new case.

**Severity.** `priority`'s legal values come from the API's own **`/getlov`** and
are **fetched, never hard-coded**. The connector declares an empty severity list
and exposes `FetchSeverityValues`.

**Entitlement.** Errors **600–614** are the entitlement class (expired contract,
no contract, warranty-only → "open a Technical SR via other channels", missing
serial). Juniper's verbatim message is shown to the operator; the call is not
retried.

**Rate limit.** **1000 invocations per hour**, hard. Correlix refuses locally at
the limit rather than burning the tenant's budget on a doomed call.

**Status polling.** `POST /querysrdetails`. `querysrlist` covers the **last 90
days** only — an older case reads as "not found", not as "closed". The
`publishSR` **webhook receiver is not built** (W3 owns that route); today the
connector polls.

**Beta caution.** The API is marked Beta and its portal is a webMethods URL, not
a stable `*.juniper.net` developer domain. The connector **fails closed** on a
response that does not match the pinned contract — naming the missing field —
rather than reporting a success it cannot substantiate. Junos Space Service Now,
the historical auto-open-a-JTAC-case mechanism, is **EOL** and must not be used.

**Test instance.** None. Juniper publishes no sandbox; validate against your own
onboarded account with a low-severity informational SR you then close.

---

## 7. Tier 3 — Fortinet, Palo Alto, Nokia, Huawei enterprise

**There is no API. Do not promise one.** Correlix automates everything *up to*
submission: classify, collect, redact, bundle, and pre-fill the exact field set
each portal asks for. The connector reports `create:false, attach:false` and
carries the portal URL and required-field list so the UI renders an honest
"not automatable" state.

| Vendor | Portal | The operational fact that changes what you do |
|---|---|---|
| Fortinet | `support.fortinet.com` | the bundle is produced **on the device** by `execute tac report` (or the GUI FortiCare Debug Report) and attached by a human. Files are deleted **30 days after the ticket closes**. P1–P4 definitions are published |
| Palo Alto | `support.paloaltonetworks.com` | a **TSF is mandatory** for many issue concentrations and the portal accepts only `.tar/.zip/.tgz/.tar.tz` — **produce the bundle as `.zip`**. Phone for Sev 1. Sev 1–4 definitions are published |
| Nokia | `customer.nokia.com/support/s/` | **phone is the vendor-preferred channel for outages.** Replying to the case email works but the **Subject line must not be altered**. The severity matrix is **not published — do not substitute one** |
| Huawei | `support.huawei.com` | the enterprise SR portal is JS-gated: its field list and severity table are **not publicly retrievable — do not assume them**. Huawei *Cloud* OSM does have a ticket API, but it opens **cloud** tickets, not device TAC cases |

**These negatives are dated (2026-09-05) and can go stale.** Fortinet's FNDN and
Huawei's enterprise SR pages are login/JS-gated, so a private or partner-only
API cannot be *disproven* — only shown to be publicly undocumented. Re-check
before telling a customer it does not exist.

---

## 8. Bundle profiles and what to do when the bundle is too big

| Profile | Ceiling | Use for |
|---|---|---|
| `full` | the connector's own limit | ServiceNow, Jira, Cisco CXD, Juniper |
| `email` | **14 MB raw** | any email path; clears Cisco 20 MB, ServiceNow 18 MiB and Exchange Online defaults simultaneously |
| link-only | n/a | when neither fits: a signed, expiring, tenant-scoped download URL in the case description |

**Never chunk.** Neither ServiceNow nor Jira documents a resumable or ranged
upload, so "chunking" would mean splitting into multiple files — a bundle-format
decision described in `MANIFEST.json`, never a silent transport behaviour.

An oversize bundle returns a typed refusal naming the limit and the smaller
profile; it is **not** retried, because retrying identical bytes cannot succeed.

---

## 9. Troubleshooting

| Symptom | Cause | What to do |
|---|---|---|
| "not configured for this tenant" | the connector block is disabled | enable it in the tenant's TAC connector configuration |
| "vendor onboarding not complete" (Cisco) | `cisco.field_map` is unbound | fill in the field names your Smart Bonding onboarding issued (§5b) |
| "case creation requires explicit human approval" | a create was attempted without an approver | open the case from the UI form; no engine path may create one |
| "contactEmail must be a real person" (Juniper) | a shared alias was used | use a named human registered on the account |
| entitlement failure with the vendor's own text | expired/absent contract, or missing serial | fix the entitlement inputs; the bundle download and portal text remain available |
| "relay does not offer STARTTLS" | the SMTP relay cannot do TLS | point at a TLS-capable relay, or set `tls_on_connect` for port 465 |
| "the documented 1000 invocations/hour budget is spent" (Juniper) | the tenant's hourly budget is exhausted | wait for the window to reset; the message names the reset time |
| attach succeeds but the vendor sees nothing (Juniper) | Beta-API schema drift | the connector names the missing response field; re-check the pinned OpenAPI spec |

---

## 10. What is deliberately NOT built

- **Cisco Support Case API v3 as a create path** — it is GET-only.
- **Junos Space Service Now** — EOL, archived docs.
- **Huawei Cloud OSM** — a real create+attach API, but for cloud tickets, not
  device TAC cases.
- **Nokia email threading** — no published per-case reply address.
- **Juniper `/updatesr` (add a note)** — its request schema is not in the pinned
  contract, and a mis-shaped update on a live support case is worse than no note.
- **Webhook receivers** (`publishSR`, `jira:issue_updated`) — W3 owns those
  routes. Every connector polls today, and one that cannot poll says so instead
  of showing a stale badge.
