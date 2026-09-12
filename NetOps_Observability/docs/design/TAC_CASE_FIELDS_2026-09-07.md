# Mandatory data per vendor to open a case (2026-09-07)

**Owner ask:** *"Study the mandatory data per vendor to open a case and enforce it."*

This document is the **field-level** companion to
[`TAC_CASE_OPENING_RESEARCH_2026-09-05.md`](TAC_CASE_OPENING_RESEARCH_2026-09-05.md)
(which answers *can we open a case at all?*) and to
[`../runbooks/tac-case-connectors.md`](../runbooks/tac-case-connectors.md)
(which answers *what must the customer own?*). It answers the third question:
**which data must be in hand before a case can be opened, per vendor, and what
happens when it is not.**

It is also the **source of record for the Go table** in
`src/backend/internal/ticketing/caseconn_required.go`. The two are held together
by `caseconn_required_test.go`, which parses the machine-checked blocks in §3
and fails if the code and this document disagree. Editing one without the other
breaks the build on purpose.

---

## 0. Sourcing rule — what "checked 2026-09-07" means here

**No vendor site was fetched for this document.** It was written with no network
access, from sources already pinned inside this repository:

| Repo source | What it establishes |
|---|---|
| `docs/design/TAC_CASE_OPENING_RESEARCH_2026-09-05.md` | the vendor facts + every citation URL, fetched from official vendor documentation on 2026-09-05 |
| `docs/runbooks/tac-case-connectors.md` | the operator-facing restatement of the same facts |
| `src/backend/internal/ticketing/caseconn_*.go` | the `Caps{}` declarations, the closed vendor tables, the ceilings and the local pre-flight refusals |
| `src/backend/internal/ticketing/vendors/{cisco,juniper}` | the two pinned request contracts and their `Validate()` — the only place a *vendor-mandatory* field list is machine-encoded |
| `src/backend/internal/tac/caseopener.go` | the `CaseForm` field names this document's `Key` column uses |

So **`checked 2026-09-07` on a claim means: re-verified on 2026-09-07 against the
repository's pinned research (vendor pages fetched 2026-09-05) and against the
connector code that encodes it.** It does **not** mean a vendor page was fetched
today. Where the pinned research establishes nothing, this document says
**OPEN QUESTION** (§4) instead of guessing — the escalation pack's explicit
honesty rule.

`src/backend/ai/tac/research/` was also checked (2026-09-07): it holds
**per-platform diagnostic command research** (what to collect), not case-opening
metadata. It contributed nothing to this document.

### Two senses of "mandatory" — kept apart everywhere below

| Tag | Meaning |
|---|---|
| **V** — vendor-mandatory | the vendor's own published contract requires it; omitting it is refused *at the vendor* |
| **C** — Correlix-mandatory | Correlix refuses locally before the call, because the field is an entitlement input, a named-human rule, or the only thing that makes the case usable. A **C** row is a product decision, not a vendor claim |

A row tagged **C** is never presented to an operator as "the vendor requires it".

---

## 1. Per-vendor summary

| Vendor / system | Mandatory data to open a case | Severity vocabulary (exact tokens) | Entitlement check the vendor performs | Attachment ceiling |
|---|---|---|---|---|
| **Cisco — Smart Bonding** (create) | synopsis · description · severity · contact name · contact email · **CCO-ID** · **serial number** *or* **contract ID + PID** · `customerUniqueTransactionID` | `S1 — Critical impact (system down)` · `S2 — Substantial impact (degradation)` · `S3 — Minimal impact (partial degradation)` · `S4 — No impact (informational)` | **Yes, hard, at create.** CCO-ID on every case, plus a serial number (hardware) **or** a contract ID + PID (software) | attaches **via CXD** → no documented limit; Correlix guard 8 GiB |
| **Cisco — SCM / CXD** (attach to an existing SR) | **SR number** (9 digits) · **per-case CXD upload token** | same S1–S4 (the vocabulary SCM shows; CXD itself takes no severity) | **No.** The SR number + token *are* the authorisation | **No size limit at all** (SCM browser upload is likewise "No limit"); Correlix guard 8 GiB |
| **Cisco — `attach@cisco.com`** (email attach) | **SR number** in the subject as `SR xxxxxxxxx` | n/a (attach only) | No | **20 MB message** → ~14.6 MB raw; Correlix's email profile caps at 14,000,000 raw bytes |
| **Juniper — Service Case API + CSP** | `appId` · `customerSourceID` · `userId` · `accountID` · `synopsis` (≤250) · `problemDescription` (≤15000) · `priority` · `contactEmail` (**a named human, not an alias**) · `softwareVersion` (**mandatory since 2024-05-16**) · `customerUniqueTransactionID` | **Not hard-coded anywhere.** Legal `priority` values come from the API's own `GET /getlov` and must be **fetched** | **Yes, hard, at create** — error class **600–614**: expired contract · no contract + out of warranty · warranty-only ("open a Technical SR via other channels") · missing serial. `userId` must be a registered Customer Service Portal user | **No documented byte cap** (`sizeInBytes` is unvalidated); Correlix guard 8 GiB. Text caps are documented and enforced locally |
| **Arista** (email / portal) | problem description · compressed `show tech-support` · network diagrams · **your name and contact information**; the case **Ref. ID** in the subject when attaching to an existing case | **Not published.** Per-level definitions are not published openly; **default priority is P3**, and priority is set by stating it in the email subject or body | **No programmatic check.** Portal accounts are restricted to users whose **corporate email domain matches the customer account** | portal upload **10 GB/file**; the email path is bounded by Correlix's 14 MB profile |
| **Nokia** | request type (Technical Problem / HRR-RMA / Feature Request) · product · problem details | **Not published** — the public TSR guide contains zero occurrences of "severity", "Critical", "Major" or "Minor". Do not substitute one | purchased maintenance + a portal account (Azure AD B2C gated) | **None documented** — the TSR guide contains zero occurrences of "attach" or "upload" |
| **Palo Alto Networks** | product · asset / serial number · symptoms **with date and time** · problem type · impact / severity · **TSF file** · contact phone | `Sev 1 — product is down and critically affects the customer production environment; no workaround yet available` · `Sev 2 — product is impaired; customer production is up but impacted` · `Sev 3 — a product function has failed; customer production is not affected` · `Sev 4 — product function is not impaired; no impact to customer business` | CSP account + asset/serial + support contract; the CSP API key requires the **Super User** role (and is a *Licensing* key, not a case key) | **No size limit published**; accepted extensions are **`.tar`, `.zip`, `.tgz`, `.tar.tz`** only, so the bundle must be a `.zip`. A **TSF is mandatory** for many issue concentrations (exempt: hard-down criticals, boot issues, US Federal/Defense/air-gapped) |
| **Fortinet** | serial number · request type (Technical Support Ticket) · priority (P1–P4) · problem description · attachments | `P1 — total loss or continuous instability of mission-critical functionality in a live or production network environment` · `P2 — significant impact on mission-critical functionality` · `P3 — minimal impact on business operations` · `P4 — additional information, or minor defects that do not impact business services` | FortiCloud account + **registered assets** + a valid FortiCare contract | **No size limit or format list published.** Files are **deleted 30 days after the ticket closes** |
| **Huawei** (enterprise / carrier networking) | product · problem description · attachments | **Not retrievable** — the enterprise SR portal is JS-gated. Do not assume one | not publicly retrievable (JS-gated). *Huawei Cloud* OSM, a different product, gates on the customer's own Cloud IAM account | **Not published** for enterprise. *Huawei Cloud* OSM: base64 accessories, **max 32 `accessory_ids` per case**, no real size cap published |
| **ServiceNow** (ITSM) | `short_description` (Correlix always writes it) + the problem statement; the target table and its write role are connection config | **None fixed by the platform** — priority/impact/urgency are per-instance choice lists | **No vendor entitlement.** An instance plus a user with write access to the target table (`itil` is ServiceNow's own example role for attaching to `incident`) | instance property **`com.glide.attachment.max_size`, default 1024 MB**; **no chunked or resumable upload**. The **inbound-email** path is far stricter: `glide.email.inbound.max_total_attachment_size_bytes` = **18 MiB total, 30 attachments** |
| **Jira** (ITSM) | issue summary + description; **project key** and issue type are connection config | **None fixed by the platform** — priority is a per-project choice list | **No vendor entitlement.** Cloud: account email + **API token** (password Basic disabled 2019-06-03). Data Center: a **PAT** | **Cloud default 1 GB/file (2 GB max)** · **Data Center default 10 MB (2 GB max)**; both are instance properties. Cloud rate-limits **20 writes / 2 s per issue** |

**Citations for every cell in this table** are listed per vendor in §2, each
tagged `checked 2026-09-07` under the rule in §0.

---

## 2. Per-vendor detail, with a citation per claim

### 2.1 Cisco

- Case **creation** is **Smart Bonding** (`POST …/rest/v1/push/call`), *not* the
  Support Case API v3, which is **GET-only** and scoped to PSS partners.
  — [Smart Bonding use cases](https://developer.cisco.com/docs/smart-bonding-customer-api/use-cases/) ·
  [Case API v3](https://developer.cisco.com/docs/support-apis/case/) *(checked 2026-09-07)*
- **Entitlement at create: a serial number (hardware) or a contract ID + PID
  (software), plus the CCO-ID on every case.** Encoded and enforced *before* the
  call in `vendors/cisco/cisco.go` `Entitlement.Validate()`.
  — [SB entitlement](https://developer.cisco.com/docs/smart-bonding-customer-api/entitlement-information/) *(checked 2026-09-07)*
- **`customerUniqueTransactionID` is required** and a repeat is treated as an
  update, not a second case; `customerCaseNumber` is the other cited request
  field. — [SB use cases](https://developer.cisco.com/docs/smart-bonding-customer-api/use-cases/) *(checked 2026-09-07)*
- **Cisco does not publish the `push/call` request schema.** The nine canonical
  case fields (`synopsis`, `description`, `severity`, `contact_email`,
  `contact_name`, `cco_id`, `serial_number`, `contract_id`, `pid`) must be bound
  to the field names the tenant's onboarding project issued; until every one is
  bound the connector fails closed with `ErrNotOnboarded`.
  — `caseconn_cisco.go` `ciscoCanonicalFields` + `missingCiscoFieldBindings`,
  runbook §5b *(checked 2026-09-07)*
- **Severity S1–S4** with Cisco's own wording.
  — [SCM case creation guide](https://www.cisco.com/c/en/us/support/docs/cx/cx-cloud/cx220971-support-case-management-case-creation-gu.html) *(checked 2026-09-07)*
- **CXD attach:** `PUT https://cxd.cisco.com/home/<file>`, Basic auth = **SR
  number / per-case token**; the token is valid **72 days**, refreshable, and is
  returned by a Smart Bonding create as `Field80` (host) / `Field81` (token).
  **No size limit** is documented. — [CXD](https://www.cisco.com/c/en/us/support/web/tac/tac-customer-file-uploads.html) ·
  [SB attachments](https://developer.cisco.com/docs/smart-bonding-customer-api/attachment-information/) *(checked 2026-09-07)*
- **Email attach** to `attach@cisco.com` requires `SR xxxxxxxxx` (9 digits) in
  the subject and is capped at a **20 MB message**.
  — `attach_email.go` `emailVendors["cisco"]` + [CXD page](https://www.cisco.com/c/en/us/support/web/tac/tac-customer-file-uploads.html) *(checked 2026-09-07)*

### 2.2 Juniper

- **`POST /createsr`** on the Service Case API (`css-caseapi`), maturity
  **Beta**; OAuth2 `client_credentials` or an API key.
  — [OpenAPI spec](https://jnprprod.devportal-aw-us.webmethods.io/portal/rest/v1/files/ea71e0db-1f98-4c24-a817-9f9648e64b20) *(checked 2026-09-07)*
- **The mandatory request fields are machine-encoded** in
  `vendors/juniper/juniper.go` `CreateSRRequest.Validate()`: `appId`,
  `customerSourceID`, `userId`, `accountID`, `synopsis`, `problemDescription`,
  `priority`, `contactEmail`, `customerUniqueTransactionID` — plus
  **`softwareVersion`, mandatory since 2024-05-16**. This is the only vendor in
  the study whose required-field list is published field-by-field.
  *(checked 2026-09-07)*
- **Text caps:** `synopsis` ≤ **250**, `problemDescription` ≤ **15000**.
  *(checked 2026-09-07, same source)*
- **`contactEmail` must be a real person and not an alias** — enforced locally by
  `isNamedHumanEmail` so a shared mailbox is refused before the call.
  — [JTAC guide](https://support.juniper.net/sites/support/pdf/guidelines/jtac-user-guide.pdf), runbook §6 *(checked 2026-09-07)*
- **Entitlement is hard-checked at create, errors 600–614** (expired contract,
  no contract + out of warranty, warranty-only → "open Technical SR via other
  channels", missing serial); Juniper's verbatim message is surfaced.
  *(checked 2026-09-07)*
- **`priority` values come from `GET /getlov` and must never be hard-coded** —
  which is why `JuniperConnector.Capabilities().SeverityValues` is deliberately
  `nil` and `FetchSeverityValues` exists. *(checked 2026-09-07)*
- **No documented attachment byte cap** (`sizeInBytes` unvalidated); attach is a
  3-step flow (`/getfileuploadtoken` → S3 PUT with STS credentials →
  `/attachfile`). **1000 invocations/hour** hard limit; `querysrlist` covers the
  **last 90 days**. *(checked 2026-09-07)*
- `userId` must be a **registered Customer Service Portal user**, and
  `appId`/`customerSourceID` are issued by the per-customer onboarding form.
  — [onboarding](https://onboarding-form-app.juniper.net) *(checked 2026-09-07)*

### 2.3 Arista

- **No case API.** "API" appears **zero times** in the official Support &
  Community Guide; CloudVision's APIs are network-state only.
  — [Support & Community Guide (PDF)](https://www.arista.com/assets/data/pdf/Arista_Support_Community_Guide.pdf) ·
  [CloudVision APIs](https://aristanetworks.github.io/cloudvision-apis/) *(checked 2026-09-07)*
- **`support@arista.com` opens a case and attaches to one**; it wants the
  problem description, a **compressed `show tech-support`**, network diagrams and
  **a name + contact**. Putting the case **Ref. ID** in the subject auto-attaches.
  — [Customer support](https://www.arista.com/en/support/customer-support) *(checked 2026-09-07)*
- **Priority: default P3**, settable by stating it in the subject or body;
  **per-level definitions are not published openly** (the `SRPriorityLevels.pdf`
  is bot/JS-gated). Correlix therefore publishes **no** Arista severity
  vocabulary. *(checked 2026-09-07)*
- **Entitlement:** portal accounts are restricted to users whose **corporate
  email domain matches the associated customer account** — a third-party
  identity is structurally blocked. *(checked 2026-09-07)*
- **Attachment:** portal upload **10 GB/file**; egress to Arista's GCP org
  **53989931248** must be allowlisted. *(checked 2026-09-07)*

### 2.4 Nokia

- **No case/ticket/TSR API.** NSP publishes exactly five APIs (NSP REST,
  RESTCONF, Kafka, NFM-P REST, NFM-P XML); the developer portal returns zero
  hits for `ticket`, `support case` or `TSR`.
  — [NSP APIs](https://documentation.nokia.com/nsp/24-4/NSP_System_Architecture_Guide/NSP-APIs.html) ·
  [developer portal](https://network.developer.nokia.com/) *(checked 2026-09-07)*
- **Portal wizard fields:** request type (Technical Problem / HRR-RMA / Feature
  Request) → product → problem details → submit.
  — [TSR Guide for Customers, 2025-08-29 (PDF)](https://www.nokia.com/asset/f/215299/) *(checked 2026-09-07)*
- **Severity matrix is not published** — zero occurrences of "severity",
  "Critical", "Major", "Minor" in the public TSR guide. *(checked 2026-09-07)*
- **No attachment path is documented** — zero occurrences of "attach"/"upload".
  *(checked 2026-09-07)*
- **Phone is the vendor-preferred channel for outages.** Replying to the case
  email works and **must not alter the Subject line**, but the per-case reply
  address is never published — which is why Nokia is a portal connector and not
  an email one. *(checked 2026-09-07)*

### 2.5 Palo Alto Networks

- **No case API.** The CSP API key is a **Licensing** key; pan.dev's catalog
  lists no case/ticket API. — [pan.dev](https://pan.dev/) ·
  [CSP user-doc index](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClNZCA0) *(checked 2026-09-07)*
- **Create-a-Case field order:** product → asset/serial → symptoms **with date
  and time** → problem type → impact/severity → upload TSF → contact phone →
  File a Case. **Phone is the channel for Sev 1.**
  — [Create a Case](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u0000008WANCA2) *(checked 2026-09-07)*
- **Sev 1–4 definitions are published.**
  — [Customer Support Plan](https://www.paloaltonetworks.com/services/support/customer-support-plan) *(checked 2026-09-07)*
- **A TSF is mandatory** for many issue concentrations (exempt: hard-down
  criticals, boot issues, US Federal/Defense/air-gapped) and only
  **`.tar/.zip/.tgz/.tar.tz`** are accepted — so the Correlix bundle must be
  produced as a `.zip` to be acceptable. **No size limit is published.**
  *(checked 2026-09-07)*

### 2.6 Fortinet

- **No case API.** FortiCare's documented API family is
  **asset/registration/licensing only**; the FortiCare guide's full table of
  contents has no API section, and no `forticare`/`ticket` `client_id` is
  documented publicly. — [FortiCare TOC](https://docs.fortinet.com/document/forticloud/26.3.0/forticare/502449/forticare) ·
  [FortiAPI auth](https://docs.fortinet.com/document/forticloud/latest/identity-access-management-iam/19322/accessing-fortiapis) *(checked 2026-09-07)*
- **Ticket fields:** All Tickets → New Ticket → **Technical Support Ticket**,
  with the serial, a priority, a problem description and attachments.
  — [Creating tickets](https://docs.fortinet.com/document/forticloud/26.3.0/forticare/502449/creating-tickets) *(checked 2026-09-07)*
- **P1–P4 definitions are published.**
  — [FortiCare case priority](https://community.fortinet.com/t5/Customer-Service/Customer-Service-Tip-Fortinet-Support-FortiCare-Case-Priority/ta-p/193771) *(checked 2026-09-07)*
- **Entitlement:** FortiCloud account + registered assets + a valid FortiCare
  contract. **Attachments have no published size limit or format list, and files
  are deleted 30 days after the ticket closes.** The diagnostic bundle is
  produced **on the device** by `execute tac report`.
  — [tac report](https://community.fortinet.com/t5/FortiGate/Technical-Tip-Download-Debug-Logs-and-execute-tac-report/ta-p/189549) *(checked 2026-09-07)*

### 2.7 Huawei

- **No public API for enterprise or carrier networking TAC.** Huawei **Cloud**
  OSM does publish `POST /v2/servicerequest/cases`, but it opens **cloud**
  tickets, not network-device TAC cases, and is explicitly positioned as an ITSM
  integration. — [Ticket API index](https://support.huaweicloud.com/intl/en-us/api-ticket/ticket_api_00002.html) ·
  [ITSM positioning](https://support.huaweicloud.com/intl/en-us/productdesc-supportplans/support-plans_01_0014.html) *(checked 2026-09-07)*
- **The enterprise SR portal is JS-gated**, so its field list and severity table
  are **not publicly retrievable — do not assume them**. The only fields the repo
  records are product, problem description and attachments.
  — `caseconn_portal.go` `portalVendors["huawei"]` *(checked 2026-09-07)*
- Huawei Cloud OSM attachments: base64 `accessory_data`, **max 32
  `accessory_ids` per case** (v1 legacy: 1), no real size cap published.
  — [Upload accessory](https://support.huaweicloud.com/intl/en-us/api-ticket/UploadJsonAccessories.html) *(checked 2026-09-07)*

### 2.8 ServiceNow

- **Create** via the Table API; **attach** via
  `POST /api/now/attachment/file?table_name=incident&table_sys_id=<id>&file_name=…`
  with the **raw bytes** in the body and the file's real `Content-Type`.
  — [Table API](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) ·
  [Attachment API](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_AttachmentAPI.html) *(checked 2026-09-07)*
- **Ceiling `com.glide.attachment.max_size`, default 1024 MB**; **no chunked or
  resumable upload is documented**.
  — [max attachment size](https://www.servicenow.com/docs/csh?topicname=sc-max-allowed-attachment-size.html&version=latest) *(checked 2026-09-07)*
- **Inbound email is a different, far stricter ceiling:**
  `glide.email.inbound.max_total_attachment_size_bytes` = **18874368 (18 MiB)
  total, 30 attachments**.
  — [attachment limit properties](https://www.servicenow.com/docs/csh?topicname=r_AttachmentLimitProperties.html&version=latest) *(checked 2026-09-07)*
- **Entitlement:** none from a vendor — an instance and a user with write access
  to the target table; `itil` is ServiceNow's own example role.
  *(checked 2026-09-07)*
- **Mandatory case fields are per instance**, set by dictionary and UI policy, so
  the platform fixes none. What Correlix *always* writes is `short_description`
  (`adapter_servicenow.go`) plus the problem statement — those are the two rows
  the table below enforces, tagged **C**. *(checked 2026-09-07)* — see also
  OPEN QUESTION Q1.

### 2.9 Jira

- **Create** + **attach** via `POST /rest/api/3/issue/{key}/attachments`,
  `multipart/form-data`, field name **`file`**, header
  **`X-Atlassian-Token: no-check`** (Data Center: `/rest/api/2`, `nocheck`).
  — [attach (DC KB)](https://support.atlassian.com/jira/kb/how-to-add-an-attachment-to-a-jira-issue-using-rest-api/) *(checked 2026-09-07)*
- **Cloud default 1 GB/file, max 2 GB; Data Center default 10 MB, max 2 GB** —
  both instance properties. — [Cloud attachment config](https://support.atlassian.com/jira-cloud-administration/docs/configure-file-attachments/) ·
  [DC attachment config](https://confluence.atlassian.com/adminjiraserver/configuring-file-attachments-938847851.html) *(checked 2026-09-07)*
- **Auth:** Cloud = account email + **API token** (password Basic disabled
  2019-06-03); Data Center = a **PAT** bearer.
  — [Basic auth](https://developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis/) *(checked 2026-09-07)*
- **Rate limit: 20 writes / 2 s per issue** on Cloud — exactly the
  create-then-attach pattern. — [rate limiting](https://developer.atlassian.com/cloud/jira/platform/rate-limiting/) *(checked 2026-09-07)*
- **Mandatory issue fields are per project** (project key + issue type are
  connection config, required by `ValidateITSM`); the platform fixes only that an
  issue has a summary. Correlix enforces the summary and the description, tagged
  **C**. *(checked 2026-09-07)* — see also OPEN QUESTION Q1.

### 2.10 Email as a transport (all vendors)

- Base64 costs ~37 % (RFC 2045 §6.8), so the binding raw-bundle ceilings are
  Cisco's 20 MB mailbox (~14.6 MB), ServiceNow's 18 MiB inbound cap (~13.8 MB)
  and the Exchange Online default (~25.5 MB). **14,000,000 raw bytes clears all
  three**, which is `EmailProfileMaxBytes`.
  — [RFC 2045](https://www.rfc-editor.org/rfc/rfc2045) ·
  [Exchange Online limits](https://learn.microsoft.com/en-us/office365/servicedescriptions/exchange-online-service-description/exchange-online-limits) *(checked 2026-09-07)*
- **RFC 1870** sets no universal limit and defines **552** as the over-size
  reply, so the sender reads the MTA's advertised `SIZE` at EHLO and treats 552
  as "degrade to link-only", never as a retryable transport error.
  — [RFC 1870](https://www.rfc-editor.org/rfc/rfc1870) *(checked 2026-09-07)*

---

## 3. The enforced table (machine-checked against `caseconn_required.go`)

Each connector below carries two fenced blocks that
`caseconn_required_test.go` parses and compares to the Go table, **in order**:

- `required-fields` — one field per line:
  `key` or `key | anyof=<group> alt=<alternative>`.
  Fields sharing an `anyof` group are alternatives; fields sharing an `alt`
  within a group must **all** be present for that alternative to count. So
  `serial_number | anyof=cisco-entitlement alt=serial` and the
  `contract_id`/`pid` pair tagged `alt=contract` read as *"a serial number, **or**
  a contract id **and** a PID"*.
- `severity` — one exact token per line, or the single line `(none published)`
  when the vendor publishes no vocabulary. The Go side must also equal the
  connector's own `Caps.SeverityValues`, which the test asserts separately, so a
  vocabulary cannot drift between the doc, the table and the capability matrix.

`Key` is the `internal/tac.CaseForm` field name where one exists
(`title`, `description`, `severity`, `product`, `serial_number`, `contract_id`,
`contact_name`, `contact_email`, `existing_case_number`), otherwise the
`CaseRequest.Fields` key the connector reads (`software_version`, `pid`,
`cco_id`, `contact_phone`, `upload_token`, `app_id`, `customer_source_id`,
`user_id`, `account_id`).

**Scope rule for a row:** a field belongs here when it is part of the *case* —
a request field, an entitlement identifier, or the reference a case attaches to.
Transport credentials (the SMTP relay, an OAuth client secret, a ServiceNow
login) are **not** rows: they are connector settings validated by
`ValidateConfig`, and confusing the two would tell an operator that a missing
password is a missing case field.

### `servicenow`

Tier 1. No vendor entitlement; the connection is the tenant's own ServiceNow
instance. Both rows are **C** (§2.8).

<!-- machine-checked: required-fields -->
```text
title
description
```

<!-- machine-checked: severity -->
```text
(none published)
```

### `jira`

Tier 1. No vendor entitlement. Project key and issue type live in the ITSM
connection, not the case form. Both rows are **C** (§2.9).

<!-- machine-checked: required-fields -->
```text
title
description
```

<!-- machine-checked: severity -->
```text
(none published)
```

### `email-arista`

Tier 1, and the **only** path Arista offers. `title` becomes the subject;
Arista asks for the problem description and "your name and contact information"
(**V**, §2.3). Severity is absent on purpose: the default is P3 and the vendor
publishes no per-level definitions.

<!-- machine-checked: required-fields -->
```text
title
description
contact_name
contact_email
```

<!-- machine-checked: severity -->
```text
(none published)
```

### `email-cisco`

Attach-to-existing only: `attach@cisco.com` files on `SR xxxxxxxxx` in the
subject (**V**, §2.1). Nothing else is required — the SR already carries the
case body.

<!-- machine-checked: required-fields -->
```text
existing_case_number
```

<!-- machine-checked: severity -->
```text
(none published)
```

### `cisco-cxd`

Attach-to-existing only. The SR number is the Basic-auth **user** and the
per-case token the **password**, so both are mandatory (**V**, §2.1). The token
is supplied per attach, used immediately and never persisted.

<!-- machine-checked: required-fields -->
```text
existing_case_number
upload_token
```

<!-- machine-checked: severity -->
```text
S1 — Critical impact (system down)
S2 — Substantial impact (degradation)
S3 — Minimal impact (partial degradation)
S4 — No impact (informational)
```

### `cisco-smart-bonding`

The entitlement triple is **V** and is validated locally before any call. The
five case-body rows are **C**: Cisco does not publish the `push/call` request
schema, so they are the canonical set Correlix binds through
`cisco.field_map` — not a claim about Cisco's own required fields (§2.1).

<!-- machine-checked: required-fields -->
```text
title
description
severity
contact_name
contact_email
cco_id
serial_number | anyof=cisco-entitlement alt=serial
contract_id | anyof=cisco-entitlement alt=contract
pid | anyof=cisco-entitlement alt=contract
```

<!-- machine-checked: severity -->
```text
S1 — Critical impact (system down)
S2 — Substantial impact (degradation)
S3 — Minimal impact (partial degradation)
S4 — No impact (informational)
```

### `juniper`

Every row except `serial_number` is **V**, from
`CreateSRRequest.Validate()` (§2.2). `serial_number` is **C**: the pinned
OpenAPI marks `serialNumber` optional, but "missing serial" is one of the
600–614 entitlement failures, so Correlix asks for it up front rather than
letting the create fail at the vendor — see OPEN QUESTION Q2. `severity` is
required but its **vocabulary is fetched**, never listed here.

<!-- machine-checked: required-fields -->
```text
title
description
severity
contact_email
software_version
serial_number
account_id
app_id
customer_source_id
user_id
```

<!-- machine-checked: severity -->
```text
(none published)
```

### `portal-fortinet`

No API (§2.6). These rows are what the **portal wizard** asks for, so Correlix
can hand the operator a complete paste-ready text; nothing is submitted by
Correlix, so "missing" here means "the portal will ask you for this", not "the
submit button is disabled". The request type is fixed
(*Technical Support Ticket*) and therefore not an operator-supplied row.

<!-- machine-checked: required-fields -->
```text
serial_number
severity
description
```

<!-- machine-checked: severity -->
```text
P1 — total loss or continuous instability of mission-critical functionality in a live or production network environment
P2 — significant impact on mission-critical functionality
P3 — minimal impact on business operations
P4 — additional information, or minor defects that do not impact business services
```

### `portal-paloalto`

No API (§2.5). Rows follow the portal's own field order. The TSF is mandatory
but is a *file*, not a field — it is the bundle, and it must be a `.zip`.

<!-- machine-checked: required-fields -->
```text
product
serial_number
description
severity
contact_phone
```

<!-- machine-checked: severity -->
```text
Sev 1 — product is down and critically affects the customer production environment; no workaround yet available
Sev 2 — product is impaired; customer production is up but impacted
Sev 3 — a product function has failed; customer production is not affected
Sev 4 — product function is not impaired; no impact to customer business
```

### `portal-nokia`

No API (§2.4). Request type is one of three fixed choices, so the two rows below
are the only operator-supplied data the public guide establishes. **No severity
vocabulary is published — do not substitute one.**

<!-- machine-checked: required-fields -->
```text
product
description
```

<!-- machine-checked: severity -->
```text
(none published)
```

### `portal-huawei`

No API for enterprise networking, and the portal is JS-gated (§2.7). Only the
three fields the repo records are known; two of them are operator-supplied.

<!-- machine-checked: required-fields -->
```text
product
description
```

<!-- machine-checked: severity -->
```text
(none published)
```

---

## 4. OPEN QUESTIONS — what this repository does **not** establish

Each of these is a gap in the *pinned research*, not a gap in the code. None may
be filled by inference; filling one means fetching the vendor page and dating a
new finding.

- **Q1 — ITSM per-instance mandatory fields.** Neither ServiceNow nor Jira fixes
  a mandatory case-field set at the platform level: a ServiceNow dictionary entry
  or UI policy, and a Jira project's field configuration, can make **any** field
  mandatory. The two rows each connector enforces are Correlix's own minimum.
  *Consequence:* a create can still be refused by the instance for a field
  Correlix never heard of. The vendor's message is surfaced verbatim.
- **Q2 — Juniper `serialNumber`.** The pinned contract marks it optional; the
  entitlement error class includes "missing serial". Whether a create without a
  serial succeeds for a contract-entitled account is **not established**.
  Correlix asks for it (tagged **C**).
- **Q3 — Cisco's `push/call` request schema.** Field *names* are not published;
  only `customerCaseNumber` and `customerUniqueTransactionID` are cited. The
  nine canonical fields are Correlix's binding surface, not a published list.
  Whether Cisco requires more (technology / problem area / case type) in the
  request is **unknown**; the research records those as *form* concepts only.
- **Q4 — Cisco case type.** `Diagnose and Fix` vs `Request RMA` is named in the
  research's UI section but no token vocabulary is published. Not enforced.
- **Q5 — Arista severity tokens.** `SRPriorityLevels.pdf` is bot/JS-gated. Only
  "default is P3" and "state it in the subject or body" are established. No
  token list exists to enforce.
- **Q6 — Nokia severity + attachment.** Not published at all (zero occurrences
  in the public TSR guide). Both are absent here on purpose.
- **Q7 — Huawei enterprise fields and severity.** JS-gated portal; not
  retrievable. A private or partner-only API cannot be *disproven*, only shown to
  be publicly undocumented.
- **Q8 — Fortinet attachment ceiling and accepted formats.** Not published.
- **Q9 — Palo Alto attachment ceiling.** Not published (the *format* list is).
- **Q10 — The `pid` gap in the seam.** `internal/tac.CaseForm` carries
  `SerialNumber` and `ContractID` but **no PID field**, while Cisco's software
  entitlement needs `contract_id` **+** `pid`. Today a contract-entitled Cisco
  create cannot be completed through the TAC seam — only the serial alternative
  can. `MissingRequired` now names `pid` explicitly, which is what makes the gap
  visible instead of silent. Closing it is a `CaseForm` change owned by the seam,
  not by this table.
- **Q11 — Negatives go stale.** Every "no API" finding is dated **2026-09-05**.
  Fortinet's FNDN and Huawei's enterprise SR pages are login/JS-gated. Re-check
  before making a customer commitment.

---

## 5. How it is enforced

`src/backend/internal/ticketing/caseconn_required.go` — pure lookup, no I/O, no
mutable global (the table is built by a function on every call):

```go
type RequiredField struct {
    Key          string // the CaseForm / CaseRequest.Fields key
    Label        string // what the operator sees
    Why          string // the vendor's (or Correlix's) reason, in one sentence
    SettingsHint string // WHERE the operator supplies it
    AnyOf        string // group id: the group is satisfied by ONE alternative
    Alt          string // alternative id within the group; "" means "this field alone"
}

func RequiredCaseFields(connectorID string) []RequiredField
func RequiredCaseFieldConnectorIDs() []string
func MissingRequired(connectorID string, have map[string]string) []RequiredField
func MissingRequiredMessage(connectorID string, have map[string]string) string
func SeverityVocabulary(connectorID string) []string
```

`MissingRequired` honours the `AnyOf` groups: an unsatisfied group returns **all**
its fields, so the caller refuses **by name** and offers both ways out —

> Cisco Smart Bonding needs your CCO-ID; a serial number, or a contract id and a
> PID. Set them in Administration → Ticket delivery → Case connectors → Cisco and
> the device record in Correlix inventory.

Requirements are separated by a semicolon and never by "and": an `AnyOf` group
already contains an "or", and *"A, and B or C"* is genuinely ambiguous about
which of the three the operator must produce.

`caseconn_required_test.go` parses §3 of this document and fails when the Go
table and the document disagree, asserts `SeverityVocabulary` equals each
connector's own `Caps.SeverityValues`, and asserts that **every** id registered
by `DefaultCaseConnectorRegistry()` has an entry — so a new connector cannot be
added without deciding what it requires.
