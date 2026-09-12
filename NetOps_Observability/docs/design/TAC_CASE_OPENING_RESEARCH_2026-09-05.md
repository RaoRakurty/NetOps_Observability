# TAC case opening — connector research (2026-09-05)

Research input for **TAC escalation pack, wave 2** (`docs/design/TAC_ESCALATION_2026-09-05.md` §4,
"CaseOpener connectors"). Owner's ask: *"find a way to open the TAC case with vendors from the
Correlix UI."*

Method: official vendor developer/support documentation only, fetched 2026-09-05. Every claim below
carries a source URL. Where a vendor has **no public programmatic path**, that is stated as a
negative **with the pages that were checked**, so the finding can be re-verified rather than
re-guessed. Nothing here is inferred from a vendor's marketing or from community posts; the two
places where only a community/JS-gated source exists are flagged inline.

**Headline:** exactly **two** network vendors publish a create-a-case-and-attach-a-file API that a
product can drive — **Cisco** (via Smart Bonding, *not* the Support Case API) and **Juniper** (via the
Service Case API). Both require the *customer* to onboard and own the credentials. Everyone else is
portal-or-email. The design's §4 assumption that "Cisco Support Case API (v3)" opens cases is
**wrong and must be corrected** — v3 is read-only.

---

## 1. The table

| Vendor | Official create+attach API? | Auth | Entitlement / registration | Attach method + limit | Status tracking | Fallback | Sources |
|---|---|---|---|---|---|---|---|
| **Cisco** | **YES — but not the API the design names.** Support **Case API v3 is read-only (GET only)**. Case *creation* is **Smart Bonding** (customer ITSM ↔ Cisco TAC), `POST …/rest/v1/push/call` | Support APIs: OAuth2 **client_credentials**, token `https://id.cisco.com/oauth2/default/v1/token`, 1 h TTL. Smart Bonding: OAuth proxy (auth model not published on the public pages) | Smart Bonding self-onboarding project per customer (analysis → implementation → test → go-live). Entitlement at create: **serial number** (HW) or **contract ID + PID** (SW), plus **CCO-ID** always. Support Case API v3 additionally gated to **PSS partners** | **CXD**: `PUT https://cxd.cisco.com/home/<file>`, Basic auth = SR number / per-case token. **Token is returned in the case-create response** (`Field80` = host, `Field81` = token), valid 72 days, refreshable. **No size limit** (SCM browser upload also "No limit"). Email attach = **20 MB** | `GET …/rest/v1/pull/call` (customer polls); Case API v3 `GET /case/v3/cases/details/case_id/{id}` | SCM portal (`mycase.cloudapps.cisco.com`), `attach@cisco.com` with `SR xxxxxxxxx` in subject | [Case API v3](https://developer.cisco.com/docs/support-apis/case/) · [auth](https://developer.cisco.com/docs/support-apis/authentication/) · [app reg](https://developer.cisco.com/docs/support-apis/application-registration/) · [SB use cases](https://developer.cisco.com/docs/smart-bonding-customer-api/use-cases/) · [SB endpoints](https://developer.cisco.com/docs/smart-bonding-customer-api/self-onboarding-guidance/) · [SB entitlement](https://developer.cisco.com/docs/smart-bonding-customer-api/entitlement-information/) · [SB attachments](https://developer.cisco.com/docs/smart-bonding-customer-api/attachment-information/) · [partner attach fields](https://developer.cisco.com/docs/smart-bonding-partner-api/attachment-information/) · [CXD](https://www.cisco.com/c/en/us/support/web/tac/tac-customer-file-uploads.html) · [SCM guide](https://www.cisco.com/c/en/us/support/docs/cx/cx-cloud/cx220971-support-case-management-case-creation-gu.html) |
| **Juniper** | **YES — cleanest of all.** Service Case API (`css-caseapi`), `POST /createsr`, `/attachfile`, `/updatesr`, `/escalatesr`, `/closesr`. Maturity: **Beta** | **OAuth2 incl. client_credentials** (token `https://apigw.juniper.net/invoke/pub.apigateway.oauth2/getAccessToken`, scopes `css-api-scope`, `css-phase2-scope`), **or** API key in `Authorization`; client-cert SSL also offered | Per-customer onboarding via `https://onboarding-form-app.juniper.net`; Juniper issues `appId` + `customerSourceID`; `userId` must be a registered Customer Service Portal user. Entitlement checked hard at create (errors 600–614: expired contract, no contract, warranty-only → "open Technical SR via other channels") | 3-step: `POST /getfileuploadtoken` → **AWS S3 STS creds** → client PUTs to S3 → `POST /attachfile` with `documentPath`. **No documented byte cap** (`sizeInBytes` unvalidated). Text caps: `problemDescription` 15000, `synopsis` 250 | `POST /querysrdetails`, `POST /querysrlist` (**last 90 days**). **Webhooks: `publishSR`** pushes SR + notes + attachments + RMAs to a client endpoint; `publishLOV` periodic | Juniper Support Portal, phone | [API catalog](https://jnprprod.devportal-aw-us.webmethods.io/portal/apis) · [OpenAPI spec](https://jnprprod.devportal-aw-us.webmethods.io/portal/rest/v1/files/ea71e0db-1f98-4c24-a817-9f9648e64b20) · [onboarding](https://onboarding-form-app.juniper.net) · [JTAC guide](https://support.juniper.net/sites/support/pdf/guidelines/jtac-user-guide.pdf) |
| **Arista** | **NO.** "API" appears **zero times** in the official Support & Community Guide; CloudVision APIs are network-state (gRPC/protobuf) only, no case resource | n/a | Portal account restricted to users whose **corporate email domain matches the customer account** | **Two scriptable attach paths to an existing case**: (a) email to `support@arista.com` with the case **Ref. ID** in subject/body → **auto-attaches**; (b) `ftp ftp.arista.com`, user `ftp`, password = your email, `cd support/<case>`, `put`. Portal upload: **10 GB/file** | None for machines; portal "My Cases" only | `support@arista.com` (DC/EOS). Needs: problem description, **`show tech-support` (compressed)**, network diagrams, name+contact. **Default priority P3**; priority settable **in the email subject or body** | [Customer support](https://www.arista.com/en/support/customer-support) · [Support & Community Guide (PDF)](https://www.arista.com/assets/data/pdf/Arista_Support_Community_Guide.pdf) · [CloudVision APIs](https://aristanetworks.github.io/cloudvision-apis/) |
| **Nokia** | **NO.** NSP publishes exactly five APIs (NSP REST, RESTCONF, Kafka, NFM-P REST, NFM-P XML) — **no case/ticket/TSR API**. Developer portal: 0 hits for `ticket`/`support case`/`TSR` | n/a | Purchased maintenance + portal account (Azure AD B2C gated) | **None documented** — the TSR guide contains 0 occurrences of "attach"/"upload" | Portal "MY CASES" only | Portal wizard (type → product → details → submit); **phone preferred for outages**. **Reply-to-case email works and is automatable — but must not change the Subject line.** Severity matrix **not published** | [TSR Guide for Customers, 2025-08-29 (PDF)](https://www.nokia.com/asset/f/215299/) · [NSP APIs](https://documentation.nokia.com/nsp/24-4/NSP_System_Architecture_Guide/NSP-APIs.html) · [Developer portal](https://network.developer.nokia.com/) · [Support portal](https://customer.nokia.com/support/s/) |
| **Huawei** | **PARTIAL — Huawei *Cloud* only, not device TAC.** Cloud OSM: `POST /v2/servicerequest/cases` + attachment upload. **No public API found for enterprise/carrier networking TAC** | `X-Auth-Token` from IAM `POST /v3/auth/tokens`; region-specific host | Customer's own Huawei Cloud IAM account. Positioned explicitly as an ITSM integration | `POST /v2/servicerequest/accessorys/json-format-content` with **base64** `accessory_data` → `accessory_id`; **max 32** `accessory_ids` per case (v1 legacy: 1). **No real size cap published** | Query ticket list / details / messages. **No webhooks** | For network devices: `support.huawei.com` portal (JS-gated; field list and severity table **not publicly retrievable** — do not assume them) | [Ticket API index](https://support.huaweicloud.com/intl/en-us/api-ticket/ticket_api_00002.html) · [CreateCases](https://support.huaweicloud.com/intl/en-us/api-ticket/CreateCases.html) · [Upload accessory](https://support.huaweicloud.com/intl/en-us/api-ticket/UploadJsonAccessories.html) · [ITSM positioning](https://support.huaweicloud.com/intl/en-us/productdesc-supportplans/support-plans_01_0014.html) |
| **Fortinet** | **NO.** FortiCare's documented API family is **asset/registration/licensing only** (`/ES/api/registration/v3/products/*`, `licenses/*`). The FortiCare guide's full TOC has **no API section** | OAuth2 **password grant** at `https://customerapiauth.fortinet.com/api/v1/oauth/token/` (customer's FortiCloud IAM API user). **No `forticare`/`ticket` `client_id` is documented anywhere public** | FortiCloud account + registered assets + valid FortiCare contract | Portal "File Upload" in the Comment step. **No size limit or format list published.** Files deleted 30 days after ticket close | None documented | Portal: All Tickets → New Ticket → Technical Support Ticket. Bundle produced **locally** by `execute tac report` / GUI *FortiCare Debug Report* and attached by a human. **P1–P4 definitions published** (see §2) | [Creating tickets](https://docs.fortinet.com/document/forticloud/26.3.0/forticare/502449/creating-tickets) · [FortiCare TOC](https://docs.fortinet.com/document/forticloud/26.3.0/forticare/502449/forticare) · [FortiAPI auth](https://docs.fortinet.com/document/forticloud/latest/identity-access-management-iam/19322/accessing-fortiapis) · [asset API endpoints](https://community.fortinet.com/t5/FortiCloud-Products/Technical-Tip-API-how-to-retrieve-list-of-registered-units-for/ta-p/194760) · [tac report](https://community.fortinet.com/t5/FortiGate/Technical-Tip-Download-Debug-Logs-and-execute-tac-report/ta-p/189549) · [priorities](https://community.fortinet.com/t5/Customer-Service/Customer-Service-Tip-Fortinet-Support-FortiCare-Case-Priority/ta-p/193771) |
| **Palo Alto** | **NO.** The CSP API key is a **Licensing** API key. pan.dev's own catalog lists no Customer Support Portal / case / ticket API; the CSP user-doc index's only API item is "Enable, Regenerate, Extend the **Licensing** API Key" | CSP API key requires **Super User** role; regeneration revokes prior keys | CSP account + asset/serial + support contract | Portal upload during case creation. **TSF is mandatory** for many issue concentrations; accepted extensions **`.tar, .zip, .tgz, .tar.tz`**. Exempt: hard-down criticals, boot issues, US Federal/Defense/air-gapped. **No size limit published** | None documented; CSP portal only | CSP → **Create a Case**: product → **asset/serial** → symptoms + date/time → problem type → impact/severity → upload TSF → contact phone → File a Case. **Phone for Sev 1.** Sev 1–4 definitions published (see §2) | [pan.dev catalog](https://pan.dev/) · [CSP user docs index](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClNZCA0) · [Create a Case](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u0000008WANCA2) · [Customer Support Plan](https://www.paloaltonetworks.com/services/support/customer-support-plan) · [AIOps for NGFW](https://docs.paloaltonetworks.com/aiops/aiops-for-ngfw) |
| **ServiceNow** (ITSM) | **YES** | Basic (default), **OAuth2** (authorization_code / password / client_credentials), MFA, cert | Instance + a user with roles to write the target table; **`itil`** named as the example role for attaching to `incident`. Free **PDI** (reclaimed after 10 days idle) | `POST /api/now/attachment/file?table_name=incident&table_sys_id=<id>&file_name=…` — **raw bytes in the body**, `Content-Type` must be the file's real type (`application/zip`). Or `POST /api/now/attachment/upload` (multipart, part name `uploadFile`). Max = **`com.glide.attachment.max_size`, default 1024 MB (1 GB)**. **No chunked/resumable upload documented.** | `GET /api/now/table/incident/{sys_id}` (`state`, `sys_updated_on`); push via **Outbound REST Message** from a business rule / workflow | Inbound email action → creates an incident and attaches. **Hard email ceiling: `glide.email.inbound.max_total_attachment_size_bytes` = 18874368 (18 MiB) total, 30 attachments** | [Table API](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html) · [Attachment API](https://www.servicenow.com/docs/bundle/zurich-api-reference/page/integrate/inbound-rest/concept/c_AttachmentAPI.html) · [max attachment size](https://www.servicenow.com/docs/csh?topicname=sc-max-allowed-attachment-size.html&version=latest) · [rate limiting](https://www.servicenow.com/docs/r/api-reference/rest-api-explorer/inbound-REST-API-rate-limiting.html) · [attachment limit properties](https://www.servicenow.com/docs/csh?topicname=r_AttachmentLimitProperties.html&version=latest) · [Outbound REST](https://www.servicenow.com/docs/csh?topicname=c_OutboundRESTWebService.html&version=latest) |
| **Jira** (ITSM) | **YES** | Cloud: **email + API token** Basic (passwords disabled since 2019-06-03), **OAuth 2.0 3LO** (`write:jira-work`; granular `write:issue:jira`, `write:attachment:jira`), Connect JWT. DC: **PAT** bearer | Cloud site or DC instance; free **developer instance** (5 users) at `go.atlassian.com/cloud-dev` | `POST /rest/api/3/issue/{key}/attachments`, **`multipart/form-data`**, field name **`file`**, header **`X-Atlassian-Token: no-check`** (DC docs use `nocheck`). **Cloud: default 1 GB/file, max 2 GB. Data Center: default 10 MB, max 2 GB** | `GET /rest/api/3/issue/{key}` (`fields.updated`, `fields.status`); **webhook `jira:issue_updated`** — dynamic webhooks **expire after 30 days** and must be refreshed; retries 5× at 5–15 min | Mail handler (limits **not documented**; bounded by the attachment setting and the fronting mail platform) | [Basic auth](https://developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis/) · [OAuth scopes](https://developer.atlassian.com/cloud/jira/platform/scopes-for-oauth-2-3LO-and-forge-apps/) · [attach (DC KB)](https://support.atlassian.com/jira/kb/how-to-add-an-attachment-to-a-jira-issue-using-rest-api/) · [Cloud attachment config](https://support.atlassian.com/jira-cloud-administration/docs/configure-file-attachments/) · [DC attachment config](https://confluence.atlassian.com/adminjiraserver/configuring-file-attachments-938847851.html) · [rate limiting](https://developer.atlassian.com/cloud/jira/platform/rate-limiting/) · [webhooks](https://developer.atlassian.com/cloud/jira/platform/webhooks/) |
| **Email** (universal) | n/a — transport | SMTP | Recipient mailbox only | See §3. **Effective raw-zip ceiling ≈ limit ÷ 1.37** | Reply threading only | The fallback of last resort | [Gmail receiving limits](https://knowledge.workspace.google.com/admin/gmail/gmail-receiving-limits-in-google-workspace) · [Exchange Online limits](https://learn.microsoft.com/en-us/office365/servicedescriptions/exchange-online-service-description/exchange-online-limits) · [RFC 1870](https://www.rfc-editor.org/rfc/rfc1870) · [RFC 2045 §6.8](https://www.rfc-editor.org/rfc/rfc2045) |

---

## 2. Published severity vocabularies (needed by the case form)

These are the vendors' own words; the UI must map Correlix incident severity onto them per vendor
rather than inventing a shared scale.

- **Cisco S1–S4** — S1 "Critical impact" (system down) · S2 "Substantial impact" (degradation) ·
  S3 "Minimal impact" (partial degradation) · S4 "No impact" (informational).
  [SCM case creation guide](https://www.cisco.com/c/en/us/support/docs/cx/cx-cloud/cx220971-support-case-management-case-creation-gu.html)
- **Fortinet P1–P4** — P1 "total loss or continuous instability of mission-critical functionality in a
  live or production network environment" · P2 "significant impact on mission-critical functionality"
  · P3 "minimal impact on business operations" · P4 "additional information … or minor defects that do
  not impact business services."
  [FortiCare case priority](https://community.fortinet.com/t5/Customer-Service/Customer-Service-Tip-Fortinet-Support-FortiCare-Case-Priority/ta-p/193771)
- **Palo Alto Sev 1–4** — Sev1 "Product is down and critically affects customer production
  environment. No workaround yet available." · Sev2 "Product is impaired and customer production is
  up but impacted." · Sev3 "A product function has failed and customer production is not affected."
  · Sev4 "Product function is not impaired and no impact to customer business."
  [Customer Support Plan](https://www.paloaltonetworks.com/services/support/customer-support-plan)
- **Arista** — per-level definitions **not published openly**; the guide says only that Arista
  "adheres to industry standards" and the MSA carries response times. **Default is P3**, and priority
  can be set by stating it in the email subject/body. The `SRPriorityLevels.pdf` is bot/JS-gated.
- **Nokia** — **not published**; the public TSR guide contains zero occurrences of "severity",
  "Critical", "Major" or "Minor". Contract/portal gated.
- **Juniper** — `priority` is a required `createsr` field whose legal values come from the API's own
  `GET /getlov` list-of-values endpoint. **Fetch it, never hard-code it.**
- **Huawei enterprise** — not retrievable (JS-gated portal). Do not assume.

---

## 3. Email fallback — the real ceilings

The universal fallback is only as good as the receiving mailbox, and **base64 costs ~37%**
(RFC 2045: 3 octets → 4 characters, plus a CRLF every 76 characters; Google publishes the same 37%
figure).

| Message limit | Raw zip that fits (÷1.37) | Where it applies |
|---|---|---|
| 20 MB | **~14.6 MB** | **Cisco `attach@cisco.com`** (hard vendor limit) |
| 25 MB | ~18.2 MB | Gmail personal send |
| 35 / 36 MB | ~25.5 / 26.3 MB | **Exchange Online default** send / receive |
| 50 MB | ~36.5 MB | Google Workspace Enterprise Standard receive |
| 70 MB | ~51.1 MB | Google Workspace Enterprise Plus receive |
| 112 MB | ~81.7 MB | Exchange Online, routed outside Microsoft datacenters |
| 18 MiB (total, not per file) | ~13.8 MB | **ServiceNow inbound email action** — the strictest common ceiling |

**Design target: keep the emailable bundle profile under ~14 MB raw.** That clears Cisco's 20 MB
vendor cap, ServiceNow's 18 MiB inbound cap and the Exchange Online default simultaneously, without
per-customer tuning. RFC 1870 sets no universal ceiling and defines `552` as the over-size reply, so
the sender must read the receiving MTA's advertised `SIZE` at EHLO and treat `552` as a first-class
outcome (degrade to link-only), not as a transport error to retry.

---

## 4. Recommendation — what to build, in order

Ranked by **feasibility × customer value**, not by vendor prominence.

### Tier 1 — build in W2 (high value, no external onboarding, testable today)

1. **ServiceNow CaseOpener** and 2. **Jira CaseOpener.**
   `internal/ticketing` already holds per-tenant ServiceNow and Jira configs with write-only secrets,
   an `Adapter` interface with `CreateIncident`/`FetchIncident`, SSRF pre-validation
   (`safehttp.ValidateURL`) and an isolation-tested store. The **only** thing missing is
   `AttachFile`. Both vendors give free test instances (PDI; Atlassian dev instance), both document
   create *and* attach, and both are worth ~1 GB per attachment against email's ~14 MB.
   Crucially this is also **where most enterprises actually escalate first** — the NOC opens its own
   incident, and the vendor case is opened *from* it (Cisco's own create path, Smart Bonding, is
   literally an ITSM-to-TAC bridge). Shipping ServiceNow/Jira attachment support therefore delivers
   the owner's goal for the majority of customers before a single vendor API is touched.

3. **Email CaseOpener (universal fallback) + portal-text mode.**
   Cheap, and it is the *only* mechanism for Arista, Nokia, Fortinet, Palo Alto and Huawei
   enterprise — five of the seven vendors. Two distinct behaviours, both worth having:
   - **open-by-email**: Arista is fully served here (`support@arista.com`, `show tech-support`
     attached, priority stated in the subject line — all of which Correlix can compose).
   - **attach-to-existing-case by email**: Arista auto-attaches on the case **Ref. ID**; Nokia
     threads on an **unmodified Subject line**; Cisco accepts `attach@cisco.com` with `SR xxxxxxxxx`.
     This turns "the admin opened the case by hand" into a supported, still-automatic attach path.

### Tier 2 — build next (real APIs, but each customer must onboard)

4. **Cisco, in two halves — attach first.**
   - **4a. CXD attach-to-existing-case.** Very high value for very little code: one authenticated
     `PUT https://cxd.cisco.com/home/<name>` with Basic auth = SR number / token, **no file-size
     limit at all** — the only path in this entire study that swallows a full `show tech-support`
     without negotiation. The admin pastes the SR number and the CXD token from SCM; Correlix
     uploads. Ship this before any create API.
   - **4b. Smart Bonding create.** `POST …/rest/v1/push/call` with entitlement (serial, or contract
     + PID, plus CCO-ID). The create response returns the CXD host and token (`Field80`/`Field81`),
     so **create → attach is fully closed-loop** once onboarded. Gate behind an opt-in flag: it needs
     a per-customer onboarding project with a Cisco test environment, so it cannot be a default-on
     feature.
   - **Correct the design doc:** §4 names "Cisco Support Case API (v3, OAuth2 client credentials)"
     as the create path. v3 exposes only `GET /cases/…` (summary, details, by contract, by user) and
     is scoped to PSS partners. It is useful for **status polling**, not for opening cases.

5. **Juniper Service Case API.** Technically the best-designed target in this study: OAuth2
   client_credentials, `POST /createsr`, an S3-token attachment flow with no documented byte cap,
   `querysrdetails`/`querysrlist` polling **and a real `publishSR` webhook**. It is ranked below
   Cisco only because (a) it is marked **Beta**, (b) onboarding is a form-and-email process that
   yields per-customer `appId`/`customerSourceID`, and (c) it hard-fails on entitlement (errors
   600–614), which needs careful UX. Note the **1000 invocations/hour** hard limit and the rule that
   `contactEmail` must be "a real person and not an alias".

### Tier 3 — do not build unless a customer asks

6. **Huawei Cloud OSM** (`POST /v2/servicerequest/cases`) — a genuine create+attach API, but it opens
   **Huawei Cloud** tickets, not network-device TAC cases. Out of scope for the escalation pack's
   purpose; document it and move on.
7. **Fortinet, Palo Alto, Nokia, Huawei-enterprise** — portal-text + bundle download only. Correlix
   can automate everything *up to* submission: classify, collect, redact, bundle, and pre-fill the
   exact field set each portal asks for (§5). **Do not promise an API on these vendors.** Note for
   Palo Alto specifically that TSF is mandatory and the portal accepts only
   `.tar/.zip/.tgz/.tar.tz`, so the bundle must be produced as a `.zip` to be acceptable.

**Explicit honesty rule (matches the design's §3c stance on unbound dialects):** the UI must say
which mode a vendor is in — *API case opening* / *attach-only* / *portal text* — and never render an
"Open case" button that silently degrades to a download. A vendor with no API is a fact to display,
not a gap to paper over.

---

## 5. Credential model — per-tenant sealed secrets

The product rule (CLAUDE.md §3a) and every source consulted point the same way: **no vendor permits a
shared, Correlix-owned support identity.**

- Cisco: `appId`-equivalent onboarding is per customer; entitlement is the customer's serial/contract
  and their **CCO-ID**.
- Juniper: `appId` + `customerSourceID` + `userId` are issued to the client at *their* onboarding;
  `contactEmail` must be a real registered human on that account.
- Arista: portal accounts are "restricted to users whose corporate email domain matches that of the
  associated customer account" — a third-party identity is structurally blocked.
- Fortinet / Palo Alto / ServiceNow / Jira: customer-owned IAM user, Super User API key, instance
  user, API token respectively.

So the model is **bring-your-own-credentials, per tenant, opt-in**:

1. **Storage.** Extend the existing pattern in `internal/ticketing/itsm_config.go`: config structs
   whose secret fields are `json:"…,omitempty"` and **write-only** (never returned on read, merged on
   write), persisted per tenant, sealed through `internal/sealedfields` (vault-backed), never logged.
   Add `internal/tac/` connector configs alongside — do not overload `ServiceNowConfig` with vendor
   TAC fields.
2. **Per-connector secret sets.**
   - Cisco: `cco_id`, `smart_bonding_client_id`/`secret`, `customer_source_id`, plus per-case CXD
     token (ephemeral, **never persisted** — it is a 72-day upload credential scoped to one SR).
   - Juniper: OAuth2 `client_id`/`client_secret` **or** API key, `appId`, `customerSourceID`,
     `userId`, `accountID`, default `contactEmail`.
   - ServiceNow / Jira: reuse what exists.
   - Email: SMTP credentials or the platform relay, plus the per-vendor destination address.
3. **Gate.** These are **per-tenant data-plane** credentials — `requirePerm` + tenant filter, **not**
   `requirePlatformAdmin`. (Contrast: the notification channels in the monitoring lane are
   platform-global and correctly sit behind `requirePlatformAdmin`. TAC credentials are the tenant's
   own vendor contract and must not be visible across tenants.)
4. **Isolation test is mandatory** (§3a.5): own-only list, cross-tenant get/put/delete → 404,
   `as_tenant` into another org ignored, and — specific to this feature — **a case record created
   under tenant A is never attachable-to from tenant B**.
5. **SSRF.** Every configurable base URL (ServiceNow instance, Jira site, DC hosts) goes through
   `safehttp.ValidateURL` as today. Vendor API hosts (`apix.cisco.com`, `cxd.cisco.com`,
   `sb.xylem.cisco.com`, `apigw.juniper.net`) should be a **pinned allowlist**, not free-form input —
   there is no legitimate reason for a tenant to point the Cisco connector at an arbitrary host.
6. **Audit.** Case create, attach, status poll and credential change are all audited events carrying
   tenant, incident, device, bundle digest and case id. The bundle's SHA256 is the link between "what
   we collected" and "what the vendor received".

---

## 6. `CaseOpener` capability matrix

One interface in `internal/tac/`, implementations pluggable; **capabilities are declared, not
assumed**, so the UI renders only what a connector can actually do.

```
type CaseOpener interface {
    Name() string
    Capabilities() Caps
    ValidateConfig(cfg Config) error
    CreateCase(ctx, cfg, req CaseRequest) (CaseRef, error)
    AttachBundle(ctx, cfg, ref CaseRef, b Bundle) (AttachResult, error)
    FetchCase(ctx, cfg, ref CaseRef) (RemoteCase, bool, error)
    AddNote(ctx, cfg, ref CaseRef, note string) error
}
type Caps struct {
    Create, Attach, Poll, Webhook, Note, Escalate, Close bool
    AttachToExistingOnly bool   // Cisco-CXD / Arista-email / Nokia-reply
    MaxAttachBytes       int64  // 0 = no documented limit
    RequiresEntitlement  bool
    SeverityValues       []string // static, or fetched (Juniper /getlov)
}
```

| Connector | Create | Attach | Poll status | Webhook | Link back | Max attach | Notes |
|---|---|---|---|---|---|---|---|
| ServiceNow | ✅ | ✅ | ✅ (`sys_updated_on`) | ⚠️ customer-built Outbound REST | ✅ record URL | 1 GB (property) | no chunked upload documented |
| Jira | ✅ | ✅ | ✅ (`fields.updated`) | ✅ `jira:issue_updated` (30-day expiry) | ✅ issue URL | Cloud 1 GB / DC 10 MB default | per-issue 20 writes / 2 s |
| Cisco — CXD | ❌ | ✅ | ❌ | ❌ | ✅ SR number | **unlimited** | attach-to-existing only; token from SCM or create response |
| Cisco — Smart Bonding | ✅ | ✅ (via CXD, token in create response) | ✅ (`pull/call`) | ❌ (pull model) | ✅ SR number | unlimited | onboarding project; entitlement hard-gated |
| Juniper | ✅ | ✅ (S3 token → `/attachfile`) | ✅ (90-day window) | ✅ `publishSR` | ✅ SR number | no documented cap | Beta; 1000 req/h; real human `contactEmail` |
| Huawei Cloud | ✅ | ✅ (base64, ≤32) | ✅ | ❌ | ✅ `incident_id` | not published | **cloud tickets, not device TAC** |
| Email | ✅ (Arista) | ✅ (ref-ID / subject-threaded) | ❌ | ❌ | ⚠️ only after a human replies | ~14 MB safe | the universal floor |
| Portal-text | ❌ | ❌ | ❌ | ❌ | manual paste-back | n/a | Fortinet, Palo Alto, Nokia, Huawei-enterprise |

**Two capability facts the UI must respect:** (1) `AttachToExistingOnly` is a first-class mode, not a
degraded create — Cisco-CXD and Arista-email are genuinely useful in it; (2) `Poll` absence means the
case link is the *only* status surface, so the incident should show "status not tracked by Correlix"
rather than a stale badge.

---

## 7. UI needs — the case form

The escalate action opens one form, **pre-filled from the bundle**, with only the fields the selected
vendor actually requires. Everything below is already derivable from what Correlix holds
(incident, RCA, device facts, topology, the collected bundle) except the entitlement identifiers and
the contact, which are tenant configuration.

**Common to every vendor** (prefilled, editable):
- **Problem statement** — Iris's evidence-only narrative from §1d. Respect vendor caps: Juniper
  `problemDescription` ≤ 15000 and `synopsis` ≤ 250; ServiceNow/Jira effectively unbounded.
- **Synopsis / subject** — one line, ≤ 250 chars, must carry the issue class and device.
- **Severity** — mapped per vendor from the incident's severity, with the vendor's own vocabulary
  shown (§2) and the mapping visible so the admin can override. Juniper's list is **fetched from
  `/getlov`**, never hard-coded. Arista's goes into the email subject line.
- **Device / serial number** — from Correlix inventory. **This is the entitlement key** for Cisco HW,
  Juniper, Arista RMA, Fortinet, Palo Alto.
- **Contact** — name, email, phone. Juniper explicitly requires a real person, not an alias; Palo
  Alto asks to confirm a contact phone; Arista requires "your name and contact information".
- **Bundle** — file list, total size, the redaction summary, SHA256, and **which delivery path will
  be used at that size** (API / email / link-only).

**Vendor-specific additions:**
- **Cisco** — CCO-ID (config); contract ID + PID when the case is software rather than hardware;
  case type (`Diagnose and Fix` vs `Request RMA`); technology / problem area; `customerCaseNumber`
  and a generated `customerUniqueTransactionID` (idempotency — Smart Bonding errors on duplicates);
  for CXD-attach mode, the SR number + upload token.
- **Juniper** — `accountID`, `caseTypeCode` (e.g. `TEC`), `followUpMethod`, `softwareVersion`
  (**mandatory since 2024-05-16**), `networkOutage` (P1 technical SRs only), and a fresh
  `customerUniqueTransactionID` per request.
- **Arista** — product category, subject line (both portal-mandatory), desired priority stated in the
  subject/body (default is P3 otherwise), and the case **Ref. ID** when attaching to an existing case.
- **Palo Alto** — asset/serial, problem type, impact, and a **`.zip`** TSF (only `.tar/.zip/.tgz/.tar.tz`
  are accepted).
- **Fortinet** — serial, request type (Technical Support Ticket), P1–P4, and a note that files are
  deleted 30 days after close.
- **Nokia** — request type (Technical Problem / HRR-RMA / Feature Request); warn that **phone is the
  vendor-preferred channel for outages** and that a reply must not alter the Subject line.
- **ServiceNow / Jira** — assignment group / project + issue type (already configured today).

**States the form must be able to show honestly:** *no connector configured* (download + portal text),
*attach-only*, *entitlement check failed* (with the vendor's own error text), *bundle too large for
this path*, and *created, attaching…* as a distinct state from *created*.

---

## 8. Risks

1. **Entitlement failure is the most likely user-visible failure, and it happens at create time.**
   Juniper enumerates it as a whole error class (600–614: expired contract, no contract + out of
   warranty, warranty-only → "open Technical SR via other channels", missing serial); Cisco requires
   serial *or* contract+PID *plus* CCO-ID; Palo Alto and Fortinet gate on asset + contract.
   *Mitigation:* validate entitlement inputs before collecting anything, surface the vendor's verbatim
   error rather than a generic failure, and always leave the download + portal-text path available so
   a failed create never strands the bundle. Where a vendor exposes an entitlement lookup (Cisco
   SN2INFO, Fortinet asset API), a pre-flight check is cheap insurance.

2. **Attachment size vs `show tech-support`.** The spread is enormous — Cisco CXD unlimited, Jira
   Cloud 1 GB, ServiceNow 1 GB by property (but **18 MiB** by email), Cisco email 20 MB, Jira DC
   10 MB by default. A `show tech-support` on a chassis is routinely tens of MB.
   *Mitigation, in order:* (a) make bundle **size a planning output** shown before collection (the
   design already promises this in §3b), with the `show tech-support` toggle defaulted per available
   path; (b) emit **two profiles** — a full bundle for API paths and a ≤14 MB "email profile" that
   drops or truncates the largest artifacts and says so in `MANIFEST.json`; (c) **link-only mode** as
   the last resort — a signed, expiring, tenant-scoped download URL in the case description instead of
   an attachment. **Do not build chunking**: neither ServiceNow nor Jira documents a resumable or
   ranged upload, so "chunking" would mean splitting into multiple files, which is a bundle-format
   decision, not a transport one. Splitting a zip across attachments should be a deliberate,
   manifest-described act, never a silent transport behaviour.

3. **Per-customer onboarding is a sales/ops dependency, not an engineering one.** Cisco Smart Bonding
   and Juniper both require the customer to complete a vendor onboarding project before a single API
   call works. A connector that is built but un-onboardable looks broken.
   *Mitigation:* ship Tier 1 (ITSM + email) first so the feature is valuable on day one; make the
   vendor connectors explicitly opt-in with a "not onboarded" state and a link to the vendor's own
   onboarding form; treat the Cisco **CXD attach** path as the low-friction Cisco entry point since it
   needs only an SR number and a token the admin can copy from SCM.

4. **Beta / moving targets.** Juniper's Service Case API is marked **Beta** and its portal host is a
   webMethods URL, not a stable `*.juniper.net` developer domain (`apidocs.juniper.net` and
   `developer.juniper.net` do not resolve). Junos Space Service Now — the historical auto-open-a-JTAC-case
   mechanism — is **EOL and its docs are archived**; it must not be built on.
   *Mitigation:* pin the OpenAPI spec into the repo as the contract of record, version the connector,
   and fail closed with a clear message on schema drift rather than silently mis-filing a case.

5. **Rate limits and idempotency.** Juniper hard-blocks at **1000 invocations/hour**; Jira Cloud
   enforces **20 writes / 2 s per issue** (exactly the create-then-attach-then-retry pattern);
   ServiceNow returns 429 with `Retry-After` but publishes **no default limit**, so it must be
   discovered from response headers at runtime. Both Cisco and Juniper require a caller-generated
   unique transaction id and treat a repeat as an update, not a new case.
   *Mitigation:* one collection/escalation per device at a time (already a design constraint),
   persisted idempotency keys, exponential backoff with jitter honouring `Retry-After`, and a bounded
   outbox — the existing ticketing worker's shape, reused.

6. **Leaking data to a third party.** The bundle goes to a vendor's cloud. The existing TAC redactor
   is the control, and it must run **before** any upload, with the redaction summary shown in the
   form. Juniper's attach path hands the client **AWS S3 STS credentials** — those are short-lived,
   per-upload, and must never be persisted or logged. Cisco's CXD token is likewise per-SR and
   ephemeral. Note also Arista's portal upload is GCP-backed with "encryption at rest pending" per
   their own guide, and Arista requires allowlisting **GCP org 53989931248** for egress.

7. **"Correlix opened a case nobody wanted."** Every vendor's entitlement/contract model means a case
   has commercial consequences, and Juniper insists a named human owns the contact.
   *Mitigation:* case creation is an **explicitly human-approved action from the UI**, never an
   autonomous output of the correlation engine — no rule, alert or auto-remediation may call
   `CreateCase`. No vendor document reviewed forbids automated creation, but none contemplates it
   either; the safe reading is human-in-the-loop.

8. **Negatives that could go stale.** Fortinet's FNDN and Huawei's enterprise SR pages are
   login/JS-gated, so a private or partner-only API cannot be *disproven* for those two — only shown
   to be publicly undocumented. Record the negative with its date and re-check before a customer
   commitment.
