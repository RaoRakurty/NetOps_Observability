# Tenant URL Strategy — how customers address Correlix, and how URLs differentiate tenants

> Research + recommendation, 2026-07-10. Prepared for owner review (queued
> overnight). Status: **PROPOSAL — nothing built.** Companion earlier decision:
> per-customer unique **ingest** URLs ("model C", 2026-06-07, parked) — this doc
> extends that question to the **app/UI/API** URLs and reconciles the two.
> All vendor claims cite primary docs (links at each claim).

## 0. TL;DR recommendation

**Hybrid: canonical path-based tenancy everywhere + a subdomain veneer for SaaS,
with the JWT claim always the source of truth and mismatches failing as 404.**

1. **Canonical grammar (works on every install, today):**
   `https://<host>/t/<tenant-slug>/...` for the UI and
   `https://<host>/api/t/<tenant-slug>/...` for the API. No wildcard DNS, no
   extra certs — a self-hosted single-hostname install (our `:8000` nginx) is
   fully addressable. This is the GitLab / Dynatrace-ActiveGate (`/e/{env-id}/`)
   precedent. **Reserve the `/t/` and `/api/t/` prefixes now** even if we build
   later.
2. **SaaS veneer:** `acme.correlix.<domain>` (wildcard DNS + one wildcard cert,
   DNS-01 ACME) resolved at the edge into the same `/t/acme` context. Subdomains
   buy: per-tenant browser **origin isolation** (with `__Host-` host-only
   cookies), per-tenant edge rate-limits / IP allowlists *before* auth, and
   unambiguous links. The app never depends on them — routing sugar only.
3. **Trust order:** authenticate first; the **token claim authorizes**, the URL
   only *selects* context; claim ≠ URL-tenant → **404** (never 403/redirect —
   no existence oracle; matches our §3a rule). Host header allowlisted at
   nginx; links in emails/alerts built from the tenant's stored canonical URL,
   never from the request Host.
4. **Identity split stays as-is:** opaque `t_…` id = eternal machine identity;
   slug = mutable human alias (rename with redirect; **released slugs are
   tombstoned forever** — Slack's reuse-after-release is a documented
   phishing/takeover lesson).
5. **Ingest (model C) composes cleanly:** per-tenant ingest endpoints live on a
   **separate stem** (`*.ingest.…` in SaaS; distinct port/path self-hosted) with
   per-tenant credentials on top — tenant known at the socket, edge/DoS blast
   radius partitioned from the app.
6. **Cells/regions later:** keep the cell **out of UI URLs** (stable tenant
   hostname; CNAME/edge maps tenant→cell so migration is a control-plane flip);
   exposing the cell in ingest URLs is fine and industry-normal.

Why a session/claim-only single URL (what we have today) is not the end state:
links then carry **no tenancy** — an RCA permalink or alert email opens in
whatever org the recipient's session holds. Datadog documents exactly this
failure and sells the fix (opt-in per-org subdomains that switch context:
<https://docs.datadoghq.com/account_management/multi_organization/>). For a
product whose core artifact is "here's the incident link," URL-carried tenancy
is table stakes.

---

## 1. What the field does (evidence)

| Vendor | App addressing | Pattern |
|---|---|---|
| Slack | `acme.slack.com` | subdomain-per-workspace; slug mutable, **released slugs reusable → known phishing/enumeration weakness** (<https://slack.com/help/articles/201663443>, <https://trufflesecurity.com/blog/identify-slack-workspace-names-from-webhook-urls>) |
| ServiceNow | `acme.service-now.com` | dedicated instance per customer; customer-owned custom URL via CNAME + dedicated VIP (<https://www.servicenow.com/docs/r/platform-security/authentication/custom-url.html>) |
| Grafana Cloud | `<stack-slug>.grafana.net` | subdomain per stack; **ingest = shared per-cell hostnames + tenant in the credential** (Basic user = instance id) (<https://grafana.com/docs/grafana-cloud/security-and-account-management/region-url-formats/>) |
| Datadog | `app.datadoghq.com` + sites `us3./us5./eu./ap1.` | session-scoped org on shared site URL; **retrofitted opt-in org subdomains to fix ambiguous deep links**; no migration between sites (<https://docs.datadoghq.com/getting_started/site/>) |
| Splunk Cloud | `acme.splunkcloud.com` | stack per customer; ingest `http-inputs-<stack>.splunkcloud.com` + HEC token |
| Atlassian | `acme.atlassian.net` | subdomain per site; data-residency realm **hidden from the URL** and migratable; custom domains require 2-label structure + auto-issued certs (<https://support.atlassian.com/organization-administration/docs/add-a-custom-domain/>) |
| Salesforce | `mycompany.my.salesforce.com` | spent a multi-year program (enhanced domains) **removing instance/cell names from URLs** so org moves don't break links |
| Microsoft Entra | tenant GUID + `contoso.onmicrosoft.com` + verified domains | **immutable machine id + mutable verified human aliases** — exactly our `t_…` + slug split (<https://learn.microsoft.com/en-us/entra/identity/users/domains-manage>) |
| Dynatrace | `{env-id}.live.dynatrace.com` **and** `/e/{env-id}/` behind ActiveGate | random unguessable env-id subdomain in SaaS, **same tenant as a path segment when self-hosted** — the exact SaaS/self-hosted duality answer |
| GitHub / GitLab | `github.com/org`, `gitlab.example.com/group` | path-based namespace, identical hosted vs self-managed; unauthorized → **404** by design |
| Okta / Auth0 | `acme.okta.com` / `acme.auth0.com` | subdomain per org + custom domains (managed ACME certs; Auth0 CNAMEs to a random edge target) |

Observability-specific: every vendor puts a **per-tenant credential on ingest**;
the tenant-in-hostname group (Grafana/Dynatrace/Splunk/Elastic) additionally
gets tenant identity at the socket — our model C, already decided.

## 2. Pattern trade-offs (condensed)

| Concern | (a) Subdomain | (b) Path `/t/slug` | (c) Claim-only (today) | (d) Custom domain |
|---|---|---|---|---|
| Browser origin isolation | ✅ (with `__Host-` cookies) | ❌ | ❌ | ✅✅ |
| Deep links carry tenant | ✅ | ✅ | ❌ (Datadog's documented pain) | ✅ |
| Pre-auth per-tenant edge controls (rate-limit, IP allowlist) | ✅ Host/SNI | ✅ path | ❌ | ✅ |
| Wildcard DNS/TLS needed | ✅ (DNS-01 ACME) | ❌ | ❌ | per-host cert automation |
| Self-hosted / air-gapped parity | ❌ breaks w/o wildcard DNS | ✅ perfect | ✅ | n/a |
| Tenant-list confidentiality | wildcard cert keeps names out of CT logs; per-tenant certs leak every customer into CT | nothing in DNS/CT | nothing | customer's DNS reveals relationship |
| Cell migration later | flip one CNAME | LB config | invisible | flip CNAME |

Key security notes:
- **Cookie scope**: subdomain isolation is only real with host-only cookies
  (`__Host-` prefix, no `Domain=`); a `Domain=`-scoped session cookie bleeds to
  every tenant subdomain (<https://devcenter.heroku.com/articles/cookies-and-herokuapp-com>).
- **Host header is attacker input**: strict allowlist at nginx, strip
  `X-Forwarded-Host` overrides, never build password-reset/alert links from the
  request Host (<https://portswigger.net/web-security/host-header>).
- **RFC 9700** forbids wildcard OAuth redirect URIs → with subdomains, SSO uses
  one canonical auth host (`auth.…`) that bounces back with tenancy in `state`
  (fits our JWT flow), not per-tenant IdP registrations
  (<https://datatracker.ietf.org/doc/rfc9700/>).
- **Offboarding**: require the customer's CNAME be deleted before releasing a
  custom domain; never recycle slugs (dangling-DNS/subdomain-takeover —
  <https://learn.microsoft.com/en-us/azure/architecture/guide/multitenant/considerations/domain-names>).

## 3. What this means for Correlix concretely

Build order when we take this on (each step is independently shippable):

1. **P0 — Reserve + route:** claim `/t/<slug>` + `/api/t/<slug>` in the SPA
   router and Go API mux; unknown/unauthorized slug → 404 page identical to
   not-found. Existing un-prefixed routes keep working for the current
   single-context session (they resolve tenant from the claim as today).
2. **P1 — Claim/URL cross-check middleware:** one Go middleware:
   `urlTenant != principalTenant(claims) && !cross → 404`; audit-log the
   mismatch. Cache/rate-limit keys include the resolved tenant.
3. **P2 — Links carry tenancy:** notification/e-mail/RCA permalink builders
   emit the tenant-scoped canonical URL from the tenant record (never request
   Host). This is the user-visible payoff and needs P0+P1 only.
4. **P3 — SaaS subdomain veneer (SaaS launch item, not needed self-hosted):**
   nginx map `^(?<slug>[a-z0-9-]+)\.correlix\.<domain>$` → set the tenant
   context header for the API + rewrite SPA entry; wildcard cert via DNS-01;
   `__Host-` cookies; host allowlist. Slug rename = alias table + 308s;
   released slugs tombstoned.
5. **P4 — Ingest stem (folds into model C when un-parked):** `*.ingest.…`
   hostnames or per-tenant tokens in the path + per-tenant credentials; keep
   the app and ingest stems separate.
6. **Later — custom domains + regional cells** per §2 rules (cells hidden in
   app URLs, visible in ingest URLs OK; Cloudflare-for-SaaS-class cert
   automation if customer domains are demanded).

Open decisions for the owner:
- **Slug vs random id in SaaS hostnames.** Vanity slugs (`acme.…`) read
  premium but leak the customer list if we ever issue per-tenant certs and are
  enumerable by probing; Dynatrace-style random short ids (`abc12345.…`) are
  unguessable and CT-safe but ugly. (Recommendation: vanity slug + wildcard
  cert only; revisit if defense-adjacent customers demand tenant-list
  confidentiality.)
- **Whether `/t/<slug>` is user-visible self-hosted** or only appears once a
  second tenant exists on an install (single-tenant installs could keep bare
  URLs and treat the default tenant as implicit).
- **Timing**: none of this blocks current work; P0–P2 are the cheap,
  high-value core and make sense before SaaS onboarding of tenant #2.

## 4. Relationship to existing decisions

- **Model C ingest (2026-06-07, parked):** unchanged and reinforced — this doc
  gives it the stem-separation + credential-on-top shape the whole industry
  uses.
- **Opaque identity model (`t_…` + slugs):** unchanged — it is exactly the
  Entra machine-id/alias split; URLs use slugs, storage/APIs keep opaque ids.
- **§3a isolation rules:** the 404-on-mismatch URL behavior is the same rule
  lifted to the routing layer.
