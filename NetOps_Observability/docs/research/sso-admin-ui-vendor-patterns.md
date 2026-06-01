# SSO / Authentication Admin UI — Vendor Patterns & Recommended Layout

Research grounding for the NetOps_Observability SSO admin section. Surveys how
Datadog, Okta, and Splunk (plus Grafana and notes on Auth0/Keycloak) design
their **admin-facing** SSO configuration pages, then synthesizes a recommended,
implementable React layout for our OIDC (Keycloak-brokered) + native LDAP/AD +
native TACACS+ providers.

> Scope note: this is about the *administrator's configuration screens*, not the
> end-user login experience. All claims are cited inline.

---

## 1. Datadog

**Where it lives:** Organization Settings → **Login Methods** → SAML section.
Initial setup is a "Configure" button under SAML; adding a second provider is
"Update" → "Add SAML".
([configuration](https://docs.datadoghq.com/account_management/saml/configuration/))

### 1a. SAML SP config
Datadog deliberately keeps the SAML form minimal — it is a **modal**, not a
multi-tab page:

- **Provider Name** — "Create a user-friendly name for this SAML provider. The
  name appears to end users when they choose a login method." (Datadog supports
  multiple SAML providers, hence the user-facing name.)
- **IdP metadata** — entered **only by XML file upload** ("browse files or
  dragging and dropping the XML metadata file onto the modal"). There is **no
  metadata-URL field**. Constraint: "The IdP metadata must contain ASCII
  characters only."
- **SP metadata / ACS / Entity ID** — Datadog exposes the Service Provider
  Entity ID and an org-specific **AssertionConsumerService** endpoint, and lets
  you **download the SP metadata XML** (or copy the ACS URL + Entity ID) to hand
  to the IdP. After enabling IdP-initiated login and saving, you re-download SP
  metadata because the ACS endpoint becomes organization-specific.
  ([saml](https://docs.datadoghq.com/account_management/saml/),
  [configuration](https://docs.datadoghq.com/account_management/saml/configuration/))
- **IdP-initiated login** — an explicit feature toggle to enable; changes the
  SP metadata.

### 1b. Group / role mapping (the most detailed part of Datadog's UI)
Organization Settings → **SAML Group Mappings** tab, with sub-tabs **Role
Mappings** and **Team Mappings**.
([mapping](https://docs.datadoghq.com/account_management/saml/mapping/))

- Each mapping = a **SAML attribute key + attribute value → Datadog role (or
  team)**. Flow: "New Mapping" → enter the SAML key/value pair → select an
  existing Datadog role → "Create". Team mappings add an "Add Row" affordance
  and a Team dropdown.
- A master **"Enable Mappings"** toggle activates the whole feature. The docs
  warn loudly: **"If a user does not match any mapping, they lose any roles they
  had previously and are prevented from logging into the org with SAML"** — this
  includes JIT-provisioned roles. (Roles gate login; team mappings do not.)
- Behavior is **additive across mappings** ("unless another mapping adds it");
  entries are **case-sensitive**; limit 1,000 role + 1,000 team mappings.
- Notably, Datadog does **not** expose an explicit "default role" field in the
  mapping UI — no-match = no access, which is the conservative default.

### 1c. Cert expiry / troubleshooting
Datadog does not surface a proactive cert-expiry banner; instead its SAML
troubleshooting guide tells admins that login failures are often "an IdP
certificate may have expired and rotated."
([troubleshooting](https://docs.datadoghq.com/account_management/saml/troubleshooting/))

**Datadog takeaways:** minimal modal for the protocol config; richness lives in
the **mapping table**; strong copy/download of SP metadata; multiple-IdP support
via a user-facing provider name; very explicit "no match = locked out" warning.

---

## 2. Okta (as the admin building app integrations)

Okta is the canonical reference because admins build SAML *and* OIDC app
integrations and run a native LDAP agent. Entry point: **Admin Console →
Applications → Applications → Create App Integration**, then pick a sign-in
method (SAML 2.0 / OIDC - OpenID Connect).
([SAML wizard](https://saml-doc.okta.com/SAML_Docs/Configure-SAML-2.0-for-Org2Org.html),
[OIDC wizard](https://help.okta.com/en-us/content/topics/apps/apps_app_integration_wizard_oidc.htm))

### 2a. SAML 2.0 (the App Integration Wizard — a multi-step flow)
- **General Settings** step: app name, optional logo.
- **Configure SAML** step:
  - **Single sign-on URL** = the **ACS URL** of the target app.
  - **Audience URI (SP Entity ID)** = the SP entityID.
  - **Name ID format** and **Application username** dropdowns.
  - **Attribute Statements** — a repeating Name / Name-format / Value table for
    user-profile claims.
  - **Group Attribute Statements** — Name (commonly `groups`) + a **filter**
    (Starts with / Equals / Contains / Matches regex) to select which Okta
    groups are emitted.
  ([SAML wizard](https://saml-doc.okta.com/SAML_Docs/Configure-SAML-2.0-for-Org2Org.html),
  [multi-IdP / group filter](https://aws.amazon.com/blogs/modernizing-with-aws/integrate-multiple-identity-providers-with-aws-iam-identity-center-using-okta/))
- Okta is the IdP here, so it *generates* the signing cert and exposes IdP
  metadata for download (the inverse of an SP-side form).

### 2b. OIDC config
- **Sign-in method:** "OIDC - OpenID Connect"; **Application type:** Web /
  SPA / Native / Service.
- **Grant types** — checkboxes (Authorization Code, etc.; "Advanced" reveals
  more).
- **Sign-in redirect URIs** and **Sign-out redirect URIs**.
- **Client ID** and **Client secret** appear on the **General tab after
  creation** (secret is generated, copy-to-clipboard).
- **Scopes** — the standard OIDC scopes (openid, profile, email, address,
  phone, offline_access) are granted by default; custom scopes require an
  authorization server policy.
  ([OIDC wizard](https://help.okta.com/en-us/content/topics/apps/apps-about-oidc.htm),
  [create OIDC](https://help.okta.com/en-us/content/topics/apps/apps_app_integration_wizard_oidc.htm))

### 2c. LDAP / AD (Directory → Directory Integrations)
- **Bind DN** (DN of the bind user) + **Bind Password** to connect to the
  directory; a **"Use SSL connection"** checkbox.
- A **Test Delegated Authentication** action: enter an LDAP username + password,
  click **Authenticate**, watch the result, then **Close**. This is the model
  test-connection UX — it validates the *whole* bind+search+auth path with a
  real credential.
- Inline error feedback is concrete, e.g. selecting "Use SSL connection"
  without LDAPS yields **"Failed to connect to the specified LDAP server."**
- A separate **LDAP agent status** view shows connected/disconnected health.
  ([LDAP troubleshooting](https://help.okta.com/en-us/content/topics/directory/ldap-troubleshooting.htm),
  [LDAP agent status](https://help.okta.com/en-us/content/topics/directory/ldap/agent-auto-update-view-ldap.htm),
  [verify connection](https://support.okta.com/help/s/article/verify-a-connection-to-the-okta-ldap-interface))

### 2d. JIT / multiple IdPs
- **JIT provisioning** creates the local account at first login from an external
  IdP; works only for users who don't already exist. Group membership can be
  full-synced or filtered at login.
- **Multiple IdPs** are handled as separate IdP objects with **routing rules**
  and account-linking; "if no match is found, Create new user (JIT)."
  ([external IdPs](https://developer.okta.com/docs/concepts/identity-providers/),
  [JIT](https://support.okta.com/help/s/article/How-can-we-create-Okta-users-from-our-existing-Identity-Provider-using-JIT-provisioning))

### 2e. Cert expiry handling (best-in-class pattern)
- Okta surfaces **pending SAML certificate expirations as a Task in the Admin
  Console Tasks list**, appearing **60 days before** the expiration date.
  Certs default to a 10-year validity. Rotation = upload the new cert to the SP.
  ([cert expiration notifications](https://support.okta.com/help/s/article/saml-certificate-expiration-notifications-in-okta),
  [rotate signing cert](https://support.okta.com/help/s/article/how-to-rotate-signing-certificate-for-custom-saml-applications))

**Okta takeaways:** wizard/stepper for protocol config; **real-credential
test-connection** for LDAP with specific error strings; client secret with
copy-to-clipboard on a post-create General tab; **time-boxed (60-day) cert
expiry tasks**; group-attribute **filtering** UI; routing rules for multi-IdP.

---

## 3. Splunk (Splunk Web)

Entry point: **Settings → Authentication Methods**; under **External**, tick
SAML or LDAP and click **Configure Splunk to use SAML / LDAP**.
([SAML for other IdPs](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.0/use-saml-as-an-authentication-scheme-for-single-sign-on/configure-saml-sso-for-other-idps),
[LDAP with Splunk Web](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.4/use-ldap-as-an-authentication-scheme/configure-ldap-with-splunk-web))

### 3a. SAML config dialog (sectioned, not tabbed)
- **General Settings:** **Single Sign on URL**, **Single Log Out URL**, **IdP's
  certificate path** (file or directory), **Entity ID**, **Sign AuthRequest**
  (checkbox), **Sign SAML Response** (checkbox). IdP metadata can be
  **uploaded as a file or pasted into a text window**; if Splunk can't parse it,
  the admin falls back to entering these parameters manually.
- **Attribute Query** (mainly PingIdentity): Attribute Query URL + sign
  request/response checkboxes.
- **Advanced Settings:** **Attribute Alias Role**, **Attribute Alias Real
  Name**, **Attribute Alias Mail** (these map IdP assertion attributes to
  Splunk's expected names), plus FQDN / load-balancer host and redirect port.
- **Enable Auto Mapped Roles** checkbox to auto-map SAML groups → Splunk roles.
  ([SAML for other IdPs](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.0/use-saml-as-an-authentication-scheme-for-single-sign-on/configure-saml-sso-for-other-idps))

### 3b. SAML group → role mapping
A dedicated **SAML Groups** page: pick a group, then in **Splunk Roles** choose
one or more roles from an **Available items** column (dual-list / picklist
pattern), Save. **Many IdP groups can map to one Splunk role.** This mapping is
the *only* way to grant IdP users access.
([map groups to roles](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.3/use-saml-as-an-authentication-scheme-for-single-sign-on/map-groups-on-a-saml-identity-provider-to-splunk-roles))

### 3c. LDAP strategy config (the most field-complete vendor form)
A single LDAP "strategy" form exposes, verbatim:
`LDAP strategy name`, `Host name`, `Port` (389/636), `SSL enabled`, `Bind DN`,
`Bind DN password`, `User base DN` (semicolon-separated for multiple),
`User base filter`, `User name attribute` (e.g. `sAMAccountName`/`uid`),
`Real name attribute`, `Email attribute`, `Group mapping attribute` (default
`dn`), `Group base DN`, `Static group search filter`, `Group name attribute`
(`cn`), `Static member attribute` (`member`/`memberUid`), `Nested groups`
(checkbox), `Dynamic group search filter`, `Dynamic member attribute`
(`memberURL`), plus advanced size/time/socket limits.
([LDAP with Splunk Web](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.4/use-ldap-as-an-authentication-scheme/configure-ldap-with-splunk-web),
[LDAP config files reference](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.0/perform-advanced-configuration-of-ldap-authentication-in-splunk-enterprise/configure-ldap-using-configuration-files))

**Splunk takeaways:** the **fullest LDAP field set** (separate static vs dynamic
group handling, nested groups); SAML config as collapsible **sections**;
**dual-list picklist** for group→role; explicit "auto-map roles" toggle;
attribute *aliasing* concept (rename incoming claim to the app's canonical name).

---

## 4. Grafana (strong native UI patterns to borrow)

Grafana ships **first-class admin UIs** for both LDAP and SAML — closest in
spirit to what we're building (config form rendered in-app, not a YAML file).

### 4a. LDAP UI
Administration → Authentication → LDAP. Mandatory: **Server host**, **Search
filter**, **Search base DNS**. Optional: **Bind DN**, **Bind password**.
Expandable subsections: **Miscellaneous** (Allow sign-up, Port, Timeout);
**Attributes** (Name, Surname, Username, Email, **Member Of**); **Group
mapping** (Group search filter, Group search base DNS, **Manage group mappings**
= DN→role + org-ID rows, plus a **"Define Grafana Admin membership"** toggle);
**Extra security** (Enable SSL, **Start TLS**, **Min TLS version** 1.2/1.3, TLS
ciphers, cert/key via base64 or file path). **Save** + **Reset to default
values** buttons.
([LDAP UI](https://grafana.com/docs/grafana/latest/setup-grafana/configure-access/configure-authentication/ldap-ui/))

Group-mapping precedence (from the file-based equivalent): **first match wins —
the topmost mapping in the list is used**; synced on every login with LDAP as
authoritative.
([ldap.toml](https://github.com/grafana/grafana/blob/main/conf/ldap.toml))

### 4b. SAML UI (excellent reference layout — tabbed/stepped)
Administration → Authentication → Configure SAML. Sections:
- **General settings:** Allow signup, Auto login, Single logout, **Identity
  provider initiated login**.
- **Sign requests:** enable signing, cert + private key (PKCS#8), **Generate key
  and certificate** button, signature algorithm.
- **Connect with Identity Provider:** *Grafana metadata* block exposing
  **Metadata URL**, **Assertion Consumer Service URL**, **Single Logout Service
  URL** (the SP values to copy to the IdP); *IdP configuration* accepts metadata
  as **Base64 / file path / URL**.
- **User mapping:** Assertion attribute mappings, **Groups attribute**, **Role
  attribute** + Role mapping, Org attribute + Org mapping, Allowed organizations.
- **Test and enable:** **Save and enable** button, an **Enabled/Disabled status
  display**, and a **Disable** button.
  ([SAML UI](https://grafana.com/docs/grafana/latest/setup-grafana/configure-access/configure-authentication/saml/saml-ui/),
  [role/team sync](https://grafana.com/docs/grafana/latest/setup-grafana/configure-access/configure-authentication/saml/configure-saml-team-role-mapping/))

**Grafana takeaways:** clean **section-per-concern** layout; **SP metadata block
with three copyable URLs**; metadata accepted three ways (URL/file/base64);
**Generate key+cert** helper; **Save-and-enable** with a live status pill; **min
TLS version** dropdown; **first-match-wins** group precedence stated explicitly.

---

## 5. Cross-vendor synthesis

| Concern | Datadog | Okta | Splunk | Grafana |
|---|---|---|---|---|
| Protocol form shape | Single modal | Multi-step wizard | Collapsible sections | Section-per-concern |
| IdP metadata input | XML upload only | (IdP side) | File **or** paste | URL / file / **base64** |
| SP metadata exposed | Download XML, copy ACS/EntityID | (IdP metadata download) | Entity ID field | **3 copyable URLs** (metadata/ACS/SLO) |
| Group→role UI | key/value→role rows, Enable toggle | group-attr filter | **dual-list picklist** | DN→role rows + admin toggle |
| Default / no-match | **No match = locked out** | JIT create | must map to get access | configurable, first-match |
| Precedence | additive | routing rules | many-groups→one-role | **first match wins** |
| Test connection | (troubleshooting docs) | **real-credential Authenticate** | — | — |
| Cert expiry | reactive (login fails) | **60-day Task entry** | cert path field | Generate key+cert |
| Enable / disable | per-provider | per-app | checkbox per method | **Save-and-enable + status pill** |
| Multi-IdP | named providers | IdP objects + routing | one method per type | per-protocol |

Universal patterns worth copying: **(a)** show SP-side values (entityID, ACS,
metadata URL) read-only with **copy-to-clipboard**; **(b)** accept IdP metadata
multiple ways with a URL field as the easy path; **(c)** a **mapping table** is
the heart of the UI; **(d)** an explicit **enable/disable** with a **status
badge**; **(e)** a **test-connection** that exercises the real path and returns
specific errors; **(f)** **proactive cert-expiry warnings** (Okta's 60-day,
Citrix's 30-day banner are the references —
[Citrix 30-day warning](https://docs.citrix.com/en-us/citrix-cloud/citrix-cloud-management/identity-access-management/saml-service-provider-signing-certificate.html)).

---

## 6. Recommended NetOps SSO admin UI

A single **Authentication** admin page with a left list of **provider tabs**:
`OIDC (Keycloak)`, `LDAP / Active Directory`, `TACACS+`. Each tab is a plain
`<form className="admin-form">` with `.kv-form` rows (label left, control right),
a sticky footer action bar, and a header status row. No component library — use
native `<input>`, `<select>`, `<textarea>`, and a small set of CSS classes.

### Shared page chrome (every tab)
- **Header row:** provider title + a **status badge** (`.badge`
  `enabled`/`disabled`/`error`) + an **Enabled** master toggle (checkbox styled
  as a switch).
- **Cert-expiry banner** (when applicable): a `.banner.warn` (amber, 30 days
  out) / `.banner.crit` (red, 7 days or expired) at the top of the tab —
  *"Signing certificate expires in N days (NotAfter 2026-08-01). [Rotate]"*.
  Threshold pattern follows Okta (60-day Task) / Citrix (30-day banner).
- **Footer action bar:** `[Test connection]` · `[Save]` · `[Save & enable]` ·
  status text/spinner.

### Tab A — OIDC (Keycloak-brokered)
Keycloak does discovery, so favor the **issuer/discovery URL** path.

```
Display name                [text]   (shown on login button)
Issuer / Discovery URL      [text]   e.g. https://kc/realms/netops  (->/.well-known)
Client ID                   [text]
Client secret               [password + reveal/copy]
Scopes                      [text]   default: openid profile email groups
Username claim              [text]   default: preferred_username
Email claim                 [text]   default: email
Groups claim                [text]   default: groups
— Service Provider (read-only, copy-to-clipboard) —
Redirect URI (callback)     [readonly + copy]  https://<host>/auth/oidc/callback
Post-logout redirect URI    [readonly + copy]
JIT provisioning            [checkbox]  Create users on first login
Default role (no match)     [select]   default: Viewer  (or "Deny login")
```
Notes: copy-to-clipboard on the **Redirect URI** mirrors every vendor exposing
SP values; the **Default role / Deny login** choice makes Datadog's "no match"
behavior an explicit, safe-by-default option rather than a surprise.

### Tab B — LDAP / Active Directory (native)
Field set modeled on Splunk's (fullest) + Grafana's TLS controls.

```
— Connection —
Host                        [text]
Port                        [number]  389 / 636
Encryption                  [select]  None | StartTLS | LDAPS
Min TLS version             [select]  1.2 | 1.3        (Grafana pattern)
Verify server cert          [checkbox]
CA certificate              [textarea/file]  (optional)
— Bind —
Bind DN                     [text]   cn=svc-netops,ou=svc,dc=corp,dc=com
Bind password               [password + reveal]
— User search —
User base DN                [text]
User search filter          [text]   default (sAMAccountName=%s) / (uid=%s)
Username attribute          [text]   sAMAccountName | uid
Display-name attribute      [text]   displayName | cn
Email attribute             [text]   mail
— Group search —
Group base DN               [text]
Group search filter         [text]   (member=%d)
Group name attribute        [text]   cn
Member attribute            [text]   member | memberUid
Nested groups               [checkbox]
JIT provisioning            [checkbox]
Default role (no group match) [select]  default: Viewer | Deny login
```

### Tab C — TACACS+ (native)
No SAML/OIDC analog in vendor docs, so model on AAA conventions (server +
shared secret + service/AV-pair mapping). Keep it deliberately small.

```
— Server —
Primary host                [text]
Secondary host (failover)   [text]   (optional)
Port                        [number]  default 49
Shared secret               [password + reveal]
Timeout (s)                 [number]  default 5
— Authentication —
Auth type                   [select]  PAP | CHAP | ASCII
Service                     [text]    default: netops  (TACACS+ service name)
— Authorization (AV-pair) —
Role AV-pair attribute      [text]    e.g. priv-lvl or custom "role"
Group→role mapping          [mapping table, see below]
Default role (no match)     [select]  default: Viewer | Deny login
```
Note for users/memory: this is a *native* TACACS+ client config; the role comes
from a TACACS+ authorization AV-pair (commonly `priv-lvl` or a custom
`role=` attribute), mapped through the shared mapping table below.

### The group → role mapping table (shared component)
One reusable `<table className="map-table">` reused by all three tabs. Columns
chosen from the cross-vendor pattern (Datadog key/value→role, Splunk
many-to-one, Grafana DN→role + first-match precedence):

```
| ↕ | Source (group DN / claim value / AV-pair) | Match | App role        | ✕ |
|---|-------------------------------------------|-------|-----------------|---|
| ⠿ | cn=netops-admins,ou=groups,dc=corp        | exact | Admin           | ✕ |
| ⠿ | cn=noc,ou=groups,dc=corp                  | exact | Operator        | ✕ |
| ⠿ | *                                         | regex | Viewer (default)| ✕ |
                                              [+ Add mapping]
```
- **Precedence = first match wins**, top→bottom; drag handle (`⠿`) to reorder.
  State this in helper text exactly as Grafana does ("topmost mapping wins").
- **Match** column: `exact` | `regex` (keep it to two; avoids Okta's 4-mode
  complexity while covering AD wildcards).
- A pinned/implicit **default row** maps the fallback `Default role`; if set to
  **Deny login**, render it as a red row so the locked-out behavior (Datadog's
  warning) is visible, not hidden.
- App roles come from a `<select>` of NetOps roles (Admin / Operator / Viewer /
  custom) — never a free-text role.

### Test-connection UX (shared)
Model on Okta's real-credential test. `[Test connection]` opens a small inline
panel, not a new page:
- **OIDC:** fetch the discovery doc → show ✓ "Discovery OK — issuer, authz,
  token, jwks endpoints resolved" or ✗ with the HTTP error.
- **LDAP/AD:** two-stage — (1) **Bind test** (✓ "Bound as <Bind DN>" / ✗
  "Failed to connect to the specified LDAP server" — reuse Okta's exact, useful
  error tone); (2) optional **Resolve user** field: type a sample username +
  password → show resolved DN, mapped groups, and the **role that would be
  assigned** (this previews the mapping table live).
- **TACACS+:** send a test authentication with a sample credential → show
  accept/reject + returned AV-pairs + resolved role.
- Feedback uses `.result.ok` (green check) / `.result.err` (red) lines with the
  raw server message preserved. Always show **what role the user would get** —
  this is the single most valuable verify output and no vendor surfaces it well.

### Cert-expiry banner pattern (shared)
For any provider holding a cert (OIDC signing key if self-managed, LDAPS server
cert pin, TACACS+ N/A):
- Compute days-to-`NotAfter` on load.
- `> 30d`: no banner (optionally a small "valid until …" line in a details
  drawer).
- `≤ 30d`: `.banner.warn` — *"Certificate expires in 23 days (NotAfter
  2026-06-24). Plan rotation."* + `[Rotate]`.
- `≤ 7d` or expired: `.banner.crit` (red, dismiss disabled) — *"Certificate
  expired / expires in 3 days — SSO logins may fail. [Rotate now]"*.
- Thresholds follow Citrix's 30-day banner and Okta's 60-day pre-warning;
  surface it **in-page** (banner) like Citrix rather than only in a task list.
  ([Citrix 30-day](https://docs.citrix.com/en-us/citrix-cloud/citrix-cloud-management/identity-access-management/saml-service-provider-signing-certificate.html),
  [Okta 60-day](https://support.okta.com/help/s/article/saml-certificate-expiration-notifications-in-okta))

### Enable/disable, default landing, multi-provider
- Each provider tab has its own **Enabled** toggle + **status badge**
  (Grafana's Save-and-enable + status pill).
- **Multiple providers** = the existing tab list; allow >1 enabled (e.g. OIDC +
  LDAP fallback). A small **"Default login method"** select at the page level
  picks which button is primary on the login screen (Datadog's named-provider
  idea generalized).
- **Default landing page** per role can live with role config, not here, but a
  per-provider **"Landing route after login"** optional field is cheap to add.

### Implementation notes (plain React)
- One `<ProviderForm>` component, switched by tab; fields driven by a small
  per-provider field-spec array so the three forms share rendering/validation.
- Reuse `.admin-form` / `.kv-form` for layout; add `.map-table`, `.badge`,
  `.banner.warn|crit`, `.result.ok|err`, and a `.switch` checkbox style.
- Inline validation on blur (URL shape, DN shape, port range); copy-to-clipboard
  buttons on every read-only SP value; password fields get a reveal toggle.
- Persist via the backend's stdlib JSON API (Postgres-ready kv store already in
  place per project memory); the mapping table serializes as an ordered array so
  **first-match precedence** is preserved.

---

## Sources

- Datadog SAML: [overview](https://docs.datadoghq.com/account_management/saml/),
  [configuration](https://docs.datadoghq.com/account_management/saml/configuration/),
  [group mapping](https://docs.datadoghq.com/account_management/saml/mapping/),
  [AuthN mappings](https://docs.datadoghq.com/account_management/authn_mapping/),
  [troubleshooting](https://docs.datadoghq.com/account_management/saml/troubleshooting/)
- Okta: [SAML 2.0 wizard](https://saml-doc.okta.com/SAML_Docs/Configure-SAML-2.0-for-Org2Org.html),
  [OIDC wizard](https://help.okta.com/en-us/content/topics/apps/apps_app_integration_wizard_oidc.htm),
  [about OIDC](https://help.okta.com/en-us/content/topics/apps/apps-about-oidc.htm),
  [LDAP troubleshooting](https://help.okta.com/en-us/content/topics/directory/ldap-troubleshooting.htm),
  [LDAP agent status](https://help.okta.com/en-us/content/topics/directory/ldap/agent-auto-update-view-ldap.htm),
  [verify LDAP connection](https://support.okta.com/help/s/article/verify-a-connection-to-the-okta-ldap-interface),
  [SAML cert expiration notifications](https://support.okta.com/help/s/article/saml-certificate-expiration-notifications-in-okta),
  [rotate signing cert](https://support.okta.com/help/s/article/how-to-rotate-signing-certificate-for-custom-saml-applications),
  [external IdPs](https://developer.okta.com/docs/concepts/identity-providers/),
  [JIT](https://support.okta.com/help/s/article/How-can-we-create-Okta-users-from-our-existing-Identity-Provider-using-JIT-provisioning),
  [multi-IdP](https://aws.amazon.com/blogs/modernizing-with-aws/integrate-multiple-identity-providers-with-aws-iam-identity-center-using-okta/)
- Splunk: [SAML for other IdPs](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.0/use-saml-as-an-authentication-scheme-for-single-sign-on/configure-saml-sso-for-other-idps),
  [map groups to roles](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.3/use-saml-as-an-authentication-scheme-for-single-sign-on/map-groups-on-a-saml-identity-provider-to-splunk-roles),
  [LDAP with Splunk Web](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.4/use-ldap-as-an-authentication-scheme/configure-ldap-with-splunk-web),
  [LDAP config-file reference](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.0/perform-advanced-configuration-of-ldap-authentication-in-splunk-enterprise/configure-ldap-using-configuration-files)
- Grafana: [LDAP UI](https://grafana.com/docs/grafana/latest/setup-grafana/configure-access/configure-authentication/ldap-ui/),
  [SAML UI](https://grafana.com/docs/grafana/latest/setup-grafana/configure-access/configure-authentication/saml/saml-ui/),
  [SAML role/team sync](https://grafana.com/docs/grafana/latest/setup-grafana/configure-access/configure-authentication/saml/configure-saml-team-role-mapping/),
  [ldap.toml example](https://github.com/grafana/grafana/blob/main/conf/ldap.toml)
- Citrix (cert-banner threshold reference): [SP signing cert](https://docs.citrix.com/en-us/citrix-cloud/citrix-cloud-management/identity-access-management/saml-service-provider-signing-certificate.html)
