# Client / Credential Registration Form — OAuth 2.0 vs SAML 2.0 Field Specification

A grounded, citation-backed mapping of the requested admin-form fields to the
authoritative standards, so the NetOps registration form aligns to the correct
spec.

**Primary framing:** OAuth 2.0 Dynamic Client Registration (RFC 7591), because
every user-requested field (grant types, client URI, logo, contacts, secret
expiry) is an OAuth client-registration concept. SAML 2.0 Metadata equivalents
are provided as a secondary mapping.

## Authoritative sources

- RFC 7591 — OAuth 2.0 Dynamic Client Registration Protocol (client metadata):
  https://datatracker.ietf.org/doc/html/rfc7591
  (§2 Client Metadata, §3.2.1 Client Information Response)
- RFC 6749 — The OAuth 2.0 Authorization Framework (grant types):
  https://datatracker.ietf.org/doc/html/rfc6749
- RFC 9700 — Best Current Practice for OAuth 2.0 Security (BCP 240):
  https://datatracker.ietf.org/doc/html/rfc9700 (§2.4)
- OASIS — Metadata for the OASIS SAML V2.0 (saml-metadata-2.0-os):
  https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf
  XSD: https://docs.oasis-open.org/security/saml/v2.0/saml-schema-metadata-2.0.xsd
- OASIS — SAML V2.0 Metadata Extensions for Login and Discovery User Interface
  v1.0 (mdui):
  https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-metadata-ui/v1.0/sstc-saml-metadata-ui-v1.0.html

---

## 1. OAuth 2.0 mapping (RFC 7591 / RFC 6749 / RFC 9700)

In RFC 7591, "client metadata" fields are **registration request inputs** the
client/admin supplies, except for a small set the **server issues in the
registration response** (§3.2.1). The latter are marked RESPONSE-only below.

| User field | RFC 7591 / 6749 parameter | Requirement | Format | Default / notes |
|---|---|---|---|---|
| Grant types | `grant_types` (§2, RFC 7591) | OPTIONAL | JSON array of strings | **Default `["authorization_code"]`** if omitted (RFC 7591 §2). Registered values from RFC 6749: `authorization_code`, `client_credentials`, `refresh_token`, `password`, `implicit`. |
| — password grant | `grant_types` value `password` (RFC 6749 §4.3) | OPTIONAL but **DEPRECATED** | array element | RFC 9700 §2.4: *"The resource owner password credentials grant ... MUST NOT be used."* Exposes user credentials to the client; incompatible with MFA. **Do not offer in the form, or hard-disable with a warning.** |
| — refresh_token | `grant_types` value `refresh_token` (RFC 6749 §6) | OPTIONAL | array element | Issues new access tokens without re-auth. |
| — client_credentials | `grant_types` value `client_credentials` (RFC 6749 §4.4) | OPTIONAL | array element | Machine-to-machine; client acts on its own behalf. |
| Client URL | `client_uri` (RFC 7591 §2) | OPTIONAL | URL string | RFC 7591: *"RECOMMENDED that clients always send this field."* Human-facing homepage of the client. |
| Icon / Logo URL | `logo_uri` (RFC 7591 §2) | OPTIONAL | URL string | Must point to a valid image file; shown on consent screens. |
| Traffic source address (allowed source-IP / CIDR) | *(none)* | **NOT in spec** | — | RFC 7591 §2 and §3.2.1 define **no** source-IP / CIDR restriction field. This is a **non-standard, vendor security extension** — keep it but label it clearly as a NetOps-proprietary control, not OAuth-standard. |
| Client expires on | `client_id_issued_at` (RFC 7591 §3.2.1) is the only standard time field for the client identity | RESPONSE-only (OPTIONAL, server-set) | NumericDate (seconds since 1970-01-01T00:00:00Z UTC) | RFC 7591 defines *issued-at*, **not** a client-ID expiry. There is **no standard `client_id_expires_at`**. A "client expires on" date is a NetOps-proprietary lifecycle control. |
| Client secret expires on | `client_secret_expires_at` (RFC 7591 §3.2.1) | RESPONSE-only; **REQUIRED if a `client_secret` is issued** | NumericDate, or `0` | Server-set. `0` means the secret does **not** expire. Admin should not type this; the server computes it. |
| Contact email | `contacts` (RFC 7591 §2) | OPTIONAL | JSON array of strings | *"ways to contact people responsible for this client, typically email addresses."* Email only — no separate phone field in OAuth. |
| Contact phone | *(none — fold into `contacts` or treat as extension)* | NOT in spec | — | RFC 7591 `contacts` is an untyped string array (email-oriented); there is no dedicated phone metadata. Use a NetOps extension field. |
| Redirect URIs (for completeness) | `redirect_uris` (RFC 7591 §2) | **Conditionally REQUIRED** | JSON array of URL strings | RFC 7591: clients using redirection-based flows (e.g. `authorization_code`) MUST register redirect URIs. Not required for `client_credentials`-only clients. |

**Server-issued response fields (admin does not enter these):**
`client_id`, `client_secret`, `client_id_issued_at`, `client_secret_expires_at`,
`registration_access_token`, `registration_client_uri` (RFC 7591 §3.2.1).

---

## 2. SAML 2.0 mapping (OASIS SAML 2.0 Metadata + mdui)

SAML 2.0 describes a relying entity via **metadata** (`<md:EntityDescriptor>`),
not via a client-registration request. The conceptual analogs:

| User field | SAML 2.0 metadata construct | Requirement (per schema) | Format / notes |
|---|---|---|---|
| Grant types | **No equivalent.** Grant types are OAuth-only. | n/a | SAML's analog is the **binding** + **profile**: `<md:AssertionConsumerService>` / endpoints with bindings such as `urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST`, `HTTP-Redirect`, `HTTP-Artifact`. A binding is REQUIRED on each endpoint element. |
| Client URL | Closest: `<mdui:UIInfo>/<mdui:InformationURL>` (mdui ext.) | OPTIONAL | The entity homepage is not a core metadata field; mdui InformationURL is the display-oriented analog. |
| Icon / Logo URL | `<mdui:UIInfo>/<mdui:Logo>` (mdui ext.) | OPTIONAL (`minOccurs=0`, repeatable) | Content is a URI to the image. Attributes `height` and `width` (positive integers) are **REQUIRED**; `xml:lang` OPTIONAL. UIInfo sits inside a role's `<md:Extensions>` and must contain ≥1 child. |
| Traffic source address | **No equivalent.** SAML metadata has no source-IP/CIDR field. | n/a | Same as OAuth — a proprietary control. |
| Client expires on / secret expires on | `validUntil` (xs:dateTime) and/or `cacheDuration` (xs:duration) on `<md:EntityDescriptor>` / role descriptor | OPTIONAL | These bound the **validity of the metadata document**, the nearest SAML analog to expiry. There is no separate "secret expiry" — SAML trust is via X.509 certs in `<md:KeyDescriptor>`, whose lifetime is the cert's `notAfter`. |
| Contact email | `<md:ContactPerson>/<md:EmailAddress>` | OPTIONAL (`minOccurs=0`, repeatable) | `ContactPerson` itself is optional/repeatable; its `contactType` **attribute is REQUIRED** (`technical`, `support`, `administrative`, `billing`, `other`). |
| Contact phone | `<md:ContactPerson>/<md:TelephoneNumber>` | OPTIONAL (`minOccurs=0`, repeatable) | Unlike OAuth, SAML **does** have a dedicated phone element. Other optional children: `Company`, `GivenName`, `SurName`. |

---

## 3. Recommended field spec for the NetOps registration form

OAuth 2.0 (RFC 7591) is the primary standard; the SAML column shows the analog.

| Field label | OAuth source (RFC 7591/6749) | SAML analog | Mandatory? | Input type | Default | Help text |
|---|---|---|---|---|---|---|
| Grant types | `grant_types` | binding/profile (no analog) | Optional | Multi-select (`authorization_code`, `client_credentials`, `refresh_token`) | `authorization_code` | Which OAuth flows this client may use. |
| Allow password grant | `grant_types`=`password` | — | Optional (discouraged) | Toggle, default OFF + warning | OFF | Deprecated by RFC 9700 (MUST NOT be used) — leave disabled. |
| Redirect URIs | `redirect_uris` | `AssertionConsumerService` Location | Conditionally required* | URL list | — | Required for authorization_code / browser redirect flows. |
| Client URL | `client_uri` | `mdui:InformationURL` | Optional (recommended) | URL | — | Public homepage of the client app. |
| Icon / Logo URL | `logo_uri` | `mdui:Logo` | Optional | URL (image) | — | Logo shown on consent screens; HTTPS, must resolve to an image. |
| Allowed source IP / CIDR | none (NetOps extension) | none | Optional | CIDR list | empty = any | NetOps-only: restrict token requests to these source addresses. Not part of OAuth/SAML. |
| Client expires on | none (NetOps extension; `client_id_issued_at` is issuance only) | `validUntil` | Optional | Date | none = never | NetOps lifecycle control; not an OAuth-standard field. |
| Client secret expires on | `client_secret_expires_at` (server-set) | cert `notAfter` | Server-issued (read-only) | Display only | `0` = never | Set by the server at registration; shown, not entered. |
| Contact email(s) | `contacts` | `ContactPerson/EmailAddress` | Optional | Email list | — | Responsible parties for this client. |
| Contact phone | none (NetOps extension) | `ContactPerson/TelephoneNumber` | Optional | Phone | — | OAuth has no phone field; SAML does. NetOps extension. |
| Contact type | — | `ContactPerson@contactType` (required in SAML) | Optional (OAuth) | Select | technical | Only meaningful if SAML metadata is also emitted. |

\* Conditionally required: `redirect_uris` is mandatory only for redirect-based
flows; a pure `client_credentials` machine client needs none.

---

## 4. What is genuinely MANDATORY vs OPTIONAL for a usable OAuth client

For OAuth 2.0 Dynamic Client Registration (RFC 7591), almost the entire metadata
set is **OPTIONAL**:

- **Conditionally REQUIRED:** `redirect_uris` — only when the client uses a
  redirection-based grant (e.g. `authorization_code`, implicit). A
  `client_credentials`-only client requires no redirect URI.
- **Defaulted, so effectively optional:** `grant_types` defaults to
  `["authorization_code"]`; `token_endpoint_auth_method` defaults to
  `client_secret_basic`; `response_types` defaults to `["code"]`.
- **Server-issued, never entered by the admin:** `client_id`,
  `client_secret`, `client_id_issued_at`, `client_secret_expires_at`
  (the last is REQUIRED in the response only *if* a secret is issued; `0` = no
  expiry) — RFC 7591 §3.2.1.
- **Purely descriptive / optional:** `client_uri`, `logo_uri`, `contacts`,
  `client_name`, `tos_uri`, `policy_uri`, `scope`.
- **Not in the spec at all (NetOps proprietary):** allowed source IP / CIDR,
  client (ID) expiry date, contact phone.

**Bottom line:** the only field a typical interactive OAuth client truly must
supply is `redirect_uris`; everything the user listed beyond grant types is
optional descriptive metadata or a non-standard NetOps extension. The form
should mark exactly one field conditionally required, default `grant_types`,
hide `password`, render the two `*_expires_at` values as read-only server output,
and clearly badge source-IP/CIDR, client-expiry, and phone as NetOps extensions
rather than OAuth-standard parameters.
