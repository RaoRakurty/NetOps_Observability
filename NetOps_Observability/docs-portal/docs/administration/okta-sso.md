---
title: Connect Okta as an identity provider
sidebar_label: Okta SSO
description: Connect Okta through the bundled Keycloak broker, map groups onto roles, and give operators a one-click tile.
page_type: task
sidebar_position: 5
---

# Connect Okta as an identity provider

Correlix speaks OIDC to a broker, and the broker speaks SAML or OIDC to Okta. The bundled Keycloak service is that broker. When this procedure is finished, an operator signs in from the Correlix login page with an **Okta** button, or opens the Correlix tile on their Okta dashboard and lands already signed in, with the role and tenant their Okta group maps to.

```text
Okta ──SAML or OIDC──▶ Keycloak (broker) ──OIDC──▶ Correlix ──▶ its own session
```

The tile experience is a Correlix-initiated bookmark launch. Correlix deliberately does not accept unsolicited identity-provider-initiated SAML, so the bookmark keeps full replay and CSRF protection while giving the same one click.

## Before you begin

- **Permission:** platform administrator. Authentication providers are platform-global plumbing, and every route behind **Platform → Security → Authentication** calls `requirePlatformAdmin`. A tenant administrator cannot configure this.
- **Okta administrator access** to your organization, because you will create two or three app integrations.
- **Correlix reachable over HTTPS.** Browsers reject Keycloak's cross-site sign-on cookies over plain HTTP. A plain-HTTP lab works in a normal browser window only, and a strict or private window requires HTTPS. See [Enable TLS](/deploy/enable-tls).
- **A local administrator account you will never federate.** If single sign-on breaks, that account is the way back in.
- **The target tenant id** for Okta users. Every user of one provider configuration lands in one tenant. Read the id from **Administration → Identity & Access**, or from `GET /api/tenants`.

Throughout, replace `correlix.example.com` with your host. Collect these values as you go: the Correlix base URL, the Keycloak realm name, the Keycloak client id and secret, and the Okta metadata URL.

## Steps

### Step 1 — Bring up Keycloak

Keycloak ships with Correlix and is opt-in.

1. In `deployment/docker/.env`, add `sso` to `COMPOSE_PROFILES`.
2. Re-run the installer. With `sso` in the profile list it creates Keycloak's database itself and starts the service:

   ```bash
   python3 scripts/install.py
   ```

3. Open the Keycloak admin console at `https://correlix.example.com/auth/` and sign in with `KEYCLOAK_ADMIN` and `KEYCLOAK_ADMIN_PASSWORD` from `.env`.
4. Create a realm, for example `correlix`.
5. In that realm, create an OpenID Connect client for Correlix:

   | Field | Required | Value |
   | --- | --- | --- |
   | **Client ID** | Yes | `netops` |
   | **Client authentication** | Yes | On, which makes it confidential |
   | **Valid redirect URIs** | Yes | `https://correlix.example.com/api/auth/sso/callback` |
   | **Web origins** | Recommended | `https://correlix.example.com` |

6. Copy the client secret from the client's **Credentials** tab.

Verify: `https://correlix.example.com/auth/realms/correlix/.well-known/openid-configuration` returns JSON whose `issuer` is exactly `https://correlix.example.com/auth/realms/correlix`. That string is used twice more, and the scheme and host must match character for character.

### Step 2 — Create the Okta SAML app

In the Okta admin console, go to **Applications → Applications → Create App Integration → SAML 2.0**. Name it as plumbing, for example *Correlix (SAML via Keycloak)*.

| Okta field | Value |
| --- | --- |
| **Single sign-on URL (ACS)** | `https://correlix.example.com/auth/realms/correlix/broker/okta-saml/endpoint` |
| **Audience URI (SP Entity ID)** | `https://correlix.example.com/auth/realms/correlix`, the realm URL and not the broker endpoint |
| **Name ID format** | EmailAddress, or Persistent |
| **Application username** | Email |

Add three attribute statements, because Keycloak maps them by name in step 3: `email` to `user.email`, `firstName` to `user.firstName`, `lastName` to `user.lastName`. Add a group attribute statement named `groups`, filtered to the groups you will map, for example *Starts with* `correlix-`.

Assign the users and groups who may sign in, then copy the SAML metadata URL from the app's **Sign On** tab.

On the app's **General** tab, tick **Do not display application icon to users**. This app's own tile performs unsolicited identity-provider-initiated SAML, which Correlix refuses, so clicking it can only produce an error. The user-facing tile is the bookmark app in step 7.

Verify: the metadata URL downloads XML in a browser.

### Step 3 — Register Okta as an identity provider in Keycloak

In the Keycloak admin console, in the realm from step 1:

1. Go to **Identity Providers → Add provider → SAML v2.0**.
2. Set **Alias** to `okta-saml`. The alias is part of the ACS URL registered in step 2, so it must match exactly.
3. Confirm **Service provider entity ID** is `https://correlix.example.com/auth/realms/correlix`, equal to the Okta **Audience URI**. This value is pinned here and does not follow your URL automatically. A host or scheme change means updating both sides.
4. Import the Okta metadata URL from step 2. It fills the sign-on URL and the signing certificate.
5. Add three **Attribute Importer** mappers: `email` to `email`, `firstName` to `firstName`, `lastName` to `lastName`.

Verify: from a private window, open

```text
https://correlix.example.com/auth/realms/correlix/protocol/openid-connect/auth?client_id=netops&response_type=code&scope=openid&kc_idp_hint=okta-saml&state=test&redirect_uri=https%3A%2F%2Fcorrelix.example.com%2Fapi%2Fauth%2Fsso%2Fcallback
```

It lands on the Okta sign-in page. Do not sign in yet.

### Step 4 — Optional, the OIDC variant

For OIDC end to end, or for both side by side:

1. In Okta, go to **Create App Integration → OIDC → Web Application**. Set the sign-in redirect URI to `https://correlix.example.com/auth/realms/correlix/broker/okta-oidc/endpoint`. Copy the client id and secret.
2. In Keycloak, go to **Identity Providers → Add provider → OpenID Connect v1.0**, set the alias to `okta-oidc`, set the discovery URL to `https://yourorg.okta.com/.well-known/openid-configuration`, and paste the client id and secret. Add the same three mappers.

:::caution OIDC needs outbound network access
SAML brokering is carried entirely by the browser. The OIDC broker flow additionally needs Keycloak to reach Okta directly for the token exchange. In an egress-restricted network SAML works where OIDC fails, and the OIDC failure appears only after the user has entered credentials and completed MFA, as a socket timeout in Keycloak's log. Prefer SAML for locked-down deployments.
:::

### Step 5 — Map roles

Correlix reads roles from the ID token's `realm_access.roles` and `groups` claims and matches them against its configured role lists.

The approach that scales is Okta group to Keycloak realm role. Create Okta groups such as `correlix-admins` and `correlix-operators`, include them in the step 2 group attribute, create the matching realm roles in Keycloak, and add one **Advanced Attribute to Role** mapper per group on the Keycloak identity provider: attribute `groups` equals `correlix-admins`, realm role `netops-admin`.

For a lab, granting a realm role directly to the Keycloak user after their first sign-in is enough.

:::caution The invisible-role trap
Keycloak's built-in realm-roles mapper writes roles into the access token only. Correlix reads the ID token, so the role never arrives, every user lands as read-only, and every screen you check looks correctly configured. Fix it once per realm: **Client scopes → roles → Mappers → realm roles**, then turn **Add to ID token** on.
:::

The role names must appear in the Correlix **Admin roles** or **Operator roles** list in step 6. The shipped defaults include `netops-admin` and `netops-operator`.

### Step 6 — Configure Correlix

Sign in to Correlix as the platform administrator and open **Platform → Security → Authentication → Single Sign-On**. Tick **Enabled** and complete the form:

| Field | Required | Value |
| --- | --- | --- |
| **Issuer** | Yes | `https://correlix.example.com/auth/realms/correlix`, exactly the issuer from step 1 |
| **Client ID** | Yes | `netops` |
| **Client secret** | Yes for a confidential client | From step 1. Write-only after saving. |
| **Providers** | Recommended | `okta-saml:Okta:saml`, with `,okta-oidc:Okta OIDC:oidc` added if you completed step 4. One login-page button per entry, and only aliases listed here are accepted on the launch URL. |
| **Default tenant** | Yes | The tenant id from *Before you begin* |
| **Default role** | Yes | The role for a user matching no mapping, `read-only` by default |
| **Admin roles** and **Operator roles** | Yes | Must contain the role names from step 5 |

Select **Save**. The tile shows **Enabled · Ready**.

:::note The OIDC environment variables are a first-boot seed
Once a configuration has been saved from this page, the saved configuration wins over the environment. Editing `OIDC_*` in `.env` afterwards changes nothing. Change it here.
:::

Verify: sign out. The login page shows the **Okta** button, selecting it lands on Okta, and signing in returns you to Correlix. Check the new account under **Administration → Identity & Access → Users** for the right email, tenant and role.

### Step 7 — Add the Correlix tile in Okta

1. In the Okta admin console, go to **Applications → Create App Integration → Bookmark App**.
2. Set the URL to `https://correlix.example.com/api/auth/sso/login?idp=okta-saml`, or `?idp=okta-oidc` for the OIDC variant.
3. Name it **Correlix**, upload the Correlix logo, and assign the same users and groups as the step 2 app.

## Result

Run all seven checks before calling the setup done. Each one proves a different link.

| # | Test | Proves |
| --- | --- | --- |
| 1 | Login page, **Okta** button, sign in | The Correlix-initiated flow, end to end |
| 2 | Okta dashboard, **Correlix** tile | The bookmark launch |
| 3 | A user in an admin-mapped group lands as Super Admin, one without lands as the default role | Role mapping, both directions |
| 4 | The new user's tenant is the intended one | Tenant assignment |
| 5 | An Okta user not assigned to the app is refused by Okta | Assignment gating |
| 6 | Tests 1 and 2 repeated in a private window | Customer-shaped browsers work |
| 7 | Your local administrator still signs in with a password | The way back in is intact |

## Troubleshooting

Every entry below comes from a real bring-up.

| Symptom | Cause | Fix |
| --- | --- | --- |
| The Keycloak container restarts forever and its log says `FATAL: database "keycloak" does not exist` | The `sso` profile was enabled by hand without creating the database | Re-run `python3 scripts/install.py`, which creates it, or run `docker compose exec postgres createdb -U $DB_USER keycloak` |
| Okta reports **Bad SAML request** | The Audience URI does not equal Keycloak's service provider entity id, often after a host or scheme change | Make Okta's **Audience URI** and Keycloak's **Service provider entity ID** identical: `https://<host>/auth/realms/<realm>` |
| Okta reports `The 'redirect_uri' parameter must be a Login redirect URI…` | OIDC variant: the broker redirect URI is not registered on the Okta app | Add `https://<host>/auth/realms/<realm>/broker/okta-oidc/endpoint` to the app's sign-in redirect URIs |
| A Keycloak error page after the Okta sign-in, with `cookie_not_found` in the Keycloak log | Plain HTTP plus a browser blocking third-party cookies. Keycloak's `Secure` cookies cannot exist over HTTP | Serve Correlix over HTTPS. On an HTTP lab, test in a normal window only |
| `502 Bad Gateway` on the Keycloak page, only for fresh or private-window visitors, with `upstream sent too big header` in the nginx log | Keycloak's cookie-less first response overflows small proxy buffers | The shipped nginx configuration sets 16k buffers on `/auth/`. If you customised nginx, add `proxy_buffer_size 16k; proxy_buffers 8 16k;` |
| The user signs in but lands read-only, and every screen looks correct | Realm roles reach the access token only, and Correlix reads the ID token | Apply the step 5 fix, then confirm the role name is listed in Correlix's Admin or Operator roles |
| Keycloak shows **User already exists** mid-login | The same email arrives from a second identity provider, and Keycloak wants explicit account linking | Complete the link once per user, enable an auto-link first-login flow for trusted providers, or use one provider per user population |
| Okta sign-in works, then Keycloak times out on the OIDC variant with a socket timeout | No Keycloak-to-Okta back-channel egress | Allow outbound 443 to your Okta organization from the Keycloak container, or use the SAML variant |
| Selecting the SAML app's own tile errors with `invalid_redirect_uri` | That is unsolicited identity-provider-initiated SAML, which Correlix refuses by design | Use the bookmark tile from step 7, and hide the SAML app's tile as step 2 describes |
| `OIDC_*` was edited in `.env` and nothing changed | A saved configuration overrides the environment | Change it at **Platform → Security → Authentication** |

## Related

- [Configure authentication](/administration/authentication) for the form reference, LDAP, TACACS+, MFA and session policy.
- [Add users and grant access](/administration/identity-access) for the role grid federated users land on.
- [Connectivity requirements](/reference/connectivity-requirements) for the outbound access the broker needs.
