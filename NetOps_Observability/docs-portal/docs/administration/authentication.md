---
title: Authentication & SSO
sidebar_label: Authentication & SSO
sidebar_position: 3
description: Connect Correlix to your identity provider — OIDC, SAML, LDAP, TACACS+ — and require MFA.
---

# Authentication & SSO

Correlix supports local accounts and your existing identity provider. Configure it at <kbd>Administration → Authentication</kbd>. You can run more than one method (e.g. SSO for humans, local break‑glass for emergencies).

## Methods at a glance

| Method | Use it for | You'll need |
| --- | --- | --- |
| **Local accounts** | Small teams, break‑glass admin | Nothing external |
| **OIDC (OpenID Connect)** | Okta, Azure AD/Entra, Google, Keycloak | Client ID/secret, issuer URL, redirect URI |
| **SAML 2.0** | Enterprise IdPs that speak SAML | IdP metadata / SSO URL + certificate |
| **LDAP / Active Directory** | Directory‑backed login & groups | LDAP URL, bind DN, base DN |
| **TACACS+** | Network‑team AAA | TACACS+ server + shared secret |

## Set up OIDC (e.g. Okta)

1. In your IdP (Okta shown), create an **OIDC web application**:
   - **Sign‑in redirect URI** — your Correlix callback URL (shown on the Authentication page).
   - Note the **Client ID**, **Client Secret**, and **Issuer** URL.
2. In Correlix, <kbd>Administration → Authentication</kbd> → **OIDC**:
   - Enter **Issuer URL**, **Client ID**, **Client Secret**, and the **redirect URI**.
   - Configure **claim mapping** — which token claims map to username, email, and **role/group** (so IdP groups become Correlix roles).
3. Save and test a sign‑in with a test account.

The same steps apply to **Azure AD/Entra**, **Google**, or **Keycloak** — only the issuer/endpoints differ.

## Set up SAML 2.0

1. In your IdP, create a **SAML app** and download its **metadata** (or note the SSO URL + signing certificate).
2. In Correlix → **SAML**, provide the IdP **SSO URL**, **entity ID**, and **certificate**, and copy Correlix's **ACS (assertion consumer service) URL** back into the IdP.
3. Map SAML attributes to username/email/role.
4. Save and test.

## Set up LDAP / Active Directory

1. In Correlix → **LDAP**, enter:
   - **Server URL** (`ldaps://…` recommended),
   - **Bind DN** + password (a service account),
   - **Base DN** and the **user/group search filters**.
2. Map LDAP **groups → roles**.
3. Test a directory login.

## Set up TACACS+

1. In Correlix → **TACACS+**, enter the **server address**, **port**, and **shared secret**.
2. Map TACACS+ privilege/attributes to roles.
3. Test.

## Multi-factor authentication (MFA)

- **Local MFA** — users enroll a TOTP authenticator app at first sign‑in.
- **Require MFA for SSO** — enforce that federated logins have completed MFA at the IdP.

Turn MFA requirements on per your policy under Authentication / Security Settings. Enrollment and enforcement then happen automatically at login.

:::info Role mapping is the key step
The value of SSO is that IdP **groups become Correlix roles**. Get the claim/attribute→role mapping right and user onboarding becomes automatic — the right people get the right access when they first sign in.
:::

## Next

- **[Users & roles](/administration/identity-access)** — what the mapped roles can do.
- **[Sessions](/administration/overview)** — idle/absolute timeouts and revocation (platform scope).
