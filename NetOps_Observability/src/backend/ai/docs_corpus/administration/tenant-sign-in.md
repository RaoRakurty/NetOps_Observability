---
title: Set up a per-tenant sign-in URL
sidebar_label: Tenant sign-in URLs
description: Set up one tenant's own sign-in link, list only that tenant's identity providers on it, and bind an SSO callback to that tenant by URL.
page_type: task
sidebar_position: 6
---

# Set up a per-tenant sign-in URL

Every tenant has its own sign-in link. Someone who opens it sees the tenant named on the page and only that tenant's identity providers, and an SSO sign-in that arrives on any other tenant's callback URL is refused.

Two link shapes exist:

| Shape | Example | Use it for |
|---|---|---|
| Tenant path | `https://correlix.example.com/t/acme` | The everyday link you hand to a customer. The `acme` part is the tenant slug, a display alias. |
| Organization path | `https://correlix.example.com/org/org_9f2c…` | The rename-proof link. The identifier is opaque and never changes, so it keeps working after a slug rename. |

The slug is an alias, not an identity. Correlix resolves it to the tenant's permanent identifier on the server, and nothing in the URL is trusted for anything except deciding which sign-in doors to show.

Custom subdomains (`acme.correlix.example.com`) and customer domains are reserved names in the design and are **not** available. They need a DNS and TLS plane that a self-hosted deployment does not have.

## Before you begin

- The tenant exists and is active. A suspended tenant's link stops resolving, and it answers exactly as an unknown link does.
- You hold **administration:admin** in the tenant, or you are a platform administrator with that tenant selected in the tenant switcher.
- Correlix reaches your identity provider, and Keycloak is running (`docker compose --profile sso up -d`).
- You know the tenant slug. Find it under **Administration → Tenants**.

## Steps

1. Open **Administration → Authentication → Single Sign-On → Identity Providers**.
2. Add the provider (SAML or OIDC) as usual, or open one you already created.
3. Save it. The provider is now bound to your tenant: the owning tenant comes from your session, never from the form, and a platform administrator binds one by selecting the tenant first.
4. Read the four values under **This tenant's sign-in URLs** and copy them:

   | Value | What your identity provider team does with it |
   |---|---|
   | Redirect URI for this tenant | Register it as the only allowed redirect URI, or reply URL, for this application. |
   | Tenant sign-in URL | Publish it to the tenant's users, or set it as the tile target. |
   | IdP-initiated tile URL | Use it when the identity provider starts the sign-in, such as an Okta dashboard tile. |
   | Redirect URI (rename-proof) | Register it as well if the tenant slug may change later. |

5. Hand those values to the identity provider team and have them register the redirect URI.
6. Open the tenant sign-in URL in a private window and sign in through the new button.

## Result

The tenant sign-in page names the tenant and lists that tenant's providers plus any provider left unbound, which is the shared front door for the whole installation. Other tenants' providers are not on the page and cannot be reached by typing an identifier.

Four refusals protect the callback. Each one is written to the audit log, and none of them creates a session:

- a sign-in link naming a tenant that does not exist, or one that is suspended, answers `404`, and both answer identically;
- a provider that is not registered for the tenant in the URL is refused by name on that tenant's own page;
- an authorization code delivered to another tenant's callback URL is refused, because the browser holds a signed candidate for the tenant it started at;
- a provider that no tenant owns keeps the shared `/api/auth/sso/callback` address and has no per-tenant URL at all.

A deep link keeps its page. Someone who opens `/t/acme/#/incidents/9f21` unauthenticated lands back on that incident after signing in.

An account created on first sign-in through a bound provider belongs to that provider's tenant. Sign-in never moves an account that already exists.

## Related

- [Connect Okta as an identity provider](./okta-sso.md)
- [Authentication](./authentication.md)
- [Tenants and organizations](./tenants-orgs.md)
- [Identity and access](./identity-access.md)
