---
topic: sso.per-tenant-urls
question: What are the tenant sign-in URLs?
keywords: tenant sign-in url, per-tenant sso, callback url, redirect uri, locator, org url, idp-initiated
---
Every tenant has its own sign-in link, and a provider bound to that tenant has
its own callback URL under it. Someone who opens the link sees the tenant named
on the page and only that tenant's providers.

The redirect URI is what the identity provider registers. A token arriving on
another tenant's callback URL is refused and audited, so the URL itself binds a
registration to one tenant.

The slug in the `/t/` form is a display alias; the `/org/` form uses the
tenant's permanent identifier and survives a rename. Register both if the slug
may change.

A provider no tenant owns keeps the shared callback address and appears
everywhere. Custom subdomains are not available.
