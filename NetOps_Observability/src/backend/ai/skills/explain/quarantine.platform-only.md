---
topic: quarantine.platform-only
question: Why is the quarantine platform-owner only?
keywords: platform owner access, quarantine gate, other tenants data
---
By definition the quarantine holds events that could not be attributed to any
tenant — so it may contain any tenant's data, or data from a sender nobody
owns. Showing it to a tenant principal would be a cross-tenant leak, which is
why the route is platform-admin only and the page lives in the provider-only
Platform section.
