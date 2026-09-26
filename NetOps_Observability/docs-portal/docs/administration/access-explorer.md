---
title: Check what an account can access
sidebar_label: Access Explorer
description: Find every tenant a person or service account reaches in Access Explorer, and the role binding that grants each one, including denies and break-glass grants.
page_type: task
sidebar_position: 3
---

# Check what an account can access

**Administration → Access & Audit → Access Explorer** answers "why does this
user have access to this tenant?". Enter a user or a service account and
Correlix lists every tenant it can act in, traced back to the binding that
grants it. Deny bindings and break-glass grants are shown, not hidden.

## Before you begin

- An administrator account. Access Explorer is gated to administrators.
- Whose access you can explain depends on your own scope. You can always
  explain yourself. An organization administrator can explain an account that
  holds a binding in one of their organizations. A platform administrator can
  explain any account.
- The username of the account, or nothing to explain your own access.

## Steps

1. Go to **Administration → Access & Audit → Access Explorer**.
2. In **Person or service**, enter the username. Leave it blank to explain
   your own account.
3. Select **Explain access**.

## What you see

A summary strip with four values: **Account**, **Tenants reached**, **Bindings**
and **Org admin of**.

**Reaches** lists each tenant the account can act in, with its organization and
the binding behind it, written as `role @ scope`. A deny binding is marked
`(deny)`. A binding with an expiry, such as a break-glass grant, is marked with
a timer.

**All bindings** lists every role binding the account holds, with its
**Role**, **Scope**, **Effect** (**Allow** or **Deny**), **Granted by** and a
**Note** that shows the expiry or the reason.

For a platform operator, **Tenants reached** reads **All**. Cross-tenant
telemetry for a compliance-restricted tenant still needs a break-glass session.

An account you are not allowed to explain returns an empty result rather than
an error, so the page never confirms whether the account exists.

## Related

- [Manage identity and access](/administration/identity-access)
- [Tenants and organizations](/administration/tenants-orgs)
- [Review sign-in sessions](/administration/sessions)
- [Audit log](/administration/audit-log)
