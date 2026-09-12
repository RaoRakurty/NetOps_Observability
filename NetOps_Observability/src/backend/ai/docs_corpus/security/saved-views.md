---
title: Create a saved findings view
description: Store a named filter set over the Exposures workbench and apply it from the findings toolbar.
page_type: task
sidebar_position: 11
---

# Create a saved findings view

A saved view is a named filter, not a saved result set. Applying one re-runs
the query under your own token, so a view can never widen what its owner may
see and can never carry another tenant's rows with it.

## Before you begin

- A role with `infrastructure:write` to create or delete a view.
  `infrastructure:read` is enough to list and apply one.
- A tenant selected. The owner is stamped from the token.

## Steps

1. Go to **Security → Configuration → Saved Views**.
2. Enter a **View name**. It is required and may be up to 80 characters.
3. Choose a **Severity**, or leave **Any severity**.
4. Choose a **Verdict**, or leave **Any verdict**.
5. Enter **Search text** to store a free-text term with the view.
6. Leave **Current verdicts only** ticked to store the view over latest
   verdicts, or untick it to store it over the full verdict history.
7. Select **Save view**.

## Result

The view appears in the table with its name, a one-line summary of its filters,
and two actions:

- **Open** goes to **Security → Exposures** with the view applied.
- **Delete** removes it.

The filter summary reads back what the view stores, for example
`severity high · verdict fail · current verdicts`. A view with no filters
summarises as `no filters — every current finding`.

The view also appears in the **Saved view…** dropdown in the Exposures toolbar,
so you can switch between views without leaving the workbench.

## Limits

| Limit | Value |
|---|---|
| Views per tenant | 100 |
| View name length | 80 characters |
| Stored filter blob | 4096 bytes |

Exceeding the per-tenant limit, or reusing a name, answers `409`. The stored
filters must be a JSON object; a scalar or an array is refused with a `400`,
because storing bytes nothing can read back is how a store starts holding
things that no longer mean anything.

## Isolation

A view is owned by the tenant on the token that created it. A tenant named in
the request body is rejected outright rather than honoured. Deleting a view id
that belongs to another tenant answers `404`, the identical answer an id that
does not exist returns, so a probe never confirms that another tenant's view
exists.

Both the create and the delete are recorded in the audit trail, as
`security_view_create` and `security_view_delete`.

## Related

- [Review exposures](/security/exposures)
- [Investigate a security finding](/security/investigate-a-finding)
- [Security section overview](/security/overview)
