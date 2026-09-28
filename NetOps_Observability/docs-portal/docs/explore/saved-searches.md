---
title: Open a saved search
sidebar_label: Saved Searches
description: Find the log searches your tenant saved, reopen one in the log search, and delete the ones nobody needs.
page_type: task
sidebar_position: 6
---

# Open a saved search

**Explore → Saved Searches** lists the log searches saved in your tenant. Open
one to run its query again in **Explore → Logs** without retyping it.

## Before you begin

- A signed-in account. Saved searches are per tenant: everyone in your tenant
  sees the same list.
- A search to open. You save one from **Explore → Logs** with **Save**. See
  [Search logs](/explore/logs).

## Steps

1. Go to **Explore → Saved Searches**.
2. Find the search by **Name** or by its **Query**.
3. Select **Open**. Correlix puts the saved query into the search and opens
   **Explore → Logs**.

To delete a saved search, select the delete control at the end of its row and
confirm. The search is
removed for everyone in your tenant.

## What you see

| Column | What it shows |
|---|---|
| **Name** | The name given when the search was saved. |
| **Query** | The saved query text. `*` matches every log line. |
| `Signal` | The log source chosen in the signal selector when the search was saved, or `all`. |
| **Updated** | When the search was last saved. |

**No saved searches yet.** means the list loaded and your tenant has not saved
one. An error line above the table means the list could not be read, which is
not the same as an empty list.

## Common questions

**Does Open restore the log source and time window too?** No. Open restores
the query text. The log search uses the time range in the top bar, and you
choose the log source on the Logs page.

**Can I rename a saved search?** Not from this page. Save the search again
under the new name, then delete the old one.

## Related

- [Search logs](/explore/logs)
- [Read device logs during an incident](/noc-guide/reading-logs)
- [Explore your data](/explore/overview)
