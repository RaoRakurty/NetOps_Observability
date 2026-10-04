---
title: Review the RCA Reports library
sidebar_label: RCA Reports
description: Find the real outages promoted to an RCA document, read where, what and who at a glance, and download the document as a PDF.
page_type: task
sidebar_position: 5
---

# Review the RCA Reports library

**Analytics → RCA Reports** is the management library of real outages. It lists
only RCA cases that were promoted to a document, and links each one to its
document and its workspace. Every candidate case, promoted or not, stays on
**Investigate → RCA**.

## Before you begin

- `infrastructure:read`. The library is per tenant: it lists your own tenant's
  outages only.

## Steps

1. Go to **Analytics → RCA Reports**.
2. Choose the window in the header: **7 days**, **30 days**, **90 days** or
   **365 days**. The chip beside it counts the promoted outages in the window.
3. Read a row, newest outage first.
4. Select **Open workspace** to open the full RCA case, or **⤓ PDF** to
   download its document.

## What you see

| Column | What it shows |
|---|---|
| **ID** | The short problem id, for example `P-5564D1`. Hover for the full id. |
| **Report** | The outage title and the report type. |
| **Where · what · owner** | Where the fault was, what failed, and the owning team. |
| **Verdict** | The analysis state: **confirmed**, **suspected** or **undetermined**. |
| **Impact** | The user or application impact state, for example **confirmed** or **detected**. |
| **Duration** | How long the outage lasted. |
| **Ended** | When the last abnormal observation was seen. |
| **Promoted** | **AUTO** when the case met every promotion rule, **MANUAL** when a person promoted it. Hover for who, when and why. |

## How a case gets into the library

A case is promoted automatically when all four hold:

- it is a production incident, not a validation scenario;
- its verdict is confirmed;
- user or application impact is confirmed;
- it lasted at least 2 minutes.

A person can also promote a case. On **Investigate → RCA**, **⤓ Export PDF** on
a case that is not promoted explains which rule is unmet and offers to promote
it. That manual promotion needs `infrastructure:write`, is recorded under your
name and is audited.

## Common questions

**The library is empty. Did nothing go wrong?** **No promoted outages in this
window** means no case in the window met the promotion rules and nobody
promoted one. Candidates are still on **Investigate → RCA**. A wider window can
show older outages.

**Why does a line say the library evaluated only some candidates?** Each
request checks at most the 100 most recent qualifying cases. When it hits that
limit the page says so, and a narrower window shows the rest.

**The PDF did not download.** The document is rendered on the server. When the
PDF renderer is off the page opens a print view instead. If both fail, the page
says the document could not be rendered.

## Related

- [Read an RCA case](/investigate/read-an-rca-case)
- [Review the Recovery Scorecard](/dashboards-reports/recovery-scorecard)
- [How root-cause analysis works](/investigate/rca-explained)
