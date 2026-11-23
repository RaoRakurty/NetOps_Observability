---
title: Allow your apps to send data from a browser
sidebar_label: Cross-origin access
description: List the web addresses of your own apps that may send data to Correlix from a browser — what the real-user tag needs — from Platform → Configuration → Cross-origin access.
page_type: task
sidebar_position: 23
---

# Allow your apps to send data from a browser

**Platform → Configuration → Cross-origin access** lists the web addresses of
your own apps that may send data to Correlix from a browser. The real-user tag
runs on your apps' pages and sends its data to Correlix, so each app that
carries the tag must be on this list; browsers block the data from any other
address.

Only the platform administrator sees this page. Organisation and tenant
administrators do not.

## Before you begin

- The web address of each app that carries the real-user tag, for example
  `https://shop.example.com`. Add a port only if the app uses one, for example
  `https://portal.example.com:8443`.

## Steps

1. Go to **Platform → Configuration → Cross-origin access**.
2. Read the line under **Allowed addresses**. It says where the list in use
   comes from:
   - **From the installation** — the value set when Correlix was installed.
     Saving here replaces it.
   - **Saved here** — a list saved on this page. It wins over the installation
     value.
   - **No app may send data from a browser yet** — neither is set.
3. Enter one address per line and select **Save**. The list is in use at once;
   nothing restarts.
4. To go back to the installation value, select **Use the installation value**.

## What is accepted

Each line must be a scheme and a host, with an optional port — exactly what a
browser sends:

| Accepted | Refused |
|---|---|
| `https://shop.example.com` | `*` or `https://*.example.com` — no wildcards |
| `https://portal.example.com:8443` | `https://shop.example.com/checkout` — no path |
| `http://localhost:5173` (a developer's machine) | `http://shop.example.com` — use https |
| `https://10.20.30.40` | `https://user:pass@shop.example.com` — no credentials |

The page points at each bad line before you save, and Correlix checks the list
again when it is saved: if any line is refused, nothing is saved. At most 50
addresses.

## What happens

- Every change is written to the audit log first, with who made it and the list
  before and after. A change the audit log cannot record is not made.
- A saved list applies to the very next request from a browser, and to live
  updates in the console from another address.
- An empty saved list means no app may send data from a browser, even if the
  installation value lists some.
- If an entry in the installation value is not a web address Correlix can allow,
  the page says so at the top, and that entry does nothing.

## Related

- [Digital experience](/monitoring/digital-experience) — the real-user setup page
- [Turn Correlix features on and off](/administration/features)
