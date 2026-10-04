---
title: Review sign-in sessions
sidebar_label: Sessions
description: Review who is signed in to Correlix right now, from where and for how long, and revoke a session to sign that person out immediately.
page_type: task
sidebar_position: 4
---

# Review sign-in sessions

**Administration → Access & Audit → Sessions** lists the live sign-in sessions.
Use it to see who is signed in, and to end a session you do not recognise or
that belongs to someone who has left.

## Before you begin

- An administrator account.
- Sessions are per tenant. A tenant administrator sees the sessions of their
  own tenant's users only. A platform administrator sees every tenant's.

## Steps

1. Go to **Administration → Access & Audit → Sessions**.
2. Read the summary: **Active** sessions, **Total** sessions, and **People**,
   the number of distinct people with an active session.
3. Type in **Search sessions…** to narrow the list by person, tenant or
   address.
4. To end a session, select **Revoke** on its row and confirm. Only an active
   session has the button.
5. Select **↻ Refresh** to reload the list.

## What you see

One row per session with **Person**, **Tenant**, **IP**, **Status**,
**Started**, **Last activity** and **Idle**, the time since the last activity.

A revoked session is signed out immediately. Revoking a session does not
disable the account, so the person can sign in again. To stop that, disable the
account in **Identity & Access**.

## Related

- [Check what an account can access](/administration/access-explorer)
- [Manage identity and access](/administration/identity-access)
- [Audit log](/administration/audit-log)
