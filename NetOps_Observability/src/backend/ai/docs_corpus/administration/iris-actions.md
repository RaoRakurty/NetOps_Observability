---
title: Approve the actions Iris proposes
sidebar_label: Actions
description: At the end of an investigation Iris can propose a note for the case's ITSM ticket or save its finding to investigation memory; nothing is sent until someone other than the person Iris answered approves the exact text.
page_type: task
sidebar_position: 16
---

# Approve the actions Iris proposes

Iris can **propose** two kinds of action. It never performs one on its own:

- **A note on the case's ticket.** One note on the ITSM ticket that is already linked to the case (ServiceNow work note or Jira comment), written from the investigation's own evidence. Iris never opens a ticket and never chooses which ticket — it uses the one the RCA view opened. Open a ticket from the RCA view first if there is none.
- **A finding saved to investigation memory.** Iris's conclusion is saved for the case, so a later investigation reads it as earlier context — marked unverified until someone rates it, never as the current state.

Iris proposes only at the end of an investigation that **concluded** with supported evidence on a known case. An action never touches a device: there is no kind of action that could.

## Before you begin

- The **Iris actions (approval needed)** switch must be on under **Platform → Configuration → Features**. A platform administrator turns it on; it is off by default.
- AI investigations must be on for the installation and for your workspace.
- A workspace administrator turns actions on for the workspace and chooses which kinds Iris may propose (none by default).

## Turn actions on for your workspace

1. Open **Iris → Settings** and go to **9. Actions Iris proposes**.
2. Tick **Iris can propose actions for this workspace**.
3. Tick each kind Iris may propose.
4. Optional: tick **Dry runs only** — Iris then shows what it would send and sends nothing.
5. Confirm that an approved action is sent to the ticketing system or saved to memory, then **Save**.

## Approve or decline an action

When Iris proposes an action, the answer shows a card: *Proposed — needs approval by someone else.* The request waits under **9. Actions Iris proposes → Waiting for approval**.

1. Read the **exact text that will be sent** and the check Correlix ran (for a ticket note: the ticket still exists and is still linked to the case).
2. **Approve and send** — or write a reason and **Decline**.

The rules:

- **Someone else decides.** The person Iris answered can withdraw the request but can never approve it. An API key can never decide.
- **It runs once.** A second approval, or a retry, returns the result of the first. A request that is not decided within 24 hours expires.
- **It stops when switched off.** If the switch or the workspace setting is turned off after Iris proposed something, the approval is refused.
- **Everything is recorded.** Each proposal, approval, decline and result is in the audit trail and in **How Iris decided** (the payload is recorded as a fingerprint, never as text).

A note has no undo: if it was wrong, add a correcting note on the ticket.
