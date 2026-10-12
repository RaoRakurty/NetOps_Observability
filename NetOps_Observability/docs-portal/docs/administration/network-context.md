---
title: Tell Iris about your network
sidebar_label: Network Context
description: Write short facts about your own network — the DR site, carrier circuit ids, maintenance windows — that Iris reads before every answer once a second administrator approves them.
page_type: task
sidebar_position: 13
---

# Tell Iris about your network

**Administration → Iris → Network Context** holds short facts about your own network that Iris reads before every answer: which site is the DR site, how your carriers name circuits, when your change windows are, which alert is a known harmless one. A fact reaches Iris only after a **second administrator** approves it.

Facts are background, not evidence. When live data disagrees with a fact, Iris goes with the live data and says so, and it never cites a fact as the cause of a problem.

## Before you begin

- **Permission:** `administration:read` to see facts, `administration:write` to write and send them for review, `administration:admin` to approve, decline, restore or stop using one.
- **Licence:** the `ai.context.author` capability. Without it the page is refused and Iris reads no facts.
- **Workspace:** facts belong to one workspace. From the Global view, choose a workspace first.
- **Platform store:** this needs the Postgres platform store (the default for new installations). On a file-backed installation the page answers *network context needs the Postgres platform store*.
- **People, not keys:** writing and approving need a signed-in person. An API key can only read.

## Steps

### 1. Write a fact

Pick the **type of fact**:

| Type | Use it for |
|---|---|
| Network layout note | A fact the topology does not show: "core-02 is the DR site". |
| What matters most | Business-critical sites and applications. |
| Maintenance window | Recurring change windows. |
| Known harmless alert | An alert your network raises legitimately, and why. |
| Carrier or provider | How a carrier's circuits are named, which AS is whose. |
| Who to escalate to | The team or role that owns a seam. Names of teams or roles only — no e-mail addresses or phone numbers. |
| Naming convention | How devices and sites are named. |
| Addressing convention | Loopback ranges, link subnets, VLAN plans. |
| Our terminology | Words your team uses: "the ring" means the metro ring. |

Leave **Site** empty for the whole network, or give the site's id (for example `dfw-hq`) — you can only choose a site you can see. Give the fact a **short name** and write it in plain text, up to **2,000 bytes**. Select **Save draft**.

Iris refuses a fact, and says which rule it broke, if the text:

- starts a line with a role such as `system:` or `assistant:`, or contains a chat-template token;
- repeats one of Iris's own section headers, or contains a bracketed reference such as `[problem:...]`;
- contains a link, an e-mail address, or the name of an Iris tool;
- contains a tab, a control character, or an invisible character.

A workspace holds up to 50 facts.

### 2. Send it for review

Your draft is listed under **Send for review**. Edit it if you need to, then select **Send for review**. From then on the text is frozen; **Take back to edit** returns it to a draft.

### 3. Another administrator reviews it

A different administrator sees it under **Review others' facts**, with the text Iris reads now beside the proposed text. **Approve** puts the new text in use. **Decline** needs a note.

You cannot approve your own text, and the approval is tied to the exact text on the reviewer's screen: if it changed after they opened it, the approval is refused and they review it again.

### 4. Check what Iris reads

**What Iris reads** shows the exact block Iris receives, in order. Iris reads at most about 4,000 characters of facts; if yours are longer, the block says how many were left out.

### Restore or stop using a fact

Open a fact under **All facts** to see every version, who wrote it, who approved it and when.

- **Restore this version** puts an earlier *approved* version back in use, as a new version that keeps its original author and approver. One administrator can do this — useful in an incident.
- **Stop using this fact** takes it out of what Iris reads. The history stays.

Both need a reason. Every change is recorded in the [audit log](audit-log.md) with the fact's id, version and a hash of its text — never the text itself.

## API

```bash
# List this workspace's facts and the types you can write
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/ai/context

# Write a draft
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"kind":"topology_note","key":"DR site","body":"core-02 is the DR site."}' \
  http://localhost:8000/api/ai/context

# Send it for review, then (as another administrator) approve the reviewed text
curl -s -X POST -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/ai/context/$ID/submit
curl -s -X POST -H "Authorization: Bearer $OTHER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"version":1,"body_sha256":"<from the fact>"}' http://localhost:8000/api/ai/context/$ID/approve

# What Iris reads now
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/ai/context/preview
```

| Response | Meaning |
|---|---|
| `400` with `problem.rule` | The text broke a rule; `problem.message` says which. |
| `400` *choose a workspace first* | You are in the Global view. |
| `403` | Your own text (approval needs someone else), an API key, or a missing permission or licence. |
| `404` | No such fact in your workspace. |
| `409` | The text changed since it was reviewed, the state moved, the name exists, or a limit was reached. |
| `503` | The Postgres platform store is not in use. |
