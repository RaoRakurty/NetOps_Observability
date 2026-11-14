---
title: Teach Iris your own runbooks
sidebar_label: Runbooks
description: Write your team's own troubleshooting methods and procedures in the same format as Iris's built-in methods; Iris uses a method once its test cases pass and a second administrator approves it.
page_type: task
sidebar_position: 14
---

# Teach Iris your own runbooks

**Administration → Iris → Runbooks** holds your team's own troubleshooting methods and procedures, written in the same format as the methods Iris ships with. There are two kinds:

- A **troubleshooting method** (*investigative*). Iris can run it: it gathers the evidence the method names, reads it, and follows the next step the method allows. It is proven by its **test cases** before anyone can approve it.
- A **procedure for a person** (*MOP*). Iris can show it, but never runs it.

A runbook reaches Iris only when its test cases pass **and** a second administrator approves exactly the text they reviewed. Iris follows only the next steps a runbook names, it can only use read-only tools, and Correlix's own methods never hand off to your text.

## Before you begin

- **Permission:** `administration:read` to see runbooks, `administration:write` to write, check and send them for review, `administration:admin` to approve, decline, restore or stop using one.
- **Licence:** the `ai.runbook.author` capability. Without it the page is refused and Iris runs only its built-in methods.
- **Workspace:** runbooks belong to one workspace. From the Global view, choose a workspace first.
- **Platform store:** this needs the Postgres platform store (the default for new installations). On a file-backed installation the page answers *tenant runbooks need the Postgres platform store*.
- **People, not keys:** writing and approving need a signed-in person. An API key can only read.

## Steps

### 1. Write a runbook

Give it a **name** — lower-case letters, digits and hyphens, up to 48 characters; it must match the `name:` line in the text. Choose the **type**, then write:

- **The method (SKILL.md)**, up to 16 KB. The page starts you with a working example. The header says when the method applies (`when_to_use`), which tools it may use (`tools`), what it reads first (`gather`), what to look for, and its `decisions` — the next methods it may hand off to and the verdicts it may give. An `applies_when:` line can limit it to devices Correlix has discovered with a given role, vendor or protocol.
- **Its test cases (CASES.yaml)**, up to 32 KB and 40 cases — for a troubleshooting method only. Each case is a question with fixed evidence, and says what Iris must do (the hand-offs, the verdict) and what it must never do (a method or tool it must not use).

Iris refuses a runbook, and says which rule it broke, if it names a tool that is not on the read-only list, if a hand-off points at a method that does not exist, or if any text line breaks the same rules as [Network Context](network-context.md) (role prefixes, links, e-mail addresses, control characters). A workspace holds up to 30 runbooks.

### 2. Check it and send it for review

Your draft is listed under **Check and submit**.

- **Run its cases** runs the test cases now and changes nothing. If a case fails, the page lists each case and what went wrong.
- **Send for review** runs the cases again and, only if they pass, sends the runbook for review. From then on the text is frozen; **Take back to edit** returns it to a draft.

### 3. Another administrator reviews it

A different administrator sees it under **Review others' runbooks**, with the approved text beside the proposed text and its test cases. **Approve** puts it in use. **Decline** needs a note.

You cannot approve your own runbook, and the approval is tied to the exact text on the reviewer's screen: if it changed after they opened it, the approval is refused and they review it again.

### 4. Check what Iris runs

**What Iris runs** lists every approved runbook:

- *Iris can run it* — its cases passed against the platform as it is now.
- *Not running: the platform changed since its cases last passed* — an upgrade changed the models Iris uses, its instructions or a tool, so the runbook's earlier proof no longer counts. Iris re-runs the cases on its own the first time the runbook would be needed; **Re-run its cases** does it now. If they pass, the runbook is back in use with no new approval (the text did not change). If they fail, it stays out until its author fixes it.

### Link it, restore it or stop using it

Open a runbook under **All runbooks**:

- **What it is about** links it to an alert rule, a problem signature, a device, site, circuit or application (written `device:edge-1`), or an incident. A link must point at something in your workspace.
- **Restore this version** puts an earlier approved version back in use as a new version; its cases run again first.
- **Stop using this runbook** takes it out of Iris. The history stays.

Both need a reason. Every change is recorded in the [audit log](audit-log.md) with the runbook's id, version and a hash of its text — never the text itself.

## API

```bash
# List this workspace's runbooks
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/ai/runbooks

# Write a draft
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d @runbook.json http://localhost:8000/api/ai/runbooks   # {"name","kind","skill_md","cases_yaml"}

# Run the cases (changes nothing), then send for review
curl -s -X POST -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/ai/runbooks/$ID/check
curl -s -X POST -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/ai/runbooks/$ID/submit

# As another administrator, approve the reviewed text
curl -s -X POST -H "Authorization: Bearer $OTHER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"version":1,"body_sha256":"<from the runbook>"}' http://localhost:8000/api/ai/runbooks/$ID/approve

# After an upgrade: re-run an approved runbook's cases
curl -s -X POST -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/ai/runbooks/$ID/reprove
```

| Response | Meaning |
|---|---|
| `400` with `problem.rule` | The text broke a rule; `problem.message` says which. |
| `400` *choose a workspace first* | You are in the Global view. |
| `403` | Your own text (approval needs someone else), an API key, or a missing permission or licence. |
| `404` | No such runbook in your workspace. |
| `409` | The text changed since it was reviewed, the state moved, the name exists, a limit was reached, the platform changed since its cases passed, or there is no approved version to re-check. |
| `422` with `problems` | The test cases did not pass; nothing was changed. |
| `503` | The Postgres platform store is not in use, or too many case runs are in progress. |
