---
title: Ask Iris from Slack or Microsoft Teams
sidebar_label: Iris in Slack and Teams
description: Connect your workspace's own Slack app or Teams bot so people can ask Iris in chat; each chat account is linked to a Correlix user and approved by a second admin, and answers use that user's own permissions.
page_type: task
sidebar_position: 15
---

# Ask Iris from Slack or Microsoft Teams

People can ask Iris a question in Slack or Microsoft Teams and get the same answer they would get in Correlix, with links back to the evidence. Iris answers **as the Correlix user the chat account is linked to**: that person's workspace and permissions, never more. Nothing can be changed from chat.

## Before you start

- A platform administrator turns on **Iris in Slack and Teams** on the **Features** page. Until then every chat app gets no answer.
- Each workspace connects **its own** chat app. Correlix never shares one app between workspaces.

## 1. Connect the chat app

Open **Iris → Settings → step 7, "Iris in Slack and Teams"** as a workspace admin.

**Slack**

1. Create a Slack app for your workspace. Give its bot the scopes `app_mentions:read`, `chat:write`, `im:history` and `commands`.
2. In Correlix, enter the **workspace ID** (starts with T), the app's **signing secret** and its **bot token** (starts with `xoxb-`), then **Save**.
3. Copy the address Correlix shows into the app's **Event Subscriptions** request URL (events `app_mention` and `message.im`) and, if you want a slash command such as `/iris`, into the command's request URL.

**Microsoft Teams**

1. Register an Azure Bot and add it to Teams.
2. In Correlix, enter your **Microsoft tenant ID**, the bot's **app ID** and its **app password**, then **Save**.
3. Copy the address Correlix shows into the bot's **messaging endpoint**.

Enter your **Correlix address** (for example `https://correlix.example.com`) so answers link back to the evidence. Secrets are never shown again after you save; leave a secret blank to keep the stored one. **New inbound address** replaces the address if it was ever exposed.

## 2. Link chat accounts

1. A person asks Iris anything in the chat. Iris replies with a one-time code (valid for 15 minutes).
2. In Correlix, that person opens **Iris → Settings → step 7** and enters the code under **Link my chat account**.
3. A **different** workspace admin approves the link under **Linked accounts**. Check the chat name matches the person: nobody can approve a link to their own account.

Until the link is approved, Iris answers in the chat only with a reminder. An admin, or the person themselves, can revoke a link at any time.

## Who sees an answer

- **Direct messages** and **slash commands** are answered privately.
- **In a channel**, only the person who asked sees the answer by default, because a shared channel can hold people who should not see that person's data. A workspace admin can choose **Everyone in the channel sees them** instead.
- Teams has no private reply inside a channel, so by default Iris asks the person to message it in a personal chat.

## Limits

- Each chat account can ask 6 questions a minute, and each workspace 60; the person's usual Iris limits and token budget also apply.
- Questions longer than 2,000 characters are refused.
- The platform administrator account cannot use Iris from chat.
- Every question is recorded in the audit trail with who asked and the outcome — never the question or the answer.
