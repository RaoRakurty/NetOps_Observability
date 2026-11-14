---
title: Connect an AI assistant to Iris over MCP
sidebar_label: Iris over MCP
description: Let an outside AI assistant use Iris's read-only network lookups through the Model Context Protocol (MCP), with one workspace API key, after a platform administrator turns it on.
page_type: task
sidebar_position: 15
---

# Connect an AI assistant to Iris over MCP

Iris can serve its **read-only lookups** to an AI assistant you already use — any client that speaks the **Model Context Protocol (MCP)**. The assistant can then ask Correlix things like "which incidents should I work first?" or "show the SD-WAN overlay state for branch-7" and get the same answers Iris itself would read.

It is read-only by construction. The assistant can look things up; it can never change a device, a setting, an incident or a ticket, and it never gets a tool that opens a session on a device.

## What the assistant can and cannot do

**Can:** read one workspace's data with the permissions of the API key it connected with. The lookups offered are:

- incidents: the active and actionable ones, history, the root-cause verdict, timeline, causal chain, blast radius, affected entities, confidence, owner, and similar past incidents;
- network: whole-network topology, the topology around a device, SD-WAN overlay state, tunnel state, measured path evidence, synthetic probe results;
- health and traffic: device health, metric anomalies, top talkers, flow summaries, service traffic;
- device logs, recent changes, and the Correlix documentation.

Each lookup is offered only when this installation has it **and** the key's permissions allow it.

**Cannot:**

- change anything — there are no write tools;
- run commands on devices (no SSH or "show" sessions), ping or traceroute;
- read another workspace — the key's own workspace always decides; switching workspaces in the request is ignored;
- read configuration diffs, security findings or your colleagues' Iris investigations;
- use Correlix's own AI provider — the assistant brings its own model.

## Before you begin

- **Licence:** the `ai.mcp` capability (every tier carries it today).
- **Platform switch:** a platform administrator turns on **Iris over MCP (read-only)** under **Administration → Features** and acknowledges that answers will leave Correlix for the assistant. Until then the endpoint does not exist (404).
- **Workspace opt-in:** the platform administrator ticks **MCP** for the workspace under **Iris settings → Workspace access**. A workspace that has not opted in is refused (403).
- **An API key:** a workspace administrator mints a key under **Administration → API Access** with the **`iris:mcp`** scope, plus the read scopes for what the assistant should see (for example `read:*`). `read:*` alone does **not** include MCP, and a key with `admin:*` is refused — mint a separate, read-only key for the assistant.

## Steps

### 1. Turn MCP on for the platform

**Administration → Features → Iris → Iris over MCP (read-only)**, then confirm the acknowledgement.

### 2. Turn MCP on for the workspace

In Iris, open **AI models** (the settings button) → **Workspace access**, and tick **MCP** on the workspace's row.

### 3. Mint the key

**Administration → API Access → New key**: choose the `iris:mcp` scope and the read scopes you want. Copy the key — it is shown once. You can restrict it to your assistant's source addresses and give it its own rate limit.

### 4. Point your assistant at Correlix

Configure an MCP server in your client with:

- **Transport:** Streamable HTTP
- **URL:** `https://<your-correlix-host>/api/ai/mcp`
- **Header:** `Authorization: Bearer <the key>`

The server speaks MCP revision **2025-06-18** (and accepts 2025-03-26 clients). It is stateless: no session id, no server-sent stream, answers as plain JSON.

### 5. Check it works

Ask the assistant to list Correlix's tools, then something simple such as "what incidents are active in Correlix?". The tool list only shows lookups this key may use.

## Limits and records

- **Per key:** 30 tool calls a minute by default (the platform can set `IRIS_MCP_CALLS_PER_MIN`), on top of the key's own request limit. Over the limit, the assistant is told the lookup was not run.
- **Per workspace:** the same per-lookup rates Iris applies everywhere.
- **Audit:** every request is in the audit log (method, tool, outcome — never the arguments or the data). Every tool call is in the AI decision ledger under the surface `mcp`, as hashes only.
- **Turning it off:** clear the workspace's **MCP** box, turn the platform switch off, or revoke the key. Each takes effect on the next request.

## Data leaves Correlix

Whatever the assistant reads goes to that assistant and to the AI provider behind it, under that provider's terms — not Correlix's. Treat the key like a read password for the workspace: give it only to an assistant your organisation has approved.
