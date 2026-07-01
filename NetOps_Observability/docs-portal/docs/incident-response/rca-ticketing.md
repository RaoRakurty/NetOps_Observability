---
title: RCA Auto-Ticketing
sidebar_label: RCA Auto-Ticketing
sidebar_position: 4
description: Automatically file one ticket per incident, carrying the root-cause diagnosis and evidence.
---

# RCA Auto-Ticketing

RCA Auto‑Ticketing closes the loop: when Correlix confirms an incident, it files **one ticket** in your connected ITSM ([ServiceNow](/incident-response/integrations#servicenow) or [Jira](/incident-response/integrations#jira)) — carrying the diagnosis, evidence, scope, recommended owner, and a link back — instead of a ticket per raw alert.

Configure it at <kbd>Incident Response → RCA Auto‑Ticketing</kbd>.

## Prerequisites

- A connected **ITSM integration** (see [Integrations](/incident-response/integrations)).

## Create a ticketing policy

1. Go to <kbd>Incident Response → RCA Auto‑Ticketing</kbd>.
2. Create a **policy** that decides *which* incidents get a ticket — for example, only **confirmed** or **suspected** verdicts, above a scope/severity threshold.
3. Use the built‑in **Simulator** to preview what the policy would do against recent incidents before enabling it.
4. Enable the policy.

## What gets filed

Each ticket includes:

- the incident's **friendly id** (e.g. `P‑CCE567`) as a shared handle,
- the **root‑cause diagnosis** and **verdict**,
- the **supporting evidence** and any **missing evidence**,
- the **recommended owner** and **next actions**, and
- a **deep link** back to the incident in Correlix.

## De-duplication

One incident → one ticket. Correlix keys tickets by the incident's correlation id, so a re‑sync updates the existing ticket and never creates duplicates.

## The result

You get a measurable, evidence‑backed loop: **detect → correlate (root cause) → auto‑file ticket → measured recovery time** (see the [Recovery Scorecard](/incidents/overview)).
