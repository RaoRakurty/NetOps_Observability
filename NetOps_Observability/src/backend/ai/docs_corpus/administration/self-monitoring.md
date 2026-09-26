---
title: Watch Correlix with the self-monitoring dashboards
sidebar_label: Self-Monitoring
description: Open the stack and network dashboards of the optional self-monitoring add-on inside the console, signed in automatically.
page_type: task
sidebar_position: 21
---

# Watch Correlix with the self-monitoring dashboards

**Platform → Tools → Self-Monitoring** opens the dashboards of the optional
self-monitoring add-on inside the console. The add-on runs Grafana, which
shows the stack and network dashboards. You are signed in to it automatically,
so there is no second login.

## Before you begin

- A platform administrator account. Self-Monitoring is platform-global.
- The self-monitoring add-on deployed: `self-monitoring` in
  `COMPOSE_PROFILES` in `deployment/docker/.env`. When the add-on is not
  running, the **Self-Monitoring** entry does not appear under **Platform →
  Tools** at all, because an empty frame is not a page.

## Steps

1. Go to **Platform → Tools → Self-Monitoring**. The page is titled **Metrics
   & Dashboards**.
2. Choose a dashboard inside the frame.
3. Select **Fullscreen** to give the dashboards the whole window, and **Exit**
   to return.
4. Select **Reload** if a dashboard stops updating.

## What you see

The Grafana dashboards shipped with the add-on, in the Correlix colours. For a
status board that needs no add-on, use
[Stack Health](/administration/stack-health).

Grafana runs unmodified in its own container. See
[Third-party components](/deploy/third-party-components) for its licence.

## Related

- [Check the health of the Correlix stack](/administration/stack-health)
- [Monitor the Correlix host](/monitoring/host-monitoring)
- [Optional modules](/deploy/optional-modules)
