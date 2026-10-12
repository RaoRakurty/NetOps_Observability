---
title: Turn Correlix features on and off
sidebar_label: Features
description: Switch Correlix features on or off from the console, see which apply at once and which after a restart, and restart Correlix to apply them.
page_type: task
sidebar_position: 22
---

# Turn Correlix features on and off

**Platform → Configuration → Features** is where the platform administrator
switches Correlix features on and off. You never edit configuration files: the
values set at install are only the starting point, and what you save here wins.

Only the platform administrator sees this page. Organisation and tenant
administrators do not.

## 1. Choose a feature

Features are grouped: **Collection**, **Discovery**, **Routing**,
**Configuration and device access**, **Integrations and automation** and
**Analytics**. Each line says what the feature does, and where its current value
came from:

- **Set at install** — the value the installer chose.
- **Changed here** — saved on this page, with who saved it and when.
- **Not set at install** — the built-in default applies.

## 2. Turn it on or off

Use the switch. The change is saved at once and written to the audit log.

Features that reach into your network or out of Correlix — SSH to devices,
configuration backup, diagnostic commands, packet capture, wireless actions,
ticket updates from your ITSM tool, the UniFi controller — ask you to confirm
before they turn **on**. Turning any feature **off** never asks.

## 3. Restart if asked

Each feature says when a change takes effect:

- **Applies at once** — in force as soon as you save.
- **Applies after restart** — the feature is started when Correlix starts.
  Until the restart, the line shows what is running now and what will run
  after it, for example *Running on now; off after restart.*

When a restart is needed, a banner offers **Restart now**. Correlix restarts
cleanly and the page updates when it is back, usually within a minute or two.
If your installation cannot restart itself, the banner tells you to restart the
Correlix service from the host instead.

## What is not on this page

- Settings that have their own page — notification channels, ITSM connections,
  SNMP discovery ranges — are changed there.
- Security controls such as encryption and TLS are set at install. A switch on
  this page can never stop Correlix from starting.
