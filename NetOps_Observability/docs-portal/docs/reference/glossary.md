---
title: Glossary
sidebar_label: Glossary
sidebar_position: 2
description: Definitions of the terms used across Correlix.
---

# Glossary

See **[Key concepts](/getting-started/concepts)** for the fuller mental model. Quick definitions:

- **Device** — a monitored network element.
- **Interface** — a port on a device; source of throughput/utilization/error metrics.
- **Site** — a location grouping for devices.
- **Metric** — a numeric time series (SNMP‑polled or gNMI‑streamed).
- **Flow** — a traffic record (NetFlow/sFlow/IPFIX).
- **Event** — anything on the timeline: syslog, trap, alert, anomaly, change.
- **Monitor** — a threshold rule that raises an alert.
- **Anomaly** — an auto‑detected deviation from normal (z‑score).
- **Alert** — an active monitor breach.
- **Incident / Correlation** — related signals grouped into one root‑caused problem.
- **Verdict** — Confirmed / Suspected / Undetermined confidence in a fault domain.
- **Evidence** — the signals supporting/contradicting a verdict, clickable to source.
- **Seam** — a responsibility boundary in the path (e.g. your network ↔ ISP).
- **Recommended owner** — the team a fault domain maps to.
- **Tenant** — an isolated customer/organization view.
- **Organization** — an account layer grouping tenants.
- **Role** — a permission set; access is role‑based.
- **Platform owner** — the cross‑tenant super‑admin.
- **Source of Truth (SoT)** — the authoritative inventory (internal, or NetBox).
- **Measurement target** — the destination a WAN interface measures to (peer, next‑hop, or public‑DNS anchor).
