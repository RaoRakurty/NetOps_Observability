---
title: Review quarantined telemetry
sidebar_label: Review quarantined telemetry
description: Read what the ingest pipeline could not attribute to a tenant, tell the three empty states apart, and decide whether a device assignment is missing.
page_type: task
sidebar_position: 12
---

# Review quarantined telemetry

When a syslog message, an SNMP trap or a flow record arrives from a sender that
is not in the device inventory, Correlix cannot attribute it to a tenant. Rather
than guess an owner, the router seals the whole event inside a metadata envelope
and holds it in an operator-only index. **Quarantine** is the view of what is
held.

Read this page when telemetry you expect is not appearing on a tenant's
dashboards. A growing quarantine depth means something is sending data that no
device record owns.

## Before you begin

- Platform owner access. The quarantine holds events that could not be
  attributed to any tenant, so no tenant principal may read it. The page is in
  the provider-only **Platform** section for that reason.
- Sealing custody enabled on the deployment (`FEATURE_SEALED_FIELDS` plus a
  `SEAL_PROVIDER`). Without it there is no quarantine stage at all: the route
  answers `501` and the page says so.
- Access to the device inventory, to check whether the sender should have a
  device record.

## Steps

### Step 1 — Read the depth and the age

1. Go to **Platform → Tools → Quarantine**.
2. Read **Envelopes held**, **Oldest** and **Oldest age**.

A depth that grows steadily is what to act on. A short-lived trickle is
normal: a device added moments ago attributes normally once enrichment
converges, which takes about a minute.

### Step 2 — Read the lane breakdown

The line above the table counts the lanes present **on the current page**, and
states that count against the real depth. Only three lanes carry the quarantine
stage, because they are the lanes whose tenant comes from a registry lookup:

| Lane | Identity that is looked up |
|---|---|
| `syslog` | The hostname in the message |
| `snmptrap` | The trap device or source address |
| `flows` | The exporter address |

### Step 3 — Read one envelope's row

Each row carries the receive time, the lane, the reason, the hashed identity,
the transport source address where one exists, the restore state and the index.

The identity is stored as a hash. The raw hostname or exporter address the
sender claimed is never kept outside the sealed envelope, so the row cannot leak
it. Match a row by assigning the sender in the device inventory and letting the
next events attribute normally.

The restore state has three values, and they mean different things:

| State | What it means |
|---|---|
| `held` | Sealed and waiting. Nothing has claimed it |
| `stranded claim` | A restore claimed the envelope and may or may not have produced it |
| `re-injected` | The bus accepted the produce, and only the tombstone remains |

### Step 4 — Decide

If the sender should be monitored, add it to the device inventory and assign it
to the owning tenant. New events from that sender attribute normally within the
enrichment window.

Recovering the events already held is a separate, deliberate operation. It is
dual-gated (platform admin **and** `sensitive_data:admin`), it is audited, and
it is deliberately not a button on this page. The procedure is in the quarantine
operations runbook, `docs/runbooks/security/quarantine-operations.md`.

## What you see

Three states that a single blank table would have collapsed:

| What the page says | What it means |
|---|---|
| Sealing custody is not enabled | There is no quarantine stage on this deployment |
| The quarantine depth is unknown | The index could not be read. It is not an empty quarantine |
| Nothing is held | Every event on those three lanes resolved to a device in the inventory |

Envelopes are deleted by an index retention policy after a bounded window,
`QUARANTINE_RETENTION_DAYS`, which is 30 days on the shipped configuration. The
page reports the oldest envelope it can see, not the policy installed on the
cluster.

## Related

- [Create a pipeline processor](/administration/processors)
- [Read the audit log](/administration/audit-log)
- [Add devices manually](/onboard-devices/add-devices-manually)
- [Check telemetry parser coverage](/administration/telemetry-coverage)
