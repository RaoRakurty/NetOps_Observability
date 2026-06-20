# External Source-of-Truth Import — Market Research & Design Decision

**Date:** 2026-06-20 · **Method:** deep-research harness (24 sources fetched, 98
claims extracted, 25 adversarially verified 3-vote, 22 confirmed / 3 refuted).
**Status:** decided → implementing the file-based MVP.

This informs the Phase-3-remainder "external SoT import" feature (see
[sot-provider-model.md](../sot-provider-model.md)).

---

## 0. The headline decision: do NOT replace Infra → Devices with NetBox

The question on the table was: *"if NetBox is the way to go, replace our
Infra → Devices section with NetBox directly."* **The research says no — emphatically.**

The entire ITOM / network-observability market runs a **clean split between two
planes**:

- **OBSERVED state** — live discovery, *always authoritative* for "what is
  actually on the wire" (up/down, telemetry, last-seen). This is our SNMP
  discovery → Infrastructure → Devices.
- **INTENDED state** — sites, geo-coordinates, ownership, "should-exist"
  inventory. Lives in a Source-of-Truth / CMDB layer *because the wire cannot
  supply it.* This is our internal sites + device→site stores.

NetBox is an **intended-state** store with **no live state**. Replacing live
discovery with it would (a) gut the core observability value (you'd read a
hand-maintained database instead of the network), (b) force every customer to
stand up and populate a CMDB just to see devices, and (c) contradict the
automation-only decision already shipped. NetBox Labs' own Discovery/Diode
product *ingests discovered data into NetBox to compute drift* — i.e. discovery
feeds the SoT, not the reverse. **Correlix already embodies the best-practice
architecture.** The work is therefore an *import that seeds intent*, never an
authority swap.

> Refuted overreach (logged): the crisp "NetBox = intent, Discovery = observed"
> equivalence was **not** fully supported — drift/reconciliation is a separate
> *Assurance* layer built on the Diode ingestion pipeline, not Discovery itself.
> And NetBrain does **not** ingest external CMDB data inbound as authority (0-3 /
> 1-2 refuted) — it *validates observed behaviour against* NetBox intent. Do not
> cite NetBrain as an inbound-import exemplar.

---

## 1. The canonical reconciliation model: ServiceNow IRE

ServiceNow's **Identification and Reconciliation Engine (IRE)** is the
industry's reference architecture for "multiple sources, one record" — the model
our importer should mirror conceptually (we implement it in stdlib):

1. **Identification rules run FIRST** — decide *how to recognise* an incoming
   record and match-or-create it. Keyed on **serial number → IP → hostname/MAC**.
   ServiceNow explicitly warns *IP is not a reliable unique identifier* (IPs
   change) → **prefer serial over IP**. Match found → update; no match → create.
2. **Reconciliation rules run SECOND** — decide *which source wins*, and they are
   **per-attribute, per-source**: different sources can each own different fields
   of one record, governed by **numeric priority where the lower number wins**;
   lower-priority sources are blocked via *attribute masking*.

The crucial takeaway for us: **model the in-app operator as the highest-priority
source per attribute.** A re-import must never clobber a field an operator edited
— the external import is a *lower-priority seed*.

(Identity-matching in practice is multi-key with strict precedence everywhere:
Device42 = serial → UUID → name; ServiceNow = serial / IP / hostname.)

---

## 2. Import mechanism: file-first, graduate to API

- **Bulk seeding is overwhelmingly file-first.** NetBox supports **CSV/YAML bulk
  import _and_ update** (an explicit `id` field flips a row from create→update),
  alongside GUI forms, REST API, and custom scripts — the whole file↔connector
  spectrum.
- **Live integrations are predominantly ONE-WAY PUSH** into the destination,
  deferring matching to its IRE (Device42→ServiceNow connector is one-way,
  manual or scheduled). A documented UX pitfall: pushed records "appear ignored"
  because IRE silently reconciled them → **our dry-run must explicitly show
  create / update / skip / conflict counts** so nothing is silently swallowed.
- **NetBox's `id` is its internal PK, not a fuzzy external matcher.** For a
  foreign-system seed we must match on *natural keys* (serial / IP / hostname)
  ourselves — copy the CSV-import UX, build the identity resolver our side.

---

## 3. Formats & geo

- **GeoJSON (RFC 7946, IETF Standards Track)** is the de-facto open interchange
  format for geographic features and **mandates WGS-84 decimal degrees** — a
  direct match for our site store. Offer it alongside CSV for sites; a site maps
  to a GeoJSON `Point` feature with `properties` (name/owner/status).
  ⚠️ GeoJSON coordinate order is **longitude-first `[lng, lat]`** — a classic bug
  source; handle explicitly.
- Geographic placement (sites, lat/lng, address, device→site binding) is
  **owned by the SoT layer**, confirmed by NetBox's first-class Site lat/lng +
  flexible device→site/location/rack placement. These are exactly the intent
  fields to import (the data SNMP can't produce).

---

## 4. Decision — MVP scope

**Build (file-based, one-way seed/enrich, lands as editable internal records):**

| Aspect | Decision |
|---|---|
| Mechanism | **File import** — CSV + JSON for both kinds; **GeoJSON** also accepted for sites. (Live API connector deferred to v2.) |
| What | **Sites** (name, slug, lat/lng, status, **owner**) + **device→site placement**. (Expected-device-list-for-drift deferred.) |
| Identify | Sites by **slug** (explicit or derived from name). Devices by **serial → mgmt-IP → hostname** against the live visible inventory. |
| Reconcile | **Non-clobbering by default**: create new records; existing records that would change are reported as **conflict** and **skipped** unless the operator opts into `overwrite`. Exact matches → unchanged. |
| Safety | **Dry-run preview is the default** — returns a per-row plan (create / update / skip / conflict / error) + counts; apply is a second, explicit call. |
| Tenancy | Tenant-scoped (`infrastructure:write`); records stamped from the token; a device/site must be visible to the caller or the row errors (never cross-tenant). Bounded body. |

**Defer (v2+):** live CMDB connectors (ServiceNow/Infoblox/NetBox API),
scheduled/continuous sync, per-attribute provenance masking, weighted
multi-attribute matching, and the should-exist drift inventory.

---

## 5. Positioning angle (validated)

*"Bring your existing CMDB/SoT to seed intent — but our live discovery stays
authoritative for observed state."* This intent-vs-observed honesty is exactly
how NetBox Assurance/Diode and NetBrain position; integrating is **table-stakes**,
and being explicit about *which layer owns which truth* is the **differentiator**.
The common buyer complaints to avoid: stale data, duplicate CIs, reconciliation
storms, and records silently "ignored" by reconciliation.

---

## Sources (primary, verified)

- ServiceNow IRE — https://www.servicenow.com/docs/r/servicenow-platform/configuration-management-database-cmdb/ire.html
- ServiceNow Identify & Reconcile (Yokohama) — https://www.servicenow.com/docs/bundle/yokohama-servicenow-platform/page/product/configuration-management/concept/c_CMDBIdentifyandReconcile.html
- Device42 autodiscovery matching — https://docs.device42.com/auto-discovery/autodisc-best-practices/
- Device42 → ServiceNow connector (one-way) — https://docs.device42.com/integration/external-integrations/device42-servicenow-connector/
- NetBox populating data (CSV/YAML + id-update) — https://netboxlabs.com/docs/netbox/getting-started/populating-data/
- NetBox Site model (lat/lng, address) — https://netboxlabs.com/docs/netbox/models/dcim/site/
- NetBox Labs Discovery/Diode — https://netboxlabs.com/docs/discovery/
- GeoJSON RFC 7946 — https://www.rfc-editor.org/rfc/rfc7946.html

**Coverage gap (honest):** the verified set is heavy on ServiceNow + NetBox +
Device42 + GeoJSON; thin on Datadog, Cisco Catalyst Center/ThousandEyes, Auvik,
Forward, IP Fabric, LogicMonitor, Kentik, SolarWinds, Infoblox — treat those as
un-researched. The architectural conclusions rest on the strong primary sources
above and are not weakened by the gap.
