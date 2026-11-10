# Runbook — moving a customer's devices onto its own discovery scan

**What this is for:** devices the platform's subnet scan found are filed under the
platform. When those devices belong to a customer (the lab's RETAIL-WALMART edges),
the platform owner gives the customer its own scan. A device found through a
customer's scan belongs to the customer, because the platform owner pointed that
probe at that network for that customer. The tenant is never inferred from what a
device answers (sysName, address or serial), and no device is re-assigned.

Owner decisions of 2026-11-10 (D1–D5) apply:

- **D1:** only the platform owner creates, changes or removes a customer's scan, and
  chooses the customer explicitly. The customer can read its own scans but cannot
  change them.
- **D2:** a customer's scan tries that customer's own SNMP profiles and nothing else.
  It never tries a platform profile.
- **D3:** the platform's copy is retired by hand (step 4). Nothing retires it
  automatically.
- **D4:** history does not move. Series, flows, syslog, traps and incidents recorded
  under the platform's id stay the Provider's and age out with retention.
- **D5:** the lab steps run later, from the main session.

Code: `internal/discoveryscope` (the stored scans and `/api/discovery/scopes`),
`internal/discovery` (`ScanScope`, `ScanDeviceIDFor`), migration
`0067_discovery_scopes.sql`.

---

## 0. Before you start

1. **PR 1–3 and tracker 387 13a are deployed.** 13a binds the controller facts and
   interface rows in the customer's partition. Without it, traps sent from interface
   addresses stay unattributed.
2. **There is licence headroom for one extra slot per device.** Each customer copy is
   a new device with a new id and its own slot. During the move a box counts twice.
   Community allows 25 devices.
3. **Note the platform ids** of the devices that will move. As the platform owner in
   the Provider view, run `GET /api/discovery/config`; the ids are listed in `found`.
4. **Check the sweep budget.** All scans share one budget of 4096 addresses per sweep,
   and the platform scan is charged first. A customer scan that would exceed it is
   refused when saved, with the address count in the message.

## 1. Create the customer's SNMP profile

Go to Administration → Discovery → SNMP Profiles. As the platform owner, viewing as
the customer, create a profile such as "RETAIL-WALMART edges" with the community or
v3 user the edges accept. The profile belongs to the customer: the store records the
owner from the token, and the secret is sealed under that customer's key.

The same community may also sit in a platform profile. That does not matter, because
the customer's scan never tries platform profiles.

## 2. Create the customer's scan

Go to Network Scan → Scans for a customer → New. Choose RETAIL-WALMART, the profile
from step 1, and the management addresses, either as one `/32` each or as the range
that covers them. Then turn the scan on.

Over the API, as the platform owner:

```
POST /api/discovery/scopes
{"tenant_id": "<RETAIL id or slug>", "name": "RETAIL edges",
 "ranges": ["10.70.0.81/32", "..."], "credential_refs": ["<profile id>"], "enabled": true}
```

Saving starts a sweep. The usual 60-second cooldown between sweeps still applies.

## 3. Check that the customer scan found the devices (wait at least one 5-minute sweep)

- The scan reports 8 found, and each one is flagged **also found by the platform
  scan**: `GET /api/discovery/scopes/{id}` → `found[].also_found_by_platform: true`.
- As RETAIL, `GET /api/devices` lists each edge once. Record which case occurred:
  - **Names matched:** the SNMP sysName equals the vManage host-name, so the edge is
    merged with its vManage twin (`labels.sources = "snmp+api"`). The base record is
    the SNMP one, so the id is the customer's scan id.
  - **Names differ:** there are two RETAIL rows, the scan device and the controller
    device. Both belong to RETAIL.
- **Expected while both copies exist:** the edge's address and name are left out of
  `device_tenant.csv`, because an identity held by two owners is ambiguous. Traps,
  syslog and flows from the edge are attributed to **nobody** until step 4. The design
  fails closed here on purpose: telemetry goes unattributed rather than to the wrong
  owner. Each device id still attributes to its own owner. Keep this window short.

## 4. Retire the platform copy (D3: by hand)

1. Network Scan (the platform scan): remove the 8 addresses from its ranges and save.
   This step alone does not retire anything. A device outside the ranges is not
   measured, so it never ages out.
2. In the **Provider view**, delete each of the 8 platform rows with
   `DELETE /api/devices/{platform id}`. The delete leaves a tombstone stamped with the
   platform as owner. A customer scan device can only be suppressed by a tombstone of
   its own id stamped with its own tenant, so the RETAIL copies stay.

## 5. Let the exports catch up (about 1 minute)

- `device_tenant.csv` is rewritten and Vector reloads it when the file's mtime
  changes.
- The trap address index rebuilds on its ticker.
- The collector pool polls the RETAIL copies with the RETAIL profile, bound by
  `credential_ref`.

## 6. Verify

- The Provider view shows none of the 8. The RETAIL view shows all 8, with model,
  site and role set (`netops_inventory_facts{state="set"}`).
- A cEDGE-81 trap carries `device = <RETAIL id>`, `attribution_basis = interface_ip`
  (or `mgmt_ip`) and `tenant_id = <RETAIL>`.
- Flows and syslog from the edges carry RETAIL.
- New VictoriaMetrics series exist under the RETAIL ids. The old series stay under the
  platform ids and age out.
- The goal-2 checks in `scripts/lab/source_parity.py` pass.
- The customer's audit trail contains a `discovery_scope_create` row for the scan.

**What the operator sees:** the 8 edges leave the Provider's device list and appear
under RETAIL, already joined to their vManage records. The Provider keeps the old
incidents in its history. The first RETAIL RCA on an edge uses only evidence
collected after the move.

---

## Troubleshooting

| Symptom | Cause | What to do |
|---|---|---|
| The scan's status says "no SNMP profiles to try … (a customer's scan tries only that customer's own SNMP profiles)" | The customer owns no profile, or the scan names profiles that were deleted or belong to someone else | Create or restore the customer's own profile (step 1) |
| The status says "the scans together would probe more than 4096 addresses per sweep" | The shared budget is used up; the platform scan is charged first | Narrow the platform ranges or this scan's ranges |
| The status says "… is not private (RFC 1918) …" | A public range was given without acknowledgement | Narrow the range, or tick "allow non-private" only if the customer uses that space internally |
| Found 0, no error | Nothing answered with the customer's profiles, or the addresses already belong to this customer from another source (for example a manual device) | Check the community or v3 user on a device. A customer scan skips addresses the customer already has |
| The edges vanished from RETAIL after the scan was turned off or deleted | Expected: a customer with no scan left is not reported. The scan memory keeps the devices, so turning the scan back on restores them under the same ids | Turn the scan back on |
| `netops_discovery_cross_owner_refused_total` is rising | A source record carried an id another owner's device holds. This needs a hash collision or a stamping bug. The incumbent row was kept | Report it as a bug and collect the `discovery source snmp: refused a record …` log lines |
| `scanner_view_stale: true` in the scope list | The last reload of the stored scans failed. The previous set stays in force and a reload is retried every minute | Check the store (Postgres `discovery_scopes`, or the platform kv) |

Metrics: `netops_discovery_scope_found_devices{scope,state}`,
`netops_discovery_scope_refused{scope}`. The `scope` label is the scope id, never a
tenant id.
