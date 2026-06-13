# Telemetry Catalog — the load-bearing replacement for MIB templates

A source-agnostic, **validated-fidelity** catalog of how this product collects and
normalizes telemetry across vendors/platforms/versions. The governing principle:

> **Validated fidelity is the product truth — not vendor documentation.**
> A path that exists in a vendor model but doesn't actually stream is *worse* than
> no path: it reads as covered and fails silently. So no row is "supported" until
> a captured fixture proves it normalizes correctly.

## The three catalogs + shared identity

| File | Role |
|------|------|
| `identity.yaml` | **Shared identity model** — canonical entity keys (device, ifName, vrf, peer, …) + the raw per-vendor aliases that reconcile to them, so metrics + events + flows join on the same identity. |
| `collection.yaml` | **Collection catalog** — `(vendor, platform, os_version, signal_family, method, path/OID/API, mode, interval)` → **fidelity_status**, last_validated, fixture, cost. |
| `normalization.yaml` | **Normalization catalog** — raw → canonical `device_*` (path match, enum map, unit, label set, **owner transport**, dedup key). Applied by `normalize.py` (code-owned, tested) — NOT buried in gnmic YAML. |
| `events.yaml` | **Event/parser catalog** — syslog/trap/API grammars → canonical event schema (Phase 2). |

## Fidelity ladder (collection.yaml `fidelity_status`)

`doc_claimed` → `lab_validated` → `live_validated` → `degraded` → `failed`

- **doc_claimed** — a reference says it exists; untested. *Candidate, not supported.*
- **lab_validated** — a captured fixture replays to correct canonical output in CI.
- **live_validated** — confirmed flowing end-to-end on the live lab.
- **degraded** — works in some conditions, fails in others (must carry `issue_ref`).
- **failed** — claimed by docs but proven not to work (must carry `issue_ref`).

Only `lab_validated` / `live_validated` may be advertised as supported.
**See the `arista/ceos … device_bgp_peer_state … degraded` row** (`ceos-bgp-gnmi-issue.md`)
— established BGP not delivered under a persistent multi-target subscription. That
row is exactly why this catalog exists.

## Tooling

```bash
cd telemetry-catalog
python3 catalog.py          # invariant check (fidelity ladder, owner collisions, fixtures exist)
python3 conformance.py      # replay validated fixtures through normalize.py, assert canonical output
python3 -m pytest -q        # invariants + conformance + explicit canonical anchors
```

`conformance.py` is the gNMI analogue of LibreNMS `.snmprec` replay: capture real
subscribe streams (`fixtures/*.jsonl`), replay through the engine, assert the
contract. This is how a `doc_claimed` row earns promotion to `lab_validated`, and
the regression guard that keeps the catalog honest.

## Phasing

- **Phase 1 (done)** — schema + harness + 3 validated families: interfaces (oper/admin status), BGP peer-state, memory.
- **Phase 2** — event/parser catalog (BGP/OSPF adjchange, link-state, firewall fw_event).
- **Phase 3** — import P1–P5 research rows as `doc_claimed` candidates (OSPF/ISIS/BFD/MPLS/LDP/IPsec/QoS/SD-WAN/firewall).
- **Phase 4** — validate vendor-by-vendor; promote rows to `lab_validated`.

## Relationship to the runtime

The gnmic canonical lane (`deployment/docker/gnmic/gnmic.yaml`) is a *derived
runtime applier* of these same rules. `scripts/audit_metric_contract.py` already
checks the gnmic lane against the emitted contract; the catalog is the authoritative
spec it must agree with. Capturing fixtures: `gnmic ... subscribe --format event`.
