# Tracker 168 — a device-local name is not a global correlation identity

**Date:** 2026-08-21 · **Branch:** `feat/observability-platform`
**Status:** **FIXED and qualified offline.** Live 1K re-run pending (that is tracker 166 Phase 10).

> **The rule.** Identity establishes **sameness**. Topology establishes
> **relationships between different entities**. Accidental string equality is
> neither. An identifier that is unique only *within* a device must never become
> a globally meaningful correlation identity on its own.

---

## The defect

An interface name is unique only within its device. Producers emitted the bare
name as an `entity_token`, and `Node.tokens()` treats every `entity_token` as a
grounding subject. So `GigabitEthernet0/5` — a string that exists on essentially
every switch in an estate — became a global rank-7 correlation subject.

A rank-7 shared-token pair is admitted when `w_t · w_topo_candidate · w_r ≥
attach_threshold`, i.e. `exp(-gap/300) · 0.5 ≥ 0.3`, i.e. **any gap ≤ 300·ln(1/0.6)
= 153 s**. Two same-named interfaces anywhere in the estate flapping within 153 s
of each other therefore admitted an edge.

Reproduced end to end, before the fix:

```
entity_id='dc1-switch-a:GigabitEthernet0/5'   tokens=('dc1-switch-a', 'GigabitEthernet0/5')
entity_id='branch-77-rtr:GigabitEthernet0/5'  tokens=('branch-77-rtr', 'GigabitEthernet0/5')

objects formed: 1
  EDGE interface:dc1-switch-a:GigabitEthernet0/5:link_state_change
    -> interface:branch-77-rtr:GigabitEthernet0/5:link_state_change
       grounding=topo:shared:GigabitEthernet0/5  rank=7  weight=0.452  (threshold 0.3)
  verdict=suspected
```

The §3/§4 gate correctly caps such an object at `suspected` — no false CONFIRMED
RCA was ever possible. **The evidence graph was still wrong**, and at estate
scale the consequence is not subtle.

### This is the third instance of a weld class the codebase already knows

`Node.tokens()` already refuses two other coincidence surfaces, for exactly this
reason: the measuring **vantage** (an observer probing two destinations does not
relate them) and a cloud **region/site** (two unrelated resources in one region
are not related). `device_part()` records a third, "#99": `ap:<id>` would have
grounded every access point in the estate to the literal token `ap`. The bare
interface name is the same class, missed.

---

## Phase 1 — the identity map

Every path that mints an interface identity, and what it emitted:

| Source | Site | Device identity | Interface identity | `entity_tokens` **before** | **after** |
|---|---|---|---|---|---|
| syslog link up/down | `producers.py:520` | `hostname` (registry-anchored) | `_IF_RE` from the message | `(host, ifname)` | `(host,)` |
| syslog LLDP neighbour | `producers.py:548` | `hostname` | message | `(host, ifname)` | `(host,)` |
| syslog STP topology | `producers.py:578` | `hostname` | message | `(host, ifname)` | `(host,)` |
| syslog device alarm (iface-scoped) | `producers.py:717` | `hostname` | message | `(host, ifname)` | `(host,)` |
| SNMP trap linkDown/Up | `producers.py:845` | G2-attributed inventory id | `_trap_interface`: ifName → ifDescr → ifIndex | `(device, iface)` | `(device,)` |
| SNMP trap generic link | `producers.py:912` | as above | as above | `(device, iface)` | `(device,)` |
| SNMP trap alarm (iface-scoped) | `producers.py:936` | as above | as above | `(device, iface)` | `(device,)` |
| syslog port/optics event | `producers.py:1077` | `hostname` | parsed port | `(host, port)` | `(host,)` |
| **SNMP polling + gNMI** (both arrive as MetricEvents) | `main.py:5409` | `device` | `if_name` → `index` (ifIndex) | `(device, iface)` | `(device,)` |
| syslog FHRP state change | `producers.py:651` | `hostname` | message (DEVICE-scoped signal) | `(host, ifname, grpN)` | `(host, host:ifname, host:grpN)` |
| syslog MAC flap | `producers.py:684` | `hostname` | ports (DEVICE-scoped signal) | `(host, mac, vlanN, portA, portB)` | `(host, mac, host:vlanN, host:portA, host:portB)` |

In every case `entity_id` was **already** the qualified `device:ifname`, so on an
interface-scoped signal the bare name was pure redundancy — and pure risk.
`attrs["interface"]` still carries the raw local name, so search and the UI are
unchanged.

---

## The fix — two layers, both load-bearing

**Layer 1 — producers stop emitting device-local names as global tokens.**
On an interface-scoped signal the bare name is dropped (`entity_id` carries it).
On a device-scoped signal that legitimately points *at* a local component (FHRP,
MAC-flap), the name is **qualified** by `_device_local(device, *names)` →
`device:name`, which preserves the intended binding to that device's own
interface node and removes the cross-device weld.

**Layer 2 — a structural backstop in `Node.tokens()`.** On a device-scoped id
(`device:component`), the bare `component` can never be a grounding subject,
whatever a producer emits. This sits beside the existing observer and cloud-site
exclusions and is what makes a future producer regression harmless.

Genuinely global identifiers are deliberately left bare: a **MAC address** and a
**peer/VTEP IP** are real global subjects, and two devices sharing one really are
related.

### Intentional semantic deltas (Phase 8)

Four existing tests asserted the old tokens. They encoded the defect, so they were
updated to enforce the corrected contract rather than the bug — each with the
reasoning inline:

* `test_metric_intake.py::test_interface_identity` — `Ethernet1` is no longer a token.
* `test_producers.py::test_hsrp_statechange_to_active_is_failover` — `Vlan10`/`grp1` → `dist-sw1:Vlan10`/`dist-sw1:grp1`. **Two routers in one real FHRP group must now relate through topology, not through a shared group number.**
* `test_producers.py::test_macflap_notif_ios` — MAC stays bare; VLAN and ports qualified.
* `test_producers.py::test_generic_alarm_interface_scoped_when_named` — `Ethernet5` is no longer a token.

Everything else is reference-equivalent: **1410 passed, 9 skipped** (1385 before
this wave), ruff / mypy / bandit clean.

---

## Phase 4/5 — the semantic test matrix

`test_local_identity_scope_168.py`, 25 tests:

| | |
|---|---|
| **A** same name, different devices | no correlation, no edge, two objects — the exact prior reproduction is now a regression test; asserted on the identity model *and* the outcome; across syslog, trap **and** the metric path; over 7 interface forms (physical, subinterface, Port-channel, Loopback, Management, `eth0`, `xe-0/0/0`) |
| **B** same device, same interface, 3 modalities | syslog + SNMP trap + metric all converge on `dc1-switch-a:GigabitEthernet0/5`, stay one object, and now relate on an **authoritative rank-1** edge (weight 1.000) instead of the rank-7 name coincidence |
| **C** topology peers | `sw1/Gi0/5 ↔ sw2/Gi0/5` = 2 objects without topology, **1 object with an `adj:` edge** when the link is in the inventory — and it relates just as well when the two interfaces have *different* names |
| **D** tenant isolation | a mixed-tenant window is refused structurally |
| **E** other token classes | FHRP group, MAC-flap VLAN/ports covered; global identifiers verified untouched |

**Mutants, all killed behaviourally:**

1. producer regresses to the bare `ifname` → the engine backstop still refuses it, and the two devices still do not weld;
2. remove the device component from the identity → the two nodes genuinely collide (proving the device component is what carries the separation);
4. cross-tenant → refused structurally;
7. over-reach control → if the filter stripped *every* shared token, the legitimate MAC and peer-IP relations would vanish; they must not, and do not;
   plus a precision control (an unrelated token is not stripped) and a path/segment control (`a->b` ids have no local component and are left alone).

---

## Phase 6 — the full token audit

Every classifier driven with the same event on two unrelated devices; the table
is what the **engine** would actually treat as a shared grounding subject:

| producer | shared between two unrelated devices | classification |
|---|---|---|
| `link_state_change` | (none) | device-scoped ✔ |
| `lldp_neighbor_change` | (none) | device-scoped ✔ |
| `stp_topology_change` | (none) | device-scoped ✔ |
| `fhrp_state_change` | (none) | device-scoped ✔ (was `grp1` + ifname) |
| `mac_flap` | `aabb.ccdd.eeff` | **globally unique — correct relation** |
| `evpn_mac_move` | `aabb.ccdd.eeff` | **globally unique — correct relation** |
| `vtep_state_change` | `10.1.1.1` | globally unique (peer VTEP) ✔ |
| `isis_adjacency_change` | (none) | device-scoped ✔ |
| `bgp_adjacency_change` | `10.3.3.3` | globally unique (peer address) ✔ |
| `device_alarm` | (none) | device-scoped ✔ |
| SNMP trap link | (none) | device-scoped ✔ |
| metric: interface | (none) | device-scoped ✔ |
| metric: bgp | `10.3.3.3` | globally unique ✔ |
| metric: device_resource | (none) | device-scoped ✔ |

**No welds remain.**

### Adjacent risks recorded, not changed

* **ifIndex vs ifName.** `metric_identity` uses `if_name` **or** `index`, so a
  poller that reports only ifIndex mints `device:105`, which will not converge
  with syslog's `device:GigabitEthernet0/5`. This is a *canonicalisation gap*,
  not a weld — it under-correlates rather than over-correlates, and closing it
  needs discovery's ifIndex→ifName map. **Not fixed here; worth its own row.**
* **VRF / routing-process / tunnel / circuit names** appear in `attrs` on the
  paths reviewed, not in `entity_tokens`, so they are not currently grounding
  subjects. If any future producer promotes one, the Layer-2 backstop only helps
  when the value is the node's own local component — a VRF name on a
  device-scoped node would not be caught. Flagged.

---

## Phase 7 — candidate density, same deterministic 1K pattern

1,000 devices × 48 interfaces = 48,000 nodes, 5,000-node cohort. "regressed
producer" re-adds the bare token to prove the backstop is real:

| | PRE-168 | POST-168 | regressed producer |
|---|---:|---:|---:|
| candidate-index groups | 1,048 | 1,000 | 1,000 |
| **largest group** | **1,000** | **48** | 48 |
| **Σ C(g,2) over groups** | **25,104,000** | **1,128,000** | 1,128,000 |
| **candidates / 5K cohort** | **4,854,740** | **117,660** | 117,660 |
| candidates / signal | 970.9 | **23.5** | 23.5 |
| emission time | 2.86 s | **0.05 s** | 0.09 s |
| `prepare_window` | 1.08 s | 1.14 s | 1.33 s |
| **modelled scoring @ 30 µs/cand** | **145.6 s** | **3.5 s** | 3.5 s |
| modelled scoring @ 70 µs/cand | 339.8 s | 8.2 s | 8.2 s |

Group sizes went from **`[1000, 1000, 1000, 1000, 1000, 1000, …]`** to
**`[48, 48, 48, 48, 48, 48, …]`** — the 48 estate-wide interface-name groups are
gone, and what remains is 1,000 per-device containment groups, which is exactly
right.

**Σ C(g,2) −95.51 % · candidates per cohort −97.58 %.**
**Backstop check: a producer regression produces results identical to POST.**

---

## Phase 7/9 — RCA objects, affected set, carried edges

Run through the real engine (150 devices × 12 interfaces = 1,800 independent,
device-local flaps):

| | PRE-168 | POST-168 |
|---|---:|---:|
| **RCA objects formed** | **1** | **150** |
| **admitted edges** (the carried-edge input) | **144,000** | **9,900** |
| largest object | **1,800 nodes** | 12 nodes |
| **most devices fused into one object** | **150** | **1** |
| objects spanning >1 device | 1 | **0** |
| `run_window` wall | 4.48 s | 3.34 s |

**Ground truth: every flap is independent and device-local, so the correct answer
for "most devices fused into one object" is 1.**

Pre-168 the engine collapsed **the entire estate into a single RCA object**. That
is the honest characterisation of the defect: not noise at the margin, but a
graph in which 150 unrelated devices were one incident. `affected()` on that
object named every device in the estate.

Carried-edge input fell **144,000 → 9,900 (−93.1 %)**, which is the direct
explanation for the ~384 k carried-edge plateau observed in the failed 166 run.

---

## What this means for the other trackers

* **All pre-168 capacity numbers are contaminated** and are retained, as
  instructed, as `PRE-168 CHARACTERIZATION` — a legitimate pathological
  high-density data point, not a capacity claim. That includes the ~800–1,000
  signals/s ceiling, the ~384 k carried-edge plateau, and the 1.25 GiB memory
  qualification.
* **Tracker 166's epoch work is retroactively more valuable, not less.** With
  scoring modelled at ~3.5 s instead of ~145.6 s, the ~1.1 s snapshot preparation
  is no longer 1 % of the cycle — it is a comparable term. Hoisting it from K× to
  1× per epoch now matters materially.
* **The 1,280 MiB planner floor is NOT changed.** It remains the qualified
  conservative floor until post-168 sizing evidence justifies revisiting it.
