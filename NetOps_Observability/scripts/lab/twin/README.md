# CORRELIX Network Digital Twin (tracker 152)

Labeled multi-tenant fault-scenario harness for the LIVE stack. Design:
[`docs/design/network-digital-twin.md`](../../../docs/design/network-digital-twin.md).
T1 core shipped the scenario DSL, bus-lane emitters (syslog/probes/cloud/
metrics), fault stories with machine-readable ground truth, the accuracy
scorer and the partition-spread proof. The **fidelity wave** adds the
protocol-faithful lanes and the `twinnet` source-IP overlay; the **gNMI
stretch** (§4.6) adds twin-served gNMI targets so the platform's
`ENABLE_GNMI_COLLECTION` path gets labelled-fault coverage.

```
twin.py run      --scenario FILE [--duration-minutes N] [--fidelity hostname|source_ip]
                 [--dry-run] [--keep] [--force]
twin.py score    --runid X
twin.py teardown --runid X
```

Example scenarios: `docs/design/examples/twin-scenario-example.yaml` (T1 core,
DX seam + negative control) and `twin-scenario-fidelity.yaml` (trap + NetFlow
lanes).

## Fidelity modes (design §3.4)

| | `hostname` (default) | `source_ip` |
|---|---|---|
| needs | nothing beyond the stack | the twin overlay (below) |
| syslog/probes/cloud/metrics | bus-direct, per-NAME registry attribution | same (unchanged) |
| SNMP traps | host → published `:162`; attribution = community + sysName varbind (`trapIdentityTrusted`) | per-device 198.19.x source IPs → api's twinnet address `:1162`; source-IP attribution |
| NetFlow/IPFIX | **skipped loudly** (a host-sourced flow can never attribute) | per-device `sampler_address` → goflow2's twinnet address; `flows_rekey` tenant attribution |
| snmpsim agents | started if the overlay is up (best-effort) | started (same) |

Trap stories (`device_restart`, `with_trap: true`) refuse to run when
`FEATURE_SNMP_TRAPS` is not `true` in the stack `.env` (the receiver is
dormant by default; enable it with `FEATURE_SNMP_TRAPS=true` + recreate the
api container). `--force` overrides — the traps then vanish, counted as sent.

## The twin overlay

```bash
cd deployment/docker
docker compose -f docker-compose.yml -f docker-compose.twin.yml up -d --build twin
# TLS stacks: insert compose.tls.yml before the twin overlay, same as .env's COMPOSE_FILE
```

One lab container (`netops-twin-1`, image built from `docker/Dockerfile`,
pinned deps in `docker/requirements.txt` — never in the product graph) plays
two roles:

* **snmpsim fleet** — `snmpsim_supervisor.py` (PID 1) watches
  `data/twin/agents/manifest.json` (written by `twin.py` from the scenario via
  `snmpsim_gen.py`) and runs one pinned `snmpsim-command-responder` per device
  on the device's 198.19.x.y twinnet alias: sysName/sysDescr + full
  ifTable/ifXTable from the scenario's `interfaces[]`; v2c community from the
  device's `snmp.community`, v3 authPriv USM creds + deterministic engine-id
  from `snmp.usm` (defaults are derived and recorded in the manifest).
* **UDP emitter agent** — `udp_agent.py` via `docker exec`: per-device /32
  aliases + source-bound trap/NetFlow datagrams (`--fidelity source_ip`).

`twinnet` is 198.19.0.0/16 (RFC 2544 space, disjoint from the mini-ladder's
198.18.x.y); docker IPAM is confined to 198.19.255.0/24 so device aliases
never collide. In `source_ip` mode `twin.py` HOT-attaches the intake
containers with `docker network connect <project>_twinnet` (api for traps,
goflow2 for flows) — restart-free, recorded in `state.json`, detached at
teardown. No product service definition changes, ever (design R-4).

Overlay teardown (after `twin.py teardown` has detached the intakes):

```bash
docker compose -f docker-compose.yml -f docker-compose.twin.yml stop twin
docker compose -f docker-compose.yml -f docker-compose.twin.yml rm -f twin
docker network rm netops_twinnet
```

## Operator runbook — pointing the REAL SNMP discovery/pollers at the agents

The twin never changes product defaults; both flows are per-install operator
actions through the platform-owner API/console:

1. **Agents up**: run a scenario with the overlay up (`--keep` keeps agents
   standing), or write a manifest with `snmpsim_gen.generate_agents` for a
   standalone fleet. Verify: `docker logs netops-twin-1` shows
   `generation …: N agents running`.
2. **Reach the agents**: attach the api container to twinnet —
   `docker network connect netops_twinnet <api-container>` (hot; reverse with
   `disconnect`). `twin.py --fidelity source_ip` does this for you.
3. **Discovery** (`PUT /api/discovery/config`, platform-owner): ranges must be
   narrow (≤ 4096 hosts) and 198.19.x is non-RFC1918, so acknowledge it:
   `{"enabled": true, "ranges": ["198.19.0.0/28"], "allow_non_private": true,
   "community": "public"}`. The sweep (≤ every 60 s) probes sysName/sysDescr
   and files scan devices named after the agents' sysName. Note: discovery
   SKIPS addresses already in inventory — twin-REGISTERED devices won't be
   re-discovered; use a standalone (unregistered) agent fleet to exercise it.
4. **Polling** (`ENABLE_SNMP_COLLECTION=true`, default on): pollers poll every
   registered device address with the device's credential profile (v2c
   community or v3 USM — create a profile matching the scenario's `snmp:`
   block / the manifest's derived USM creds and bind it via `credential_ref`).
   Unbound devices fall back to `SNMP_COMMUNITY` (default `public`).
   **v3 note**: snmpsim selects the data file by v3 CONTEXT NAME, so a v3
   credential profile for twin agents must set `context` to the device's
   data-file name (its `snmp.community`, default `public`) — empty-context v3
   requests go unanswered (verified live against snmpsim-lextudio 1.1.1).
5. **Cleanup**: `twin.py teardown --runid X` stops agents + detaches intakes;
   delete any scan devices discovery created; disable/narrow the discovery
   config again.

## gNMI targets (design §4.6)

The twin serves gNMI itself — a **minimal OpenConfig fake**, not a general gNMI
stack. `gnmi_server.py` binds one listener per device (`57400 + index`) and
speaks Capabilities / Get / Subscribe over a stdlib gRPC-on-HTTP/2 stack
(`gnmi_proto.py` protobuf, `gnmi_hpack.py` HPACK, `gnmi_h2.py` framing) — **no
new wheel in the twin image**; `docker/requirements.txt` is unchanged.

It serves exactly the leaves `deployment/docker/gnmic/gnmic.yaml` subscribes
to on its OpenConfig targets, with the enum spellings the canonical lane's
processors expect:

| subscription | paths | mode |
|---|---|---|
| `oc-interfaces` | `/interfaces/interface/state/counters/*`, `…/oper-status`, `…/admin-status` | SAMPLE 30 s |
| `oc-bgp` | `…/bgp/neighbors/neighbor/state/session-state`, `…/established-transitions`, `…/afi-safis/afi-safi/state/prefixes/received` | ON_CHANGE + 30 s heartbeat |

The server runs as a HOST process started by `twin.py` — a flagged deviation
from design §4.6's "whatever serves gNMI lives in the twin container". The
boundary that clause protects is "not in a product service", which holds
either way; and because this target needs no dependency, it needs no image, so
the gNMI lane works with no twin overlay container at all (unlike the snmpsim
fleet, which needs the image's pinned wheels). One code path, and it is the
one proven end-to-end.

**Identity**: gnmic labels every sample `source: <target name>`, so a twin
device's gNMI identity is its run-prefixed TARGET NAME (`twx-<runid>-<device>`),
not its address — which is what carries through to `source`/`device` in
VictoriaMetrics and makes teardown-by-prefix work.

**Faults**: `link_down_cascade` with `params: {with_gnmi: true}` also moves the
gNMI state — `oper-status UP→DOWN` + that port's counters stall, and every
declared BGP session goes `ESTABLISHED→IDLE` — at the same instants and under
the same `story_id` as the syslog/trap manifestations. The ops are appended to
`<run>/gnmi-faults.jsonl`, which the target server tails; the manifestation
table (device, path, before→after, canonical series) rides into
`ground_truth.jsonl` as `labels.gnmi_manifestations`. No target running ⇒ the
lane SKIPS LOUDLY into `skipped_by_lane`, exactly like trap/flows.

**Wiring gnmic to the twin** (gnmic has no dynamic target discovery in our
pinned config, so the merge is manual — design §4.6):

1. `twin.py run` renders `<run>/gnmi/gnmic-targets.yaml`, addressed at the
   `<project>_netops` bridge gateway (a container on the stack network reaches
   the host there; `127.0.0.1` would resolve to gnmic's own container).
2. Merge those rows under `targets:` in `deployment/docker/gnmic/gnmic.yaml`
   and restart gnmic — a PRODUCT service recreate, so it is an explicit
   operator step, never something the twin does.
3. Remove the rows at teardown: they name run-scoped `twx-` devices.

**Where the evidence lands** (verified live, gnmic 0.46.0 → vmauth →
VictoriaMetrics):

* raw lane (`metric-prefix: gnmi`) — `gnmi_interfaces_interface_state_counters_*`
  with `source=twx-…`; the counter stall reads as `rate(...) == 0`;
* canonical lane — `device_bgp_peer_state{device=twx-…,peer=…,transport="gnmi"}`
  `6 → 1`, plus `device_bgp_fsm_transitions`;
* **oper-status lands in NEITHER**, by current platform configuration, not by
  twin limitation: the raw lane's `prometheus_write` drops non-numeric values
  (the OpenConfig enum is the string `"DOWN"`), and the canonical lane maps it
  to a number but then deletes the whole `device_if_*` family in the
  `ownership-gate` processor, because interfaces are SNMP-owned today. Flipping
  interface ownership to gNMI (gnmic.yaml's documented procedure) is what would
  surface it.

Standalone (without a twin run):

```bash
python3 scripts/lab/twin/gnmi_server.py --manifest <run>/gnmi/manifest.json \
    --fault-journal /tmp/faults.jsonl --ready-file /tmp/gnmi-ready.json
echo '{"device":"twx-…-edge-a1","op":"if_down","ifname":"Ethernet1"}' \
    >> /tmp/faults.jsonl
```

## Mini-ladder composition (design §8.3)

```bash
python3 scripts/scale-miniladder.py --load-generator twin \
    --twin-scenario docs/design/examples/twin-scenario-fidelity.yaml \
    --twin-duration-minutes 5 [--twin-fidelity source_ip]
```

The ladder keeps every verdict (preflight / onboard-linearity / drain /
accounting / memflat / cleanup); the burst phase delegates emission to
`twin.py run --keep`, feeds accounting from `twin-report.json`
(`emitted_by_lane.syslog` + the canary) under the twin's `twx-` namespace, and
cleanup tears the twin run down through its own verified teardown. The default
(`--load-generator internal`) path is untouched.

## Outputs

Per run dir (`data/twin/<ts>-<runid>/`): `events.jsonl` (journal, all lanes),
`ground_truth.jsonl`, `twin-report.json` (per-lane emitted AND
`skipped_by_lane` — undeliverable lanes are counted, never silent),
`spread-report.json`, `accuracy-report.{json,md}`, and — when the scenario
uses the gNMI lane — `gnmi/manifest.json`, `gnmi/gnmic-targets.yaml`,
`gnmi-faults.jsonl` (the applied fault ops) and `gnmi-target.log`.
