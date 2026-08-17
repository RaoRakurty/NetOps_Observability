# CORRELIX Network Digital Twin (tracker 152)

Labeled multi-tenant fault-scenario harness for the LIVE stack. Design:
[`docs/design/network-digital-twin.md`](../../../docs/design/network-digital-twin.md).
T1 core shipped the scenario DSL, bus-lane emitters (syslog/probes/cloud/
metrics), fault stories with machine-readable ground truth, the accuracy
scorer and the partition-spread proof. The **fidelity wave** adds the
protocol-faithful lanes and the `twinnet` source-IP overlay.

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
`spread-report.json`, `accuracy-report.{json,md}`.
