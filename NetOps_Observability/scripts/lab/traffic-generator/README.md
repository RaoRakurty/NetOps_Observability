# tgen — NetOps lab traffic generator

An Ostinato-style, stream-based traffic generator for the observability lab. It
**crafts traffic** two ways, selectable per run:

1. **Flow telemetry** (default, highest value) — emits RFC-correct **IPFIX
   (RFC 7011)**, **NetFlow v9 (RFC 3954)** and **sFlow v5** flow records straight
   to the collector (goflow2 on the NMS). This populates the platform's flow
   analytics (top talkers, by-app, by-proto, geo, TCP flags) with realistic
   **enterprise / SaaS / AI** application traffic — independent of whether the
   lab dataplane can sample (cEOS/SRL containers can't; see ROOT-CAUSE notes).

2. **Real packets** — crafts genuine TCP/UDP/ICMP/QUIC/HTTP(S) frames via raw
   sockets, batched with `sendmmsg` for high rate, so VM exporters (Cisco
   c8000v, FortiGate) sample real traffic.

Traffic is driven by an **application catalog** (`tgen/catalog.py`) modelling
real apps by destination prefix, L4 protocol, ports and byte/packet profile:
ChatGPT/OpenAI, GitHub Copilot, Claude/Anthropic, Microsoft 365 (Outlook,
SharePoint, OneDrive), Teams (signaling + UDP media), Zoom, Webex, Slack,
Google Workspace, Salesforce (CRM), Workday (HR), SAP SuccessFactors, Concur
(Travel), ServiceNow (ITSM), Jira, Box/Dropbox, DNS, NTP, generic HTTPS/QUIC.

## Performance model

Inspired by the DPDK userspace-datapath approach (toonk.io), but pragmatic for a
veth-based containerlab on a commodity VM (no PMD-bindable NICs):

- **Pluggable sender backend** (`tgen/sender.py`): `udp` (batched `sendmmsg`),
  `raw` (AF_PACKET), and a documented `dpdk` seam for line-rate on capable HW.
- **Batched syscalls** — records are packed and flushed with one `sendmmsg` per
  batch (hundreds of datagrams per call), not one `send` per record.
- **Multi-worker** — N processes fan out across cores; each owns a slice of the
  stream mix. Rate is token-bucket controlled per worker.
- **Pre-built templates** — IPFIX/NetFlow templates and packet skeletons are
  built once; only the per-flow fields are mutated in the hot loop.

## Run

```bash
# build + run as a container on the lab host (10.70.245.120)
./deploy.sh                         # builds image + runs against the NMS

# or directly
python3 -m tgen --collector 10.70.245.122 --mode ipfix --pps 5000 --duration 0
python3 -m tgen --mode netflow9 --apps ai,m365,zoom --workers 4
python3 -m tgen --mode packets --proto tcp,udp,icmp,quic   # real frames (needs CAP_NET_RAW)
```

See `config.yaml` for the declarative stream mix.

## Model lineage

- **Ostinato** — per-stream packet definition + rate control.
- **Ixia-C / OTG (Open Traffic Generator)** — the declarative *flow* model:
  a flow is `{endpoints, packet headers, rate, size, duration}`. `config.yaml`
  mirrors that shape so it reads like an OTG/snappi config. (If you'd rather run
  the real thing, Ixia-C drops into containerlab as `keysight_ixia-c-one`; this
  tool is the lightweight, app-aware, telemetry-emitting alternative.)
- **DPDK userspace datapath** (toonk.io) — the performance North Star: batched
  syscalls, pre-built templates, multi-core fan-out. True PMD line-rate needs
  bindable NICs (not veth), so the `dpdk` backend is a documented seam.
- **Python raw-socket crafting** (the precision-packets approach) — `packets.py`.
