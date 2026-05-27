# Ingestion guide

Everything coming *into* the platform from network devices flows through
two containers: **Vector** (Syslog + Docker container logs) and
**goflow2** (NetFlow / IPFIX / sFlow). Both ship to Loki. The
architecture follows the reference Collection / Ingestion Layer pattern.

```
   Routers / Switches / Firewalls
         │           │           │
      Syslog      NetFlow      sFlow
        514         2055        6343    (ports on the Docker host)
         │           │           │
         ▼           ▼           ▼
       ┌──────┐   ┌─────────────────┐
       │Vector│   │    goflow2      │
       │      │   │ (decodes flow   │
       │      │   │  protocols      │
       │      │   │  to JSON)       │
       └──┬───┘   └────────┬────────┘
          │                │ stdout (JSON)
          │ ┌──────────────┘
          │ │ docker_logs source
          ▼ ▼
       ┌────────────┐
       │   Loki     │   labels: job=logs|syslog|netflow
       └────────────┘
```

## Ports

| Protocol            | Container port | Host port (env)         | Standard |
|---------------------|---------------:|-------------------------|---------:|
| Syslog UDP/TCP      |           5514 | `SYSLOG_PORT` (5514)    |      514 |
| NetFlow v5/v9       |           2055 | `NETFLOW_PORT` (2055)   |     2055 |
| IPFIX               |           4739 | `IPFIX_PORT` (4739)     |     4739 |
| sFlow               |           6343 | `SFLOW_PORT` (6343)     |     6343 |

Linux with rootful Docker can bind 514 directly:

```
SYSLOG_PORT=514 docker compose up -d
```

On Docker Desktop / rootless / macOS, stick to 5514 and configure the
devices accordingly, or front the host with iptables / pf to redirect
514 → 5514.

## Device configuration examples

Replace `MONITOR_HOST` with the host running the Docker stack. Replace
`5514` / `2055` / `4739` / `6343` with whatever you set in `.env`.

### Cisco IOS / IOS-XE — Syslog

```
logging trap informational
logging source-interface Loopback0
logging host MONITOR_HOST transport udp port 5514
```

### Cisco IOS — NetFlow v9

```
flow exporter NETOPS
  destination MONITOR_HOST
  source Loopback0
  transport udp 2055
  template data timeout 60
  export-protocol netflow-v9

flow monitor NETOPS-FM
  exporter NETOPS
  record netflow ipv4 original-input

interface GigabitEthernet0/0
  ip flow monitor NETOPS-FM input
  ip flow monitor NETOPS-FM output
```

### Juniper Junos — Syslog

```
set system syslog host MONITOR_HOST any info
set system syslog host MONITOR_HOST port 5514
```

### Juniper Junos — IPFIX

```
set services flow-monitoring version-ipfix template IPFIX-T template-refresh-rate 30
set forwarding-options sampling instance NETOPS family inet output
  flow-server MONITOR_HOST port 4739 version-ipfix
```

### Arista EOS — sFlow

```
sflow source-interface Loopback0
sflow destination MONITOR_HOST 6343
sflow run
```

### Linux host — rsyslog forwarder

Add to `/etc/rsyslog.d/00-netops.conf`:

```
*.* @MONITOR_HOST:5514       # UDP
# or for TCP with reliable delivery:
*.* @@MONITOR_HOST:5514
```

Then `systemctl restart rsyslog`.

## Verifying ingestion

After devices start sending traffic:

```
# Syslog should show up in Loki under job=syslog
curl -G 'http://localhost:8000/api/logs/search' \
  --data-urlencode 'query={job="syslog"}' \
  --data-urlencode 'limit=20' | jq

# NetFlow records under job=netflow
curl -G 'http://localhost:8000/api/logs/search' \
  --data-urlencode 'query={job="netflow"}' \
  --data-urlencode 'limit=20' | jq

# What hosts are sending Syslog?
curl http://localhost:8000/api/logs/labels | jq
```

In the dashboard, the **Logs** tab takes the same LogQL queries:

```logql
{job="syslog"} |= "BGP-3-NOTIFICATION"
{job="netflow"} | json | dst_port=22         # SSH flows
{job="syslog", host="core-router-01"} | json
```

## Operational notes

* **UDP loss.** Syslog over UDP and NetFlow are unreliable by design.
  Vector buffers incoming syslog; if the device link is lossy or the host
  is loaded you'll see gaps. For Syslog, prefer TCP (`@@host:port` in
  rsyslog) when the device supports it.

* **High flow rates.** goflow2 in a single container is fine for tens of
  thousands of flows/sec. Beyond that, run multiple goflow2 instances
  behind a load balancer (or skip ahead to the Kafka phase).

* **Sampling.** NetFlow exporters typically subsample. The `sampling_rate`
  field is preserved in the JSON; aggregations should multiply by it to
  estimate the un-sampled volume.

* **Vector backpressure.** If Loki falls behind, Vector will reject new
  syslog packets at the UDP socket level. Watch `vector_buffer_*` and
  `vector_events_received_total` in Prometheus.

## Where this is going

This phase replaces Promtail with Vector and adds device-side ingestion.
The next steps in the reference architecture are:

1. **Kafka / Redpanda** between Vector and Loki/Victoria so producers and
   consumers decouple and replay becomes possible. goflow2 has a native
   Kafka transport; Vector has a Kafka sink. The change is mostly
   reconfiguration.
2. **OpenSearch** replacing Loki for true full-text search. Vector has an
   `elasticsearch` sink that targets OpenSearch unchanged.
3. **Correlation/AI service** consuming from Kafka to do anomaly
   detection and feeding back into the alert engine.

These are bigger lifts. Each is a follow-up phase.
