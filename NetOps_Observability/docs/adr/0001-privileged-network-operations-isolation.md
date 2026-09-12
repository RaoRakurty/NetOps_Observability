# ADR 0001 — Privileged Network Operations Isolation

- Status: **Accepted** (2026-06-10)
- Context: active measurement (STAMP, traceroute) and future diagnostics need
  elevated Linux capabilities (raw sockets, etc.). Where should that privilege
  live?

## Decision

- The **API service SHALL remain unprivileged.**
- Features requiring `CAP_NET_RAW`, `CAP_NET_BIND_SERVICE`, `CAP_BPF`, or other
  elevated capabilities **SHALL execute in dedicated worker/prober services**,
  not in the API container.
- Workers communicate with the rest of the platform through **Redis, NATS,
  Kafka, or other internal messaging/storage mechanisms** — never shared
  in-process state with the API.
- Privileged services are **disabled by default**.
- Capabilities are **granted only to the specific service requiring them**
  (`cap_drop: [ALL]` + the single `cap_add` it needs).

## Rationale

- **Least privilege** — the large, internet-adjacent, auth-bearing API keeps the
  default (reduced) capability set.
- **Reduced blast radius** — a compromise of a prober yields raw-socket access in
  a minimal container, not the API's data/credentials.
- **Multi-tenant SaaS readiness** — privileged blast radius is a recurring
  question for tenant isolation; isolating it answers it once.
- **Easier SOC2 / security reviews** — "which service can do X" has a crisp,
  per-service answer.
- **Future advanced diagnostics** — eBPF, packet capture, synthetic agents slot
  in as additional privileged workers without touching the API.

## Consequences

- Probers/workers communicate results out-of-band. For the traceroute path
  topology: the prober publishes to **Redis** (`netops:probe:paths`, JSON, TTL);
  the API reads it for `GET /api/probe/paths`. Metrics (STAMP/traceroute
  `probe_*`) flow independently to VictoriaMetrics.
- One image, multiple roles: the same backend binary runs as the API or, with
  `PROBER_ONLY=true`, as the prober (only the probe collectors; no HTTP/DB/auth).
- Slightly more deployment surface (an extra compose service) — accepted for the
  security posture.

## The network diagnostics plane (direction)

The prober is the **first member of a future diagnostics plane**. As Correlix
grows, privileged/active collectors fan into a correlation layer rather than the
API:

```
SNMP · Flows · Traceroute · STAMP · OTel
                 ↓ (Redis / NATS / Kafka)
          Correlation Engine
                 ↓
           Topology Graph
                 ↓
                API
```

This ages better than attaching more capabilities to the API container, and it
is the structural home for the app's end goal: observability + correlation for
root-cause across application and underlying network.

See [[active-measurement]] · [[metrics-standards]].
