# mock-nms — vManage stand-in for the NMS integration cycle (#95)

A stdlib-only Cisco Catalyst SD-WAN Manager (vManage) API stub that lets you
exercise the WHOLE controller-intelligence cycle — auth → poll → transform →
route → VictoriaMetrics / `netops.controller_events` / state table → RCA
signals → UI — with **no real controller**.

## Run it

```bash
cd deployment/docker
docker compose --profile mock-nms up -d --build mock-nms
```

Then in the UI (Infrastructure → NMS Integrations) connect a **vManage /
Catalyst SD-WAN Manager** integration:

| Field    | Value                                          |
|----------|------------------------------------------------|
| Base URL | `http://mock-nms:8091`                         |
| Username | `correlix` (env `MOCK_NMS_USER`)               |
| Password | `correlix-mock-secret` (env `MOCK_NMS_PASSWORD`) |
| Streams  | `alarms`, `statistics` (others serve empty)    |

Requires `FEATURE_NMS_INTEGRATIONS=true` on the api service.

## What it simulates

- **JWT auth** (`POST /jwt/login`) — wrong creds → 401; polls without the
  Bearer → 401 (exercises the runtime's re-auth path).
- **A flapping BFD session** — down ≈90s / up ≈90s, new alarm uuid per
  transition: each phase change is a fresh controller EVENT + a state
  TRANSITION (watch `flap_count` grow in the integration's States view), while
  steady-state polls are deduped.
- **Approute metrics** (`/dataservice/statistics/approute`) — four tunnels with
  smoothly jittering latency/jitter/loss/QoE; the mpls tunnel's loss spikes
  during the BFD-down phase, so the metric lane visibly corroborates the event
  lane.

## Watch it

```bash
curl -s http://localhost:8098/inspect | jq   # logins/polls served + current flap phase
```

Restarting the container does NOT reset the flap phase (wall-clock keyed).
