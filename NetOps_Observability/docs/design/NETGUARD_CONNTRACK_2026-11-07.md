# Netguard — automatic stale-conntrack remedy (tracker 373 remainder)

Status: **PLAN, awaiting owner decisions D1–D6** (2026-11-07). Research: Fable
`researcher`; premises re-verified in the main session where marked ✔.

## Problem

After a container recreate, a chatty fixed-source-port UDP sender (traps :162,
syslog :514, NetFlow/IPFIX/sFlow) can keep a conntrack entry created while
Docker's DNAT rule was absent. Its packets then bypass DNAT, land on
docker-proxy and arrive re-sourced from the bridge gateway, so attribution
breaks. Already shipped: host port == container port (#126), masked-source
detection + `IngestSenderAddressMasked` (#127), helm `externalTrafficPolicy:
Local` (8727b881 ✔). Port parity closes the deploy-time window but not the
ones Correlix never sees: firewall reloads (`prepare-host.sh` installs ufw),
dockerd restarts, operator overrides, future engine behaviour
(`src/config/rules.yaml` alert comment admits residual leaks).

Facts: a stale entry is UDP, orig-dst = a host address on a published port,
**no DST_NAT status, reply-src = the host address** (not the gateway — the
gateway is docker-proxy's harmless second leg). Healthy = DST_NAT set, reply-src
= container IP. Reading conntrack also needs `CAP_NET_ADMIN`, so no unprivileged
host process can even look. `install_doctor` has no Docker-29.5 check ✔.

## Design

1. **Where.** A one-shot `netguard` container, never long-running: Go binary
   `/netguard` in the backend image; compose service with
   `profiles: [netguard]`, `network_mode: host`, `cap_drop: [ALL]`,
   `cap_add: [NET_ADMIN]`, `read_only`, `no-new-privileges`, `restart: "no"`,
   mem/pids limits, no volumes/ports/secrets/docker.sock. Invoked as
   `cd $COMPOSE_DIR && timeout 60 docker compose run --rm --no-deps -T netguard`.
   Rejected: conntrack-tools on the host (installer runs as docker-group user,
   offline appliances, GPL-2.0 mirror duty); a privileged sidecar (24/7
   NET_ADMIN on host netns, violates ADR 0001); flushing from the detector
   (api must stay unprivileged, §3).
2. **What is deleted.** IPv4 UDP; orig-dst-port ∈ the project's published
   UDP ports (host==container, ≤32, derived from `docker ps` labels);
   orig-dst-IP a local non-loopback address; orig-src not loopback;
   `status & IPS_DST_NAT == 0` and reply-src == orig-dst. Healthy flows are only
   counted; IPv6 never touched.
3. **How.** Stdlib `syscall` netlink (no §6 change): `IPCTNL_MSG_CT_GET`
   dump → streamed filter (≤10k candidates) → `IPCTNL_MSG_CT_DELETE` with
   `CTA_TUPLE_ORIG` + `CTA_ID` (exact entry; ENOENT = already gone).
   Rescan after ~3 s: stale again on the same port ⇒ DNAT missing ⇒
   `recurring`. Kernel replies only from pid 0 + matching seq, every NLA
   length bounds-checked, byte/message caps, `SO_RCVTIMEO`. CTA_*/IPS_* values
   verified against the uapi headers. Output: one JSON line of counts
   (device IPs only with `--verbose`); exit 0 clean · 10 fixed · 20 recurring
   · 1 error · 2 usage; modes `--check` / `--flush`.
4. **When.** Event-driven after the health gate in `deploy.sh`,
   `install-correlix.sh` (install/start/upgrade), `install.py`, and as a
   `deploy-qualify.sh` check (`--flush` then `--check` must be stale=0).
   Plus an installer-managed user-crontab sweep (the `TLS_CRON_MARK`
   mechanism) for firewall reloads / dockerd restarts — a deliberate §16.4
   exception (no Docker event fires on a firewall reload). Wrapper
   `scripts/udp-conntrack-guard.sh` (§16: pipefail, explicit PATH, flock,
   timeouts, atomic heartbeat, `skipped_stack_down`).
5. **Failure is never silent.** `stack-watchdog.sh` reads the heartbeat
   (stale / error / recurring / unsupported ⇒ problem + push; fixed ⇒ warning),
   `install_doctor` mirrors it, and the in-stack `IngestSenderAddressMasked`
   keeps firing through vmalert whatever the guard does — remedy watches the
   cause, detector the symptom.

## Tests

`internal/netguard`: golden request bytes, decode fixtures (healthy, stale,
IPv6, nested, unknown, truncated/oversized NLA, multipart, ENOENT/EPERM,
seq/pid mismatch), filter table, caps/timeouts, fuzz target. `cmd/netguard`:
args, JSON schema, exit codes. Real-kernel job (build tag
`conntrackintegration`, sudo netns + veth): stale deleted, healthy intact with
same CTA_ID, second run deletes 0, DNAT removed ⇒ recurring — new backend-ci
job mapped in `ci-gate` + `CI_RULES` + `test_test_plan.py` case. pytest:
compose envelope (caps exact; image in the bundle's base set —
`make-installer.sh` only takes base-service images), wrapper with fake docker,
crontab/deploy/qualify/watchdog/doctor extensions. No tenant data ⇒ no §3a
test (a future UI view must be `requirePlatformAdmin` + its own test).

Lab proof without sudo: deploy; `netguard --check` shows healthy_dnat > 0 on
live ports and stale = 0 (proves the netlink read path under AppArmor/seccomp);
force-recreate syslog-ng + api while cEDGE-81 sends ⇒ source kept, masked
counter flat. **Gap:** the delete path is proven only in CI unless D6.

## Files, in order

ADR 0001 addendum → `src/backend/internal/netguard/*` → `cmd/netguard` +
`Dockerfile.backend` + compose service + envelope test → CI netns job →
`scripts/udp-conntrack-guard.sh` + pytest → hooks/cron in deploy / install /
qualify → watchdog + doctor → runbook `ingest-sender-address-masked.md`,
liveness matrix row, alert text (+ helm copy), tracker 373, INVARIANTS only
after lab + CI proof.

## Risks

Hand-rolled ctnetlink (mitigated: goldens, real-kernel CI, fuzz, exact
`CTA_ID` delete; protocol is in the tuple so TCP cannot be hit) · dump cost on
100k+ tables every sweep (later: in-kernel `CTA_FILTER`, kernel ≥ 5.9) ·
rootless / userns-remap / `iptables:false` ⇒ reported `unsupported`, not fixed
· profiled-service image membership in the bundle · installer GUI `cx_stage`
contract if a stage is added · the "29.5.0-specific" claim is unverified.

## Owner decisions

- **D1** Accept a default-on privileged one-shot (NET_ADMIN, host netns,
  launched via the install user's docker socket) as an ADR 0001 addendum.
  *Recommended.*
- **D2** Implementation: stdlib hand-written ctnetlink (*recommended*, no §6
  change) · or amend §6 for a conntrack library · or ship conntrack-tools
  (GPL-2.0).
- **D3** Sweep interval: 1 / **2 (recommended)** / 5 min / post-deploy only.
- **D4** Observability: heartbeat + watchdog + doctor alongside the masked
  alert (*recommended*) · or also push a metric (needs a host ingest
  credential).
- **D5** Drop the "Docker 29.5.0 doctor warning" for a guard-status check
  (*recommended*; no evidence of a 29.5.0-specific defect).
- **D6** Allow a one-time lab drill that plants a stale entry to prove the
  delete path on the lab.
