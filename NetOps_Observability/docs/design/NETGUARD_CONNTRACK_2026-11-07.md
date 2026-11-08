# Netguard — automatic stale-conntrack remedy (tracker 373 remainder)

Status: **SUPERSEDED (owner decision 2026-11-08)** — Correlix will NOT build netguard. The plan of record is host-network telemetry ingress (DEFERRED by the owner on 2026-11-08 — ~3–4 days; revisit with the Collector tier / after Iris), per the owner's research `docs/research/PRESERVE_ORIGINAL_SOURCE_IP_2026-11-08.md`. This document is kept for the rationale and the research below.

Original status: PLAN, awaiting owner decisions D1–D6 (2026-11-07). Research: Fable
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

---

## Research update 2026-11-08 (Fable; premises re-checked in the main session ✔)

**Verdict: keep netguard, modified — but prove Docker's own flush first.** Lab facts ✔:
Docker Engine **29.5.2**; `prepare-host.sh` runs `firewall-cmd --reload`; the compose
network has no `enable_ipv6`.

**What Docker already does.** Since Engine 23 (moby PR #44742, fixing #44688 — our
exact symptom) Docker deletes stale UDP conntrack entries for published ports after
installing the NAT rules on every container start. Two regressions: 29.5.0 broke it
entirely (fixed in 29.5.1, moby #52640; Akvorado users hit it, akvorado#2431), and
moby#53384 (still open, fix PR #53385 approved, unmerged) flushes by CONTAINER port
— which is why the lab's 162→1162 mapping broke and why host==container parity (#126)
fixes the deploy path. **Not covered by Docker:** firewalld reloads
(`handleFirewalldReloadNw` re-applies rules with no flush — and our own prepare-host
triggers one), rule wipes Docker doesn't see, future regressions (the installer tracks
docker-ce latest). **IPv6 senders are always masked** (IPv4-only network → docker-proxy
relays them) — a separate cause no conntrack fix can solve.

**Prior art.** Akvorado (OSS NetFlow, compose) shipped exactly this as `conntrack-fixer`
(NET_ADMIN, host netns, docker events) 2022–2025, removed when Docker ≥23 flushed —
then hit by 29.5.0. kube-proxy reconciles with the same predicate (UDP to a service port
whose reply-src is not a serving endpoint), deletes by full tuple; lessons: dst-port
must be matched (k8s#129982: 12 GB memory, endless delete loops), flush only AFTER rules
exist (k8s#106163), skip ports with no serving endpoint. CNI portmap flushes by host
port after ADD/DEL.

**Competitors avoid NAT instead of repairing it.** ElastiFlow: "network_mode must be set
to host" (the bridge loses the source IP); Splunk SC4S: `--network host`; New Relic
ktranslate flows and Kentik kproxy: `--net=host`; Datadog/Dynatrace/LogicMonitor:
host/VM agents. No commercial vendor ships a conntrack flush. They can, because their
collectors only need outbound HTTPS; ours talk to internal Kafka/Vector by compose DNS,
which makes host networking expensive in TODAY's stack and cheap in the Collector tier.

**Revised order.** (1) No-sudo lab drill: force-recreate syslog-ng + api while cEDGE-81
sends; the masked counter must stay flat. (2) Doctor/qualify check: warn on Docker <23
or ==29.5.0 (corrects D5). (3) Close our own firewalld-reload window in prepare-host
(reload before the stack starts, or follow it with a guard run). (4) Netguard as defence
in depth, with the corrections below. (5) Strategic: host-network UDP receivers in the
Collector tier (tracker 372) — add source-address preservation as a C3/C5 requirement.

**Corrections to this plan (must be in the build).**
- E1 CRITICAL: a CT_DELETE without CTA_TUPLE_ORIG/REPLY FLUSHES THE WHOLE TABLE (all
  families with version 0); unknown attribute IDs are silently ignored. Encoder-side
  assertion that every DELETE carries a parseable ORIG tuple (proto 17, IPv4 dst) before
  sendto; golden decode test of our own DELETE bytes; netns CI case proving an
  unrelated TCP entry survives.
- E2: container→host-IP hairpin traffic on a published port is relayed un-DNATed and
  would be deleted every sweep → false `recurring` pages. Exclude orig-src in local
  docker bridge subnets / local addresses; prove in netns CI.
- E3: per-port skip when the publishing container is not running/healthy (kube-proxy
  lesson).
- E4: use IPS_DST_NAT (bit 5, 0x20), NOT DST_NAT_DONE (bit 8, set by the null binding
  too); mask NLA_F_NESTED; EBUSY (offloaded, ≤5.15) and ENOENT are benign.
- E5: kernel-side dump filter: CTA_STATUS=0 + CTA_STATUS_MASK=IPS_DST_NAT with
  nfgen_family=AF_INET (Linux ≥5.15 — every supported OS); userland filter as fallback.
  (CTA_FILTER is ≥5.8, not 5.9.)
- E6: stream-decode with a hard cap; never accumulate failed deletes; dumps are not
  snapshots (ctnetlink never sets NLM_F_DUMP_INTR) — the rescan covers it.
- Kernel constants verified against uapi headers: NETLINK_NETFILTER 12, subsys
  CTNETLINK 1, CT_GET 1 / CT_DELETE 2, CTA_TUPLE_ORIG 1, CTA_STATUS 3, CTA_ID 12,
  CTA_FILTER 25, CTA_STATUS_MASK 26; CAP_NET_ADMIN required for every nfnetlink message
  incl. dumps.
- Name the problem precisely: "ufw reload" is unproven; the proven window is firewalld.
  Runbook/alert must separate "stale entry" from "IPv6 sender".

Sources (full list in the research report): moby #53384, #53385, #52640, #44742, #44688;
akvorado#2431, commit f9eee6f; kube-proxy pkg/proxy/conntrack/cleanup.go, k8s#126130,
#129982, PR #130484, PR #106163; CNI portmap main.go; kernel nf_conntrack_netlink.c,
nfnetlink.c, nfnetlink_conntrack.h; ElastiFlow, SC4S, New Relic, Datadog, Dynatrace,
LogicMonitor, Kentik docs.
