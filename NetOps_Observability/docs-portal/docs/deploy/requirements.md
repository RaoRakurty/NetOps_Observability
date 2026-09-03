---
title: Deployment requirements
description: Host platform, CPU/RAM/disk floors, software prerequisites, kernel settings and host ports the Correlix installer checks before it will install.
page_type: reference
sidebar_position: 2
---

# Deployment requirements

The installer checks every item on this page. `install-correlix.sh` refuses to install on a host that fails a hard gate, and warns on a soft one.

## Host platform

| Requirement | Value | Enforcement |
|---|---|---|
| CPU architecture | `x86_64` | Hard stop on anything else. |
| Operating system | Ubuntu 22.04 LTS or newer, Debian 12 or newer | Hard stop. Other Linux distributions are not validated; `CORRELIX_SKIP_OS_CHECK=1` bypasses the gate at your own risk. |
| Virtualisation | Bare metal or any hypervisor | Not checked. |
| Root or sudo | Required for host preparation, not for running the stack | `prepare-host.sh` needs root. The stack runs as a member of the `docker` group. |

## CPU, memory and disk

| Resource | Hard floor (install refuses) | Warned range | Recommended |
|---|---|---|---|
| vCPU | 2 | 2 to 3 | 4 or more |
| RAM | 6 GB detected (the message states the 8 GB requirement) | 6 to 14 GB | 16 GB or more |
| Free disk on the Docker root | 20 GB detected, and the message states the 40 GB requirement | 20 to 39 GB | 100 GB or more |

Disk is measured on the filesystem holding `docker info -f '{{.DockerRootDir}}'`, not on `/`. Flow retention dominates long-term disk, and the resource planner refuses a plan whose retention cannot fit. Size a production host from [Plan host resources](/deploy/sizing) rather than from this table.

## Software prerequisites

| Component | Requirement | Note |
|---|---|---|
| Docker Engine | Installed and running, with the invoking user able to reach the daemon | `prepare-host.sh` installs `docker-ce` from Docker's official apt repository. |
| Docker Compose | The **Compose v2 plugin** (`docker compose`) | The legacy `docker-compose` binary is not supported and the installer rejects it by name. |
| `python3` | Present on the host | Runs `scripts/install.py` and the resource planner. |
| `zstd` | Required for bundle installs | Unpacks `correlix-images-*.tar.zst`. Not needed for a source-checkout install. |
| Time sync | `chrony` or `systemd-timesyncd` active | Telemetry timestamps and session tokens need a correct clock. |

## Kernel settings

`prepare-host.sh` persists these in `/etc/sysctl.d/99-correlix.conf`. Apply the equivalents by hand on a distribution it does not support.

| Setting | Value | Why |
|---|---|---|
| `vm.max_map_count` | `262144` | OpenSearch refuses to start below this. Without it the search store crash-loops after an otherwise clean install. |
| `vm.overcommit_memory` | `1` | Valkey background saves. |
| `vm.swappiness` | `10` | Keeps the JVM and the stores out of swap. |
| `net.core.rmem_max` | `26214400` | UDP receive headroom for the syslog, NetFlow and sFlow receivers. It must stay at or above the `so-rcvbuf` syslog-ng requests. |

`prepare-host.sh --check` audits every item and prints `PASS` or `FIX` per row without changing anything. It exits non-zero when something needs fixing, and `install-correlix.sh` runs it as a hard gate before installing.

## Host ports

These are the ports the shipped compose file publishes on the host.

| Port | Protocol | Service | Condition |
|---|---|---|---|
| 8000 | TCP | Web console and REST API | Default. Change with `install.py --port` or `BASE_PORT` in `.env`. |
| 443 | TCP | Web console over TLS | Only when TLS is enabled. See [Enable TLS and mTLS](/deploy/enable-tls). |
| 514 | UDP and TCP | Syslog from devices | Always published, so a device configured with `logging host <nms> 514` reaches the collector without reconfiguration. |
| 5514 | UDP and TCP | Syslog, alternate port | `SYSLOG_PORT`, default `5514`. Both host ports reach the same container port. |
| 162 | UDP | SNMP traps | Mapped to the unprivileged container port 1162. `SNMP_TRAP_PORT` changes the host side. |
| 2055 | UDP | NetFlow v5 and v9 | Always published. |
| 4739 | UDP | IPFIX | Always published. |
| 6343 | UDP | sFlow | Always published. |
| 11019 | TCP | BMP receiver | `BMP_PORT`, default `11019`. The listener only binds when `FEATURE_BMP=true`. |

Docker publishes its ports through iptables and bypasses UFW, so a UFW rule does not close a published container port. Restrict container exposure with the compose port mappings and with an upstream network ACL, and use UFW for host services such as SSH.

For the outbound side (Correlix reaching devices on SNMP, ICMP and gNMI), see [Connectivity requirements](/reference/connectivity-requirements).

## What the installer generates

| Path | Contents | In version control |
|---|---|---|
| `deployment/docker/.env` | Every generated credential, the resource plan block, feature flags, the compose profile and file chains | No. Created at install, mode `0600`. |
| `data/` | Every store: PostgreSQL, ClickHouse, OpenSearch, VictoriaMetrics, Kafka, Valkey, the user store, sealed blobs | No. Created at install. |
| `data/install-timing.json` | Per-stage wall clock for the run, written on success and on failure | No. |
| `resource-plan.json`, `resource-plan.txt` | The generated sizing plan, machine-readable and human-readable | No. |

Losing `.env` loses the credentials for every store. Back it up with `data/`, as [Back up and restore](/deploy/back-up-and-restore) describes.

## Browser

The console is a React single-page application. Use a current version of Chrome, Edge, Firefox or Safari. When TLS is enabled with the installer-generated certificate, the certificate is self-signed and the browser warns once until you replace it.

## Related

- [Install Correlix on a Linux host](/deploy/install-linux)
- [Plan host resources](/deploy/sizing)
- [Connectivity requirements](/reference/connectivity-requirements)
