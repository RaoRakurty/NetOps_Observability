---
title: Deploy Correlix
description: What the Deploy section covers - sizing, installing, securing, verifying, upgrading and backing up a Correlix deployment on a single Linux host.
page_type: index
sidebar_position: 1
---

# Deploy Correlix

You are the administrator who installs and maintains the Correlix host. The pages below cover the whole life of a deployment: sizing the hardware, installing on a connected or air-gapped host, enabling TLS, turning on optional modules, proving the pipeline is doing work, upgrading, and protecting the data. If you want to see Correlix running before you plan a production host, start with the [quickstart](/getting-started/quickstart) instead.

Correlix ships as a Docker Compose stack on one Linux host. The default profile set starts more than 18 long-lived services. Those are the ingest edge (syslog-ng, goflow2, and the SNMP collectors inside the api), a Vector aggregation tier, a single-node Apache Kafka bus in KRaft mode, and three stores (OpenSearch, VictoriaMetrics, ClickHouse). Beside them run PostgreSQL, the Valkey cache (compose service name `redis`), the correlation engine, the Go API and the React console. One nginx front-end publishes the console on TCP 8000, or on 443 when TLS is enabled.

## Pages

| Page | What it gives you |
|---|---|
| [Deployment requirements](/deploy/requirements) | The host platform, CPU/RAM/disk floors, software prerequisites, kernel settings and ports the installer checks. |
| [Plan host resources](/deploy/sizing) | Declare a workload, generate per-container limits, review the plan and roll it back. |
| [Reference capacity](/deploy/reference-capacity) | The ratified capacity SLO, the reference box it was measured on, and how to read a capacity claim. |
| [Install Correlix on a Linux host](/deploy/install-linux) | The standard install from a source checkout on a host with registry access. |
| [Install without internet access](/deploy/install-air-gapped) | Build an offline bundle, verify it, and install from it on a host with no egress. |
| [Enable TLS and mTLS](/deploy/enable-tls) | Turn on the transport mesh: ingress TLS on 443, mTLS between services, per-store certificates. |
| [Turn on an optional module](/deploy/optional-modules) | The modules that need more than a flag set to `true`, and what each one additionally requires. |
| [Verify a deployment is doing work](/deploy/verify-deployment) | Run the post-deploy gate that proves the engines are consuming and producing, not merely running. |
| [Upgrade a deployment](/deploy/upgrade) | The upgrade path, the bootstraps an upgrade must re-run, and how to roll back. |
| [Back up and restore](/deploy/back-up-and-restore) | Snapshot policy, off-host backup, the restore drill, and restoring for real. |

## Two facts to carry through the section

**Generated state is not in version control.** `deployment/docker/.env` and the whole `data/` tree are created at install time and are gitignored. `.env` holds every generated credential; `data/` holds every store. A backup that covers neither is not a backup.

**A green container is not a working pipeline.** Every service can report healthy while a lane produces nothing, and that has happened twice in this platform's history. [Verify a deployment is doing work](/deploy/verify-deployment) is the step that closes the gap, and it belongs at the end of every install and every upgrade.

## Related

- [Connectivity requirements](/reference/connectivity-requirements) - the authoritative port table to hand to a firewall team.
- [Feature flags](/reference/feature-flags) - every `FEATURE_` and `ENABLE_` switch with its shipped default.
- [Administration](/administration/overview) - what to configure once the stack is up.
