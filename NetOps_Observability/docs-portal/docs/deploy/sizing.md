---
title: Plan host resources
description: Generate per-container memory and CPU limits from a declared workload, review the plan before applying it, and roll it back if the result is wrong.
page_type: task
sidebar_position: 3
---

# Plan host resources

Correlix sizes itself to the host and the workload at install time. The planner reads the host capacity, subtracts an operating-system reserve and a safety reserve, and derives a memory and CPU limit for every container plus the application-internal limits inside each one. You get a reviewed, reproducible plan instead of hand-edited JVM heaps.

Do this before you install on a production host, when the host changes, and when the workload grows.

## Before you begin

- Shell access to the Correlix host and `python3` on it.
- The workload you expect: device count, interface count, flow records per second and their retention in days, log events per second and their retention in days, concurrent operators, concurrent analytical queries, tenant count.
- Free disk on the Docker root filesystem. The planner validates storage alongside memory and refuses a memory-adequate plan that has inadequate disk.
- A maintenance window if you are replanning a running stack. Applying a plan recreates the containers whose limits changed.

## Steps

1. Read what the host actually has. This command writes nothing.

   ```bash
   python3 scripts/resource_planner.py --detect-json
   ```

   ```json
   {"cpus": 4.0, "disk_free_bytes": 6505271296, "mem_bytes": 16766005248, "mem_gib": 15.6, "suggested_profile": "demo"}
   ```

2. Pick a profile from the [profile table](#profiles), or accept `auto`, which selects by detected RAM.

3. Declare the workload in `correlix-sizing.yaml`. Copy `deployment/docker/correlix-sizing.example.yaml` and edit it. Every value is optional; a missing input falls back to the profile default.

   ```yaml
   profile: custom
   workload:
     devices: 500
     interfaces: 20000
     flows:
       records_per_second: 15000
       retention_days: 30
     logs:
       events_per_second: 3000
       retention_days: 14
     users:
       concurrent_users: 20
       concurrent_analytical_queries: 8
     tenants: 10
   ```

4. Generate the plan. On a first install, pass the flag to the installer:

   ```bash
   python3 scripts/install.py --plan-resources --sizing-file correlix-sizing.yaml
   ```

   On an existing install, regenerate only the plan block and exit:

   ```bash
   python3 scripts/install.py --replan --sizing-file correlix-sizing.yaml
   ```

5. Read `resource-plan.txt` beside `.env` before applying anything. It states every allocation, the evidence class behind each coefficient, and any warning the planner raised.

6. Apply the plan.

   ```bash
   cd deployment/docker && docker compose up -d
   ```

7. If the result is wrong, restore the previous plan and reapply. `--rollback-plan` restores `.env` and both plan artifacts from their `.plan.bak` copies. It does not restart services.

   ```bash
   python3 scripts/install.py --rollback-plan
   cd deployment/docker && docker compose up -d
   ```

## Result

`deployment/docker/.env` carries a managed block between these markers, holding every `*_MEM_LIMIT`, `*_CPU_LIMIT` and internal variable the compose file reads:

```
# >>> correlix-resource-plan >>>
...
# <<< correlix-resource-plan <<<
```

Beside it sit `resource-plan.json` (deterministic, machine-readable) and `resource-plan.txt` (the human explanation), plus `.plan.bak` copies of the previous versions of all three.

An existing installation changes nothing until an operator runs `--replan`. Compose `:-` defaults equal the pre-planner lab constants, so an install with no plan behaves exactly as it did before.

## Profiles

Profiles are defaults, not the mechanism. Any workload input overrides its profile default.

| Profile | Typical host | Behaviour |
|---|---|---|
| `demo` | 8 to 16 GiB | Evaluation mode. Caps are allowed to oversubscribe the host, with relaxed guards and loud warnings. |
| `small` | 32 GiB | Strict budget enforcement from here up. |
| `medium` | 64 GiB | Strict budget enforcement. |
| `large` | 128 GiB | Strict budget enforcement. |
| `custom` | Any | Purely workload-derived. |
| `auto` | Any | Selects by detected RAM: under 24 GiB gives `demo`, under 48 GiB `small`, under 96 GiB `medium`, otherwise `large`. |

`--plan-resources` with no value means `auto`, and `auto` is the default. `--no-plan-resources` skips planning entirely and keeps the static compose defaults.

## The planner refuses a plan it cannot fit

When the declared workload does not fit the host, the planner stops with an explanation instead of shrinking components below their operational minimums:

```
The requested workload cannot safely fit on this deployment.
  Available Correlix memory : 25.6 GiB
  Estimated minimum memory  : 32.4 GiB
  Available storage (free)  : 500.0 GiB
  Estimated required storage: 1281.2 GiB
  Primary contributors:
    - clickhouse   14.0 GiB
    - opensearch    9.0 GiB
  Recommended corrective action:
    - Increase host memory / disk
    - Reduce retention (flows/logs/metrics days)
    - Reduce query/user concurrency inputs
```

A refusal is the correct outcome, not a defect in the planner. Grow the host, cut retention days, or cut the concurrency inputs, then replan. At high ingest rates the plan also warns that storage IOPS capability is undeclared; validate SSD or NVMe before production.

## What the plan does not size

`BUS_PARTITIONS` appears in the generated plan so the setting is visible, and it is deliberately not derived from the workload. It resolves as explicit override, then existing install, then `1`. Two independent reasons keep automatic sizing switched off:

- The throughput figure available for scaling it was measured while a correlation defect was still active, so it is a lower bound on a degraded system rather than a capacity constant.
- Partition ownership changes are not yet proven correctness-safe. Correlation window state is in-process and does not follow partitions, so sizing a knob that moves ownership would automate an action whose correctness cost is unmeasured.

Three properties matter more than the number itself:

- **Raise-only.** Kafka partitions can be increased but never reduced, and the topic bootstrap only alters topics upward. An override below the live value is refused with an explanation.
- **It is a multiplier, not a count.** The value is applied to 17 bus topics on a single-node broker, so `BUS_PARTITIONS=4` is about 68 broker partitions. Correlation subscribes to 12 of those topics, so five topics carry partitions no consumer reads.
- **It caps correlation replicas.** A consumer group cannot have more active members than partitions. Replicas beyond `BUS_PARTITIONS` join, receive nothing and process nothing. The plan names the exact idle count.

The planner reads `.env`, not the broker. If `BUS_PARTITIONS` was ever set outside the installer, confirm the live topology with the broker's own topic description before replanning.

## Precedence

Later rows win.

| Source | Example |
|---|---|
| Compose `:-` defaults (lab tier) | `${CLICKHOUSE_MEM_LIMIT:-5g}` |
| Named profile | `--plan-resources medium` |
| Workload-derived plan | `correlix-sizing.yaml` `workload:` block |
| `overrides:` in the sizing file | `clickhouse_mem: 12g` |
| A hand-set variable in `.env` outside the managed block | An emergency pin |

A hand-set value outside the managed block is detected, honoured, and warned about:

```
[warn] legacy override CLICKHOUSE_MEM_LIMIT=5g pins clickhouse (generated
       recommendation was 12.0 GiB); remove it from .env to adopt generated sizing
```

:::note Generated plans are engineering estimates
Every scaling coefficient carries an evidence class: vendor-recommended, repository-existing, conservative-provisional, or unknown-measurement-required. A plan containing provisional coefficients says so. Treat allocations as reviewed estimates, not certified sizing, and check them against [Reference capacity](/deploy/reference-capacity).
:::

## Related

- [Reference capacity](/deploy/reference-capacity) - the measured envelope, and the language to use for a capacity claim.
- [Deployment requirements](/deploy/requirements) - the floors the installer enforces.
- [Install Correlix on a Linux host](/deploy/install-linux) - where the plan is generated on a first install.
