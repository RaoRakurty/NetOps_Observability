---
title: Verify a deployment is doing work
description: Run scripts/deploy-qualify.sh after every deploy to prove the engines joined their consumer groups, lag is draining and both Vector tiers are emitting.
page_type: task
sidebar_position: 9
---

# Verify a deployment is doing work

`docker compose up` exiting 0 is not evidence. Neither is a clean `docker compose ps`, a green healthcheck, or a green external watchdog. `scripts/deploy-qualify.sh` asks the question none of those ask: is the pipeline actually consuming and producing?

Run it after every install and every upgrade.

## Why this exists

Two incidents produced the same shape, where liveness was perfect and the pipeline was dead.

| Date | What happened |
|---|---|
| 2026-09-02 | The correlation engine's Kafka consumer never started. Its subscribe call failed on one optional topic, and the client abandoned the whole 14-topic subscription. The engine consumed nothing for three hours. Every container reported healthy, `docker compose ps` was clean, and the off-host watchdog stayed green throughout. |
| 2026-08-16 | `vector-router` and correlation went authorization-dead for about 80 minutes after a wipe emptied the KRaft ACL store, which is the authorization state itself since default-deny was enforced. Lag froze, nothing moved, and every healthcheck stayed green. |

A healthcheck answers "is the process up". Nothing in the stack asked "is the engine consuming and producing". This script is that missing question, asked as a gate.

## Before you begin

- Shell access on the Correlix host, with permission to reach the Docker daemon.
- A stack that has finished starting. The gate polls inside a bounded window and reports a real verdict either way, but a stack mid-start wastes the window.
- About five minutes. The default qualification window is 300 seconds.
- Know that the gate is safe to run on a live deployment. It never restarts, recreates, scales or deletes a long-lived service, and never touches a data volume. Phase 1 recreates only the one-shot bootstrap containers whose entire purpose is to run once and exit, and only when their work is outstanding.

## Steps

1. Run the gate from the repository root.

   ```bash
   bash scripts/deploy-qualify.sh
   ```

2. Read the per-check lines as they print. Each check lands in the ledger exactly once with one of four verdicts: `PASS`, `FAIL`, `SKIPPED` or `ADVISORY`.

3. Read the summary block at the end and act on the result line.

4. If the result is `INCOMPLETE`, read each `SKIPPED` line for its reason and remedy. A skipped required check is an unanswered question, not a good answer.

5. Re-run after fixing. Every phase-1 bootstrap is idempotent and safe to re-run on a healthy stack.

## Result

The run ends with a `deploy-qualify SUMMARY` block. It names the compose project, the window it used and the time, then reprints every check with its verdict, then a count line of passed, failed, skipped-required, skipped-advisory and advisory. The last thing it prints is one of three result lines, with the count substituted into the middle two.

Qualified:

```
  RESULT: QUALIFIED — every required check passed. The engines are
  consuming and producing, not merely running.
```

Not qualified:

```
  RESULT: NOT QUALIFIED — %d required check(s) FAILED.
  The stack may report every container healthy and still be doing no work.
  Do not treat this deploy as complete.
```

Incomplete:

```
  RESULT: INCOMPLETE — %d required check(s) could not be evaluated.
  Nothing failed, but "we could not check" is not "it passed" — that
  conflation is precisely what made both incidents invisible. See each
  SKIPPED line above for the reason and its remedy.
```

| Exit code | Meaning |
|---|---|
| `0` | Every required check passed. |
| `1` | At least one required check failed. The platform is not qualified. |
| `2` | Incomplete. Nothing failed, but at least one required check could not be evaluated. |
| `3` | Precondition failure. Docker, the compose project or the repository layout is not usable, and nothing was qualified. |

## Phase 1: the bootstraps

These run first, in this order. Each is idempotent.

| Check | What it applies |
|---|---|
| `B1` Kafka ACL matrix | The per-principal topic and group ACLs, piped into the running broker. Applied only on a TLS or mTLS broker; skipped loudly on a plaintext broker, where minting a first ACL would start denying everyone. |
| `B2` Kafka topic creation | The canonical topic list, with partition increases only. It reads the topic list first and re-runs the one-shot only when a topic is actually missing. |
| `B3` OpenSearch ISM policy | The retention policies, the snapshot repository and policy, and the replica posture. |
| `B4` Router lanes writable | A read-only audit. Every index pattern the router writes to is covered by the writer role, and every declared index template exists in the live cluster. |

`B4` is the check that catches the failure mode this page exists for. An upgrade that adds a lane but forgets its role entry makes that lane silently write-dead. The router's bulk write comes back `403`, Vector classifies a `403` as non-retriable, and the batch is dropped. The result is no index, no consumer lag, no rejected-document counter and no red healthcheck.

Skip the whole phase with `--no-bootstrap` when you want qualification only.

## Phase 2: the qualification

Everything here polls inside one shared bounded window, so the phase as a whole is bounded by `--timeout`. When the window closes, each remaining assertion still gets one final evaluation, so it reports a real verdict rather than vanishing.

| Check | Class | What it proves |
|---|---|---|
| `Q1` | Required | Correlation joined its consumer group. |
| `Q2` | Required | Every router consumer group has a live member. |
| `Q3` | Required | Correlation lag is draining, not strictly increasing. |
| `Q4` | Required | The Vector aggregator sinks are emitting events. |
| `Q5` | Required | The Vector router sinks are emitting events. |
| `Q6` | Required | No bootstrap-class Kafka errors in the correlation or router logs. |
| `Q7` | Required | The API answers `200` with a non-empty body. |
| `Q9r` | Required | The OpenSearch cluster status is not red. |
| `Q8` | Advisory | The alert-delivery heartbeat is fresh. |
| `Q9` | Advisory | The OpenSearch cluster status is present and green or yellow. |

An advisory check is reported and never fatal.

## Options

| Option | Default | What it changes |
|---|---|---|
| `--timeout SECONDS` | `300` | The phase-2 window. Minimum 10. |
| `--project NAME` | Discovered from the running containers | The compose project name. |
| `--no-bootstrap` | Off | Skips phase 1 entirely. |
| `--help` | | Prints the full check list. Exits 0 and contacts nothing. |

## Reading the correlation engine's own health

The correlation engine serves `/healthz` from a sidecar that is independent of its event loop, so a saturated loop cannot make the probe time out and trigger a self-inflicted restart. The body carries the honest state.

```json
{
  "status": "ok",
  "health_reasons": [],
  "consumer": {
    "assignment": {
      "netops.syslog": [0, 1, 2, 3],
      "netops.flows": [0, 1, 2, 3],
      "netops.metrics": [0, 1, 2, 3]
    }
  }
}
```

`status` is `ok` only while the required subscription is live. Exactly one condition degrades it: the supervisor has tried and is not currently consuming, which is the state a restart loop produces. When that happens the body reads:

```json
{"status": "degraded", "health_reasons": ["consumer_not_running"]}
```

`health_reasons` is empty exactly when `status` is `ok`, so an operator reading the body does not have to diff the consumer block to find out which condition fired.

Two states deliberately do not degrade it. A dropped optional evidence lane is a named field, a log line and a gauge, because "should this lane be on?" is a configuration question rather than an unhealthy engine. A process that has never started a consumer answers `503` with a starting status until its first health snapshot exists.

Degradation is carried in the body and in the metrics, never in the container healthcheck. The sidecar keeps answering `200` and the compose healthcheck keeps testing only for `200`, so nothing here can flap a container.

## Related

- [Upgrade a deployment](/deploy/upgrade) - the bootstraps an upgrade must re-run, and why exiting 0 proves none of them.
- [Install Correlix on a Linux host](/deploy/install-linux) - the install this gate closes.
- [Enable TLS and mTLS](/deploy/enable-tls) - the ACL matrix phase 1 applies.
