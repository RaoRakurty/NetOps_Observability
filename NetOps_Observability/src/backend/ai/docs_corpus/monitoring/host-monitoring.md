---
title: Monitor Correlix itself
sidebar_label: Monitor Correlix itself
description: Route Correlix's own platform self-health alerts to a phone topic, and run the external watchdog that survives the stack dying.
page_type: task
sidebar_position: 6
---

# Monitor Correlix itself

Correlix has two alert audiences, and they are not the same people.

| Audience | What it carries | Where it goes |
|---|---|---|
| Platform self-health | Everything the rule evaluator sends through the alert receiver: engine liveness, ingest, bus, storage, host and platform layers. | The host-monitoring route in this page, which pushes to the operator's phone topic. |
| Product and tenant alerts | Monitor rules, BGP watch, per-tenant security findings. | The configured [notification channels](/incident-response/notifications), unchanged. |

The stack reporting on itself belongs on the same phone channel the external
watchdog already uses. A tenant-facing channel can never be pointed at the
operator's host-monitoring topic, and the refusal that enforces that is
described under [Configure a notification channel](/incident-response/notifications).

## Why this is a route and not another channel

The product channel set is operator-configured state. It can be empty, disabled
or misconfigured, and it lives behind the same api this route reports on. A stack
that can only tell you it is broken through a channel someone had to configure
first is not self-reporting.

The host-monitoring route depends on nothing but an environment-provided topic.
It works on a fresh install with no notification configuration at all, which is
exactly the install where "the correlation engine has consumed nothing for three
hours" most needs to reach a human.

## Before you begin

- An ntfy topic you subscribe to on your phone. On the public `https://ntfy.sh`
  service the topic name is the only secret: anyone who learns or guesses it can
  read and publish your alerts. Mint a high-entropy name with
  `openssl rand -hex 16`, or run a self-hosted ntfy server with authentication.
- Shell access to the deployment's `.env`, and the ability to restart the api
  container.
- `VMALERT_WEBHOOK_TOKEN` set, so the alert receiver exists at all. Without it
  the receiver is not registered and nothing reaches this route.

## Steps

### Step 1: set the topic

1. Set `PLATFORM_ALERTS_NTFY_TOPIC` in `deployment/docker/.env` to the topic you
   want platform self-health pushed to.
2. Leave it empty to fall back to `WATCHDOG_NTFY_TOPIC`, the topic the external
   watchdog already publishes to. That fallback is the default destination.

| Variable | What it sets |
|---|---|
| `PLATFORM_ALERTS_NTFY_TOPIC` | The host-monitoring topic. Empty falls back to `WATCHDOG_NTFY_TOPIC`. |
| `PLATFORM_ALERTS_NTFY_SERVER` | The ntfy server for this route. Empty falls back to `NTFY_ALERT_SERVER`, then to `https://ntfy.sh`. |
| `PLATFORM_ALERTS_NTFY_TOKEN` | The bearer token for an authenticated server. Empty falls back to `NTFY_ALERT_TOKEN`. |

The server and token fall back to the product ntfy wiring. The topic never does.
A platform alert must not land on a product topic.

### Step 2: tune the noise controls

1. Set `PLATFORM_ALERTS_WARNING_DIGEST_INTERVAL` to how often the accumulated
   warning tier may be summarised into a single push. It takes a Go duration such
   as `30m` or `1h`, and the compose default is `30m`.
2. Set `PLATFORM_ALERTS_PUSH_BUDGET` to the sustained outbound push allowance per
   hour for this topic. The compose default is `30`. A value of `0` or lower
   disables the guard, which is the escape hatch for a self-hosted ntfy with no
   limits of its own.
3. Set `PLATFORM_ALERTS_PUSH_BUDGET_PAGE_RESERVE` to how many of those tokens
   only a page may spend, so a warning digest can never be the reason a page is
   refused. The compose default is `10`, and the value is clamped into
   `[0, budget-1]`.

An invalid duration or a non-numeric count falls back to the default and logs a
warning. A typo never silently turns the digest off.

### Step 3: restart and confirm the wiring

1. Restart the api service.
2. Read the boot log line for the route. It reports the server, whether a token
   is set, and which variable supplied the topic. The topic itself is never a log
   field: knowing an ntfy topic is enough to read every alert published to it and
   to publish forgeries.

If no topic is configured, the api logs one warning, once, saying that platform
alerts are not pushed to host monitoring and naming the two variables to set. It
is logged once rather than per alert, because one warning per alert per cool-down
is its own outage.

## Result

Platform self-health alerts arrive on your phone, classified by tier.

| Tier | What it is | Priority | How it is sent |
|---|---|---|---|
| `page` | One of the nine `tier: page` rules. | High | Pushed immediately, and retried. |
| `resolved` | The resolution of any alert. | Low | Pushed immediately when it resolves a page. |
| warning | Every other firing alert. | Default | Folded into the periodic digest. |

The lock-screen title leads with the tier and the rule name, because the first
two words decide whether you get out of bed. The body repeats the rule and
summary, then a fixed, ordered set of labels: `severity`, `layer`, `rule_layer`,
`tier`, `service`, `instance`, `job`, `consumergroup`, `container`. The list is
fixed rather than "every label", because an unbounded label dump makes the one
line that matters unreadable.

### What never reaches this route

- **Anything naming a tenant.** An alert carrying `tenant`, `org`, `customer`,
  `account` or their variants is dropped and logged. This is platform-global
  plumbing, and one tenant's identity on every operator's phone is a
  cross-tenant disclosure.
- **Anything naming a customer network object.** An alert with no platform
  `layer` stamp that nevertheless carries `device`, `interface`, `peer`,
  `circuit` or a similar label is customer telemetry. It belongs to the
  tenant-scoped RCA policy lane, and it is dropped here.
- **The heartbeat.** `AlertingHeartbeat` always fires and is never routed to a
  person. It stamps `netops_alert_webhook_heartbeat_timestamp_seconds`, which is
  the only end-to-end proof that the delivery chain works. Paging an operator
  every cool-down to say the pager works is how a pager gets muted.

### How delivery is bounded

Delivery is asynchronous. The evaluator's POST does not wait on an external
push: a single batch can carry hundreds of alerts and the evaluator retries
anything slow, so a blocking push turns into a self-inflicted request storm.

- The push queue is bounded at 256 jobs. Beyond it, a job is dropped, counted and
  logged rather than blocking the request or growing without limit.
- Only the page tier retries: one send plus four retries, with exponential
  backoff from 2 seconds, each wait capped at 30 seconds and the whole delivery
  capped at 2 minutes. The server's own `Retry-After` wins when it sends one.
  Backoff carries jitter so two api instances sharing a topic do not retry in
  lockstep.
- A digest is never retried. It is re-sent next window with the accumulated
  content, so a retry would spend the budget the digest exists to protect for no
  new information.
- Title and tag text ride HTTP headers, so CR, LF and every other control or
  non-ASCII byte collapses to a space before the request is built. That closes
  header injection from a rule annotation.
- A transport error is scrubbed of the request URL before it is logged, because
  the topic is a credential.
- A page that is refused or never lands is logged at error level, not warning.
  Nobody was told about a page-worthy condition, and that log line is the only
  remaining trace.

## The external watchdog

`scripts/stack-watchdog.sh` runs outside the stack, from cron, once a minute. It
is the only layer that survives the whole stack dying, and it is deliberately
independent of the stack's own notifiers, because they cannot report their own
death.

Each run:

1. Checks that every compose service is running, and healthy where a healthcheck
   exists.
2. Probes the console on `:8000` and the api liveness endpoint.
3. Queries the metric store directly for consumer-group membership on the
   correlation group and every `netops-router-*` lane, and for the age of the
   alert-delivery heartbeat. Set `ENGINE_CONSUMER_CHECK=0` to disable that block.
4. Pings the healthchecks.io URL when healthy. If the host or its network dies,
   the pings stop and healthchecks.io alerts you off-host. That is the
   dead-man's-switch.
5. Pushes an ntfy notification on a state transition, up to down and down to up,
   tracked per problem class. A sustained outage produces one push, not one per
   minute, and a standing advisory problem can no longer swallow the push for a
   new critical one.

Configuration lives in `scripts/stack-watchdog.env` beside the script, or in
`/etc/correlix/stack-watchdog.env` on a packaged install. The sibling file wins
when both exist, and `WATCHDOG_ENV` overrides both. No secrets are baked into
the script.

| Variable | What it sets |
|---|---|
| `NTFY_TOPIC` | The topic phone pushes go to. Required for any ntfy delivery. |
| `NTFY_SERVER` | A self-hosted ntfy server. Defaults to the public service. |
| `NTFY_TOKEN` | Bearer token for an authenticated server. |
| `HC_PING_URL` | The healthchecks.io ping URL. Blank disables the dead-man's-switch. |
| `WATCHDOG_WEBHOOK_URL` | A generic webhook posted on every up-to-down and down-to-up transition. |
| `WATCHDOG_SERVICES` | Overrides the compose services checked. |

To confirm delivery works, run the script with `--test`. It exercises every
configured channel, including the api liveness probe.

:::caution
`--test` sends a real push to the phone subscribed to the topic. Do not run it
casually.
:::

## Related

- [Monitoring and alerting](/monitoring/overview)
- [Alert rules reference](/reference/alert-rules)
- [Configure a notification channel](/incident-response/notifications)
- [Verify a deployment](/deploy/verify-deployment)
