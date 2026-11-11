---
title: Monitor Correlix itself
sidebar_label: Monitor Correlix itself
description: Send Correlix's own platform self-health alerts to ntfy or text messages from the Platform alerts page, and run the external watchdog that survives the stack dying.
page_type: task
sidebar_position: 6
---

# Monitor Correlix itself

Correlix has two alert audiences, and they are not the same people.

| Audience | What it carries | Where it goes |
|---|---|---|
| Platform self-health | Everything the rule evaluator sends through the alert receiver: engine liveness, ingest, bus, storage, host and platform layers. | The host-monitoring route on this page: ntfy and/or text messages, set up on Platform → Platform alerts. |
| Product and tenant alerts | Monitor rules, BGP watch, per-tenant security findings. | The configured [notification channels](/incident-response/notifications), unchanged. |

A tenant-facing channel can never be pointed at the operator's host-monitoring
topic or at the watchdog's topic, and the refusal that enforces that is
described under [Configure a notification channel](/incident-response/notifications).

## Why this is a route and not another channel

The product channel set is tenant-facing alert routing, with severity gates and
contact points. The host-monitoring route is the stack reporting on itself to
the operator, by tier. It is a different audience with a different policy, so it
has its own page and its own settings.

The route is set up in the web console only. There is no environment variable
for it: `PLATFORM_ALERTS_NTFY_TOPIC`, `PLATFORM_ALERTS_NTFY_SERVER` and
`PLATFORM_ALERTS_NTFY_TOKEN` were retired on 2026-11-11 and are ignored. If one
is still set, the api logs a warning at start-up and the page lists it.
`WATCHDOG_NTFY_TOPIC` is no longer a fallback destination either. It only stops
a product channel from reusing the watchdog's topic.

Until a channel is set up, the route is loud rather than quiet: the api logs that
platform alerts reach nobody, `netops_alert_webhook_host_route_enabled` reads 0,
and the platform administrator sees a banner.

## Before you begin

- The platform administrator account. Tenant and organisation administrators do
  not see this page.
- For ntfy: a topic you subscribe to on your phone. On the public
  `https://ntfy.sh` service the topic name is the only secret: anyone who learns
  or guesses it can read and publish your alerts. Mint a high-entropy name with
  `openssl rand -hex 16`, or run a self-hosted ntfy server with authentication.
  The server address must start with `https://`, and Correlix refuses a server
  on a private address unless the installation allows it (`SSRF_ALLOWED_HOSTS`).
- For text messages: a Twilio Account SID, auth token, a Twilio number to send
  from, and up to five numbers to text, all in international format such as
  `+14155550100`. Text messages cost money; see the limit below.
- `VMALERT_WEBHOOK_TOKEN` set, so the alert receiver exists at all. Without it
  the receiver is not registered and nothing reaches this route.

## Steps

### Step 1: open the page

Go to **Platform → Platform alerts**.

### Step 2: set up one or both channels

1. Under **ntfy**, turn it on, keep or change the server, enter the topic and,
   for a protected topic, the access token.
2. Under **Text messages (Twilio)**, turn it on and enter the Account SID, auth
   token, the number to send from and the numbers to text.
3. Choose what each channel receives: **Pages** (the four page conditions and
   the all-clear after each) and **Warning summary** (everything else, sent at
   most once per digest window). By default ntfy receives both and text messages
   receive pages only.
4. Select **Save**. The change applies at once, with no restart, and is audited.

Secrets are write-only. After saving, the page shows that a token is set but
never shows it. Leave a secret field empty to keep the saved value.

### Step 3: send a test

Select **Send test** for each channel. The page answers in plain words: sent,
credentials refused, rate limited, could not reach the service, or the service
refused the message. A test uses the saved settings, and a text message test
counts against the hourly limit.

### Text-message limit

At most the configured number of text messages leave per hour, across all
numbers (default 10, one message per number). Half of the limit is kept for
pages, so the warning summary can never use up what a page needs. Past the
limit, the text message is not sent and the api logs an error for a page; ntfy
still carries it if it is turned on.

### Tune the noise controls (install defaults)

These remain install-time defaults in `.env`:

1. `PLATFORM_ALERTS_WARNING_DIGEST_INTERVAL` is how often the accumulated
   warning tier may be summarised into a single push. It takes a Go duration such
   as `30m` or `1h`, and the compose default is `30m`.
2. `PLATFORM_ALERTS_PUSH_BUDGET` is the sustained outbound ntfy push allowance
   per hour for the push server, shared with the product ntfy channel. The
   compose default is `30`. A value of `0` or lower disables the guard, which is
   the escape hatch for a self-hosted ntfy with no limits of its own.
3. `PLATFORM_ALERTS_PUSH_BUDGET_PAGE_RESERVE` is how many of those tokens only a
   page may spend. The compose default is `10`, clamped into `[0, budget-1]`.

An invalid duration or a non-numeric count falls back to the default and logs a
warning. A typo never silently turns the digest off.

### If the saved settings cannot be read

The api keeps the last settings it read and retries every minute;
`netops_platform_alert_store_readable` reads 0 and the page says so. If the
settings cannot be read when the api starts, it uses the sealed copy it keeps on
the server (`data/platform_alert_route.lastgood.json`), so pages still reach your
channels. Opening that copy still needs the vault. If neither can be read,
nothing is in force: re-enter the settings and tick **Replace the saved
settings** to overwrite the unreadable record.

### When platform alerts reach nobody

If no channel receives pages, or nothing could be read, for 15 minutes, the
`PlatformAlertsReachNobody` page rule fires, and the external watchdog pushes a
`PLATFORM_ALERTS_UNROUTED` alert over its own ntfy topic after 10 minutes. A fresh
install that never sets up this page therefore pages through the watchdog. That
is intended: set up a channel.

## Result

Platform self-health alerts arrive on the channels you chose, classified by tier.

| Tier | What it is | Priority | How it is sent |
|---|---|---|---|
| `page` | One of the eleven `tier: page` rules. | High | Pushed immediately, and retried. |
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

The watchdog is set up on the host, not on the Platform alerts page, on purpose:
it is the layer that must keep working when the whole stack is down.

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
