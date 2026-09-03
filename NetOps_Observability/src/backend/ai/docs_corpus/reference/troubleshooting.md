---
title: Troubleshooting
sidebar_label: Troubleshooting
description: Symptom-indexed diagnostics for sign-in, discovery, device status, empty telemetry planes and the honest refusals.
page_type: reference
sidebar_position: 60
---

# Troubleshooting

Find the symptom in the index, then work the checks in order. They are ordered from most to least likely. Most onboarding problems are reachability or credentials. Most refusals on this page are deliberate: Correlix would rather say it cannot answer than answer with a number nobody measured.

| Symptom | Jump to |
| --- | --- |
| Cannot sign in, account locked, signed out | [Sign-in problems](#sign-in-problems) |
| Discovery finds nothing | [Discovery finds nothing](#discovery-finds-nothing) |
| Device status dot stays red or amber | [Device stays Down or Degraded](#device-stays-down-or-degraded) |
| The SNMP metrics column shows no data | [No SNMP metrics](#no-snmp-metrics) |
| The Syslog or Traps column shows no data | [No syslog or traps](#no-syslog-or-traps) |
| The Flows column shows no data | [No flows](#no-flows) |
| A dashboard panel shows a dash or 0% | [Panels show a dash or 0%](#panels-show--or-0) |
| A route answers `404` and the feature exists in the documentation | [A module answers 404](#a-module-answers-404) |
| A route answers `403` and you are an administrator | [A route answers 403](#a-route-answers-403) |
| Parser coverage answers `503` | [Parser coverage answers 503](#parser-coverage-answers-503) |
| Protocol-diagnostics collect answers `503` | [Protocol diagnostics cannot collect](#protocol-diagnostics-cannot-collect) |
| The BGP watchlist answers `503` | [The BGP watchlist is not initialised](#the-bgp-watchlist-is-not-initialised) |
| Sealed-field routes answer `501` | [Sealed fields answer 501](#sealed-fields-answer-501) |
| The audit log looks empty | [The audit log looks empty](#the-audit-log-looks-empty) |

## Sign-in problems {#sign-in-problems}

**Error: "invalid username or password" on a password you believe is correct**

Causes. The wrong sign-in method for the account. A federated account cannot authenticate as a local one, or the reverse. An account whose status is disabled. A password that expired under the scope's policy.

Solutions.

1. Confirm the method selector above the username field matches how the account is provisioned.
2. If the account uses MFA, the password step succeeds first and the 6-digit code is asked second. A rejected code usually means the authenticator's clock has drifted or the code expired while it was being typed. Wait for the next code.
3. Ask an administrator to check the account's status under **Administration → Identity & Access**. The message is deliberately the same for a wrong password and an unknown username, so it never confirms whether an account exists.

**Error: "account temporarily locked due to failed sign-ins; try again later", HTTP 429**

Causes. Consecutive failed sign-ins reached the scope's threshold. The shipped policy is 3 attempts and a 900-second lock, which is 15 minutes.

Solutions.

1. Wait for the lock to expire. The response carries a `Retry-After` header with the remaining seconds. More wrong guesses while locked do not extend it, but they do not help either.
2. A successful sign-in clears the counter.
3. An administrator can change the threshold and duration per scope under **Administration → Identity & Access → (scope) → Security Settings**. See [Configure authentication](/administration/authentication).

**Error: "sign-in temporarily unavailable due to failed-login pressure", HTTP 429**

Cause. The lockout tracker is full of live locks, which happens under a username-spraying attack.

Solution. This is the deliberate response, and it clears itself as locks expire. Refusing sign-ins loudly is the lesser failure: the alternative is silently not counting failures, which would disable brute-force protection for every account while the console still reported lockout as enabled.

**Message: "You were signed out due to inactivity" or "Your session reached its time limit"**

Cause. Not an error. Sessions carry an idle timeout, 30 minutes by default, and an absolute lifetime, 12 hours by default.

Solution. Sign in again. An administrator can shorten either window per scope, and a per-role policy can shorten it further but never lengthen it.

## Discovery finds nothing {#discovery-finds-nothing}

Condition. A scan completed and no devices appeared under **Infrastructure → Devices**.

Causes and solutions, in order of likelihood.

1. **Reachability.** Confirm the deployment host can reach the management subnet on UDP 161. A firewall or ACL on the path is the most common cause. See [Connectivity requirements](/reference/connectivity-requirements).
2. **Range.** Confirm the devices are inside the scanned CIDR ranges. Discovery reports only hosts that are both in range and answering SNMP.
3. **Credential.** Confirm a stored credential works across the range, under **Administration → Data Collection → SNMP Profiles**. A v2c community does not onboard a v3-only device.
4. **Device side.** Confirm the SNMP agent is enabled and its ACL permits the deployment host's source address.
5. Re-run the scan after each fix. The full procedure is [Discover devices](/onboard-devices/snmp-discovery).

## Device stays Down or Degraded {#device-stays-down-or-degraded}

Condition. The status dot under **Infrastructure → Devices** is amber or red. The dot reflects heartbeat freshness: **Up** means heard from within 5 minutes, **Degraded** means stale for 5 to 15 minutes or the device has an active alert, and **Down** means nothing for more than 15 minutes.

Causes and solutions.

1. **Amber with recent data.** Check **Operations → Active Alerts**. A reachable but unhealthy device reads Degraded on purpose. Resolve the alert and the dot returns to green.
2. **Red, or never green.** Verify UDP 161 reachability from the deployment host to the device's management address.
3. Verify SNMP is enabled on the device and permits the host's source address.
4. Verify the credential matches: the right community or user, and the right SNMP version. Attach a per-device credential if this device differs from the default. See [SNMP profiles](/onboard-devices/snmp-profiles).
5. Verify the management address on the device record. A typo polls the wrong host indefinitely.

## No SNMP metrics {#no-snmp-metrics}

Condition. The device is listed, and its SNMP metrics cell under **Administration → Data Collection → Data Sources** reads no data.

Causes and solutions.

1. Work the [Device stays Down](#device-stays-down-or-degraded) checks first. A device that cannot be polled cannot produce metrics.
2. Confirm a credential is actually attached, either per device or a default that authenticates against this device.
3. Wait one full poll cycle, which is 60 seconds, after each change, then re-check. See [Data sources](/onboard-devices/data-sources).
4. If some families appear and others do not, check [Metric families](/reference/metrics). Several families come only from a vendor profile, and a few names in the product are produced by no shipped collector at all.

## No syslog or traps {#no-syslog-or-traps}

Condition. Syslog or Traps reads no data while SNMP metrics is green. These are push planes. Correlix cannot fetch them, so the device has to send.

Causes and solutions.

1. Confirm the device is configured to send to the deployment address on the right port. Syslog listens on UDP and TCP 514 and on UDP and TCP 5514. Traps listen on UDP 162. See [Send syslog](/send-data/syslog) and [Send traps](/send-data/traps).
2. Confirm the source address the device sends from is one Correlix knows for that device, normally its management address. A message sourced from a loopback, or one that crosses NAT, arrives and attaches to no device. Fix it with the device's source-interface setting.
3. Confirm the path allows the port inbound. UDP drops silently, so a firewall block looks identical to a device that is not sending.
4. For traps specifically, confirm `FEATURE_SNMP_TRAPS` is on. The host port is published either way, so a port scan showing 162 open is not evidence that the receiver is running.
5. Generate a test event, then look for it under **Explore → Logs** and **Explore → Events** within a minute.

## No flows {#no-flows}

Condition. The Flows column reads no data.

Causes and solutions.

1. Confirm flow export is configured on the device toward the deployment address and the matching port: NetFlow on UDP 2055, IPFIX on UDP 4739, sFlow on UDP 6343. See [Send flows](/send-data/flows).
2. On sampled protocols, confirm a sampling rate is set. With no sampling there are no records.
3. Confirm the path allows the port inbound.
4. Flows exist only where traffic flows. Push traffic through a monitored interface, then check **Explore → Flows**.

## Panels show a dash or 0% {#panels-show--or-0}

**A panel shows a dash.** This is honest rather than broken. That metric is not being collected for that device. Either the plane that feeds it is not onboarded, or a prerequisite value has not been read yet. Interface utilisation needs the interface speed, for example. Confirm what is actually collected on the [coverage matrix](/onboard-devices/data-sources), and check [Metric families](/reference/metrics) for whether any collector emits that family at all.

**Utilisation shows 0%.** Usually the link is genuinely idle: a small amount of traffic divided by the link speed rounds to zero. Utilisation reflects the last polling window. Push traffic across the link and watch the sparkline on [WAN interface metrics](/infrastructure/wan-interface-metrics).

The two states are different facts. A dash means not measured. A zero means measured as zero.

## A module answers 404 {#a-module-answers-404}

Condition. A route documented in this portal answers `404`, and the console does not show the feature.

Causes.

1. **The feature's flag is off.** A module that is off does not register its routes at all, so a flag-off deployment does not even enumerate the feature. The BMP routes behave this way: with `FEATURE_BMP` off, `/api/bgp/bmp/sessions`, `/api/bgp/bmp/updates` and `/api/bgp/bmp/stats` all answer `404`.
2. **The resource belongs to another tenant.** Cross-tenant access to a resource by id returns `404`, identical to an id that does not exist, so another tenant's ids are never revealed. This applies to devices, processors, API keys and catalog templates alike.

Solutions.

1. Check the flag and its shipped default in [Feature flags](/reference/feature-flags), then enable it and restart the affected service.
2. If you expected a resource you own, confirm which tenant you are acting as. A platform administrator scoped into one tenant sees only that tenant. The acting tenant follows every page and every query.

## A route answers 403 {#a-route-answers-403}

Condition. You hold `administration:admin` and a route still answers `403 platform administrator required`.

Cause. The surface is platform-global plumbing rather than per-tenant data. Authentication providers, token policy, notification channels, regions topology, stack configuration and the parser statistics are gated on being the platform owner, not on holding an admin level. A tenant or organization administrator holds full `administration:admin` inside their own tenant, so a scope-blind admin check on platform-global configuration would be a privilege leak.

Solutions.

1. Read which plane the surface is on in the [Administration overview](/administration/overview).
2. Ask the platform administrator to make the change.
3. The refusal is recorded. It appears in the [audit log](/administration/audit-log) with decision `deny` and the status the caller received.

Two other `403` messages have different causes. `tenant suspended` means the owning tenant is [suspended](/administration/tenants-orgs#suspend-a-tenant). `source address not permitted for this API key` means the call came from outside the key's allowed CIDR list.

## Parser coverage answers 503 {#parser-coverage-answers-503}

Condition. `GET /api/telemetry/unrecognized` answers `503` with `no admission verdict available for this lane`.

Causes.

1. **No document in the window carries the ingest admission stamp.** The endpoint defines an unrecognized line as a document the admission stamp did not admit. Without the stamp there is no verdict to read.
2. **You asked for the trap lane.** The SNMP trap lane publishes no admission stamp, so unrecognized-shape mining is not defined for it. The syslog lane is the one that is.

Solutions.

1. Confirm syslog is actually arriving and being indexed. See [No syslog or traps](#no-syslog-or-traps).
2. Confirm the ingest pipeline is running the admission-stamp configuration. The error names the file and the generator that produces it.
3. Widen the window with `days`, up to 30.

The endpoint will not guess the verdict, and it will not re-derive it. An empty list here would read as "your network sends nothing the parser cannot handle", which is the opposite of what an unstamped window means. See [Check telemetry parser coverage](/administration/telemetry-coverage).

## Protocol diagnostics cannot collect {#protocol-diagnostics-cannot-collect}

Condition. `POST /api/troubleshoot/protocol-diagnostics/collect` answers `503 protocol-diagnostics collector is not configured on this deployment`.

Cause. No capture transport is wired. `FEATURE_PROTOCOL_DIAG_COLLECT` is off by default, and with it off there is no SSH runner to reach the device.

Solutions.

1. Paste the device output by hand. The analyze route works on pasted output and matches it against the same signature catalog.
2. Enable the collector: set `FEATURE_PROTOCOL_DIAG_COLLECT`, provide the SSH credential, and confirm outbound TCP 22 to the device. See [Collect from a device](/investigate/collect-from-a-device).

The refusal is deliberate. Correlix returns an honest `503` rather than a fabricated capture, because a diagnostic built on invented output is worse than no diagnostic. Note that a device you cannot see answers `404` before this check runs, so a `503` means the device is yours and the transport is missing.

## The BGP watchlist is not initialised {#the-bgp-watchlist-is-not-initialised}

Condition. A `/api/bgp/watchlist` call answers `503 BGP watchlist store is not initialised`.

Cause. This is a construction failure, not a deployment shape. The watchlist ships with two backends and one of them is always chosen: PostgreSQL with row-level security when a relational store is configured, and a tenant-keyed file register otherwise. A deployment without PostgreSQL still has a working watchlist.

Solutions.

1. Check the API's startup log. The store is selected at boot, so a failure there is the cause.
2. Do not add a database to fix this. The file backend exists precisely so that the watchlist, the RPKI view, the live-feed view and the alerting evaluator work without one.

A separate `403` on a watchlist write means something else: a cross-tenant principal must scope into a concrete tenant with the tenant switcher before writing. The write is refused rather than applied to every tenant.

## Sealed fields answer 501 {#sealed-fields-answer-501}

Condition. `POST /api/pipeline/processors/unseal` or `POST /api/pipeline/processors/seal/rotate` answers `501 sealed fields are not enabled on this deployment`.

Cause. `FEATURE_SEALED_FIELDS` is off, which is the shipped default.

Solutions.

1. If you do not seal values, nothing is wrong. The access trail still reads and is genuinely empty.
2. To enable sealing you need both the flag and real key custody through `SEAL_PROVIDER`. With the flag on and no custody the API refuses to start rather than running with sealing inert, so there is no state in which the feature reports itself on while values pass through in plaintext. See [Review sensitive-data access](/administration/sensitive-data-access).

## The audit log looks empty {#the-audit-log-looks-empty}

Condition. The audit page shows no rows, or a total you do not believe.

Causes and solutions.

1. **Successful reads are not recorded.** Only mutations and denials are. If you expected a `GET` that succeeded, it is not there by design.
2. **A `503` is not an empty trail.** The message is explicit: `audit trail is temporarily unreadable; this is NOT an empty trail — retry`. Retry rather than recording a clean bill of health.
3. **A total of `-1` means unknown.** On the relational backend a failed count returns `-1`, never `0`, so that a failure cannot render as "nobody did anything".
4. **Check your scope.** A tenant administrator sees only their own tenant's events.
5. **Check the window.** `before` and `since` take RFC 3339 timestamps, and a malformed value is refused by name rather than being replaced with a default.

## Still stuck

- Ask [Iris](/iris-ai/ask-iris) in the console. It reasons over this deployment's own state.
- Re-check the [Connectivity requirements](/reference/connectivity-requirements) port table against your firewall rules.
- Walk the layer checks in [Verify a device is monitored](/onboard-devices/verify-monitoring) to find exactly which layer breaks.
- Read [Honest states](/reference/honest-states) for the general rule behind every refusal on this page.
