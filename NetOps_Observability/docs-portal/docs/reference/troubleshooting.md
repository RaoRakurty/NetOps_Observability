---
title: Troubleshooting onboarding
sidebar_label: Troubleshooting
sidebar_position: 3
description: Symptom-indexed diagnostics — sign-in, discovery, device status, and every "No data" column.
---

# Troubleshooting

Find your symptom in the index, then work the numbered checks **top to bottom** — they're ordered from most to least likely. Most onboarding issues are reachability or credentials; most sign-in issues resolve themselves or need an admin.

| Symptom | Jump to |
| --- | --- |
| Can't sign in / account locked / signed out | [Sign-in problems](#sign-in-problems) |
| Discovery finds nothing | [Discovery finds nothing](#discovery-finds-nothing) |
| Device status dot stays red or amber | [Device stays Down or Degraded](#device-stays-down-or-degraded) |
| "SNMP metrics" column shows no data | [No SNMP metrics](#no-snmp-metrics) |
| "Syslog" or "Traps" column shows no data | [No syslog or traps](#no-syslog-or-traps) |
| "Flows" column shows no data | [No flows](#no-flows) |
| A dashboard panel shows "—" or 0% | [Panels show "—" or 0%](#panels-show--or-0) |

## Sign-in problems {#sign-in-problems}

**"Invalid credentials" on a correct-looking password**

1. Confirm you picked the right **method** — a directory (LDAP/TACACS+) account won't authenticate as a **Local account**, and vice versa. The selector is above the username field.
2. If your account uses **MFA**, the password step succeeds first and the 6-digit code is asked second — a rejected *code* usually means the authenticator app's clock has drifted or the code expired mid-typing; wait for the next code.
3. Still failing → an administrator can check your account status (active / invited / disabled) under <kbd>Administration → Identity & Access</kbd>. See [Authentication](/administration/authentication).

**"Account temporarily locked due to failed sign-ins"**

Repeated failures trigger a temporary lockout that clears on its own after the configured window.

1. Wait a few minutes and try once with the correct password — more wrong guesses extend the lock.
2. If you're locked out of the only admin account, another administrator can review sign-in policy and sessions under <kbd>Administration</kbd>.

**"You were signed out due to inactivity" / "Your session reached its time limit"**

Not an error — server-side sessions have an idle timeout and an absolute lifetime. Sign in again; work in open tabs is not lost by navigation-free views, but assume unsaved form input is gone. If timeouts feel too aggressive, an administrator can tune session policy.

## Discovery finds nothing {#discovery-finds-nothing}

You ran a discovery scan and no devices appeared in <kbd>Infrastructure → Devices</kbd>.

1. **Range** — are the target devices actually inside the scanned CIDR range(s)? Discovery only reports hosts that are both in range *and* answering SNMP.
2. **Reachability** — can the Correlix host reach the management subnet on **UDP 161**? Check firewalls/ACLs along the path first; this is the #1 cause. See [Connectivity requirements](/reference/connectivity-requirements).
3. **Credential** — is there a stored credential that works across the range (<kbd>Administration → Data Collection → SNMP Profile Manager</kbd>)? A v2c community won't onboard v3-only devices.
4. **SNMP on the devices** — is the agent enabled, and does its ACL allow Correlix's source address?
5. Re-run and re-check — discovery is idempotent, so re-running never creates duplicates. Full procedure: [Discover devices](/onboard-devices/snmp-discovery).

## Device stays Down or Degraded {#device-stays-down-or-degraded}

The status dot in <kbd>Infrastructure → Devices</kbd> reflects heartbeat freshness: **Up** (green) = heard from within 5 minutes; **Degraded** (amber) = stale for 5–15 minutes *or* the device has active alerts; **Down** (red) = nothing for over 15 minutes.

1. **Amber with recent data?** Check <kbd>Monitoring → Active Alerts</kbd> — a reachable-but-sick device reads Degraded on purpose. Resolve the alert and the dot returns to green.
2. **Red / never went green:** verify UDP 161 reachability from Correlix to the device's management IP (firewall/ACL on the path).
3. Verify **SNMP is enabled** on the device and permits Correlix's source address.
4. Verify the **credential matches** — right community/user, right SNMP version. Attach a per-device credential if this device differs from your default. See [SNMP profiles & credentials](/onboard-devices/snmp-profiles).
5. Verify the **management IP is correct** in the device record (a typo polls the wrong host forever).

## No SNMP metrics {#no-snmp-metrics}

The device is listed, but its **SNMP metrics** cell in <kbd>Administration → Data Collection → Data Sources</kbd> stays "no data".

1. Run the [Device stays Down](#device-stays-down-or-degraded) checks — a device that can't be polled can't produce metrics.
2. Confirm a **credential is actually attached** — per-device, or a default that authenticates against this device.
3. Wait one full poll cycle (~1 minute) after fixing anything, then re-check the matrix. See [Data Sources & coverage](/onboard-devices/data-sources).

## No syslog or traps {#no-syslog-or-traps}

**Syslog** or **Traps** stays "no data" while SNMP metrics is green. These are *push* planes — Correlix can't fetch them; the device must send.

1. Confirm the device is **configured to send** to Correlix's address on UDP **514** (syslog) / UDP **162** (traps) — device-side CLI examples in [Send syslog](/send-data/syslog) and [Send traps](/send-data/traps).
2. Confirm the **source IP** the device sends from is one Correlix knows for that device (its management IP). Loopback-sourced or NAT'd messages arrive but attribute to nothing — fix with the device's source-interface setting.
3. Confirm the path **allows UDP 514 / 162 inbound** to Correlix — UDP drops silently, so a firewall block looks identical to "device not sending".
4. Generate a test event (bounce a lab interface, exit config mode) and look for it in <kbd>Logs → Log Search</kbd> and <kbd>Monitoring → Events</kbd> within a minute.

## No flows {#no-flows}

1. Confirm **flow export is configured** on the device toward Correlix's address and the right port — NetFlow **2055**, IPFIX **4739**, sFlow **6343**. Device-side examples: [Send flows](/send-data/flows).
2. On sampled protocols (sFlow, sampled NetFlow), confirm a **sampling rate is set** — no samples, no records.
3. Confirm the path allows the flow **UDP port inbound**.
4. Flows only exist where traffic flows — send some traffic through a monitored interface, then check the **Flows** column and the <kbd>Flows</kbd> explorer.

## Panels show "—" or 0% {#panels-show--or-0}

**A panel shows "—"** — this is honest, not an error: that specific metric isn't being collected for that device yet. Common causes: the plane that feeds it isn't onboarded (e.g. flows), or a prerequisite value hasn't been read yet (utilization needs the interface speed). Confirm what's actually collected on the [coverage matrix](/onboard-devices/data-sources).

**Utilization shows 0%** — usually the link is genuinely idle: a little traffic divided by link speed rounds to zero. Utilization reflects the last polling window; push traffic across the link and watch it move — each interface on [WAN Interface Metrics](/infrastructure/wan-interface-metrics) has a live sparkline for exactly this test.

## Still stuck?

- Ask **[Iris AI](/iris-ai/overview)** in the console — e.g. *"why isn't leaf1 collecting SNMP?"* — it can reason over your instance's own state.
- Re-check the [Connectivity requirements](/reference/connectivity-requirements) port table against your firewall rules.
- Walk the four-layer check in [Verify a device is monitored](/onboard-devices/verify-monitoring) to find exactly which layer breaks.
