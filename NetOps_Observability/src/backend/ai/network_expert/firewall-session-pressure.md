---
id: firewall-session-pressure
title: Firewall Session / Resource Pressure
fault_domains: firewall, security, forwarding, dc, wan
signals: device_session_count, firewall_session_drop, device_cpu_percent, device_mem_percent
keywords: firewall, session, conntrack, table full, cpu, memory, ngfw, fortigate, palo alto, drops, new connections
owner: Security / Firewall
---

# Firewall Session / Resource Pressure

## Symptoms
- New connections fail or are slow while existing ones work.
- Firewall session count near capacity; CPU/memory elevated.
- Intermittent drops correlate with traffic spikes.

## Common fault domains
- Session-table exhaustion (conntrack full).
- Control-plane CPU/memory pressure (logging, inspection, DoS).
- A traffic surge / scan inflating session creation.

## Correlix evidence to check
- device_session_count vs. platform capacity over time.
- device_cpu_percent / device_mem_percent on the firewall.
- Firewall deny/drop logs and new-connection failures.
- Flow surge or scan pattern feeding the session growth.

## Supporting evidence
- Session count climbing toward the platform limit before the drops.
- CPU/memory pressure coincident with the impact.

## Contradicting evidence
- Sessions and resources normal but drops present → policy/route, not pressure.
- Only one app affected → policy rule, not global session pressure.

## Missing evidence
- Per-policy session breakdown may not be exported.
- Inspection-engine internals not directly observable.

## Recommended owner
Security / Firewall team.

## Next actions
1. Compare session count to the platform capacity.
2. Check CPU/memory pressure in the same window.
3. Identify the traffic surge or scan driving session creation.
4. Mitigate (rate-limit the source, tune timeouts) and/or scale.
5. Confirm new-connection success recovers.

## Escalation note
Firewall <device> session pressure since <start UTC>: sessions <n>/<cap>, CPU <pct>, mem <pct>. Driver: <surge | scan | logging>.

## ITSM note template
Firewall <device> at <pct> session capacity since <start UTC>. New connections failing. Driver: <source/surge>. Action: <rate-limit | timeout tuning | scale>.
