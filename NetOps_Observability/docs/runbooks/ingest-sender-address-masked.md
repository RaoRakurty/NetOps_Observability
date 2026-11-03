<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Correlix -->

# Devices' sender addresses lost to the Docker bridge gateway

Alert: **IngestSenderAddressMasked** (warning). The collector status for
`snmptrap` may also say "trap(s) arrived from the Docker bridge gateway".
Tracker 373.

## What it means

Syslog, SNMP traps and NetFlow/IPFIX identify the device by the packet's
**source address**. Some of these packets are reaching Correlix from the
Docker bridge gateway (for example `172.18.0.1`) instead of from the device.
The gateway can never be a real device, so these events:

- cannot be matched to a device or a tenant;
- stay searchable in Log Search, but never feed root-cause analysis.

The devices sending most often (often the ones that are failing) are hit first.

## Why it happens

1. **A stale connection-tracking entry after a container restart.** While a
   receiver container is being recreated, a device that keeps sending (every
   few seconds, from the same source port) creates a conntrack entry with no
   port forwarding. Docker clears such entries when it re-creates the mapping,
   but since Docker Engine 29.5.0 it only clears entries for the **container**
   port (moby#53384). If the host port differs from the container port, the
   stale entry survives, and Docker's userland proxy re-sends the packets from
   the gateway. Correlix publishes every telemetry UDP port with host port =
   container port so Docker's own clean-up covers it; this alert catches what
   remains (Docker 29.5.0, older engines, overrides).
2. **IPv6 senders.** The Correlix network is IPv4. A device sending over IPv6
   is relayed by Docker's proxy and always arrives from the gateway. Send
   telemetry over IPv4.

## Fix

On the Correlix host, as root:

```sh
# 1. See the stale entries: the reply source is the host address, not the
#    container (a healthy entry shows the container address, e.g. 172.18.0.21).
conntrack -L -p udp --orig-port-dst 162

# 2. Clear them for every published telemetry port. Deleting UDP entries is
#    safe: the next packet creates a fresh, correctly forwarded entry.
for p in 162 514 5514 2055 4739 6343; do conntrack -D -p udp --orig-port-dst "$p"; done
```

`conntrack` is in the `conntrack` package (`apt-get install conntrack`,
`dnf install conntrack-tools`). "0 flow entries have been deleted" is fine.

Without installing a package, a short pause also works (drops traps for about
two minutes):

```sh
iptables -t raw -I PREROUTING -p udp --dport 162 -j DROP; sleep 130
iptables -t raw -D PREROUTING -p udp --dport 162 -j DROP
iptables -t raw -S PREROUTING   # confirm the rule is gone
```

## Check

- The alert clears within about 15 minutes.
- In Log Search, new traps from the device show its own address as the host,
  and the `snmptrap` collector no longer reports the gateway.
- `netops_ingest_source_masked_events` stops increasing.

## If you changed a telemetry port

`SNMP_TRAP_PORT`, `SYSLOG_PORT`, `NETFLOW_PORT`, `IPFIX_PORT` and `SFLOW_PORT`
move both the host and the container side together. Do not edit the compose
`ports:` entries by hand to map one port to a different one;
`tests/test_compose_udp_port_parity.py` guards this.
