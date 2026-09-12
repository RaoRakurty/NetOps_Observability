---
title: Capture packets on a device
description: Run a bounded on-device packet capture on one interface, write a filter the allowlist grammar accepts, and download the sealed result.
page_type: task
sidebar_position: 14
---

# Capture packets on a device

A capture collects packets on one interface of one device for a bounded time,
fetches the file, seals it under your tenant key, and makes it available to
download. It is an explicit, audited operator action. There is no scheduler and
no sweep.

## Before you begin

- `FEATURE_PACKET_CAPTURE` must be `true` on the backend. It defaults to off,
  and with it off no capture route is registered: every path answers `404`, so
  the feature is not enumerable. On the lab stack:

  ```bash
  curl -s -H "Authorization: Bearer $TOKEN" \
    http://localhost:8000/api/devices/spine1/pcap
  ```

  ```text
  404 page not found
  ```

- `SEAL_PROVIDER` must be configured. Correlix refuses to start the module
  rather than store packet captures in cleartext.
- Capture credentials: `PCAP_SSH_USER` plus either `PCAP_SSH_PASSWORD` or
  `PCAP_SSH_KEY`.
- A role with `infrastructure:write` to start, download or delete a capture.
  `infrastructure:read` is enough to list captures and read their status.
- A device on a supported platform: Cisco IOS-XE, Cisco NX-OS, Juniper Junos or
  Arista EOS.

## Steps

1. Go to **Infrastructure → Devices** and select the device.
2. Select the **Packet capture** tab.
3. Choose an **Interface**, or type one when no interface list is available.
4. Set **Duration** on the slider. The range is 1 to 60 seconds.
5. Set **Max packets**. The range is 1 to 10,000.
6. Enter a **Filter (optional)**, for example `host 10.0.0.1 and port 179`.
7. Select **Start capture**.
8. Wait for the row to reach **Done**, then select **Download**.

## Result

The capture appears in the history table and moves through its states. The
console polls until it reaches a terminal state.

| Status | What it means |
|---|---|
| **Running** | The capture is still collecting on the device |
| **Done** | The capture finished and the file is available to download |
| **Failed** | The capture did not complete, and the reason is on the row |
| **Expired** | Retention closed and the file was deleted. The counts are what the capture recorded; the packets are gone |

The API answers `202 Accepted` on start:

```json
{"capture_id": "…", "status": "running", "expires_at": "…"}
```

The download is served as `application/vnd.tcpdump.pcap` with a filename built
only from server-minted ids.

An empty history says nothing was captured, not that nothing was there.

## The guardrails

The bounds are not configurable. An operator knob that could raise the maximum
capture duration to an hour would be the same unbounded capture the design
forbids, wearing a configuration file.

| Bound | Value |
|---|---|
| Duration | 60 seconds maximum, 30 seconds when the request omits it |
| Packets | 10,000 maximum, 2000 when the request omits it |
| File size | 25 MiB |
| Concurrency | One capture per device at a time |
| Filter length | 256 characters |
| Interface name | 64 characters, starting with a letter |

A breach of any bound is a `400` naming the bound, not a silent clamp. An
operator who asked for a ten-minute capture must be told they cannot have one,
because a silently shortened capture is a capture that missed the event it was
meant to catch.

- Duration too long: `duration_s must be 60 seconds or less (a packet capture
  is a bounded, privileged action on a production device — there is no
  unbounded capture)`.
- Too many packets: `max_packets must be 10000 or less`.
- A second capture on the same device: `409` with `a packet capture is already
  running for this device`.
- A file that would exceed 25 MiB: the capture is marked failed with
  `packet capture exceeded the maximum capture size`. It is never truncated
  into a short file that would look valid.

Teardown is unconditional. The cleanup command runs on every exit path,
including a failed fetch and a failed seal, with its own fresh timeout, so a
capture point is not left configured on a production interface. A profile that
declares a capture start with no cleanup fails the build.

## The filter grammar

The filter you type never reaches the device. It is parsed against a closed
allowlist grammar, and the command is rebuilt from the validated tokens.

Accepted tokens:

| Token | Value it takes |
|---|---|
| `host` | An IP address |
| `net` | A network prefix, or a bare address |
| `port` | An integer from 0 to 65535 |
| `portrange` | `lo-hi`, both valid ports, `lo` not greater than `hi` |
| `vlan` | An integer from 0 to 4094 |
| Protocols | `ip`, `ip6`, `arp`, `rarp`, `tcp`, `udp`, `icmp`, `icmp6`, `sctp`, `broadcast`, `multicast` |
| Qualifiers | `src`, `dst`, `ether` |
| Logic | `and`, `or`, `not`, and parentheses |

Only letters, digits, `.`, `:`, `/`, `-`, parentheses and spaces are permitted.
Quotes, backticks, semicolons, pipes, ampersands, redirects, backslashes and
newlines are not in the character set at all. An unknown token is refused,
never passed through in case the device understands it.

The check runs on the character set first, then on the structure, then on each
value through the standard-library address and port parsers. The accepted
filter is re-rendered canonically as lowercase, single-spaced tokens.

A filter on a platform whose profile cannot apply one is **refused**, not run
unfiltered. Silently widening a capture you deliberately narrowed would collect
traffic you did not ask for.

## What happens to the file

- **Sealed at rest.** The blob is encrypted under a per-tenant key with the
  tenant, device and capture id bound into it, so a blob copied between tenants
  or devices fails to open rather than being served to the wrong operator. The
  blob store refuses to write anything that does not carry the seal marker.
- **Metadata only in the database.** A dumped database yields an inventory of
  captures, never a packet.
- **Retention is per device and count-based.** `PCAP_KEEP` defaults to 20,
  bounded between 1 and 200. A running capture is never pruned.
- **Download is `infrastructure:write`, deliberately not read.** Revealing
  payload is not a read-level act.

Three actions are audited with a `sensitive` tag: starting a capture
(`pcap_capture_started`), the moment packet payload leaves the device
(`pcap_capture_fetched`), and the download (`pcap_capture_downloaded`). The
download is written to the audit trail before a byte reaches the response.
Deleting a capture is audited too.

## What it does not do

- It does not reconfigure the device beyond the capture point, and it never
  leaves the capture point behind.
- It captures on **one interface**, one capture per device at a time.
- It never runs a shell command built from operator text.
- It never guesses a capture command for an unknown platform. That answers
  `no packet-capture command set is bound for this device's platform`.
- It has no scheduler, no worker and no background sweep.

## Related

- [Back up a device configuration](/security/config-backup)
- [Investigate a security finding](/security/investigate-a-finding)
- [Optional modules](/deploy/optional-modules)
- [Feature flags reference](/reference/feature-flags)
