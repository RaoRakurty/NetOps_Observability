# Syslog frames the platform cannot read

**Alert:** `SyslogBadFramesRising` (warning). **Counter:** `netops_ingest_syslog_bad_frames{reason}`, from the router.

## What it means

More frames than usual are reaching syslog-ng in a shape it cannot read as syslog. Nothing is lost: each one is stored with its whole text in `message_original`. But the engine gets no severity from it, so a device sending these is not being read.

The alert compares the last 15 minutes with the 6 hours before, so one sender that is always wrong clears by itself after about 2 hours. The counter keeps counting.

| `reason` | The frame |
|---|---|
| `malformed_pri` | Starts with `<` but has no valid priority: empty, not a number, or above 191 |
| `malformed_5424` | Starts like RFC 5424 (`<PRI>1 `) but is truncated or has a bad timestamp |
| `no_pri` | Has no priority at all. Also the tail of a TCP line longer than 32 KiB |
| `oversized` | Is at least 32 KiB, so it may have lost its end |

## What to do

1. Find the sender. In Logs, search `frame_problem:<reason>` and read `source_ip` on the results.
2. Open a record and read `message_original`, which is the frame as received.
3. If a device changed firmware or logging format, check its syslog settings. If the shape is real and valid, add an `edge_shapes` row to a vendor pack (`telemetry-catalog/README.md`).
4. If the sender is not a network device, block it from the syslog port: the port has no authentication.
