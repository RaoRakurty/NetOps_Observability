# Parse coverage alerts

The `parse-coverage` group in `src/config/rules-scale-slo.yaml` (warning tier, never
pages) watches the VALUE of `parser_status`, because the field being present proves
nothing: it is present on every record, including when its value is `unparsed`. That is
how Cisco SD-WAN syslog sat 100% unparsed with nothing raised (tracker 387).

Counters: `netops_parse_status_events{lane,vendor,parser_id,parser_status}`,
`netops_trap_varbinds{vendor,resolution}` and
`netops_flow_enrichment_events{exporter,sampling,as_numbers}` on vector-router, and
`corr_syslog_high_severity_no_signal_total` on the correlation engine.

## ParseLaneStuckUnparsed

A lane has been at least 99% unparsed for over an hour, above a volume floor. Unparsed
means `unparsed` on syslog and `raw_only` on traps; a partly decoded trap was read.

1. Open **Telemetry coverage** and read **Coverage by vendor**. "Not covered yet" on the
   vendor sending the lines is the usual answer: there is no vendor pack for it.
2. If the records read vendor `unknown`, inventory does not know the sender and the text
   matched nothing. Check that the device is discovered, under the name it sends.
3. If a covered vendor is at 0%, suspect the framing before the grammar: the message may
   not be reaching Stage B in the shape the grammar expects.

The remedy is a pack in `telemetry-catalog/vendor-packs/` or a framing fix. Records are
stored either way; nothing is lost while this fires.

## ParseUnparsedShareRose

A lane that was parsing has stopped: the unparsed share over the last hour is well above
the previous six. Usual causes are a software upgrade changing a format, a grammar or
framing change we shipped, or a new device type. Read the new shapes under **Unrecognized
message shapes** on the same page.

A lane that was always unparsed cannot fire this one. That is what
`ParseLaneStuckUnparsed` is for.

## EngineIgnoredHighSeverityLinesRose

The engine read an error-or-worse severity from a line's own text, a grammar's alarm floor
kept it from the generic net, and no typed or `known_benign` row took it (owner decision D3:
only qualifying critical events open an incident alone). The lines are stored and
searchable, but none reach RCA. The count spans the prefilter and the classifier, since a
pack's literal usually lets its lines past the prefilter.

It reads zero on Cisco SD-WAN today, which is a true answer: that pack's `below_floor` rows
take these lines at `warn`, so they can join a component without opening one. It exists for
the pack that ships without such a row. A steady count is expected, since a device can repeat
a benign error every few seconds. A rise usually means a fault nobody has written a rule for. Read the lines, then add a typed
rule, or a `known_benign` row if it really is noise. Never lower the alarm floor to clear
this alert: that is the false-incident problem D3 exists to prevent.

## Deploy-time reading

`scripts/deploy-qualify.sh` prints the same ratio per lane as advisory check Q10. It never
fails a deploy: the lane's records are still stored.

## Scorecard ratchet

`telemetry-catalog/vendor_coverage_floor.json` holds a floor for each count on the
scorecard, and `scripts/gen-vendor-coverage.py --check` fails CI when one drops. Lowering a
floor is a hand edit, in a diff somebody reviews.
