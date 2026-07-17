package main

// ch_time_wire.go — ClickHouse → API wire format for timestamps (log-time
// standard, docs/design/log-time-standard.md rule R1 / slice S3).
//
// ClickHouse's toString(DateTime64) renders a ZONE-LESS string
// ("2026-07-16 21:56:03.562") in the server timezone. JavaScript — and any
// naive consumer — parses such strings as LOCAL time, which is exactly the
// mixed-zone display defect audited as F11/F12. Every ClickHouse-backed
// SELECT therefore renders datetimes with chISO: explicit UTC, RFC 3339
// ("2026-07-16T21:56:03.562Z"), so the instant is unambiguous on the wire
// regardless of the ClickHouse server timezone.
//
// Server-side consumers of these strings (parseChTS, parseCHTime,
// ticketing/report layouts) accept both RFC 3339 and the legacy zone-less
// form, so mixed fleets during rollout stay readable.

// chISO wraps a ClickHouse DateTime/DateTime64 SQL expression (a column,
// or an aggregate like max(ts)) so it is SELECTed as an RFC 3339 UTC string.
// Sub-second precision follows the column type, exactly as toString did.
func chISO(expr string) string {
	return "concat(replaceOne(toString(" + expr + ", 'UTC'), ' ', 'T'), 'Z')"
}
