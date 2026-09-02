package igpmon

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// events.go — the typed adjacency-change signals, read tenant-scoped from the
// correlation spine.
//
// Two tables, not one. `netops.corr_signals` is the live raw spine (30-day TTL);
// `netops.corr_signals_archive` is where a signal lands when it is attached to a
// correlation object. A signal can be in either or both, so an adjacency
// timeline that reads only one is silently short. They are UNION ALL'd and
// deduplicated on signal_id, which is deterministic (UUIDv5 over
// source+native_id+ts) and therefore identical across the two tables.
//
// Both tables carry the tenant_iso FORCE row policy keyed on the `tenant_scope`
// custom setting, so the scope passed to CHQuery — NOT this file's WHERE clause
// — is the enforcing boundary. The WHERE clause narrows; the policy isolates.

// Table names, named once so the pinned SQL test and the query cannot drift.
const (
	tableSignals = "netops.corr_signals"
	tableArchive = "netops.corr_signals_archive"
)

// scopeReadsNothing reports whether a ClickHouse tenant_scope literal admits no
// rows at all. An unauthenticated or tenant-less principal fails closed here
// rather than reaching the DB with a scope the policy might not recognize.
func scopeReadsNothing(scope string) bool {
	s := strings.TrimSpace(scope)
	return s == "" || s == "__none__"
}

// chToken keeps only the characters valid in a device / entity identifier so an
// interpolated ClickHouse string literal cannot be used for injection. Quotes
// and backslashes are DROPPED, not escaped (the house shape-validate rule), and
// the result is length-bounded. An identifier that loses characters here simply
// will not match a row — which is the safe direction.
func chToken(v string) string {
	v = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '.' || r == '_' || r == ':' || r == '-' || r == '/':
			return r
		default:
			return -1
		}
	}, v)
	if len(v) > 128 {
		v = v[:128]
	}
	return v
}

// chList renders a validated identifier set as a ClickHouse IN list. Empty
// input yields "" so the caller can omit the predicate entirely.
func chList(vals []string) string {
	out := make([]string, 0, len(vals))
	seen := make(map[string]bool, len(vals))
	for _, v := range vals {
		t := chToken(v)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, "'"+t+"'")
	}
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, ",")
}

// encodeCursor / decodeCursor implement the keyset position over
// (ts DESC, signal_id DESC) — the same shape the unified event feed uses.
func encodeCursor(tsMillis int64, signalID string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%d|%s", tsMillis, signalID)))
}

func decodeCursor(s string) (millis int64, signalID string, ok bool) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return 0, "", false
	}
	ms, sid, found := strings.Cut(string(raw), "|")
	if !found {
		return 0, "", false
	}
	m, err := strconv.ParseInt(ms, 10, 64)
	if err != nil || m < 0 || !isUUIDToken(sid) {
		return 0, "", false
	}
	return m, sid, true
}

// isUUIDToken validates the cursor's signal_id half: 36 characters, hex and
// dashes only. A cursor is caller-supplied input and is interpolated into SQL.
func isUUIDToken(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
				return false
			}
		}
	}
	return true
}

// eventsSQL builds the bounded, keyset-paginated adjacency-change read.
//
// It is a pure function of an already-validated EventQuery so the exact SQL can
// be pinned by a test: the isolation properties of a query you cannot see are
// the ones that rot.
func eventsSQL(q EventQuery) string {
	pred := []string{
		"kind = '" + chToken(q.Kind) + "'",
		"entity_type = 'device'",
		fmt.Sprintf("ts >= fromUnixTimestamp64Milli(toInt64(%d))", q.SinceMS),
	}
	if in := chList(q.Devices); in != "" {
		pred = append(pred, "entity_id IN ("+in+")")
	}
	if q.CursorMS > 0 && q.CursorID != "" {
		pred = append(pred, fmt.Sprintf(
			"(toUnixTimestamp64Milli(ts), toString(signal_id)) < (toInt64(%d), '%s')",
			q.CursorMS, chToken(q.CursorID)))
	}
	where := strings.Join(pred, " AND ")
	const cols = `toUnixTimestamp64Milli(ts) AS ts_ms, toString(signal_id) AS signal_id, ` +
		`toString(source) AS source, entity_id AS device, toString(severity) AS severity, ` +
		`JSONExtractString(attrs,'peer') AS peer, JSONExtractString(attrs,'state') AS state, ` +
		`JSONExtractString(attrs,'ifname') AS ifname`
	// Over-fetch so the cross-table dedup cannot hand back a short page, but
	// keep the over-fetch itself bounded (§9: every read has a ceiling).
	fetch := q.Limit * 2
	if fetch > maxFetchRows {
		fetch = maxFetchRows
	}
	return "SELECT ts_ms, signal_id, source, device, severity, peer, state, ifname FROM (" +
		" SELECT " + cols + " FROM " + tableSignals + " WHERE " + where +
		" UNION ALL" +
		" SELECT " + cols + " FROM " + tableArchive + " WHERE " + where +
		" ) ORDER BY ts_ms DESC, signal_id DESC LIMIT " + strconv.Itoa(fetch) + " FORMAT JSON"
}

// maxFetchRows caps the raw row count any single ClickHouse read may pull back,
// independent of the caller's limit.
const maxFetchRows = 4000

// fetchEvents runs the read and returns deduplicated events, newest first.
// A scope that admits nothing short-circuits before the DB is touched.
func (a *API) fetchEvents(ctx context.Context, scope string, q EventQuery) ([]Event, error) {
	if scopeReadsNothing(scope) {
		return nil, nil
	}
	rows, err := a.deps.CHQuery(ctx, scope, eventsSQL(q))
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(rows))
	out := make([]Event, 0, len(rows))
	for _, r := range rows {
		id := cellString(r["signal_id"])
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ms := cellInt(r["ts_ms"])
		out = append(out, Event{
			TSMillis: ms,
			TS:       time.UnixMilli(ms).UTC().Format(time.RFC3339Nano),
			SignalID: id,
			Device:   cellString(r["device"]),
			Peer:     cellString(r["peer"]),
			IfName:   cellString(r["ifname"]),
			State:    normalizeEventState(cellString(r["state"])),
			Severity: cellString(r["severity"]),
			Source:   cellString(r["source"]),
		})
	}
	// The UNION arms are each ordered, but the dedup pass must not assume the
	// engine preserved a total order across them.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].TSMillis != out[j].TSMillis {
			return out[i].TSMillis > out[j].TSMillis
		}
		return out[i].SignalID > out[j].SignalID
	})
	return out, nil
}

// normalizeEventState maps the parser's emitted state vocabulary onto the three
// values the timeline speaks. The parsers emit exactly up/down/unknown
// (parser_rules.py state scans), and an unrecognized value stays "unknown"
// rather than being guessed into up.
func normalizeEventState(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "up":
		return "up"
	case "down":
		return "down"
	case "":
		return "unknown"
	default:
		return "unknown"
	}
}

// cellString reads a ClickHouse FORMAT JSON cell as a string.
func cellString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", x)
	}
}

// cellInt reads a ClickHouse FORMAT JSON cell as an int64. 64-bit integers come
// back QUOTED by default (output_format_json_quote_64bit_integers), so both
// shapes have to be accepted or every timestamp silently becomes zero.
func cellInt(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}
