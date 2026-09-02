package secapi

// query.go — the OpenSearch query BUILDERS. Every function here is PURE (a
// Filters + a tenant clause in, a body map out) so the exact wire shape is
// byte-pinnable in a test, which is the only way an isolation clause can be
// proven never to have been dropped.
//
// FIELD CONTRACT (the half of the pair whose other half is
// deployment/docker/vector-router/vector.yaml + the netops-secfindings index
// template). The router writes the secbus EvidenceEvent shape: the
// classification (status, control, standards, scan id, evidence class) rides in
// `attrs.*`, and identity/severity/seam ride at the top level. The index
// template ALSO declares the direct secfindings.Finding json names so a future
// direct-Finding writer cannot land unmapped — but nothing writes them today.
//
//	QUERIES AND AGGREGATIONS THEREFORE PIN THE WIRE SHAPE, and DECODING accepts
//	both (see finding.go). If a direct-Finding writer is ever added, the field
//	constants below and the decoder must be extended TOGETHER — a filter and a
//	facet that disagree about which field they read is worse than either.
import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Indexed field names, in one place so a mapping change is a single edit.
const (
	FieldTime          = "ts"            // canonical event time, epoch millis (the &log_lane contract)
	FieldDocID         = "cx_finding_id" // sha2(native_id|scan_id) — the document _id
	FieldNativeID      = "native_id"     // the producer's deterministic verdict identity
	FieldSeverity      = "severity"
	FieldStatus        = "attrs.status"
	FieldStatusID      = "attrs.status_id"
	FieldSeamType      = "seam_type"
	FieldSeamID        = "seam_id"
	FieldFramework     = "attrs.standards"
	FieldEvidenceClass = "attrs.evidence_class"
	FieldScanID        = "attrs.scan_id"
	FieldControlID     = "attrs.control_id"
	FieldControlTitle  = "attrs.control_title"
	FieldRawRuleID     = "attrs.raw_rule_id"
	FieldEntityID      = "entity_id"
	FieldEntityTokens  = "entity_tokens"
)

// searchFields is the bounded field list free text searches. It spans the
// narrative TEXT fields the index template declares and the keyword fields the
// wire shape actually carries today, with lenient:true so a keyword field in
// the list can never turn a search into a 400.
//
// HONESTY: observed/intended/status_detail/remediation are declared in the
// mapping but are NOT on the bus wire — secbus deliberately keeps narrative and
// raw evidence OFF the bus (§5c by-reference, LLM06 no payloads). Until a
// direct-Finding writer exists, `q` matches control ids/titles, rule ids and the
// device, not the narrative.
var searchFields = []string{
	FieldControlTitle,
	FieldControlID,
	FieldRawRuleID,
	FieldEntityID,
	"title",
	"control_title",
	"observed",
	"intended",
	"detail",
	"status_detail",
	"remediation",
}

// currentFoldSource is the projection a current-state fold pulls back per
// group. Narrow on purpose: the fold reads one document per native_id, and the
// difference between this list and `_source: true` is the difference between a
// bounded aggregation and dragging the whole document set through the heap.
var currentFoldSource = []string{
	FieldSeverity, FieldStatus, FieldSeamType, FieldSeamID,
	FieldFramework, FieldEvidenceClass, FieldEntityID, FieldScanID, FieldTime,
}

// TrendBuckets is the accepted ?bucket= vocabulary → the OpenSearch
// fixed_interval it maps to. A closed vocabulary (never a passthrough string)
// is what keeps an interval out of the DSL that the caller chose the cost of.
var TrendBuckets = map[string]string{
	"1h":  "1h",
	"6h":  "6h",
	"12h": "12h",
	"1d":  "1d",
	"7d":  "7d",
	"30d": "30d",
}

// trendBucketOrder pins the vocabulary order in error messages.
var trendBucketOrder = []string{"1h", "6h", "12h", "1d", "7d", "30d"}

// trendIntervalSpan is each accepted interval's real duration. It exists
// because time.ParseDuration cannot read "1d" (Go has no day unit) while
// OpenSearch's fixed_interval can — so the bucket-count guard needs its own
// table rather than re-parsing the DSL token.
var trendIntervalSpan = map[string]time.Duration{
	"1h":  time.Hour,
	"6h":  6 * time.Hour,
	"12h": 12 * time.Hour,
	"1d":  24 * time.Hour,
	"7d":  7 * 24 * time.Hour,
	"30d": 30 * 24 * time.Hour,
}

// ParseBucket folds ?bucket= onto the accepted vocabulary; "" means the 1d
// default. An unknown bucket is an error, never a silent fallback — a caller
// who asked for 1h and silently received 1d is reading a different chart than
// the one they requested.
func ParseBucket(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return TrendBuckets["1d"], nil
	}
	iv, ok := TrendBuckets[strings.ToLower(s)]
	if !ok {
		return "", fmt.Errorf("bucket must be one of %s (got %q)", strings.Join(trendBucketOrder, ", "), s)
	}
	return iv, nil
}

// anyOf builds a bool/should over one logical field that is stored under more
// than one physical name (seam type vs seam id, device uid vs entity token).
func anyOf(clauses ...any) map[string]any {
	return map[string]any{"bool": map[string]any{
		"should":               clauses,
		"minimum_should_match": 1,
	}}
}

// BuildFilters renders the filter clause list for a Filters set. tenantClause is
// oslog.TenantFilter's output — nil for the platform owner (cross-tenant), the
// per-doc isolation clause for everyone else — and is placed FIRST so it is
// visible at the head of every pinned body: a diff that drops it is unmissable.
func BuildFilters(f Filters, tenantClause map[string]any) []any {
	clauses := make([]any, 0, 8)
	if tenantClause != nil {
		clauses = append(clauses, tenantClause)
	}
	clauses = append(clauses, map[string]any{"range": map[string]any{FieldTime: map[string]any{
		"gte":    f.Since.UTC().Format(time.RFC3339),
		"lte":    f.Until.UTC().Format(time.RFC3339),
		"format": "strict_date_optional_time",
	}}})
	if len(f.Severity) > 0 {
		clauses = append(clauses, map[string]any{"terms": map[string]any{FieldSeverity: f.Severity}})
	}
	if len(f.Status) > 0 {
		clauses = append(clauses, map[string]any{"terms": map[string]any{FieldStatus: f.Status}})
	}
	if len(f.Seam) > 0 {
		// A seam filter names either the seam TYPE ("ISP", "internet") or a
		// specific seam id; both are keyword fields on the doc.
		clauses = append(clauses, anyOf(
			map[string]any{"terms": map[string]any{FieldSeamType: f.Seam}},
			map[string]any{"terms": map[string]any{FieldSeamID: f.Seam}},
		))
	}
	if len(f.Framework) > 0 {
		clauses = append(clauses, map[string]any{"terms": map[string]any{FieldFramework: f.Framework}})
	}
	if len(f.Device) > 0 {
		// The subject is grounded as entity_id; entity_tokens additionally
		// carries the device:/host: co-location keys, so a caller may filter by
		// either the device id or its hostname.
		clauses = append(clauses, anyOf(
			map[string]any{"terms": map[string]any{FieldEntityID: f.Device}},
			map[string]any{"terms": map[string]any{FieldEntityTokens: f.Device}},
		))
	}
	if f.Q != "" {
		clauses = append(clauses, map[string]any{"simple_query_string": map[string]any{
			"query":            f.Q,
			"fields":           searchFields,
			"default_operator": "and",
			"lenient":          true,
		}})
	}
	return clauses
}

// BuildQuery wraps the filter list in the bool query every read shares.
func BuildQuery(f Filters, tenantClause map[string]any) map[string]any {
	return map[string]any{"bool": map[string]any{"filter": BuildFilters(f, tenantClause)}}
}

// MaxResultWindow mirrors OpenSearch's index.max_result_window default. It
// bounds the COLLAPSED page path, which pages by offset (see PagePos) and
// therefore cannot walk past the window the way a keyset can.
const MaxResultWindow = 10000

// PagePos is the resolved position of one page. Exactly one half is used, and
// WHICH one is decided by the collapse — not by preference:
//
//	After — the (ts desc, doc id desc) KEYSET, for the uncollapsed list. It
//	        pages arbitrarily deep at constant cost.
//	From  — a result-window OFFSET, for the CURRENT-state (collapsed) list.
//
// The split is forced by OpenSearch, not chosen: verified live against the
// deployed 2.16 cluster, a body carrying both `collapse` and `search_after` is
// REJECTED — "cannot use `collapse` in conjunction with `search_after`" — before
// the mapping is even consulted. `collapse` + `from`/`size` IS accepted (also
// verified live), so the collapsed list pages by offset, the cursor carries that
// offset opaquely, and the handler refuses to page past MaxResultWindow rather
// than silently serving a short page.
type PagePos struct {
	After []any
	From  int
}

// ListBody builds the findings page.
//
// CURRENT-STATE COLLAPSE (the decision record's "Doc identity" section): every
// scan's verdict is RETAINED, so the list of "what is true now" is a QUERY-TIME
// collapse, not a mutable upsert. `collapse: {field: native_id}` with the
// (ts desc, doc id desc) sort returns exactly the newest verdict per verdict
// identity in one pass. The exact total then has to come from a cardinality
// aggregation over native_id — hits.total counts DOCUMENTS, i.e. every
// historical verdict, and would inflate the number the CTEM page is built on.
// precision_threshold is set above any page this API will serve, so the count
// is exact at the sizes that matter.
func ListBody(f Filters, tenantClause map[string]any, size int, pos PagePos) map[string]any {
	body := map[string]any{
		"size":    size,
		"query":   BuildQuery(f, tenantClause),
		"_source": true,
		"sort": []any{
			map[string]any{FieldTime: map[string]any{"order": "desc", "unmapped_type": "date"}},
			map[string]any{FieldDocID: map[string]any{"order": "desc", "unmapped_type": "keyword"}},
		},
	}
	if f.Current {
		body["collapse"] = map[string]any{"field": FieldNativeID}
		body["aggs"] = map[string]any{"current_total": map[string]any{
			"cardinality": map[string]any{"field": FieldNativeID, "precision_threshold": 40000},
		}}
		if pos.From > 0 {
			body["from"] = pos.From
		}
		return body
	}
	// Exact totals, always (owner directive: DON'T HIDE) — without this
	// OpenSearch caps hits.total at 10k and a capped page would understate how
	// much actually matched.
	body["track_total_hits"] = true
	if len(pos.After) > 0 {
		body["search_after"] = pos.After
	}
	return body
}

// GetBody builds the single-document lookup. It is a normal SEARCH over the
// caller's index pattern rather than a GET /_doc: the pattern is the isolation
// boundary, and a doc-id GET would have to name a concrete index (which the
// caller does not know) or scan every one (which would reach another tenant's).
// Zero hits is the ONLY answer for both "no such finding" and "another
// tenant's finding" — the handler turns it into 404 either way.
func GetBody(id string, tenantClause map[string]any, since, until time.Time) map[string]any {
	f := Filters{Since: since, Until: until}
	clauses := append(BuildFilters(f, tenantClause),
		map[string]any{"term": map[string]any{FieldDocID: id}})
	return map[string]any{
		"size":             1,
		"track_total_hits": false,
		"query":            map[string]any{"bool": map[string]any{"filter": clauses}},
		"sort":             []any{map[string]any{FieldTime: map[string]any{"order": "desc", "unmapped_type": "date"}}},
	}
}

// facetAggs are the five terms aggregations the facets contract names.
func facetAggs() map[string]any {
	terms := func(field string) map[string]any {
		return map[string]any{"terms": map[string]any{
			"field": field,
			"size":  MaxFacetTerms,
			// Deterministic tie-breaking so two identical counts do not swap
			// order between polls and make the UI flicker.
			"order": []any{
				map[string]any{"_count": "desc"},
				map[string]any{"_key": "asc"},
			},
		}}
	}
	return map[string]any{
		"severity":       terms(FieldSeverity),
		"status":         terms(FieldStatus),
		"seam":           terms(FieldSeamType),
		"framework":      terms(FieldFramework),
		"evidence_class": terms(FieldEvidenceClass),
	}
}

// FacetsBody builds the facet counts over EVERY retained verdict in the window.
func FacetsBody(f Filters, tenantClause map[string]any) map[string]any {
	return map[string]any{
		"size":             0,
		"track_total_hits": true,
		"query":            BuildQuery(f, tenantClause),
		"aggs":             facetAggs(),
	}
}

// CurrentFoldBody builds the CURRENT-state fold: one bucket per native_id with
// the newest verdict in it. Facets and the CTEM funnel are folded from these
// buckets in Go rather than from a plain terms aggregation, because a terms agg
// over the raw index counts every historical verdict — a control that failed in
// 30 consecutive scans would appear 30 times in "current exposures" and inflate
// every funnel number the page is built on.
//
// It is BOUNDED by MaxCurrentGroups; `native_total` (a cardinality over the same
// field) says how many groups actually exist, so the handler can report an
// honest truncation instead of a quietly short answer.
func CurrentFoldBody(f Filters, tenantClause map[string]any, groups int) map[string]any {
	return map[string]any{
		"size":             0,
		"track_total_hits": false,
		"query":            BuildQuery(f, tenantClause),
		"aggs": map[string]any{
			"native_total": map[string]any{
				"cardinality": map[string]any{"field": FieldNativeID, "precision_threshold": 40000},
			},
			"by_native": map[string]any{
				"terms": map[string]any{
					"field": FieldNativeID,
					"size":  groups,
					"order": []any{map[string]any{"_key": "asc"}},
				},
				"aggs": map[string]any{
					"latest": map[string]any{"top_hits": map[string]any{
						"size":    1,
						"sort":    []any{map[string]any{FieldTime: map[string]any{"order": "desc"}}},
						"_source": map[string]any{"includes": currentFoldSource},
					}},
				},
			},
		},
	}
}

// TrendBody builds the date_histogram + status breakdown.
//
// `current` is deliberately NOT applied here: a trend IS the history, and
// collapsing to the latest verdict per identity before bucketing by time would
// draw every finding at one instant and call it a trend. The handler documents
// this and the parameter is accepted (so one filter set drives every panel)
// without changing the answer.
func TrendBody(f Filters, tenantClause map[string]any, interval string) map[string]any {
	return map[string]any{
		"size":             0,
		"track_total_hits": false,
		"query":            BuildQuery(f, tenantClause),
		"aggs": map[string]any{
			"trend": map[string]any{
				"date_histogram": map[string]any{
					"field":          FieldTime,
					"fixed_interval": interval,
					"min_doc_count":  0,
					"extended_bounds": map[string]any{
						"min": f.Since.UTC().Format(time.RFC3339),
						"max": f.Until.UTC().Format(time.RFC3339),
					},
				},
				"aggs": map[string]any{
					"status": map[string]any{"terms": map[string]any{
						"field": FieldStatus,
						"size":  len(StatusFacetKeys),
					}},
				},
			},
		},
	}
}

// TrendBucketCount is how many buckets a window/interval pair will produce. The
// handler calls it BEFORE issuing the query and refuses over MaxTrendBuckets:
// min_doc_count 0 + extended_bounds makes the histogram dense, so a 365-day
// window at a 1h interval is 8,760 buckets of response the caller chose the
// cost of. Refusing is the F-71 posture — a silently coarsened interval would
// answer a different question with a 200.
func TrendBucketCount(f Filters, interval string) (int, error) {
	iv, ok := trendIntervalSpan[interval]
	if !ok || iv <= 0 {
		return 0, fmt.Errorf("unsupported trend interval %q", interval)
	}
	span := f.Until.Sub(f.Since)
	if span <= 0 {
		return 0, fmt.Errorf("empty time range")
	}
	return int(span/iv) + 1, nil
}

// CoverageBody counts the DISTINCT assessed devices in the window (the coverage
// denominator's numerator) and names the most recent scan. Both are single
// aggregations over the already-filtered set — never a document scan.
func CoverageBody(f Filters, tenantClause map[string]any) map[string]any {
	return map[string]any{
		"size":             0,
		"track_total_hits": false,
		"query":            BuildQuery(f, tenantClause),
		"aggs": map[string]any{
			"assessed_devices": map[string]any{
				"cardinality": map[string]any{"field": FieldEntityID, "precision_threshold": 40000},
			},
			"last_scan": map[string]any{"top_hits": map[string]any{
				"size":    1,
				"sort":    []any{map[string]any{FieldTime: map[string]any{"order": "desc"}}},
				"_source": map[string]any{"includes": []string{FieldScanID, FieldTime}},
			}},
		},
	}
}

// ---- cursor ----------------------------------------------------------------

// Cursor is a decoded page position. It is an OPAQUE token to the client on
// purpose: which of the two paging mechanisms is in play is an OpenSearch
// constraint, not something a caller should have to know or track.
type Cursor struct {
	// Collapsed marks an offset cursor (the current-state list).
	Collapsed bool
	// Millis/DocID are the keyset values of an uncollapsed cursor.
	Millis int64
	DocID  string
	// Offset is the result-window position of a collapsed cursor.
	Offset int
}

// EncodeKeysetCursor renders the cursor over the (ts desc, cx_finding_id desc)
// sort. It needs its own codec rather than reusing the events feed's: a
// finding's document id is the sha2(native_id|scan_id) hex digest, not a UUID,
// so decodeFeedCursor would reject every valid cursor this API produces.
func EncodeKeysetCursor(tsMillis int64, docID string) string {
	return base64.RawURLEncoding.EncodeToString(
		[]byte("k|" + strconv.FormatInt(tsMillis, 10) + "|" + docID))
}

// EncodeOffsetCursor renders the collapsed list's opaque offset cursor.
func EncodeOffsetCursor(offset int) string {
	return base64.RawURLEncoding.EncodeToString([]byte("c|" + strconv.Itoa(offset)))
}

// DecodeCursor parses a cursor. ok=false for anything malformed; the caller then
// serves page 1 rather than 500 (the correlations-list precedent — a stale
// cursor is a client-side artefact, not an outage).
func DecodeCursor(s string) (Cursor, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return Cursor{}, false
	}
	kind, rest, found := strings.Cut(string(raw), "|")
	if !found {
		return Cursor{}, false
	}
	switch kind {
	case "c":
		n, err := strconv.Atoi(rest)
		if err != nil || n < 0 || n > MaxResultWindow {
			return Cursor{}, false
		}
		return Cursor{Collapsed: true, Offset: n}, true
	case "k":
		msPart, id, ok := strings.Cut(rest, "|")
		if !ok {
			return Cursor{}, false
		}
		ms, err := strconv.ParseInt(msPart, 10, 64)
		if err != nil || ms < 0 || !isSafeToken(id) {
			return Cursor{}, false
		}
		return Cursor{Millis: ms, DocID: id}, true
	default:
		return Cursor{}, false
	}
}
