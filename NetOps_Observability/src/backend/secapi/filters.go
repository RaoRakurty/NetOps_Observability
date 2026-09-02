// Package secapi is the READ surface over the security-findings store plus the
// small mutable control-plane state behind it (P3-API,
// docs/design/SECURITY_FINDINGS_STORE_DECISION_2026-08-28.md).
//
// It is a SUBPACKAGE, not another file in the flat root package (CLAUDE.md §2 +
// the root-package ratchet): the transports it needs are INJECTED as function
// seams on Deps — the OpenSearch client, the tenant-scoped ClickHouse reader,
// the device registry count and the authorization gate all live in package
// backend and are handed in, so this package depends on no core state and can
// be exercised without standing up a server.
//
// ISOLATION (CLAUDE.md §3a) is the package's first property, not a decoration:
//   - every OpenSearch read names ONLY the caller's own index pattern
//     (oslog.TenantIndexPattern) and carries the per-doc oslog.TenantFilter
//     clause — the identical chokepoint pair the applogs/flows handlers use;
//   - a finding id outside the caller's pattern answers 404, never 403 and
//     never another tenant's document;
//   - the PG control-plane state is read and written through WithTenant, under
//     the tenant_iso FORCE-RLS policy of migration 0037, and the file fallback
//     filters by tenant IN the store (there is no unscoped "list all");
//   - the tenant on every write is stamped from the authenticated principal;
//     a tenant in a request body or query string is ignored.
package secapi

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/secfindings"
)

// Query bounds. Every one of these exists because an unbounded value here is a
// read whose cost is chosen by the caller (§9 bounded IO, the #100 lesson).
const (
	// MaxListLimit caps one page of findings.
	MaxListLimit = 500
	// DefaultListLimit is the page size a caller that asks for none gets.
	DefaultListLimit = 100
	// MaxFacetTerms caps how many buckets a terms aggregation may return, so a
	// hostile or merely diverse field cannot turn a facet into a full scan.
	MaxFacetTerms = 50
	// MaxCurrentGroups caps the native_id fold used to answer "current state"
	// for facets/posture. Beyond it the answer is TRUNCATED and says so rather
	// than silently under-counting (see FoldTruncated).
	MaxCurrentGroups = 5000
	// MaxTrendBuckets caps a date_histogram.
	MaxTrendBuckets = 400
	// MaxFilterValues caps one multi-valued filter (severity=a,b,c…).
	MaxFilterValues = 20
	// MaxTokenLen caps one filter token.
	MaxTokenLen = 128
	// MaxQueryLen caps the free-text search string.
	MaxQueryLen = 256
	// MaxWindow is the widest time range a single query may span (365 days):
	// the index is date-partitioned, so an unbounded range is an unbounded
	// index pattern expansion.
	MaxWindow = 365 * 24 * time.Hour
	// DefaultWindow is the range applied when the caller names neither bound.
	DefaultWindow = 30 * 24 * time.Hour
)

// Severities is the accepted severity vocabulary (secfindings.Severity*). A
// token outside it is a 400, never a silently empty result: "?severity=hgih"
// answering 200 with nothing reads exactly like "you have no high findings".
var Severities = []string{
	secfindings.SeverityCritical,
	secfindings.SeverityHigh,
	secfindings.SeverityMedium,
	secfindings.SeverityLow,
	secfindings.SeverityInfo,
}

// PrioritySeverities are the severities the CTEM funnel counts as
// "prioritize". Declared here, off the secfindings constants, so a rename in
// the model is a compile error rather than a funnel that silently drops a
// severity tier and reads as an improvement in posture.
var PrioritySeverities = map[string]bool{
	secfindings.SeverityCritical: true,
	secfindings.SeverityHigh:     true,
}

// StatusAliases maps the API's status vocabulary onto the canonical
// secfindings status token STORED in the index (StatusID.String()). The UI
// speaks pass/warn/fail; the store speaks Pass/Warning/Fail. Both the honest
// non-verdicts (NotApplicable, Error) and the zero value (Unknown) are
// addressable on purpose — an unassessed control must be selectable, because
// the one thing it must never do is disappear into "clear".
var StatusAliases = map[string]string{
	"pass":           "Pass",
	"warn":           "Warning",
	"warning":        "Warning",
	"fail":           "Fail",
	"notapplicable":  "NotApplicable",
	"not_applicable": "NotApplicable",
	"na":             "NotApplicable",
	"error":          "Error",
	"unknown":        "Unknown",
}

// StatusFacetKeys is the response key each canonical status folds onto in the
// facets/trend payloads. pass/warn/fail are the three the contract names; the
// remaining three are additive and always present, so a caller can never read a
// non-verdict as a pass.
var StatusFacetKeys = map[string]string{
	"Pass":          "pass",
	"Warning":       "warn",
	"Fail":          "fail",
	"NotApplicable": "not_applicable",
	"Error":         "error",
	"Unknown":       "unknown",
}

// statusFacetOrder pins the response key order (map iteration is random; a
// byte-pinned test and a stable UI both need determinism).
var statusFacetOrder = []string{"pass", "warn", "fail", "not_applicable", "error", "unknown"}

// Filters is the validated, already-bounded parameter set behind every read.
// It is produced ONLY by ParseFilters (or by the saved-view path, which feeds
// the same parser) so no unvalidated caller string ever reaches a query body.
type Filters struct {
	Severity  []string // canonical severity tokens
	Status    []string // canonical secfindings status tokens ("Pass"…)
	Seam      []string // seam type or seam id
	Framework []string // standards tag (CIS/800-53/PCI/ATT&CK…)
	Device    []string // entity id / device uid / hostname
	Q         string   // free text over the narrative + title fields
	Since     time.Time
	Until     time.Time
	// Current selects the latest verdict per native_id (query-time collapse)
	// instead of every retained verdict.
	Current bool
}

// FilterQueryKeys are the filter parameters every findings route accepts. They
// are declared once so RejectUnknownQuery cannot drift from the parser (an
// accepted-but-unparsed parameter is the F-61 failure: a 200 for a request that
// was never honoured).
var FilterQueryKeys = []string{"severity", "status", "seam", "framework", "device", "q", "since", "until", "current"}

// isSafeToken reports whether a caller-supplied filter token is a plain
// identifier we are willing to put in a terms clause. It is deliberately
// restrictive (§3: all input is malicious): letters, digits and the punctuation
// real control ids, seam ids, CVEs and hostnames use.
func isSafeToken(s string) bool {
	if s == "" || len(s) > MaxTokenLen {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == ':', r == '/', r == '(', r == ')', r == '+':
		default:
			return false
		}
	}
	return true
}

// splitTokens parses one comma-separated multi-valued filter, deduping and
// bounding it. An empty parameter yields no clause (not an empty IN () that
// matches nothing).
func splitTokens(key, raw string, max int) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, 4)
	for _, part := range strings.Split(raw, ",") {
		t := strings.TrimSpace(part)
		if t == "" {
			continue
		}
		if !isSafeToken(t) {
			return nil, fmt.Errorf("%s contains an unsupported value %q", key, t)
		}
		if seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
		if len(out) > max {
			return nil, fmt.Errorf("%s accepts at most %d values", key, max)
		}
	}
	return out, nil
}

// oneOf folds each token onto the allowed vocabulary, case-insensitively, and
// dedupes AFTER folding — splitTokens dedupes the raw strings, so "HIGH,high"
// survives it as two tokens that are one value.
func oneOf(key string, tokens, allowed []string) ([]string, error) {
	out := make([]string, 0, len(tokens))
	seen := map[string]bool{}
	for _, t := range tokens {
		lower := strings.ToLower(t)
		ok := false
		for _, a := range allowed {
			if lower == a {
				if !seen[a] {
					seen[a] = true
					out = append(out, a)
				}
				ok = true
				break
			}
		}
		if !ok {
			return nil, fmt.Errorf("%s must be one of %s (got %q)", key, strings.Join(allowed, ", "), t)
		}
	}
	return out, nil
}

// ParseFilters validates the shared filter parameters off a request. Every
// failure is an ERROR the handler answers 400 with — never a silently ignored
// parameter, and never a clamp that returns fewer rows than were asked for with
// a 200 (audit F-57/F-71/F-74).
//
// now is injected so the default window is deterministic in tests.
func ParseFilters(r *http.Request, now time.Time) (Filters, error) {
	q := r.URL.Query()
	var f Filters
	var err error

	sev, err := splitTokens("severity", q.Get("severity"), MaxFilterValues)
	if err != nil {
		return Filters{}, err
	}
	if f.Severity, err = oneOf("severity", sev, Severities); err != nil {
		return Filters{}, err
	}

	statuses, err := splitTokens("status", q.Get("status"), MaxFilterValues)
	if err != nil {
		return Filters{}, err
	}
	for _, s := range statuses {
		canon, ok := StatusAliases[strings.ToLower(s)]
		if !ok {
			return Filters{}, fmt.Errorf("status must be one of pass, warn, fail, not_applicable, error, unknown (got %q)", s)
		}
		f.Status = append(f.Status, canon)
	}

	if f.Seam, err = splitTokens("seam", q.Get("seam"), MaxFilterValues); err != nil {
		return Filters{}, err
	}
	if f.Framework, err = splitTokens("framework", q.Get("framework"), MaxFilterValues); err != nil {
		return Filters{}, err
	}
	if f.Device, err = splitTokens("device", q.Get("device"), MaxFilterValues); err != nil {
		return Filters{}, err
	}

	f.Q = strings.TrimSpace(q.Get("q"))
	if len(f.Q) > MaxQueryLen {
		return Filters{}, fmt.Errorf("q must be at most %d characters", MaxQueryLen)
	}

	if f.Since, f.Until, err = parseWindow(q.Get("since"), q.Get("until"), now); err != nil {
		return Filters{}, err
	}

	switch strings.TrimSpace(q.Get("current")) {
	case "":
		f.Current = false
	case "1", "true", "TRUE", "True":
		f.Current = true
	case "0", "false", "FALSE", "False":
		f.Current = false
	default:
		return Filters{}, fmt.Errorf("current must be one of 1/0/true/false (got %q)", q.Get("current"))
	}
	return f, nil
}

// parseWindow resolves [since, until]. Both accept RFC3339 or a unix stamp (the
// oslog.ParseTimeFlexible vocabulary, duplicated here so this package does not
// depend on the log projection for a two-format parse). An inverted or
// over-wide range is a 400: silently swapping the bounds would answer a
// question the caller did not ask.
func parseWindow(since, until string, now time.Time) (time.Time, time.Time, error) {
	end := now.UTC()
	if s := strings.TrimSpace(until); s != "" {
		t, err := parseTime(s)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("until: %w", err)
		}
		end = t
	}
	start := end.Add(-DefaultWindow)
	if s := strings.TrimSpace(since); s != "" {
		t, err := parseTime(s)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("since: %w", err)
		}
		start = t
	}
	if !start.Before(end) {
		return time.Time{}, time.Time{}, fmt.Errorf("since must be strictly before until")
	}
	if end.Sub(start) > MaxWindow {
		return time.Time{}, time.Time{}, fmt.Errorf("time range must span at most %d days", int(MaxWindow.Hours()/24))
	}
	return start.UTC(), end.UTC(), nil
}

// parseTime accepts RFC3339 or a unix stamp (seconds or nanoseconds), the two
// shapes the Explore time picker and the API's own cursors already speak. An
// unrecognized value is an error — never "now".
func parseTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("unrecognized time %q (want RFC3339 or a unix stamp)", s)
	}
	if n > 1_000_000_000_000_000 {
		return time.Unix(0, n).UTC(), nil
	}
	return time.Unix(n, 0).UTC(), nil
}
