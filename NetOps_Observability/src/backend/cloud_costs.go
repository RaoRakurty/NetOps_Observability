package main

// cloud_costs.go — the cloud cost read surface (Wave 5 #18 slice 2).
//
//   GET /api/cloud/costs?provider=&account=&service=&from=&to=&limit=
//
// Serves the normalized daily cost records the cloud poller ingests from the
// providers' OWN cost APIs (AWS Cost Explorer / Azure Cost Management) into
// ClickHouse netops.cloud_costs via the netops.cloudcosts bus topic. Every row
// is a figure the provider itself billed; when nothing landed (no billing
// access connected), the endpoint returns an empty list and the UI shows its
// honest empty state — we never synthesize a cost.
//
// Tenant isolation (§3a): every query carries the caller's tenant_scope
// SETTINGS clause, enforced by the STRICT tenant_iso_cloud_costs row policy in
// ClickHouse itself (billing data is per-tenant financial data — no
// untagged-shared clause). Bounded (#100): the read is day-range-pruned
// (partitioned by (tenant_id, month)) with a hard window ceiling and a LIMIT.
//
// This file also owns the table's boot-converge DDL (cloudCostsSchemaDDL,
// appended to chConvergeStmts) so existing deployments converge without
// manual SQL — init.sql carries the identical DDL for fresh installs.

import (
	"errors"
	"fmt"
	"net/http"
	"netops/backend/internal/chschema"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	// Default read window when the caller names none: the last 30 billed days.
	cloudCostDefaultWindowDays = 30
	// Hard ceiling: ~a quarter. Anything wider clamps here, never silently
	// widens (the honored window is echoed back).
	cloudCostMaxWindowDays = 92
	cloudCostDefaultLimit  = 500
	cloudCostMaxLimit      = 2000
	cloudCostServiceMaxLen = 128
)

// cloudCostsSchemaDDL is the boot-converge DDL for the cost store: table +
// STRICT tenant row policy (atomic OR REPLACE via chschema.StrictRowPolicyDDL — no
// policyless window, self-heals a reset access store). Mirrors init.sql.
func cloudCostsSchemaDDL() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS netops.cloud_costs
(
    ts              DateTime64(3) DEFAULT now64(3),
    day             Date,
    tenant_id       LowCardinality(String) DEFAULT '',
    provider        LowCardinality(String),
    account         String,
    service         String,
    amount          Float64,
    currency        LowCardinality(String),
    granularity     LowCardinality(String) DEFAULT 'daily',
    collection_path LowCardinality(String) DEFAULT ''
)
ENGINE = ReplacingMergeTree(ts)
PARTITION BY (tenant_id, toYYYYMM(day))
ORDER BY (tenant_id, provider, account, service, day)
TTL day + INTERVAL 400 DAY
SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1`,
		chschema.StrictRowPolicyDDL("cloud_costs"),
	}
}

// ── pure helpers (unit-tested in cloud_costs_test.go) ────────────────────────

var costDayRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// costDayOK validates a caller-supplied day literal before it is embedded in
// the query (toDate('...')). Strict form only — anything else fails closed.
func costDayOK(s string) bool {
	if !costDayRe.MatchString(s) {
		return false
	}
	_, err := time.Parse("2006-01-02", s)
	return err == nil
}

// costProviderOK: the provider filter is a closed enum, never free text.
func costProviderOK(p string) bool {
	return p == "aws" || p == "azure" || p == "gcp"
}

// costAccountOK bounds the account filter: AWS account ids, Azure subscription
// GUIDs and GCP project ids are all [A-Za-z0-9._-] tokens.
func costAccountOK(a string) bool {
	if a == "" || len(a) > 64 {
		return false
	}
	for _, c := range a {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '.' || c == '_' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

// clampCostService normalizes the optional service filter (a provider billing
// service name — free text with spaces/parens, e.g. "Amazon Elastic Compute
// Cloud - Compute"): control characters stripped, length-capped. It is
// embedded ESCAPED as an exact-match literal, never a pattern.
func clampCostService(raw string) string {
	raw = strings.TrimSpace(raw)
	var b strings.Builder
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	s := b.String()
	if len(s) > cloudCostServiceMaxLen {
		s = s[:cloudCostServiceMaxLen]
	}
	return strings.TrimSpace(s)
}

// costWindow resolves the [from, to] day range: explicit valid days win,
// absent defaults to the last cloudCostDefaultWindowDays ending yesterday
// (the newest COMPLETE billed day — the in-flight day is never implied).
// A malformed day or an inverted range is a 400 (zero-trust: validate, never
// guess); a too-wide range clamps to the ceiling and the honored values are
// echoed back to the caller.
func costWindow(fromRaw, toRaw string, now time.Time) (from, to string, err error) {
	yesterday := now.UTC().AddDate(0, 0, -1).Format("2006-01-02")
	to = yesterday
	if toRaw != "" {
		if !costDayOK(toRaw) {
			return "", "", errors.New("invalid to day (want YYYY-MM-DD)")
		}
		to = toRaw
	}
	toT, _ := time.Parse("2006-01-02", to)
	from = toT.AddDate(0, 0, -(cloudCostDefaultWindowDays - 1)).Format("2006-01-02")
	if fromRaw != "" {
		if !costDayOK(fromRaw) {
			return "", "", errors.New("invalid from day (want YYYY-MM-DD)")
		}
		from = fromRaw
	}
	fromT, _ := time.Parse("2006-01-02", from)
	if fromT.After(toT) {
		return "", "", errors.New("from is after to")
	}
	if floor := toT.AddDate(0, 0, -(cloudCostMaxWindowDays - 1)); fromT.Before(floor) {
		from = floor.Format("2006-01-02")
	}
	return from, to, nil
}

// clampCostLimit bounds the caller-supplied row limit; junk/absent → default.
func clampCostLimit(raw string) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n <= 0 {
		return cloudCostDefaultLimit
	}
	if n > cloudCostMaxLimit {
		return cloudCostMaxLimit
	}
	return n
}

// costFilterSQL renders the optional provider/account/service predicates.
// Callers pass only pre-validated values (closed enum / token / clamped
// escaped literal) — nothing here is raw request input.
func costFilterSQL(provider, account, service string) string {
	var b strings.Builder
	if provider != "" {
		fmt.Fprintf(&b, " AND provider = '%s'", provider)
	}
	if account != "" {
		fmt.Fprintf(&b, " AND account = '%s'", account)
	}
	if service != "" {
		fmt.Fprintf(&b, " AND service = '%s'", escapeCHString(service))
	}
	return b.String()
}

// cloudCostsSQL is the ONE read this surface issues: day-range-pruned,
// LIMIT-bounded, FINAL (ReplacingMergeTree — restated days must read as the
// replaced row, not both versions), carrying the caller's tenant_scope for
// the STRICT row policy.
func cloudCostsSQL(fromDay, toDay, pred string, limit int, scope string) string {
	return fmt.Sprintf(`
SELECT toString(day)      AS day,
       toString(provider) AS provider,
       account            AS account,
       service            AS service,
       amount             AS amount,
       toString(currency) AS currency
  FROM netops.cloud_costs FINAL
 WHERE day >= toDate('%s') AND day <= toDate('%s')%s
 ORDER BY day DESC, provider, account, service
 LIMIT %d
 SETTINGS tenant_scope = '%s'
 FORMAT JSONEachRow`, fromDay, toDay, pred, limit, scope)
}

// chCostRow is one cost row as read from (and re-served as) JSON.
type chCostRow struct {
	Day      string  `json:"day"`
	Provider string  `json:"provider"`
	Account  string  `json:"account"`
	Service  string  `json:"service"`
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
}

// handleCloudCosts serves GET /api/cloud/costs — the tenant's own daily
// provider-billed cost records, newest day first.
func (s *server) handleCloudCosts(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET"))
		return
	}
	q := r.URL.Query()
	provider := strings.TrimSpace(q.Get("provider"))
	if provider != "" && !costProviderOK(provider) {
		writeError(w, http.StatusBadRequest, errors.New("invalid provider"))
		return
	}
	account := strings.TrimSpace(q.Get("account"))
	if account != "" && !costAccountOK(account) {
		writeError(w, http.StatusBadRequest, errors.New("invalid account"))
		return
	}
	service := clampCostService(q.Get("service"))
	from, to, err := costWindow(q.Get("from"), q.Get("to"), time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	limit := clampCostLimit(q.Get("limit"))
	rows := chJSONRows[chCostRow](cloudCostsSQL(
		from, to, costFilterSQL(provider, account, service), limit,
		safeScopeLiteral(chTenantScope(r))))
	if rows == nil {
		rows = []chCostRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"costs": rows,
		"count": len(rows),
		// the HONORED window — the UI label never claims a range the data
		// doesn't cover (clamps are echoed, never silent).
		"from":      from,
		"to":        to,
		"truncated": len(rows) == limit,
	})
}
