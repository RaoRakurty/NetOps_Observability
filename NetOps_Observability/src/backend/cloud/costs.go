package cloud

// costs.go — the cloud-cost surface domain (Phase-2 W4.9, extracted from
// package main's cloud_costs.go): the schema DDL (composed into main's
// converge set — the W(phase-1)-55 inversion), the shape validators
// (day/provider/account/service), the bounded window and limit clamps, and
// the injection-safe filter + read SQL. The handler and its CH proxy stay in
// main.

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/chschema"
)

const (
	// Default read window when the caller names none: the last 30 billed days.
	CostDefaultWindowDays = 30
	// Hard ceiling: ~a quarter. Anything wider clamps here, never silently
	// widens (the honored window is echoed back).
	CostMaxWindowDays = 92
	CostDefaultLimit  = 500
	CostMaxLimit      = 2000
	CostServiceMaxLen = 128
)

// CostsSchemaDDL is the boot-converge DDL for the cost store: table +
// STRICT tenant row policy (atomic OR REPLACE via chschema.StrictRowPolicyDDL — no
// policyless window, self-heals a reset access store). Mirrors init.sql.
func CostsSchemaDDL() []string {
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

// CostDayOK validates a caller-supplied day literal before it is embedded in
// the query (toDate('...')). Strict form only — anything else fails closed.
func CostDayOK(s string) bool {
	if !costDayRe.MatchString(s) {
		return false
	}
	_, err := time.Parse("2006-01-02", s)
	return err == nil
}

// CostProviderOK: the provider filter is a closed enum, never free text.
func CostProviderOK(p string) bool {
	return p == "aws" || p == "azure" || p == "gcp"
}

// CostAccountOK bounds the account filter: AWS account ids, Azure subscription
// GUIDs and GCP project ids are all [A-Za-z0-9._-] tokens.
func CostAccountOK(a string) bool {
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

// ClampCostService normalizes the optional service filter (a provider billing
// service name — free text with spaces/parens, e.g. "Amazon Elastic Compute
// Cloud - Compute"): control characters stripped, length-capped. It is
// embedded ESCAPED as an exact-match literal, never a pattern.
func ClampCostService(raw string) string {
	raw = strings.TrimSpace(raw)
	var b strings.Builder
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	s := b.String()
	if len(s) > CostServiceMaxLen {
		s = s[:CostServiceMaxLen]
	}
	return strings.TrimSpace(s)
}

// CostWindow resolves the [from, to] day range: explicit valid days win,
// absent defaults to the last CostDefaultWindowDays ending yesterday
// (the newest COMPLETE billed day — the in-flight day is never implied).
// A malformed day or an inverted range is a 400 (zero-trust: validate, never
// guess); a too-wide range clamps to the ceiling and the honored values are
// echoed back to the caller.
func CostWindow(fromRaw, toRaw string, now time.Time) (from, to string, err error) {
	yesterday := now.UTC().AddDate(0, 0, -1).Format("2006-01-02")
	to = yesterday
	if toRaw != "" {
		if !CostDayOK(toRaw) {
			return "", "", errors.New("invalid to day (want YYYY-MM-DD)")
		}
		to = toRaw
	}
	toT, _ := time.Parse("2006-01-02", to) // discard: CostDayOK above vetted the format
	from = toT.AddDate(0, 0, -(CostDefaultWindowDays - 1)).Format("2006-01-02")
	if fromRaw != "" {
		if !CostDayOK(fromRaw) {
			return "", "", errors.New("invalid from day (want YYYY-MM-DD)")
		}
		from = fromRaw
	}
	fromT, _ := time.Parse("2006-01-02", from) // discard: CostDayOK above vetted the format
	if fromT.After(toT) {
		return "", "", errors.New("from is after to")
	}
	if floor := toT.AddDate(0, 0, -(CostMaxWindowDays - 1)); fromT.Before(floor) {
		from = floor.Format("2006-01-02")
	}
	return from, to, nil
}

// ClampCostLimit bounds the caller-supplied row limit; junk/absent → default.
func ClampCostLimit(raw string) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n <= 0 {
		return CostDefaultLimit
	}
	if n > CostMaxLimit {
		return CostMaxLimit
	}
	return n
}

// CostFilterSQL renders the optional provider/account/service predicates.
// Callers pass only pre-validated values (closed enum / token / clamped
// escaped literal) — nothing here is raw request input.
func CostFilterSQL(provider, account, service string) string {
	var b strings.Builder
	if provider != "" {
		fmt.Fprintf(&b, " AND provider = '%s'", provider)
	}
	if account != "" {
		fmt.Fprintf(&b, " AND account = '%s'", account)
	}
	if service != "" {
		fmt.Fprintf(&b, " AND service = '%s'", EscapeCH(service))
	}
	return b.String()
}

// The day predicate and ORDER BY are TABLE-QUALIFIED (cloud_costs.day) on
// purpose. `toString(day) AS day` is a projection alias that shadows the Date
// column, and ClickHouse resolves a SELECT alias inside the WHERE and ORDER BY
// of the same query — so the unqualified form compared the String expression to
// toDate() and the server refused the whole surface with
//
//	Code: 386. DB::Exception: There is no supertype for types String, Date …
//	(NO_COMMON_TYPE)
//
// Qualification is the minimal fix here because the alias names are also the
// served wire fields (CostRow); alias resolution does not touch a qualified
// name, so the predicate binds the raw Date and the JSON contract is unchanged.
//
// CostsSQL is the ONE read this surface issues: day-range-pruned,
// LIMIT-bounded, FINAL (ReplacingMergeTree — restated days must read as the
// replaced row, not both versions), carrying the caller's tenant_scope for
// the STRICT row policy.
func CostsSQL(fromDay, toDay, pred string, limit int, scope string) string {
	return fmt.Sprintf(`
SELECT toString(day)      AS day,
       toString(provider) AS provider,
       account            AS account,
       service            AS service,
       amount             AS amount,
       toString(currency) AS currency
  FROM netops.cloud_costs FINAL
 WHERE cloud_costs.day >= toDate('%s') AND cloud_costs.day <= toDate('%s')%s
 ORDER BY cloud_costs.day DESC, cloud_costs.provider, account, service
 LIMIT %d
 SETTINGS tenant_scope = '%s'
 FORMAT JSONEachRow`, fromDay, toDay, pred, limit, scope)
}

// CostRow is one cost row as read from (and re-served as) JSON.
type CostRow struct {
	Day      string  `json:"day"`
	Provider string  `json:"provider"`
	Account  string  `json:"account"`
	Service  string  `json:"service"`
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
}

// handleCloudCosts serves GET /api/cloud/costs — the tenant's own daily
// provider-billed cost records, newest day first.
