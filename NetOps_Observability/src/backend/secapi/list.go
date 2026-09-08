// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package secapi

// list.go — the NON-HTTP findings read.
//
// Everything else in this package answers an *http.Request. The AI assistant's
// read-only `get_security_findings` tool has no request: it is called from the
// orchestrator with an already-resolved principal. It must NOT get a private
// query path — a second way to reach the findings index is a second way to get
// the isolation wrong (§3a rule 4: the storage layer enforces it, in ONE place).
//
// So this is the same three steps HandleFindings takes, minus the HTTP framing:
// scope(p) derives the index pattern + per-doc tenant clause, ListBody builds
// the query, DecodeFinding reads the rows. The filter set is re-validated here
// because it did NOT come through ParseFilters — a struct literal is exactly the
// path that could otherwise put an unvalidated token in a terms clause.

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrNoSearch reports that no findings backend is configured on this
// deployment. Callers turn it into "this capability is not wired" — never into
// an empty result, which would read as "you have no findings" (the same
// distinction search() makes for a non-2xx upstream).
var ErrNoSearch = errors.New("secapi: no findings search backend is configured")

// ListFindings returns one bounded page of the PRINCIPAL'S OWN findings, newest
// first. It is the non-HTTP twin of HandleFindings: same scope, same query
// body, same decoder — so a change to the isolation clause cannot reach one
// caller and miss the other.
//
// limit is clamped into [1, MaxListLimit]. There is no cursor: this path exists
// for a bounded assistant lookup, not for pagination.
func (a *API) ListFindings(p Principal, f Filters, limit int) ([]Finding, error) {
	if a == nil || a.d.Search == nil {
		return nil, ErrNoSearch
	}
	if err := validateFilters(&f, a.now()); err != nil {
		return nil, err
	}
	switch {
	case limit <= 0:
		limit = DefaultListLimit
	case limit > MaxListLimit:
		limit = MaxListLimit
	}
	index, tenantClause := scope(p)
	a.count("list")
	resp, err := a.search(index, ListBody(f, tenantClause, limit, PagePos{}))
	if err != nil {
		return nil, err
	}
	out := make([]Finding, 0, len(resp.Hits.Hits))
	for _, h := range resp.Hits.Hits {
		fn, derr := DecodeFinding(h.Source, h.ID)
		if derr != nil {
			return nil, fmt.Errorf("decode finding %s: %w", h.ID, derr)
		}
		out = append(out, fn)
	}
	return out, nil
}

// validateFilters re-applies ParseFilters' vocabulary, token AND WINDOW rules to
// a Filters built as a struct literal, canonicalizing in place. It is
// deliberately the same rules and the same wording, so a programmatic caller
// cannot reach a query shape an HTTP caller could not.
//
// now is the caller's clock, injected for the same reason ParseFilters takes it.
func validateFilters(f *Filters, now time.Time) error {
	for i, s := range f.Severity {
		canon := strings.ToLower(strings.TrimSpace(s))
		if !containsToken(Severities, canon) {
			return fmt.Errorf("severity must be one of %s (got %q)", strings.Join(Severities, ", "), s)
		}
		f.Severity[i] = canon
	}
	for i, s := range f.Status {
		canon, ok := StatusAliases[strings.ToLower(strings.TrimSpace(s))]
		if !ok {
			return fmt.Errorf("status must be one of pass, warn, fail, not_applicable, error, unknown (got %q)", s)
		}
		f.Status[i] = canon
	}
	for name, list := range map[string][]string{
		"seam": f.Seam, "framework": f.Framework, "device": f.Device,
	} {
		if len(list) > MaxFilterValues {
			return fmt.Errorf("%s accepts at most %d values", name, MaxFilterValues)
		}
		for _, v := range list {
			if !isSafeToken(v) {
				return fmt.Errorf("%s value %q is not a valid identifier", name, v)
			}
		}
	}
	if len(f.Q) > MaxQueryLen {
		return fmt.Errorf("q must be at most %d characters", MaxQueryLen)
	}
	return resolveWindow(f, now)
}

// resolveWindow defaults and then bounds a struct-literal caller's time range,
// exactly as parseWindow does for an HTTP caller.
//
// WHY THIS EXISTS (review 2026-09-08, H2). BuildFilters emits the `ts` range
// clause UNCONDITIONALLY. A Filters with a zero Since and a zero Until therefore
// renders as `ts` between 0001-01-01T00:00:00Z and 0001-01-01T00:00:00Z: a legal
// strict_date_optional_time point range that matches NOTHING. The assistant's
// findings tool builds precisely that literal, because ai.FindingsQuery carries
// no time fields at all, so an operator asking "what security findings does this
// device have" was told "none" over a tenant with failing criticals. An empty
// answer that is really a broken query is the false clear ErrNoSearch was
// written to prevent, arriving through the other door.
//
// The refusals are ERRORS, never a clamp: a caller who asked for a range we will
// not serve must be told so, not handed a different range with a 200.
func resolveWindow(f *Filters, now time.Time) error {
	if f.Until.IsZero() {
		f.Until = now.UTC()
	} else {
		f.Until = f.Until.UTC()
	}
	if f.Since.IsZero() {
		f.Since = f.Until.Add(-DefaultWindow)
	} else {
		f.Since = f.Since.UTC()
	}
	if !f.Since.Before(f.Until) {
		return errors.New("since must be strictly before until")
	}
	if f.Until.Sub(f.Since) > MaxWindow {
		return fmt.Errorf("time range must span at most %d days", int(MaxWindow.Hours()/24))
	}
	return nil
}

func containsToken(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
