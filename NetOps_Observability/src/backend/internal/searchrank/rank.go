// Package searchrank is the unified-search ranking core (Phase-2 W4.3,
// extracted from package main's search_unified.go): the hit/score model, the
// prefix/word/substring ranking, the case-id hex parser, the per-kind result
// cap and ordering vocabulary. The five per-kind searchers and the handler
// stay in main (they hold srv and its stores).
package searchrank

import (
	"sort"
	"strings"
	"time"
)

const (
	MinQueryLen = 2
	MaxQueryLen = 128
	PerKindCap  = 8
	TotalCap    = 32
	Timeout     = 2 * time.Second
)

// Hit is one typed, deep-linkable result. Href is the SPA hash route
// (without the leading "#/") — the UI navigates, it never interprets the id.
type Hit struct {
	Kind     string `json:"kind"` // device | resource | app | account | case
	ID       string `json:"id"`
	Label    string `json:"label"`
	Sublabel string `json:"sublabel,omitempty"`
	Href     string `json:"href"`
}

// ScoredHit carries the internal rank so the handler can order before writing.
type ScoredHit struct {
	Hit
	// RankScore is lower-is-better (0 = exact/prefix match).
	RankScore int
}

// KindOrder fixes the tie-break order between kinds (infrastructure
// first, then the cloud nouns, then cases).
var KindOrder = map[string]int{"device": 0, "resource": 1, "app": 2, "account": 3, "case": 4}

// Rank scores a query against a candidate's fields: 0 exact (case-fold),
// 1 prefix, 2 substring, -1 no match. q must already be lowercased.
func Rank(q string, fields ...string) int {
	best := -1
	for _, f := range fields {
		if f == "" {
			continue
		}
		lf := strings.ToLower(f)
		var r int
		switch {
		case lf == q:
			r = 0
		case strings.HasPrefix(lf, q):
			r = 1
		case strings.Contains(lf, q):
			r = 2
		default:
			continue
		}
		if best == -1 || r < best {
			best = r
		}
		if best == 0 {
			return 0
		}
	}
	return best
}

// CaseHex extracts the hex prefix a case-id query addresses, or "" when
// the query does not look like a case handle. Accepted: "P-5564D1" (any prefix
// of the display id, ≥2 hex) or a bare hex/UUID prefix of ≥4 chars ("5564d1a0",
// "5564d1a0-…"). The result is UPPERCASE HEX ONLY — safe to inline in SQL.
func CaseHex(q string) string {
	s := strings.ToUpper(strings.TrimSpace(q))
	explicit := false
	if strings.HasPrefix(s, "P-") {
		explicit = true
		s = s[2:]
	}
	s = strings.ReplaceAll(s, "-", "") // tolerate UUID dashes
	if s == "" || len(s) > 32 {
		return ""
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'F') {
			return ""
		}
	}
	if !explicit && len(s) < 4 {
		return "" // a 2-char bare hex ("ab") is almost never a case lookup
	}
	if explicit && len(s) < 2 {
		return ""
	}
	return s
}

// handleUnifiedSearch is GET /api/search?q=… — see the file header for scope,
// bounds and ranking. Gated like every surface it fans out to
// (infrastructure:read); each sub-search re-applies the principal's tenant.
func CapKind(hits []ScoredHit) []ScoredHit {
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].RankScore != hits[j].RankScore {
			return hits[i].RankScore < hits[j].RankScore
		}
		return hits[i].Label < hits[j].Label
	})
	if len(hits) > PerKindCap {
		hits = hits[:PerKindCap]
	}
	return hits
}

func NonEmpty(vals ...string) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}
