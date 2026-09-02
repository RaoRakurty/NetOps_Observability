package bgpdepth

// rpki.go — origin validation per watchlist prefix.
//
// Source: the RIPEstat "rpki-validation" data call, verified live 2026-09-02:
//
//	GET /data/rpki-validation/data.json?resource=AS3333&prefix=193.0.0.0/21
//	→ data: {"resource":"3333","prefix":"193.0.0.0/21","status":"valid",
//	         "validator":"routinator",
//	         "validating_roas":[{"origin":"3333","prefix":"193.0.0.0/21",
//	                             "validity":"valid","max_length":21}]}
//
// The call needs BOTH the prefix and the origin ASN, so the caller supplies an
// OriginResolver: the verdict must judge the announcement that is REALLY in the
// table, never a hypothetical origin taken from a request parameter.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// RPKICacheTTL — a ROA changes on the scale of hours; a minute of cache
	// collapses a page refresh storm into one upstream call.
	RPKICacheTTL = 5 * time.Minute
	// RPKIMaxPrefixes bounds a batch: a watchlist is operator-controlled, but
	// "bounded" is not negotiable (§9).
	RPKIMaxPrefixes = 50
	// rpkiConcurrency caps parallel upstream calls inside one batch.
	rpkiConcurrency = 4
)

// RPKIState is the normalized, UI-facing verdict. RIPEstat emits several
// spellings ("invalid_asn", "invalid_length", "unknown", "not-found"); the API
// promises exactly these four so the frontend never string-matches upstream.
type RPKIState string

const (
	RPKIValid       RPKIState = "valid"
	RPKIInvalid     RPKIState = "invalid"
	RPKIUnknown     RPKIState = "unknown" // no ROA covers the prefix
	RPKIUnavailable RPKIState = "unavailable"
)

// NormalizeRPKIState maps an upstream status onto the four promised states and
// returns the reason where upstream distinguished one. Anything unrecognized is
// "unavailable" — NEVER silently downgraded to "valid".
func NormalizeRPKIState(raw string) (RPKIState, string) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "valid":
		return RPKIValid, ""
	case "invalid":
		return RPKIInvalid, ""
	case "invalid_asn", "invalid-asn":
		return RPKIInvalid, "origin_as"
	case "invalid_length", "invalid-length":
		return RPKIInvalid, "max_length"
	case "unknown", "not-found", "notfound", "not_found":
		return RPKIUnknown, ""
	default:
		return RPKIUnavailable, ""
	}
}

// ROA is one validating ROA as published.
type ROA struct {
	Origin    string `json:"origin"`
	Prefix    string `json:"prefix"`
	MaxLength int    `json:"max_length"`
	Validity  string `json:"validity"`
}

// RPKIResult is one prefix's verdict. Error is set INSTEAD of a verdict when
// the lookup failed — a failed lookup is never rendered as a state.
type RPKIResult struct {
	Prefix    string    `json:"prefix"`
	Origin    string    `json:"origin,omitempty"` // "AS3333"
	State     RPKIState `json:"state"`
	Reason    string    `json:"reason,omitempty"`
	Validator string    `json:"validator,omitempty"`
	ROAs      []ROA     `json:"roas,omitempty"`
	FetchedAt time.Time `json:"fetched_at"`
	Error     string    `json:"error,omitempty"`
}

// OriginResolver returns the prefix's currently ANNOUNCED origin ASN in bare
// digit form ("3333"), or "" when the prefix is not announced / not resolvable.
type OriginResolver func(ctx context.Context, prefix string) string

// ValidateRPKI validates ONE prefix. originASN may be empty, in which case
// resolve is consulted; if that also yields nothing the result is an honest
// "unavailable" naming the reason.
func ValidateRPKI(ctx context.Context, f Fetcher, now func() time.Time, resolve OriginResolver, prefix, originASN string) RPKIResult {
	out := RPKIResult{Prefix: prefix, State: RPKIUnavailable, FetchedAt: now()}
	origin := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(originASN)), "AS")
	if origin == "" && resolve != nil {
		origin = resolve(ctx, prefix)
	}
	if origin == "" {
		out.Error = "origin ASN not determinable (prefix not announced?)"
		return out
	}
	out.Origin = "AS" + origin
	data, err := f.RIPEstat(ctx, "rpki-validation", "AS"+origin, "prefix="+urlEscape(prefix), RPKICacheTTL)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	var body struct {
		Status         string `json:"status"`
		Validator      string `json:"validator"`
		ValidatingROAs []struct {
			Origin    string `json:"origin"`
			Prefix    string `json:"prefix"`
			MaxLength int    `json:"max_length"`
			Validity  string `json:"validity"`
		} `json:"validating_roas"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		out.Error = fmt.Sprintf("unparsable rpki-validation payload: %v", err)
		return out
	}
	state, reason := NormalizeRPKIState(body.Status)
	out.State, out.Reason = state, reason
	if state == RPKIUnavailable && body.Status != "" {
		out.Error = fmt.Sprintf("unrecognized upstream status %q", clip(body.Status, 40))
	}
	out.Validator = clip(body.Validator, 40)
	for _, r := range body.ValidatingROAs {
		if len(out.ROAs) >= 16 { // bounded (§9)
			break
		}
		out.ROAs = append(out.ROAs, ROA{
			Origin: clip(r.Origin, 12), Prefix: clip(r.Prefix, 64),
			MaxLength: r.MaxLength, Validity: clip(r.Validity, 24),
		})
	}
	return out
}

// ValidateRPKISet validates a whole watchlist with bounded concurrency, in a
// DETERMINISTIC output order (input order), so a page render never reshuffles.
func ValidateRPKISet(ctx context.Context, f Fetcher, now func() time.Time, resolve OriginResolver, prefixes []string) ([]RPKIResult, bool, error) {
	if f == nil {
		return nil, false, errors.New("bgpdepth: no fetcher")
	}
	truncated := false
	if len(prefixes) > RPKIMaxPrefixes {
		prefixes, truncated = prefixes[:RPKIMaxPrefixes], true
	}
	out := make([]RPKIResult, len(prefixes))
	sem := make(chan struct{}, rpkiConcurrency)
	var wg sync.WaitGroup
	for i, p := range prefixes {
		wg.Add(1)
		go func(i int, p string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				out[i] = RPKIResult{Prefix: p, State: RPKIUnavailable, FetchedAt: now(), Error: ctx.Err().Error()}
				return
			}
			out[i] = ValidateRPKI(ctx, f, now, resolve, p, "")
		}(i, p)
	}
	wg.Wait()
	return out, truncated, nil
}

// SortRPKIWorstFirst orders results so the thing an operator must act on is at
// the top: invalid → unavailable → unknown (no ROA) → valid, then by prefix.
func SortRPKIWorstFirst(rs []RPKIResult) {
	rank := map[RPKIState]int{RPKIInvalid: 0, RPKIUnavailable: 1, RPKIUnknown: 2, RPKIValid: 3}
	sort.SliceStable(rs, func(i, j int) bool {
		if rank[rs[i].State] != rank[rs[j].State] {
			return rank[rs[i].State] < rank[rs[j].State]
		}
		return rs[i].Prefix < rs[j].Prefix
	})
}
