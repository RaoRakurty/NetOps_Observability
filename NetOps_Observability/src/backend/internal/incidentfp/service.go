// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package incidentfp

// service.go — recall: exact-key candidates, fingerprints (stored, or built
// within a budget and written through), then the documented rerank.

import (
	"context"
	"errors"
	"sort"
	"time"
)

// Recall bounds.
const (
	MaxCandidates = 50 // candidates examined after the exact-key prefilter
	EnrichBudget  = 8  // fingerprints built per request when not stored
)

// ErrBadWindow is a window outside the closed vocabulary.
var ErrBadWindow = errors.New("incidentfp: unknown window")

// Deps are the server seams. Every one reads the GIVEN tenant only.
type Deps struct {
	Store Store
	// Candidates lists the tenant's CLOSED, non-internal, non-merged incidents
	// since t, as fingerprints derived from their time-metrics rows (partial:
	// no chain, no symptoms).
	Candidates func(ctx context.Context, tenant string, since time.Time) ([]Fingerprint, error)
	// Build derives the full fingerprint of one of the tenant's incidents.
	Build func(ctx context.Context, tenant, id string) (Fingerprint, error)
	Now   func() time.Time
	// Built counts fingerprints built and stored on demand (metrics).
	Built func(n int)
}

// keyShare is how many exact keys a candidate shares with the subject (the
// prefilter: a candidate sharing none is never examined).
func keyShare(s, c Fingerprint) int {
	n := 0
	if s.Signature != "" && s.Signature == c.Signature {
		n++
	}
	if first(s.Devices) != "" && overlap(s.Devices, c.Devices) {
		n++
	}
	if overlap(s.Interfaces, c.Interfaces) {
		n++
	}
	if overlap(s.Paths, c.Paths) {
		n++
	}
	if s.SeamType != "" && s.SeamType == c.SeamType && s.Provider != "" && s.Provider == c.Provider {
		n++
	}
	return n
}

// Recall answers "have we seen this before?" for subject, within tenant.
func (d Deps) Recall(ctx context.Context, tenant string, subject Fingerprint, window string) (Result, error) {
	dur, ok := WindowFor(window)
	if !ok {
		return Result{}, ErrBadWindow
	}
	if window == "" {
		window = DefaultWindow
	}
	if tenant == "" {
		r := Rank(subject, nil, window)
		r.Note = "This incident belongs to no workspace, so there is no history to compare it with."
		return r, nil
	}
	now := time.Now
	if d.Now != nil {
		now = d.Now
	}
	cands, err := d.Candidates(ctx, tenant, now().Add(-dur))
	if err != nil {
		return Result{}, err
	}
	type scored struct {
		f     Fingerprint
		share int
	}
	var pre []scored
	for _, c := range cands {
		if c.CorrelationID == subject.CorrelationID {
			continue
		}
		if k := keyShare(subject, c); k > 0 {
			pre = append(pre, scored{c, k})
		}
	}
	sort.SliceStable(pre, func(i, j int) bool {
		if pre[i].share != pre[j].share {
			return pre[i].share > pre[j].share
		}
		return pre[i].f.OccurredAt.After(pre[j].f.OccurredAt)
	})
	if len(pre) > MaxCandidates {
		pre = pre[:MaxCandidates]
	}
	ids := make([]string, 0, len(pre))
	for _, p := range pre {
		ids = append(ids, p.f.CorrelationID)
	}
	stored := map[string]Fingerprint{}
	if d.Store != nil && len(ids) > 0 {
		if stored, err = d.Store.Get(ctx, tenant, ids); err != nil {
			return Result{}, err
		}
	}
	budget, built := EnrichBudget, 0
	fps := make([]Fingerprint, 0, len(pre))
	for _, p := range pre {
		if f, ok := stored[p.f.CorrelationID]; ok {
			fps = append(fps, f)
			continue
		}
		if d.Build != nil && budget > 0 {
			budget--
			if f, err := d.Build(ctx, tenant, p.f.CorrelationID); err == nil && f.CorrelationID == p.f.CorrelationID {
				if d.Store != nil && d.Store.Put(ctx, tenant, f) == nil {
					built++
				}
				fps = append(fps, f)
				continue
			}
		}
		fps = append(fps, p.f) // partial: scored without chain or symptoms
	}
	if d.Built != nil && built > 0 {
		d.Built(built)
	}
	r := Rank(subject, fps, window)
	// Examined is every closed incident in the window, not only those that
	// shared a key: "none similar" and "no history" must not be confused.
	r.Examined = len(cands) - countSelf(cands, subject.CorrelationID)
	if len(r.Matches) == 0 {
		if r.Examined > 0 {
			r.Note = "Earlier incidents were compared, and none is similar enough to show."
		} else {
			r.Note = "No closed incidents in this window to compare with."
		}
	}
	return r, nil
}

func countSelf(cs []Fingerprint, id string) int {
	n := 0
	for _, c := range cs {
		if c.CorrelationID == id {
			n++
		}
	}
	return n
}
