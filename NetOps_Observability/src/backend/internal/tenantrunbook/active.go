// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tenantrunbook

// active.go — what reaches Iris, and keeping it proven (tracker 337 N-F2).
//
// A runbook RUNS only when all of these hold: it is investigative (a MOP is a
// procedure for a human and never runs), it has an ACTIVE version (two people
// approved exactly that text), and that version's cases PASSED under the
// fingerprint that is current now. The last rule is what "re-run all cases on a
// model, prompt or tool-schema change" means: a change moves the fingerprint, the
// stamp no longer matches, and the runbook stops running until its cases pass
// again. Reprove re-runs them for the active text — the text is unchanged, so the
// approval (bound to its hash) still holds and no second person is needed; a
// failure is recorded so the page can say why the runbook stopped.
//
// Nothing here widens tenancy: ActiveSkills takes one tenant's rows and stamps
// that tenant, and ai.SkillSet.Overlay refuses a mix.

import (
	"context"
	"errors"
	"sync"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/orgcontext"
)

// Skipped is a runbook left out of a tenant's skill set, with the reason.
type Skipped struct {
	ID     string
	Name   string
	Reason string // stale_cases | parse_error
}

// ActiveSkills parses one tenant's runnable runbooks. rows must all be tenant's
// (the store guarantees it); a row of another tenant is skipped, never stamped.
// current is the harness fingerprint now; a stale or failed stamp is skipped
// with Reason "stale_cases" so the caller can re-prove it.
func ActiveSkills(tenant string, rows []Runbook, current string, tools []string) ([]*ai.Skill, []Skipped) {
	var out []*ai.Skill
	var skipped []Skipped
	for _, r := range rows {
		if r.TenantID != tenant || r.RunbookKind != KindInvestigative {
			continue
		}
		v, ok := r.Active()
		if !ok {
			continue
		}
		if !Runnable(r, v.Version, current) {
			skipped = append(skipped, Skipped{ID: r.ID, Name: r.Name(), Reason: "stale_cases"})
			continue
		}
		src, err := SplitBody(v.Body)
		if err != nil {
			skipped = append(skipped, Skipped{ID: r.ID, Name: r.Name(), Reason: "parse_error"})
			continue
		}
		sk, err := Parse(tenant, r.Name(), r.RunbookKind, src, tools)
		if err != nil {
			skipped = append(skipped, Skipped{ID: r.ID, Name: r.Name(), Reason: "parse_error"})
			continue
		}
		out = append(out, sk)
	}
	return out, skipped
}

// Runnable reports whether version of r has passed its cases under current:
// its own frozen stamp, or a passing re-check, under that fingerprint.
func Runnable(r Runbook, version int, current string) bool {
	if current == "" {
		return false
	}
	if st, ok := r.Harness[version]; ok && st.Passed && st.Fingerprint == current {
		return true
	}
	st, ok := r.Recheck[version][current]
	return ok && st.Passed
}

// ReproveResult is one Reprove: whether the active text's cases now pass under
// the current platform, and the problems when they do not.
type ReproveResult struct {
	Version     int           `json:"version"`
	Passed      bool          `json:"passed"`
	AlreadyOK   bool          `json:"already_current"`
	Fingerprint string        `json:"fingerprint,omitempty"`
	Cases       int           `json:"cases"`
	Problems    []CaseProblem `json:"problems,omitempty"`
}

// ErrNothingActive: the runbook has no active version to re-prove.
var ErrNothingActive = errors.New("tenantrunbook: the runbook has no approved version to re-check")

// reproveTarget is the version a Reprove proves, or ErrNothingActive. A MOP has
// nothing to prove and is always current.
func reproveTarget(r Runbook) (orgcontext.Version, error) {
	v, ok := r.Active()
	if !ok {
		return orgcontext.Version{}, ErrNothingActive
	}
	return v, nil
}

// reproveDecide is the locked step of a Reprove: cur is what the row holds now.
// It returns the re-check to record for the version that was proven, and only if
// that version is still the active one with the same text (an approval or
// rollback in between wins; the result is then simply not recorded). The frozen
// Harness stamp is never touched.
func (c Config) reproveDecide(cur Runbook, version int, sha string, res HarnessResult, now time.Time) (Stamp, bool) {
	v, ok := cur.Active()
	if !ok || v.Version != version || v.BodySHA256 != sha || res.Fingerprint == "" {
		return Stamp{}, false
	}
	at := now.UTC()
	return Stamp{Passed: res.Passed, Fingerprint: res.Fingerprint, At: &at}, true
}

// withRecheck returns r with st recorded for version.
func withRecheck(r Runbook, version int, st Stamp) Runbook {
	after := r.clone()
	if after.Recheck[version] == nil {
		after.Recheck[version] = map[string]Stamp{}
	}
	after.Recheck[version][st.Fingerprint] = st
	return after
}

// reprovePrepare runs the harness over the active version, before any lock. It
// returns AlreadyOK without running when the stamp is current.
func (c Config) reprovePrepare(ctx context.Context, r Runbook, list func() ([]Runbook, error)) (orgcontext.Version, HarnessResult, ReproveResult, error) {
	v, err := reproveTarget(r)
	if err != nil {
		return v, HarnessResult{}, ReproveResult{}, err
	}
	if r.RunbookKind == KindMOP {
		return v, HarnessResult{}, ReproveResult{Version: v.Version, Passed: true, AlreadyOK: true, Fingerprint: FingerprintNotApplicable}, nil
	}
	if c.Harness == nil {
		return v, HarnessResult{}, ReproveResult{}, errors.New("tenantrunbook: no harness is configured")
	}
	fp := c.Harness.Fingerprint()
	if Runnable(r, v.Version, fp) {
		return v, HarnessResult{}, ReproveResult{Version: v.Version, Passed: true, AlreadyOK: true, Fingerprint: fp}, nil
	}
	res, err := c.prove(ctx, r, v, list)
	if err != nil {
		return v, HarnessResult{}, ReproveResult{}, err
	}
	if !res.Passed && res.Fingerprint == "" {
		// A refusal (timeout, crash, a text that no longer parses) carries no
		// fingerprint; it is still a failure under the platform as it is now,
		// and is recorded as one so the page can say why the runbook stopped.
		res.Fingerprint = fp
	}
	return v, res, ReproveResult{Version: v.Version, Passed: res.Passed, Fingerprint: res.Fingerprint, Cases: res.Cases, Problems: res.Problems}, nil
}

// ---- the per-tenant overlay cache -----------------------------------------

// OverlayCache holds one built skill set per tenant, valid for one fingerprint.
// It is invalidated per tenant when what is active changes (Deps.Changed) and
// misses on its own when the fingerprint moves. Bounded: a set is per tenant and
// a tenant's runbooks are capped (MaxRunbooksPerTenant).
type OverlayCache struct {
	mu   sync.Mutex
	sets map[string]overlayEntry
}

type overlayEntry struct {
	fingerprint string
	set         *ai.SkillSet
	built       time.Time
}

// overlayTTL bounds how long a built set is reused even without an
// invalidation, so a missed signal (another replica's approval) heals.
const overlayTTL = 5 * time.Minute

// Get returns the cached set for tenant under fingerprint.
func (c *OverlayCache) Get(tenant, fingerprint string, now time.Time) (*ai.SkillSet, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.sets[tenant]
	if !ok || e.fingerprint != fingerprint || now.Sub(e.built) > overlayTTL {
		return nil, false
	}
	return e.set, true
}

// Put stores tenant's set.
func (c *OverlayCache) Put(tenant, fingerprint string, set *ai.SkillSet, now time.Time) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sets == nil {
		c.sets = map[string]overlayEntry{}
	}
	c.sets[tenant] = overlayEntry{fingerprint: fingerprint, set: set, built: now}
}

// Invalidate drops tenant's set.
func (c *OverlayCache) Invalidate(tenant string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.sets, tenant)
}
