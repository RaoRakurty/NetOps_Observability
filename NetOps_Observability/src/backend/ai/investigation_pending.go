package ai

// investigation_pending.go — the WRITE side of IRIS Phase B investigation
// memory: the short-lived bridge between "the assistant concluded something"
// and "an operator judged it".
//
// WHY A BRIDGE AT ALL. A memory row is only worth keeping once it has an
// OUTCOME (design §3.5: memory states whether the conclusion was confirmed or
// rejected). The conclusion is known when the skill chain finishes; the
// judgement arrives later, on the existing thumbs up/down feedback call. This
// buffer holds the concluded investigation in between — in memory only, never
// on disk, never persisted, and never read by the model.
//
// BOUNDS + ISOLATION (§9, §3a). Entries are keyed by (tenant, subject): one
// principal can never take another's — and therefore can never attach an
// outcome to another tenant's investigation. Each principal keeps at most
// maxPendingPerPrincipal entries, the buffer as a whole at most
// maxPendingPrincipals principals (oldest-touched evicted first), and every
// entry expires after PendingInvestigationTTL. Nothing here survives a restart:
// an unjudged investigation is simply forgotten, which is the correct outcome.

import (
	"sync"
	"time"
)

const (
	// PendingInvestigationTTL is how long a concluded investigation waits for an
	// operator's judgement. Beyond it the rating is no longer plausibly about
	// that answer, so the entry is dropped rather than mislabelled.
	PendingInvestigationTTL = 30 * time.Minute
	// maxPendingPerPrincipal bounds one operator's unjudged conclusions.
	maxPendingPerPrincipal = 8
	// maxPendingPrincipals bounds the whole buffer (§9: all queues are bounded).
	maxPendingPrincipals = 512
)

// ConcludedInvestigation is what a finished skill chain concluded, before any
// operator has judged it. Verdict is MODEL-WRITTEN narrative: it is stored and
// replayed as DATA (escaped on render, never executed, never a rule) exactly
// like device output or log text — §15 LLM02.
type ConcludedInvestigation struct {
	// AnswerID is the id stamped on the Answer this investigation produced, so
	// a later rating can name exactly which answer it judged.
	AnswerID string
	// Entity keys, resolved ONCE per turn under the caller's tenant.
	DeviceID      string
	DeviceName    string
	Peer          string
	Prefix        string
	CorrelationID string
	// Skills is the chain that ran, in order; Verdict the final narrative;
	// Citations the evidence ids it rested on.
	Skills      []string
	Verdict     string
	Citations   []string
	ConcludedAt time.Time
}

// HasKey reports whether the conclusion is about an entity that could ever be
// recalled. One without a key is not worth remembering.
func (c ConcludedInvestigation) HasKey() bool {
	return c.DeviceID != "" || c.DeviceName != "" || c.Peer != "" || c.Prefix != "" || c.CorrelationID != ""
}

// PendingInvestigations is the bounded, per-principal buffer of concluded but
// unjudged investigations. The zero value is not usable — build it with
// NewPendingInvestigations.
type PendingInvestigations struct {
	mu  sync.Mutex
	now func() time.Time // injectable clock (tests); nil-safe via clock()
	by  map[string]*pendingBucket
}

type pendingBucket struct {
	touched time.Time
	entries []pendingEntry
}

type pendingEntry struct {
	inv ConcludedInvestigation
	at  time.Time
}

// NewPendingInvestigations builds an empty buffer.
func NewPendingInvestigations() *PendingInvestigations {
	return &PendingInvestigations{by: map[string]*pendingBucket{}}
}

func (p *PendingInvestigations) clock() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now().UTC()
}

// pendingKey is the (tenant, subject) identity an entry is filed under. Both
// halves come from the authenticated principal, never from a request body.
func pendingKey(tenant, sub string) string { return normTenant(tenant) + "\x1f" + sub }

// Stash files one concluded investigation for (tenant, sub). A conclusion with
// no entity key, or no verdict text, is dropped: it could never be recalled.
func (p *PendingInvestigations) Stash(tenant, sub string, inv ConcludedInvestigation) {
	if p == nil || !inv.HasKey() || inv.Verdict == "" {
		return
	}
	now := p.clock()
	if inv.ConcludedAt.IsZero() {
		inv.ConcludedAt = now
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneLocked(now)
	key := pendingKey(tenant, sub)
	b := p.by[key]
	if b == nil {
		b = &pendingBucket{}
		p.by[key] = b
	}
	b.touched = now
	b.entries = append(b.entries, pendingEntry{inv: inv, at: now})
	if len(b.entries) > maxPendingPerPrincipal {
		b.entries = b.entries[len(b.entries)-maxPendingPerPrincipal:]
	}
	p.evictLocked()
}

// Take removes and returns the concluded investigation an operator is judging.
//
//	answerID != ""  → the entry with that exact answer id, for THIS principal.
//	answerID == ""  → the principal's most recent unjudged conclusion.
//
// The empty-id form exists because the shipped feedback call does not yet carry
// an answer id; it is deliberately scoped to the SAME (tenant, subject) that
// produced the conclusion, so the worst case is that an operator's rating lands
// on their own previous answer — never on another operator's, and never on
// another tenant's.
func (p *PendingInvestigations) Take(tenant, sub, answerID string) (ConcludedInvestigation, bool) {
	if p == nil {
		return ConcludedInvestigation{}, false
	}
	now := p.clock()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneLocked(now)
	key := pendingKey(tenant, sub)
	b := p.by[key]
	if b == nil || len(b.entries) == 0 {
		return ConcludedInvestigation{}, false
	}
	idx := -1
	for i := len(b.entries) - 1; i >= 0; i-- {
		if answerID == "" || b.entries[i].inv.AnswerID == answerID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return ConcludedInvestigation{}, false
	}
	inv := b.entries[idx].inv
	b.entries = append(b.entries[:idx], b.entries[idx+1:]...)
	if len(b.entries) == 0 {
		delete(p.by, key)
	}
	return inv, true
}

// Len reports how many entries the buffer holds (tests + bound assertions).
func (p *PendingInvestigations) Len() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, b := range p.by {
		n += len(b.entries)
	}
	return n
}

// pruneLocked drops expired entries (call with mu held).
func (p *PendingInvestigations) pruneLocked(now time.Time) {
	cutoff := now.Add(-PendingInvestigationTTL)
	for key, b := range p.by {
		kept := b.entries[:0]
		for _, e := range b.entries {
			if e.at.After(cutoff) {
				kept = append(kept, e)
			}
		}
		b.entries = kept
		if len(b.entries) == 0 {
			delete(p.by, key)
		}
	}
}

// evictLocked enforces the whole-buffer bound, oldest-touched principal first
// (call with mu held).
func (p *PendingInvestigations) evictLocked() {
	for len(p.by) > maxPendingPrincipals {
		oldestKey, oldest := "", time.Time{}
		for key, b := range p.by {
			if oldestKey == "" || b.touched.Before(oldest) {
				oldestKey, oldest = key, b.touched
			}
		}
		delete(p.by, oldestKey)
	}
}

// InvestigationRowFrom projects a judged conclusion into the store row. The
// OWNER is the tenant argument — taken by the caller from the authenticated
// principal, never from anything the client sent (§3a rule 2).
func InvestigationRowFrom(tenant string, inv ConcludedInvestigation, outcome InvestigationOutcome, resolvedAt time.Time) InvestigationRow {
	return InvestigationRow{
		TenantID:      tenant,
		DeviceID:      inv.DeviceID,
		DeviceName:    inv.DeviceName,
		Peer:          inv.Peer,
		Prefix:        inv.Prefix,
		CorrelationID: inv.CorrelationID,
		Skills:        inv.Skills,
		Verdict:       inv.Verdict,
		Citations:     inv.Citations,
		Outcome:       validOutcome(outcome),
		CreatedAt:     inv.ConcludedAt,
		ResolvedAt:    resolvedAt,
	}
}
