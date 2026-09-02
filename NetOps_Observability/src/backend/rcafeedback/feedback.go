// Package rcafeedback holds the operator VERDICT feedback loop for RCA cases
// (Project 2, P7): the record an operator writes after reading a correlation
// case — "the engine got this right / wrong / partly right", and when it was
// wrong, WHICH claim was wrong.
//
// This is the instrument behind the "false-positive RCA rate" success metric
// and the design-partner loop. It is deliberately a separate bounded context
// from rca_action_items (corrective work) and ai_feedback (a rating of an Iris
// ANSWER, not of a correlation object).
//
// The package holds the vocabulary, the validation, the append-only store
// (file + Postgres behind ONE interface, tenant isolation enforced IN the
// store per CLAUDE.md §3a rule 4), the summary arithmetic and the metric. The
// HTTP shell (RBAC, ClickHouse ownership pre-read, audit) stays in the root
// package where the routing layer lives.
package rcafeedback

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Verdicts is the closed verdict vocabulary. "partial" is not a hedge: it means
// the engine reached the right neighbourhood but at least one claim was wrong,
// which is why it counts in the denominator of the false-positive rate but not
// the numerator.
var Verdicts = map[string]bool{"correct": true, "wrong": true, "partial": true}

// VerdictOrder is Verdicts in a stable presentation order (map iteration is not).
var VerdictOrder = []string{"correct", "wrong", "partial"}

// WrongParts is the closed set of RCA claim surfaces an operator can point at.
// They mirror what an RCA case actually asserts: the cause, the seam owner, the
// affected set, the evidence, and the recovery story.
var WrongParts = map[string]bool{
	"cause": true, "owner": true, "affected": true, "evidence": true, "recovery": true,
}

const (
	// MaxReasonChars bounds the free-text reason (CHARACTERS, not bytes — an
	// operator writing in a non-Latin script gets the same allowance).
	MaxReasonChars = 500
	// MaxPerCase bounds the register per (tenant, case) — §9, everything bounded.
	// An operator revising a verdict adds a row; 100 revisions on one case is
	// already far past honest use.
	MaxPerCase = 100
	// MaxCorrelationVersion is the sanity ceiling on a client-supplied version
	// (the object version column is a UInt32 in ClickHouse).
	MaxCorrelationVersion = 1 << 30
)

// ErrLimit is returned when a case hits MaxPerCase (HTTP 400 upstream).
var ErrLimit = fmt.Errorf("a correlation case is capped at %d feedback entries", MaxPerCase)

// ErrNotFound is the typed miss for callers that need an error; the HTTP layer
// maps a cross-tenant miss to 404 without ever revealing existence.
var ErrNotFound = errors.New("rca feedback entry not found")

// Feedback is one operator verdict on one correlation object. Append-only: a
// row is never edited, so there is no UpdatedAt/UpdatedBy.
type Feedback struct {
	ID            string `json:"id"`
	TenantID      string `json:"tenant_id"`
	CorrelationID string `json:"correlation_id"`

	// Verdict is one of Verdicts.
	Verdict string `json:"verdict"`
	// WrongPart is one of WrongParts, or "" — empty is REQUIRED for a
	// "correct" verdict (a correct case has no wrong part).
	WrongPart string `json:"wrong_part,omitempty"`
	// Reason is optional operator prose, capped at MaxReasonChars.
	Reason string `json:"reason,omitempty"`

	// CorrelationVersion is the object version the operator actually saw.
	// nil = the client did not say. An honest NULL beats a guessed "latest":
	// the whole point of the field is to know WHICH rendering was judged.
	CorrelationVersion *int `json:"correlation_version,omitempty"`

	// TopHypothesis is the engine's template id for the judged object, copied
	// at write time so the false-positive rate stays attributable to a template
	// even after the object is re-versioned or aged out.
	TopHypothesis string `json:"top_hypothesis,omitempty"`
	// VerdictTier is the engine's own confidence tier at write time
	// (undetermined | suspected | confirmed).
	VerdictTier string `json:"verdict_tier,omitempty"`

	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// NormTenant is the single tenant-normalization rule for this package.
func NormTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// Validate checks the operator-supplied fields of a feedback row. It validates
// ONLY what the caller may set — identity, tenant and stamps are server-owned
// and are applied after validation.
//
// objectVersion is the correlation object's current version as read from
// ClickHouse, or 0 when unknown; a client-supplied CorrelationVersion above it
// is refused (an operator cannot have seen a version that does not exist yet).
func Validate(f *Feedback, objectVersion int) error {
	f.Verdict = strings.ToLower(strings.TrimSpace(f.Verdict))
	if !Verdicts[f.Verdict] {
		return fmt.Errorf("verdict must be one of correct, wrong, partial (got %q)", f.Verdict)
	}
	f.WrongPart = strings.ToLower(strings.TrimSpace(f.WrongPart))
	if f.WrongPart != "" && !WrongParts[f.WrongPart] {
		return fmt.Errorf("wrong_part must be one of cause, owner, affected, evidence, recovery (got %q)", f.WrongPart)
	}
	if f.Verdict == "correct" && f.WrongPart != "" {
		return errors.New(`wrong_part is meaningless on a "correct" verdict — omit it, or say wrong/partial`)
	}
	f.Reason = strings.TrimSpace(f.Reason)
	if n := utf8.RuneCountInString(f.Reason); n > MaxReasonChars {
		return fmt.Errorf("reason must be at most %d characters (got %d)", MaxReasonChars, n)
	}
	if f.CorrelationVersion != nil {
		v := *f.CorrelationVersion
		if v < 1 || v > MaxCorrelationVersion {
			return fmt.Errorf("correlation_version must be between 1 and %d (got %d)", MaxCorrelationVersion, v)
		}
		if objectVersion > 0 && v > objectVersion {
			return fmt.Errorf("correlation_version %d is ahead of the object's current version %d", v, objectVersion)
		}
	}
	return nil
}

// ---- summary arithmetic (pure) -------------------------------------------------

// Bucket is one (verdict, template) group count as the store returns it. The
// stores aggregate; this package derives. Keeping the derivation pure is what
// makes the file and Postgres backends provably agree.
type Bucket struct {
	Verdict  string `json:"verdict"`
	Template string `json:"template"` // the object's top_hypothesis at write time
	N        int    `json:"n"`
}

// Counts is a per-verdict tally plus the derived false-positive rate.
type Counts struct {
	Correct int `json:"correct"`
	Wrong   int `json:"wrong"`
	Partial int `json:"partial"`
	// N is the denominator: correct + wrong + partial.
	N int `json:"n"`
	// FalsePositiveRate is wrong / N. NIL when N == 0 — "no operator has judged
	// anything yet" is not "the false-positive rate is zero", and reporting 0
	// for an empty sample is exactly the dishonesty this metric exists to kill.
	FalsePositiveRate *float64 `json:"false_positive_rate"`
}

// TemplateCounts is Counts for one engine template (top_hypothesis).
type TemplateCounts struct {
	Template string `json:"template"`
	Counts
}

// Summary is the windowed answer served by GET /api/correlations/feedback/summary.
type Summary struct {
	Counts
	// ByTemplate is the per-template breakdown, ordered by N desc then template
	// asc so the response is stable.
	ByTemplate []TemplateCounts `json:"by_template"`
}

// add folds one bucket into a Counts (without the derived rate).
func (c *Counts) add(verdict string, n int) {
	switch verdict {
	case "correct":
		c.Correct += n
	case "wrong":
		c.Wrong += n
	case "partial":
		c.Partial += n
	default:
		// An unknown verdict cannot be silently absorbed into the denominator:
		// it would move the rate without being visible anywhere. Stores only
		// ever hold values the CHECK constraint / Validate admitted, so this is
		// unreachable by construction; ignoring it keeps the arithmetic honest
		// if the vocabulary is ever widened without updating this fold.
		return
	}
	c.N += n
}

// seal computes the derived rate. Called once per Counts after folding.
func (c *Counts) seal() {
	if c.N == 0 {
		c.FalsePositiveRate = nil
		return
	}
	rate := float64(c.Wrong) / float64(c.N)
	c.FalsePositiveRate = &rate
}

// Summarize folds store buckets into the served summary. Pure and total: an
// empty input yields an all-zero summary with a NIL rate and an empty (never
// nil) breakdown slice.
func Summarize(buckets []Bucket) Summary {
	var s Summary
	byTpl := map[string]*Counts{}
	for _, b := range buckets {
		if b.N <= 0 {
			continue
		}
		s.add(b.Verdict, b.N)
		tpl := b.Template
		if tpl == "" {
			tpl = "undetermined" // the engine's own name for "no template matched"
		}
		c, ok := byTpl[tpl]
		if !ok {
			c = &Counts{}
			byTpl[tpl] = c
		}
		c.add(b.Verdict, b.N)
	}
	s.seal()
	s.ByTemplate = make([]TemplateCounts, 0, len(byTpl))
	for tpl, c := range byTpl {
		if c.N == 0 {
			continue
		}
		c.seal()
		s.ByTemplate = append(s.ByTemplate, TemplateCounts{Template: tpl, Counts: *c})
	}
	sort.Slice(s.ByTemplate, func(i, j int) bool {
		if s.ByTemplate[i].N != s.ByTemplate[j].N {
			return s.ByTemplate[i].N > s.ByTemplate[j].N
		}
		return s.ByTemplate[i].Template < s.ByTemplate[j].Template
	})
	return s
}
