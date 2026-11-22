// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package probercontrol

// results.go — the prober's RESULTS are signed too (tracker 475, 2026-11-22).
//
// P3 signed the api → prober direction (switches, targets). The other
// direction stayed open: the prober published its traced paths into the
// key-value store (netops:probe:paths:<vantage>, the legacy single key, and the
// PROBE_PATHS_FILE fallback) as plain JSON, and the api believed every field —
// the tenant a path is served to, its hops (which feed the RCA direction
// enrichment and the seam bootstrap), its vantage. Any service holding the
// Valkey password could write a path into any tenant's view.
//
// The same key and the same v1 envelope now carry the results. The signed
// payload is a ResultRecord: the vantage that measured it, when it was sealed,
// and the body. The reader checks, in order: a key is loaded; the envelope is
// signed and verifies (the KIND is bound into the MAC, so a switch or targets
// record copied into a path slot does not verify); the record decodes; it was
// read from its own vantage's slot; it is not older than the reader's MaxAge
// (or stamped in the future); and it is not older than the newest record this
// reader already accepted from that vantage (a replayed older record cannot
// roll a path back). Every refusal is counted by reason and reported once per
// change, and the refused record contributes nothing.
//
// ROLLOUT. The api and the prober ship in one image and are deployed together.
// A prober that predates this change (or a hand-run one) publishes unsigned
// JSON; that is refused unless the platform administrator turns on the
// console-only Features switch PROBE_PATHS_ACCEPT_UNSIGNED, which accepts the
// unsigned form only (never a bad signature) and counts every such record as
// unsigned_accepted.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// KindProbePaths is the record kind of a prober's traced-path set.
const KindProbePaths = "probe-paths"

// EnvAcceptUnsignedPaths is the console-only Features switch that accepts the
// unsigned path records a pre-tracker-475 prober publishes.
const EnvAcceptUnsignedPaths = "PROBE_PATHS_ACCEPT_UNSIGNED"

// resultSchema is the ResultRecord schema version; any other is refused.
const resultSchema = 1

// maxResultVantages bounds the reader's per-vantage replay marks. A real
// install has a handful of vantages; past the bound the marks are reset (the
// MaxAge check still holds), so a flood of invented vantage ids cannot grow
// memory.
const maxResultVantages = 4096

// ResultRecord is the signed payload of one result publish.
type ResultRecord struct {
	Schema   int             `json:"schema"`
	Vantage  string          `json:"vantage"`
	IssuedAt time.Time       `json:"issued_at"`
	Body     json.RawMessage `json:"body"`
}

// Result-record reasons (metric label values; closed set).
const (
	ReasonVerified         Reason = "verified"          // signed, fresh, from its own slot
	ReasonUnsignedAccepted Reason = "unsigned_accepted" // unsigned, accepted under the legacy switch
	ReasonWrongVantage     Reason = "wrong_vantage"     // signed for another vantage's slot
	ReasonReplayed         Reason = "replayed"          // older than one already accepted from that vantage
)

// resultReasons is every reason a result read can end in, in exposition order.
var resultReasons = []Reason{
	ReasonVerified, ReasonUnsignedAccepted, ReasonNoKey, ReasonUnsigned, ReasonBadSignature,
	ReasonInvalid, ReasonWrongVantage, ReasonStale, ReasonReplayed,
}

// SealResult signs body (a JSON value) as a result record of kind measured by
// vantage, stamped now.
func SealResult(ring *Keyring, kind, vantage string, body []byte, now time.Time) (string, error) {
	vantage = strings.TrimSpace(vantage)
	if vantage == "" {
		return "", errors.New("probercontrol: a result record needs its vantage")
	}
	if !json.Valid(body) {
		return "", errors.New("probercontrol: the result body is not JSON")
	}
	payload, err := json.Marshal(ResultRecord{Schema: resultSchema, Vantage: vantage, IssuedAt: now.UTC(), Body: body})
	if err != nil {
		return "", fmt.Errorf("probercontrol: seal result: %w", err)
	}
	return ring.Seal(kind, payload)
}

// Opened is a result record the reader accepted.
type Opened struct {
	// Body is the record's body (the unsigned record itself, under the legacy
	// switch).
	Body []byte
	// Vantage is the signed vantage. "" for an unsigned record: nothing about
	// it is proven.
	Vantage string
	// Signed reports whether the record verified.
	Signed bool
}

// ResultReport is told about a slot whose outcome changed (structured logging
// lives with the caller).
type ResultReport func(kind, slot string, reason Reason)

// ResultVerifier opens result records on the api side. Safe for concurrent use.
type ResultVerifier struct {
	ring           *Keyring
	kind           string
	maxAge         time.Duration
	now            func() time.Time
	acceptUnsigned func() bool
	report         ResultReport

	mu     sync.Mutex
	high   map[string]time.Time // vantage → newest IssuedAt accepted
	last   map[string]Reason    // slot → last outcome (report on change)
	counts map[Reason]uint64
}

// NewResultVerifier builds a verifier for records of kind. maxAge is the
// oldest record still believed (the publish TTL of the channel). A nil
// acceptUnsigned reads false; a nil report reports nothing.
func NewResultVerifier(ring *Keyring, kind string, maxAge time.Duration, now func() time.Time,
	acceptUnsigned func() bool, report ResultReport) *ResultVerifier {
	if now == nil {
		now = time.Now
	}
	return &ResultVerifier{
		ring: ring, kind: kind, maxAge: maxAge, now: now, acceptUnsigned: acceptUnsigned, report: report,
		high: map[string]time.Time{}, last: map[string]Reason{}, counts: map[Reason]uint64{},
	}
}

// Open verifies raw, read from the slot of vantage (slot "" = a slot that
// names no vantage: the legacy single key or the shared file). ok is false for
// every refusal; the reason says which.
func (v *ResultVerifier) Open(slot, raw string) (Opened, Reason, bool) {
	o, why := v.open(strings.TrimSpace(slot), raw)
	v.note(slot, why)
	return o, why, why == ReasonVerified || why == ReasonUnsignedAccepted
}

func (v *ResultVerifier) open(slot, raw string) (Opened, Reason) {
	if v == nil {
		return Opened{}, ReasonNoKey
	}
	payload, err := v.ring.Open(v.kind, raw)
	switch {
	case errors.Is(err, ErrNoKey):
		return Opened{}, ReasonNoKey
	case errors.Is(err, ErrUnsigned):
		if v.acceptUnsigned != nil && v.acceptUnsigned() && json.Valid([]byte(raw)) {
			return Opened{Body: []byte(raw)}, ReasonUnsignedAccepted
		}
		return Opened{}, ReasonUnsigned
	case err != nil:
		return Opened{}, ReasonBadSignature
	}
	var rec ResultRecord
	if json.Unmarshal(payload, &rec) != nil || rec.Schema != resultSchema ||
		strings.TrimSpace(rec.Vantage) == "" || len(rec.Body) == 0 || rec.IssuedAt.IsZero() {
		return Opened{}, ReasonInvalid
	}
	if slot != "" && rec.Vantage != slot {
		return Opened{}, ReasonWrongVantage
	}
	now := v.now()
	if age := now.Sub(rec.IssuedAt); age > v.maxAge || age < -futureSkew {
		return Opened{}, ReasonStale
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if prev, seen := v.high[rec.Vantage]; seen && rec.IssuedAt.Before(prev) {
		return Opened{}, ReasonReplayed
	}
	if _, seen := v.high[rec.Vantage]; !seen && len(v.high) >= maxResultVantages {
		v.high = map[string]time.Time{}
	}
	v.high[rec.Vantage] = rec.IssuedAt
	return Opened{Body: rec.Body, Vantage: rec.Vantage, Signed: true}, ReasonVerified
}

// note counts the outcome and reports a slot whose outcome changed.
func (v *ResultVerifier) note(slot string, why Reason) {
	if v == nil {
		return
	}
	v.mu.Lock()
	v.counts[why]++
	prev, seen := v.last[slot]
	changed := !seen || prev != why
	if changed {
		if !seen && len(v.last) >= maxResultVantages {
			v.last = map[string]Reason{}
		}
		v.last[slot] = why
	}
	report := v.report
	v.mu.Unlock()
	if changed && report != nil && (seen || why != ReasonVerified) {
		report(v.kind, slot, why)
	}
}

// Count returns how many reads ended in why (tests).
func (v *ResultVerifier) Count(why Reason) uint64 {
	if v == nil {
		return 0
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.counts[why]
}

// WriteMetrics renders netops_prober_results_total{kind,reason}.
func (v *ResultVerifier) WriteMetrics(w io.Writer) {
	if v == nil {
		return
	}
	v.mu.Lock()
	counts := make(map[Reason]uint64, len(v.counts))
	for k, n := range v.counts {
		counts[k] = n
	}
	v.mu.Unlock()
	fmt.Fprintf(w, "# HELP netops_prober_results_total Prober result records read by the api, by kind and outcome (tracker 475: verified, or why it was refused).\n")
	fmt.Fprintf(w, "# TYPE netops_prober_results_total counter\n")
	for _, r := range resultReasons {
		fmt.Fprintf(w, "netops_prober_results_total{kind=%q,reason=%q} %d\n", v.kind, r, counts[r])
	}
}
