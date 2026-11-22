// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package probercontrol

// dem.go — the Digital Experience channels are signed too (tracker 475,
// 2026-11-22).
//
// The prober's DEM runner shares the key-value store with every service that
// holds the Valkey password, and both of its channels were plain JSON:
//
//   - netops:dem:targets (api → prober): the experience work queue. Anyone who
//     could write it chose the hosts the prober's HTTP/DNS/TCP/ICMP checks
//     dial, and the tenant each result is filed under.
//   - netops:dem:runs:<vantage> (prober → api): the per-run records the
//     reliability grade is computed from. Each run names its tenant, so a
//     forged run landed in that tenant's experience scores.
//
// The work queue is a DEMTargetsRecord sealed with the P3 key under its own
// kind (dem-targets). The record carries the api's issued-at AND the TTL it
// published with: the projector's cadence is an api setting the prober cannot
// see, so the api states how long the record is good for and the signature
// binds that statement. The prober reads it with a DEMTargetsReader, which
// refuses — every doubt is an EMPTY queue, never the previous one — an
// unsigned or badly signed record, any record while it holds no key, a record
// that will not decode, one older than its own TTL (capped at
// MaxDEMTargetsAge) or stamped in the future, and one older than a record it
// already accepted (a kept copy replayed to roll the queue back).
//
// The run records are a ResultRecord (results.go) of kind dem-runs: the
// vantage that ran the checks, when it sealed them, and the batch. The api
// opens them with a ResultVerifier exactly as it opens the path sets, so the
// refusals, the per-vantage replay mark and the metric
// (netops_prober_results_total{kind="dem-runs",reason}) are the same code.
//
// ROLLOUT. The api and the prober ship in one image. A prober older than this
// change publishes unsigned runs; the api refuses them unless the platform
// administrator turns on the console-only DEM_RUNS_ACCEPT_UNSIGNED switch. It
// is a separate switch from PROBE_PATHS_ACCEPT_UNSIGNED on purpose: runs feed
// a tenant's experience grade and the severity of its experience incidents,
// paths feed the topology and RCA direction — accepting one unproven channel
// while an old prober is upgraded must not silently accept the other. There is
// no switch in the other direction: an old api publishes an unsigned queue,
// and the new prober measures nothing until the api is upgraded too (the two
// are deployed together, and measuring unproven targets is the hole itself).

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	// KindDEMTargets is the record kind of the experience work queue.
	KindDEMTargets = "dem-targets"
	// KindDEMRuns is the record kind of a prober's experience run batch.
	KindDEMRuns = "dem-runs"
	// EnvAcceptUnsignedDEMRuns is the console-only Features switch that accepts
	// the unsigned run batches a pre-tracker-475 prober publishes.
	EnvAcceptUnsignedDEMRuns = "DEM_RUNS_ACCEPT_UNSIGNED"
	// DEMTargetsSchemaVersion is the work-queue record's wire version; any
	// other is refused.
	DEMTargetsSchemaVersion = 1
	// MaxDEMTargetsAge caps the TTL a work-queue record may claim: three times
	// the projector's slowest cadence (15 min), the longest TTL it publishes.
	MaxDEMTargetsAge = 45 * time.Minute
)

// DEMTargetsRecord is the signed payload of the experience work queue.
type DEMTargetsRecord struct {
	V        int       `json:"v"`
	IssuedAt time.Time `json:"issued_at"`
	// TTLSec is how long the api published the record for; the prober believes
	// it no longer than that (and never longer than MaxDEMTargetsAge).
	TTLSec int `json:"ttl_sec"`
	// Targets is the work queue (a JSON array of dem.WireTarget). Carried as
	// raw JSON so this package stays independent of the dem domain.
	Targets json.RawMessage `json:"targets"`
}

// SealDEMTargets signs targets (a JSON array) as the work queue issued now and
// good for ttlSec.
func SealDEMTargets(ring *Keyring, targets []byte, ttlSec int, now time.Time) (string, error) {
	if ttlSec <= 0 {
		return "", errors.New("probercontrol: a work queue needs a positive TTL")
	}
	if !isJSONArray(targets) {
		return "", errors.New("probercontrol: the work queue is not a JSON array")
	}
	payload, err := json.Marshal(DEMTargetsRecord{V: DEMTargetsSchemaVersion, IssuedAt: now.UTC(), TTLSec: ttlSec, Targets: targets})
	if err != nil {
		return "", fmt.Errorf("probercontrol: seal work queue: %w", err)
	}
	return ring.Seal(KindDEMTargets, payload)
}

// DEMTargetsReader opens the signed work queue on the prober. Safe for
// concurrent use.
type DEMTargetsReader struct {
	ring *Keyring
	now  func() time.Time

	mu     sync.Mutex
	newest time.Time // IssuedAt of the newest record accepted
}

// NewDEMTargetsReader builds the prober-side reader. A nil now reads the wall
// clock.
func NewDEMTargetsReader(ring *Keyring, now func() time.Time) *DEMTargetsReader {
	if now == nil {
		now = time.Now
	}
	return &DEMTargetsReader{ring: ring, now: now}
}

// Open verifies raw (the value read from the work-queue key) and returns the
// queue's JSON array. The reason is ReasonPublished for an accepted record,
// ReasonNotPublished for an empty key, and the refusal otherwise — in which
// case the body is nil and nothing may be measured from it.
func (r *DEMTargetsReader) Open(raw string) ([]byte, Reason) {
	if r == nil {
		return nil, ReasonNoKey
	}
	if strings.TrimSpace(raw) == "" {
		return nil, ReasonNotPublished
	}
	payload, err := r.ring.Open(KindDEMTargets, raw)
	switch {
	case errors.Is(err, ErrNoKey):
		return nil, ReasonNoKey
	case errors.Is(err, ErrUnsigned):
		return nil, ReasonUnsigned
	case err != nil:
		return nil, ReasonBadSignature
	}
	var rec DEMTargetsRecord
	if json.Unmarshal(payload, &rec) != nil || rec.V != DEMTargetsSchemaVersion || rec.IssuedAt.IsZero() ||
		rec.TTLSec <= 0 || !isJSONArray(rec.Targets) {
		return nil, ReasonInvalid
	}
	maxAge := time.Duration(rec.TTLSec) * time.Second
	if maxAge > MaxDEMTargetsAge {
		maxAge = MaxDEMTargetsAge
	}
	if age := r.now().Sub(rec.IssuedAt); age > maxAge || age < -futureSkew {
		return nil, ReasonStale
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if rec.IssuedAt.Before(r.newest) {
		return nil, ReasonReplayed
	}
	r.newest = rec.IssuedAt
	return rec.Targets, ReasonPublished
}

// isJSONArray reports whether b is a JSON array (null is not one).
func isJSONArray(b []byte) bool {
	var a []json.RawMessage
	return json.Unmarshal(b, &a) == nil && a != nil
}
