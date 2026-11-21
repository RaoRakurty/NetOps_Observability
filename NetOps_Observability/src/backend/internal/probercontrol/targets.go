// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package probercontrol

// targets.go — the prober's measurement targets, from the per-tenant Digital
// Experience catalogue (Paths redesign P3, 2026-11-21).
//
// A catalogue target with "trace the path" or "STAMP probe" ticked becomes a
// path-discovery or STAMP target. The api projects every tenant's ticked
// targets into ONE signed record and publishes it beside the switch record;
// the prober reads it every check.
//
// THREE LAYERS of target validation, because the prober sends raw packets:
//
//  1. save — dem.Target.Validate refuses an address that is never probed.
//  2. publish (here, api side) — the api RESOLVES each name itself, applies the
//     full probetarget rule against the OWNING tenant's live inventory
//     (internal space only when that tenant owns the exact address), and
//     publishes the PINNED address — never a name, so the prober cannot be
//     DNS-rebound into another address later.
//  3. the prober — believes the record only when it verifies (sign.go), takes
//     only IP literals, and refuses again every address that is never probed.
//     It cannot re-check ownership (it holds no inventory); the signature is
//     what carries the api's decision to it.
//
// Every target carries its tenant, and every path is stamped with it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"netops/backend/internal/probetarget"
)

const (
	// TargetsKey is where the api publishes the target record.
	TargetsKey = "netops:prober:targets"
	// TargetsChannel names the publish channel in the api's failure counter.
	TargetsChannel = "prober-targets"
	// TargetsSchemaVersion is the record's wire version; any other is refused.
	TargetsSchemaVersion = 1
	// MaxTargets bounds each list the prober accepts. The prober traces its
	// list every minute; an unbounded list is an unbounded raw-packet budget.
	MaxTargets = 500
)

// Collector names inside the record.
const (
	ForTraceroute = "traceroute"
	ForStamp      = "stamp"
)

// WireTarget is one destination in the published record. Addr is the address
// the api resolved and checked — the prober dials exactly that.
type WireTarget struct {
	ID     string `json:"id"`
	Tenant string `json:"tenant"`
	Site   string `json:"site,omitempty"`
	Addr   string `json:"addr"`
}

// TargetsRecord is the published payload.
type TargetsRecord struct {
	V          int          `json:"v"`
	IssuedAt   time.Time    `json:"issued_at"`
	Traceroute []WireTarget `json:"traceroute"`
	Stamp      []WireTarget `json:"stamp"`
}

// ── api side ────────────────────────────────────────────────────────────────

// Collect assembles the two lists from the catalogue (already resolved,
// checked and pinned by the caller — layer 2) and how many were dropped.
type Collect func(ctx context.Context) (traceroute, stamp []WireTarget, dropped int, err error)

// TargetsPublisher republishes the signed target record every PublishEvery.
type TargetsPublisher struct {
	kv      KV
	collect Collect
	ring    *Keyring
	now     func() time.Time
	logf    Logf

	lastErr     string
	lastDropped int
}

// NewTargetsPublisher builds the api-side target publisher.
func NewTargetsPublisher(kv KV, collect Collect, ring *Keyring, now func() time.Time, logf Logf) *TargetsPublisher {
	return &TargetsPublisher{kv: kv, collect: collect, ring: ring, now: now, logf: logf}
}

// PublishOnce writes one record. No channel: nothing is published (the
// prober then reads its install-time environment lists).
func (p *TargetsPublisher) PublishOnce(ctx context.Context) error {
	if p.kv == nil || !p.kv.Configured() {
		return nil
	}
	tr, st, dropped, err := p.collect(ctx)
	if err != nil {
		return fmt.Errorf("probercontrol: target list unavailable: %w", err)
	}
	if dropped != p.lastDropped && p.logf != nil {
		// A count, never the addresses: a refused address is still the
		// tenant's data.
		p.logf("prober-targets: %d catalogue target(s) are NOT being measured (unresolvable, never-probed, or an internal address the tenant does not own)", dropped)
	}
	p.lastDropped = dropped
	if len(tr) > MaxTargets {
		tr = tr[:MaxTargets]
	}
	if len(st) > MaxTargets {
		st = st[:MaxTargets]
	}
	b, err := json.Marshal(TargetsRecord{V: TargetsSchemaVersion, IssuedAt: p.now().UTC(), Traceroute: tr, Stamp: st})
	if err != nil {
		return fmt.Errorf("probercontrol: encode targets: %w", err)
	}
	body, err := p.ring.Seal(KindTargets, b)
	if err != nil {
		return err
	}
	if err := p.kv.SetEX(ctx, TargetsChannel, TargetsKey, body, TTLSeconds); err != nil {
		return fmt.Errorf("%w: %w", errTransport, err)
	}
	return nil
}

// Run publishes now and then every PublishEvery until ctx ends; a failure
// before the transport is logged once per change (the transport logs its own).
func (p *TargetsPublisher) Run(ctx context.Context) {
	t := time.NewTicker(PublishEvery)
	defer t.Stop()
	for {
		pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		err := p.PublishOnce(pctx)
		cancel()
		msg := ""
		if err != nil && !errors.Is(err, errTransport) {
			msg = err.Error()
		}
		if msg != p.lastErr && p.logf != nil {
			if msg == "" {
				p.logf("prober-targets: publishing signed target records again")
			} else {
				p.logf("prober-targets: target records are NOT being published, so the prober measures no catalogue target: %s", msg)
			}
		}
		p.lastErr = msg
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ── prober side ─────────────────────────────────────────────────────────────

// TargetsReader reads the signed target record on the prober.
type TargetsReader struct {
	kv   KV
	ring *Keyring
	now  func() time.Time
}

// NewTargetsReader builds the prober-side reader.
func NewTargetsReader(kv KV, ring *Keyring, now func() time.Time) *TargetsReader {
	return &TargetsReader{kv: kv, ring: ring, now: now}
}

// Configured reports whether a channel exists. Without one the prober uses its
// install-time environment lists, as before P3.
func (r *TargetsReader) Configured() bool { return r.kv != nil && r.kv.Configured() }

// Read returns the verified targets for one collector, how many it refused
// (layer 3), and why the list reads as it does. Every doubt is an EMPTY list,
// never a stale or unverified one.
func (r *TargetsReader) Read(ctx context.Context, which string) ([]WireTarget, int, Reason) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	raw, err := r.kv.Get(cctx, TargetsKey)
	cancel()
	if err != nil {
		return nil, 0, ReasonUnread
	}
	if raw == "" {
		return nil, 0, ReasonNotPublished
	}
	payload, err := r.ring.Open(KindTargets, raw)
	switch {
	case errors.Is(err, ErrNoKey):
		return nil, 0, ReasonNoKey
	case errors.Is(err, ErrUnsigned):
		return nil, 0, ReasonUnsigned
	case err != nil:
		return nil, 0, ReasonBadSignature
	}
	var rec TargetsRecord
	if err := json.Unmarshal(payload, &rec); err != nil || rec.V != TargetsSchemaVersion || rec.IssuedAt.IsZero() {
		return nil, 0, ReasonInvalid
	}
	if age := r.now().Sub(rec.IssuedAt); age > MaxAge || age < -futureSkew {
		return nil, 0, ReasonStale
	}
	var list []WireTarget
	switch which {
	case ForTraceroute:
		list = rec.Traceroute
	case ForStamp:
		list = rec.Stamp
	default:
		return nil, 0, ReasonInvalid
	}
	if len(list) > MaxTargets {
		list = list[:MaxTargets]
	}
	out := make([]WireTarget, 0, len(list))
	refused := 0
	for _, t := range list {
		a, err := netip.ParseAddr(t.Addr)
		if err != nil || probetarget.Classify(a) == probetarget.ClassRefused || t.Tenant == "" {
			refused++ // not a pinned address, never probed, or unowned
			continue
		}
		t.Addr = a.Unmap().String()
		out = append(out, t)
	}
	return out, refused, ReasonPublished
}
