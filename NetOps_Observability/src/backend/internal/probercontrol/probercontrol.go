// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package probercontrol delivers the platform administrator's Features-page
// switches for the prober's active-measurement collectors from the api to the
// prober container (Paths redesign P2, 2026-11-20).
//
// The prober runs with NET_RAW and reads nothing from the api's settings
// store, so a switch saved on the Features page could not reach it: path
// discovery and active probing could only be turned on by editing .env, which
// customers never do. The api now resolves each delivered switch exactly as
// the Features page shows it (a saved value wins over the install value, which
// wins over the default — internal/featureflags) and publishes the result on
// the shared key-value channel the api already uses to hand the prober its
// work (netops:dem:targets, netops:wan:circuits): Valkey, password-authenticated
// (SEC-012.1) and TLS-wrapped when the install turns TLS on (SEC-012.2). The
// prober reads it before every collector check.
//
// FAIL CLOSED. Privileged measurement is off by default (ADR 0001), so every
// doubt reads OFF: an unread channel, a record nobody published, a record that
// will not decode, a record older than MaxAge (the api stopped publishing), a
// record stamped in the future, and a switch the record does not name. The one
// exception is a deployment with NO channel configured at all (a hand-made
// install without the key-value service): there the prober's own environment
// is the only setting that exists, and it is read as before.
//
// SIGNED (P3, sign.go). Every record is an HMAC-SHA256 envelope under a key
// only the api and the prober hold; the prober reads an unsigned or
// badly-signed record, or any record while it holds no key, as OFF.
//
// This package owns the wire contract and both ends' logic; the transport is
// injected (KV), so it never imports the collectors and is tested without a
// server.
package probercontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// The switches delivered to the prober. Each is an environment variable name,
// the same name the Features page and the install use.
const (
	// EnvTraceroute is scheduled path discovery (collectors/traceroute.go).
	EnvTraceroute = "FEATURE_TRACEROUTE"
	// EnvActiveProbe is the STAMP (RFC 8762) sender (collectors/stamp.go).
	EnvActiveProbe = "FEATURE_ACTIVE_PROBE"
)

// Delivered lists every switch this package carries, sorted.
func Delivered() []string {
	out := []string{EnvActiveProbe, EnvTraceroute}
	sort.Strings(out)
	return out
}

const (
	// Key is where the api publishes the switch record.
	Key = "netops:prober:switches"
	// Channel names the publish channel in the api's failure counter.
	Channel = "prober-switches"
	// SchemaVersion is the record's wire version; any other is refused. 2 =
	// the record travels inside a signed envelope (P3); a v1 prober reads a v2
	// envelope as an unknown schema, which is OFF.
	SchemaVersion = 2
	// PublishEvery is how often the api republishes.
	PublishEvery = 30 * time.Second
	// TTLSeconds expires the record when the api stops publishing.
	TTLSeconds = 120
	// MaxAge is how old a record may be before the prober treats it as stale.
	// Four publish intervals: one missed or slow publish never flips a
	// collector, a stopped api turns measurement off within two minutes.
	MaxAge = 120 * time.Second
	// futureSkew tolerates clock difference between the api and the prober
	// (same host in compose; separate nodes elsewhere).
	futureSkew = 60 * time.Second
	// CheckEvery is how often the prober re-checks a switch. A change applies
	// within one check: no restart.
	CheckEvery = 15 * time.Second
)

// Record is the published wire format.
type Record struct {
	V        int             `json:"v"`
	IssuedAt time.Time       `json:"issued_at"`
	Switches map[string]bool `json:"switches"`
}

// KV is the key-value channel, injected. Get returns "" with a nil error when
// nothing is published at key.
type KV interface {
	Configured() bool
	SetEX(ctx context.Context, channel, key, val string, ttlSec int) error
	Get(ctx context.Context, key string) (string, error)
}

// ── api side ────────────────────────────────────────────────────────────────

// Resolver answers the running value of a switch as the Features page shows it.
type Resolver func(env string) bool

// Publisher republishes the resolved switches every PublishEvery.
type Publisher struct {
	kv      KV
	resolve Resolver
	ring    *Keyring
	now     func() time.Time
	logf    Logf

	lastErr string // dedupes the signing-failure log line
}

// NewPublisher builds the api-side publisher. ring signs every record; with no
// key loaded nothing is published (the prober then reads every switch OFF).
func NewPublisher(kv KV, resolve Resolver, ring *Keyring, now func() time.Time, logf Logf) *Publisher {
	return &Publisher{kv: kv, resolve: resolve, ring: ring, now: now, logf: logf}
}

// Encode renders the signed record for the switches as resolved now.
func (p *Publisher) Encode() (string, error) {
	rec := Record{V: SchemaVersion, IssuedAt: p.now().UTC(), Switches: map[string]bool{}}
	for _, env := range Delivered() {
		rec.Switches[env] = p.resolve(env)
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return "", fmt.Errorf("probercontrol: encode: %w", err)
	}
	return p.ring.Seal(KindSwitches, b)
}

// PublishOnce writes one record. A deployment with no channel publishes
// nothing and reports no error: the prober reads its own environment there.
func (p *Publisher) PublishOnce(ctx context.Context) error {
	if p.kv == nil || !p.kv.Configured() {
		return nil
	}
	body, err := p.Encode()
	if err != nil {
		return err
	}
	if err := p.kv.SetEX(ctx, Channel, Key, body, TTLSeconds); err != nil {
		return fmt.Errorf("%w: %w", errTransport, err)
	}
	return nil
}

// errTransport marks a failure the transport already counted and logged.
var errTransport = errors.New("probercontrol: publish failed")

// Run publishes now and then every PublishEvery until ctx ends. A failed
// publish is retried on the next tick; the prober turns the collectors off
// once the record ages past MaxAge, which is the safe direction. A transport
// failure is counted and logged by the transport; a failure BEFORE the
// transport (no signing key) is logged here, once per change.
func (p *Publisher) Run(ctx context.Context) {
	t := time.NewTicker(PublishEvery)
	defer t.Stop()
	for {
		pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := p.PublishOnce(pctx)
		cancel()
		p.noteErr(err)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// noteErr logs a publish failure that the transport did not see (it never
// got that far), once per distinct failure, and the recovery once.
func (p *Publisher) noteErr(err error) {
	msg := ""
	if err != nil && !errors.Is(err, errTransport) {
		msg = err.Error()
	}
	if msg == p.lastErr || p.logf == nil {
		p.lastErr = msg
		return
	}
	if msg == "" {
		p.logf("prober-switch: publishing signed switch records again")
	} else {
		p.logf("prober-switch: switch records are NOT being published, so the prober reads every switch OFF: %s", msg)
	}
	p.lastErr = msg
}

// ── prober side ─────────────────────────────────────────────────────────────

// Reason says why a switch reads the way it does. It is a metric label and a
// log field, so it is a closed, low-cardinality set.
type Reason string

const (
	ReasonPublished    Reason = "published"  // the api's record says so
	ReasonNoChannel    Reason = "no_channel" // no key-value channel: the prober's own environment
	ReasonUnread       Reason = "channel_unread"
	ReasonNotPublished Reason = "not_published" // no record, or the record omits this switch
	ReasonInvalid      Reason = "invalid"       // will not decode, or an unknown schema version
	ReasonStale        Reason = "stale"         // older than MaxAge, or stamped in the future
	ReasonNoKey        Reason = "no_key"        // the prober holds no signing key
	ReasonUnsigned     Reason = "unsigned"      // the record is not a signed envelope
	ReasonBadSignature Reason = "bad_signature" // the signature does not verify
)

// Decision is one switch's effective state and why.
type Decision struct {
	On     bool
	Reason Reason
}

// LookupEnv is os.LookupEnv, injected.
type LookupEnv func(key string) (string, bool)

// Logf is log.Printf, injected.
type Logf func(format string, args ...any)

// Reader decides each switch on the prober from the published record.
type Reader struct {
	kv   KV
	ring *Keyring
	env  LookupEnv
	now  func() time.Time
	logf Logf

	mu   sync.Mutex
	last map[string]Decision
}

// NewReader builds the prober-side reader. ring verifies every record.
func NewReader(kv KV, ring *Keyring, env LookupEnv, now func() time.Time, logf Logf) *Reader {
	return &Reader{kv: kv, ring: ring, env: env, now: now, logf: logf, last: map[string]Decision{}}
}

// Decide reads the channel and returns the switch's effective state. Every
// change of state or reason is logged once, as one structured line.
func (r *Reader) Decide(ctx context.Context, env string) Decision {
	d := r.decide(ctx, env)
	r.mu.Lock()
	prev, seen := r.last[env]
	r.last[env] = d
	r.mu.Unlock()
	if (!seen || prev != d) && r.logf != nil {
		r.logf("prober-switch: switch=%s on=%t reason=%s", env, d.On, d.Reason)
	}
	return d
}

func (r *Reader) decide(ctx context.Context, env string) Decision {
	if r.kv == nil || !r.kv.Configured() {
		v, _ := r.env(env)
		return Decision{On: v == "true", Reason: ReasonNoChannel}
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	raw, err := r.kv.Get(cctx, Key)
	cancel()
	if err != nil {
		return Decision{Reason: ReasonUnread}
	}
	if raw == "" {
		return Decision{Reason: ReasonNotPublished}
	}
	payload, err := r.ring.Open(KindSwitches, raw)
	switch {
	case errors.Is(err, ErrNoKey):
		return Decision{Reason: ReasonNoKey}
	case errors.Is(err, ErrUnsigned):
		return Decision{Reason: ReasonUnsigned}
	case err != nil:
		return Decision{Reason: ReasonBadSignature}
	}
	var rec Record
	if err := json.Unmarshal(payload, &rec); err != nil || rec.V != SchemaVersion || rec.IssuedAt.IsZero() {
		return Decision{Reason: ReasonInvalid}
	}
	now := r.now()
	if age := now.Sub(rec.IssuedAt); age > MaxAge || age < -futureSkew {
		return Decision{Reason: ReasonStale}
	}
	on, ok := rec.Switches[env]
	if !ok {
		return Decision{Reason: ReasonNotPublished}
	}
	return Decision{On: on, Reason: ReasonPublished}
}
