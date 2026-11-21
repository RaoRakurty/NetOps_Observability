// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package probercontrol

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// targetKV accepts the targets channel too.
type targetKV struct{ *fakeKV }

func (k targetKV) SetEX(_ context.Context, channel, key, val string, ttl int) error {
	if channel != TargetsChannel && channel != Channel {
		return errors.New("unexpected channel " + channel)
	}
	if k.setErr != nil {
		return k.setErr
	}
	k.vals[key], k.ttl[key] = val, ttl
	return nil
}

func collectOf(tr, st []WireTarget, dropped int) Collect {
	return func(context.Context) ([]WireTarget, []WireTarget, int, error) { return tr, st, dropped, nil }
}

// Round trip: the api publishes both lists signed; the prober reads each
// collector's list with every target's tenant intact.
func TestTargetsRoundTrip(t *testing.T) {
	kv := targetKV{newKV()}
	tr := []WireTarget{{ID: "dem-1", Tenant: "acme", Site: "branch-40", Addr: "203.0.113.10"}}
	st := []WireTarget{{ID: "dem-2", Tenant: "globex", Addr: "198.51.100.20"}}
	p := NewTargetsPublisher(kv, collectOf(tr, st, 0), ring(), clock(t0), nil)
	if err := p.PublishOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if kv.ttl[TargetsKey] != TTLSeconds {
		t.Fatalf("ttl = %d", kv.ttl[TargetsKey])
	}
	r := NewTargetsReader(kv, ring(), clock(t0.Add(30*time.Second)))
	got, refused, why := r.Read(context.Background(), ForTraceroute)
	if why != ReasonPublished || refused != 0 || len(got) != 1 || got[0] != tr[0] {
		t.Fatalf("traceroute: %+v %d %s", got, refused, why)
	}
	got, _, _ = r.Read(context.Background(), ForStamp)
	if len(got) != 1 || got[0].Tenant != "globex" {
		t.Fatalf("stamp: %+v", got)
	}
}

// Layer 3: even inside a validly signed record the prober takes only pinned
// IP literals with an owner, and refuses every never-probed address again.
func TestTargetsReaderRefusesWhatIsNeverProbed(t *testing.T) {
	kv := targetKV{newKV()}
	tr := []WireTarget{
		{ID: "a", Tenant: "acme", Addr: "10.20.0.1"},       // internal: the api's ownership check carried by the signature
		{ID: "b", Tenant: "acme", Addr: "127.0.0.1"},       // loopback
		{ID: "c", Tenant: "acme", Addr: "169.254.169.254"}, // metadata
		{ID: "d", Tenant: "acme", Addr: "branch-edge"},     // a name, not a pinned address
		{ID: "e", Tenant: "", Addr: "203.0.113.5"},         // no owner
		{ID: "f", Tenant: "acme", Addr: "::ffff:203.0.113.6"},
	}
	if err := NewTargetsPublisher(kv, collectOf(tr, nil, 0), ring(), clock(t0), nil).PublishOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, refused, why := NewTargetsReader(kv, ring(), clock(t0)).Read(context.Background(), ForTraceroute)
	if why != ReasonPublished || refused != 4 || len(got) != 2 || got[0].Addr != "10.20.0.1" || got[1].Addr != "203.0.113.6" {
		t.Fatalf("got %+v refused=%d why=%s", got, refused, why)
	}
}

// Every doubt is an EMPTY list: unread, unpublished, unsigned, forged, a
// switches record copied into the targets key, stale, wrong schema, no key.
func TestTargetsReaderFailsClosed(t *testing.T) {
	good, err := json.Marshal(TargetsRecord{V: TargetsSchemaVersion, IssuedAt: t0, Traceroute: []WireTarget{{ID: "a", Tenant: "acme", Addr: "203.0.113.1"}}})
	if err != nil {
		t.Fatal(err)
	}
	signed := func(kind string, b []byte) string {
		raw, err := ring().Seal(kind, b)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	forged, err := NewKeyring(&keyVal{v: strings.Repeat("q", 43)}, clock(t0)).Seal(KindTargets, good)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := json.Marshal(TargetsRecord{V: TargetsSchemaVersion, IssuedAt: t0.Add(-MaxAge - time.Second), Traceroute: []WireTarget{{ID: "a", Tenant: "acme", Addr: "203.0.113.1"}}})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		val    string
		getErr error
		ring   *Keyring
		want   Reason
	}{
		{"unread", "", errors.New("down"), ring(), ReasonUnread},
		{"not published", "", nil, ring(), ReasonNotPublished},
		{"unsigned", string(good), nil, ring(), ReasonUnsigned},
		{"forged", forged, nil, ring(), ReasonBadSignature},
		{"switches record in the targets key", signed(KindSwitches, good), nil, ring(), ReasonBadSignature},
		{"stale", signed(KindTargets, stale), nil, ring(), ReasonStale},
		{"wrong schema", signed(KindTargets, []byte(`{"v":9,"issued_at":"2026-11-20T10:00:00Z"}`)), nil, ring(), ReasonInvalid},
		{"no key on the prober", signed(KindTargets, good), nil, NewKeyring(nil, clock(t0)), ReasonNoKey},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kv := targetKV{newKV()}
			kv.getErr = c.getErr
			if c.val != "" {
				kv.vals[TargetsKey] = c.val
			}
			got, _, why := NewTargetsReader(kv, c.ring, clock(t0)).Read(context.Background(), ForTraceroute)
			if why != c.want || len(got) != 0 {
				t.Fatalf("got %+v %s, want empty %s", got, why, c.want)
			}
		})
	}
}

// The api with no key publishes nothing; a collect failure publishes nothing
// (never a partial or empty list that would read as "the tenant removed its
// targets"); the list is bounded.
func TestTargetsPublisherRefusesAndBounds(t *testing.T) {
	kv := targetKV{newKV()}
	if err := NewTargetsPublisher(kv, collectOf(nil, nil, 0), NewKeyring(nil, clock(t0)), clock(t0), nil).PublishOnce(context.Background()); !errors.Is(err, ErrNoKey) {
		t.Fatalf("no key: %v", err)
	}
	failing := func(context.Context) ([]WireTarget, []WireTarget, int, error) {
		return nil, nil, 0, errors.New("catalogue unreadable")
	}
	if err := NewTargetsPublisher(kv, failing, ring(), clock(t0), nil).PublishOnce(context.Background()); err == nil {
		t.Fatal("a collect failure must be returned")
	}
	if len(kv.vals) != 0 {
		t.Fatalf("nothing may be published: %v", kv.vals)
	}
	many := make([]WireTarget, MaxTargets+10)
	for i := range many {
		many[i] = WireTarget{ID: "x", Tenant: "acme", Addr: "203.0.113.1"}
	}
	if err := NewTargetsPublisher(kv, collectOf(many, nil, 0), ring(), clock(t0), nil).PublishOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _, _ := NewTargetsReader(kv, ring(), clock(t0)).Read(context.Background(), ForTraceroute)
	if len(got) != MaxTargets {
		t.Fatalf("bounded list = %d, want %d", len(got), MaxTargets)
	}
}
