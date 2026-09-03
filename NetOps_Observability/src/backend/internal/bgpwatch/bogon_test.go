package bgpwatch

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// TestStaticBogonTableParses is the guard on the embedded literals: every row
// must be a syntactically valid, ALREADY-MASKED CIDR, and must carry an RFC and
// a reason. A row that silently failed to parse would quietly un-bogon a whole
// reserved block.
func TestStaticBogonTableParses(t *testing.T) {
	for _, rows := range [][]staticBogon{staticBogonsV4, staticBogonsV6} {
		for _, r := range rows {
			p, err := netip.ParsePrefix(r.cidr)
			if err != nil {
				t.Fatalf("bogon row %q does not parse: %v", r.cidr, err)
			}
			if p.Masked().String() != p.String() {
				t.Fatalf("bogon row %q is not in masked/canonical form", r.cidr)
			}
			if strings.TrimSpace(r.rfc) == "" || strings.TrimSpace(r.why) == "" {
				t.Fatalf("bogon row %q must name its RFC and its reason", r.cidr)
			}
		}
	}
	s := NewBogonSet()
	if got, want := s.StaticCount(), len(staticBogonsV4)+len(staticBogonsV6); got != want {
		t.Fatalf("compiled %d blocks, want %d — a row was dropped", got, want)
	}
}

func TestBogonLookupContainmentAndDirection(t *testing.T) {
	s := NewBogonSet()
	cases := []struct {
		prefix string
		want   bool
		block  string
	}{
		{"10.1.2.0/24", true, "10.0.0.0/8"},        // contained → bogon
		{"10.0.0.0/8", true, "10.0.0.0/8"},         // equal → bogon
		{"192.0.2.0/24", true, "192.0.2.0/24"},     // TEST-NET-1
		{"100.64.0.0/10", true, "100.64.0.0/10"},   // CGNAT
		{"198.18.5.0/24", true, "198.18.0.0/15"},   // benchmarking
		{"2001:db8:1::/48", true, "2001:db8::/32"}, // v6 documentation
		{"fc00::/7", true, "fc00::/7"},             // unique-local
		{"193.0.0.0/21", false, ""},                // a real RIPE NCC prefix
		{"2001:67c:2e8::/48", false, ""},           // a real v6 prefix in 2000::/3
		{"0.0.0.0/0", false, ""},                   // a default route COVERS 10/8; not a bogon announcement
	}
	for _, c := range cases {
		p := netip.MustParsePrefix(c.prefix)
		e, ok := s.Lookup(p)
		if ok != c.want {
			t.Fatalf("%s: bogon=%v, want %v (%+v)", c.prefix, ok, c.want, e)
		}
		if ok && e.Block != c.block {
			t.Fatalf("%s: matched %s, want %s", c.prefix, e.Block, c.block)
		}
	}
}

// The IPv6 architecture rule: outside 2000::/3 is undelegated space, reported
// as unallocated rather than needing a snapshot table row.
func TestBogonV6OutsideGlobalUnicastIsUnallocated(t *testing.T) {
	s := NewBogonSet()
	e, ok := s.Lookup(netip.MustParsePrefix("4000::/16"))
	if !ok || e.Reason != ReasonUnallocated {
		t.Fatalf("4000::/16 should be unallocated, got %+v ok=%v", e, ok)
	}
	if _, ok := s.Lookup(netip.MustParsePrefix("2400::/12")); ok {
		t.Fatal("2400::/12 is inside delegated global unicast and must not be a bogon")
	}
}

type fakeGetter struct {
	body string
	err  error
	n    int
}

func (f *fakeGetter) Get(_ context.Context, _ string, maxBytes int64) ([]byte, error) {
	f.n++
	if f.err != nil {
		return nil, f.err
	}
	b := []byte(f.body)
	if int64(len(b)) > maxBytes {
		b = b[:maxBytes]
	}
	return b, nil
}

func noSleep(context.Context, time.Duration) error { return nil }
func fixedJitter() float64                         { return 0.5 }

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

func TestBogonFeedParsesCachesAndSurvivesFailure(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	s := NewBogonSet()
	g := &fakeGetter{body: "# comment\n\n5.10.0.0/16\n203.0.113.0/24\nnot-a-cidr\n"}
	if err := s.RefreshFeed(context.Background(), g, "https://example.net/fullbogons.txt", fixedClock(now), noSleep, fixedJitter); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	st := s.FeedStatus(true)
	if st.Entries != 2 {
		t.Fatalf("kept %d rows, want 2 (the unparsable row must be dropped, not guessed)", st.Entries)
	}
	e, ok := s.Lookup(netip.MustParsePrefix("5.10.1.0/24"))
	if !ok || e.Reason != ReasonFullBogonFeed {
		t.Fatalf("feed row did not match: %+v ok=%v", e, ok)
	}

	// Cached: a second call inside the TTL does not refetch.
	before := g.n
	if err := s.RefreshFeed(context.Background(), g, "https://example.net/fullbogons.txt", fixedClock(now.Add(time.Minute)), noSleep, fixedJitter); err != nil {
		t.Fatalf("cached refresh: %v", err)
	}
	if g.n != before {
		t.Fatalf("refetched inside the TTL (%d → %d)", before, g.n)
	}

	// A LATER failure must not un-bogon anything: the previous rows stand and
	// the error is recorded rather than swallowed.
	bad := &fakeGetter{err: errors.New("upstream down")}
	err := s.RefreshFeed(context.Background(), bad, "https://example.net/fullbogons.txt", fixedClock(now.Add(2*FeedTTL)), noSleep, fixedJitter)
	if err == nil {
		t.Fatal("a failing feed must return an error, not a silent success")
	}
	if bad.n != feedAttempts {
		t.Fatalf("made %d attempts, want %d", bad.n, feedAttempts)
	}
	if _, ok := s.Lookup(netip.MustParsePrefix("5.10.1.0/24")); !ok {
		t.Fatal("a feed outage silently dropped the previously fetched rows")
	}
	if s.FeedStatus(true).Error == "" {
		t.Fatal("the feed error must be visible on the status block (§10)")
	}
}

func TestBogonFeedRefusesEmptyResult(t *testing.T) {
	s := NewBogonSet()
	g := &fakeGetter{body: "# nothing but comments\n"}
	if err := s.RefreshFeed(context.Background(), g, "", fixedClock(time.Now()), noSleep, fixedJitter); err == nil {
		t.Fatal("a feed with no parsable rows must be an error, not an empty accepted set")
	}
}

func TestSightingRegisterIsPerTenantAndBounded(t *testing.T) {
	r := newSightingRegister()
	at := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	mk := func(p string) Sighting {
		return Sighting{Prefix: p, Source: "feed", Peer: "rrc00", FirstSeen: at, LastSeen: at}
	}
	if !r.note("acme", mk("10.0.0.0/8")) {
		t.Fatal("first sighting should report NEW")
	}
	if r.note("acme", mk("10.0.0.0/8")) {
		t.Fatal("a repeat sighting must not report NEW (it would re-alert forever)")
	}
	r.note("globex", mk("192.168.0.0/16"))

	if got := r.list("acme", 0); len(got) != 1 || got[0].Prefix != "10.0.0.0/8" {
		t.Fatalf("acme sees %+v — cross-tenant leak", got)
	}
	if got := r.list("globex", 0); len(got) != 1 || got[0].Prefix != "192.168.0.0/16" {
		t.Fatalf("globex sees %+v — cross-tenant leak", got)
	}
	if got := r.list("", 0); len(got) != 0 {
		t.Fatalf("a scopeless read returned %d rows; it must return none", len(got))
	}
	if got := r.list("*", 0); len(got) != 0 {
		t.Fatal("the '*' wildcard must not be a readable tenant here")
	}

	// Bounded: the register never grows past SightingMaxPerTenant.
	for i := 0; i < SightingMaxPerTenant+50; i++ {
		s := mk("10.0.0.0/8")
		s.Peer = "peer-" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		s.LastSeen = at.Add(time.Duration(i) * time.Second)
		r.note("acme", s)
	}
	if got := len(r.list("acme", 0)); got > SightingMaxPerTenant {
		t.Fatalf("register grew to %d rows, bound is %d", got, SightingMaxPerTenant)
	}
}
