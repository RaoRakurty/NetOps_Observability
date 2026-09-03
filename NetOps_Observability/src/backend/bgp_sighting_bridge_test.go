package backend

// bgp_sighting_bridge_test.go — the two IMMEDIATE sighting paths.
//
// Before this wiring, Evaluator.NoteSighting had no callers at all: the only
// way a bogon sighting ever reached /api/bgp/bogons was the evaluator's own
// 5-minute sweep, and on a stack whose watchlist read failed the sweep returned
// before it ever ran (found live, 2026-09-03: real BMP bytes for a bogon prefix
// in the store, "bogons seen" empty). These tests hold the chain end to end:
//
//	router → bmp.Store.Apply → Applied.Announced (tenant-stamped by the store)
//	       → server.bgpWatchNoteBMPAnnounce → Evaluator.NoteSighting
//	       → GET /api/bgp/bogons for THAT tenant only.

import (
	"net/netip"
	"testing"
	"time"

	"netops/backend/internal/bgpdepth"
	"netops/backend/internal/bgpwatch"
	"netops/backend/internal/bmp"
)

// bmpApplyAnnounce drives real Route Monitoring frames (built by this package's
// own independent wire-format witness, bmpAnnounce in bmp_deps_test.go) through
// a real bmp.Store, and returns what the store reported — the same value the
// listener hands the observer.
func bmpApplyAnnounce(t *testing.T, store *bmp.Store, sessionID, tenant, device string, prefixes ...string) []bmp.AnnouncedPrefix {
	t.Helper()
	if err := store.Open(sessionID, tenant, device, "203.0.113.9:40000"); err != nil {
		t.Fatalf("open bmp session: %v", err)
	}
	var out []bmp.AnnouncedPrefix
	for _, cidr := range prefixes {
		applied := store.Apply(sessionID, bmpAnnounce(t, "198.51.100.7", 64500, cidr))
		if applied.StoredUpdates != 1 {
			t.Fatalf("store took %d updates for %s, want 1", applied.StoredUpdates, cidr)
		}
		out = append(out, applied.Announced...)
	}
	return out
}

// The store stamps the OWNING TENANT on every announcement it reports, so the
// observer never has to (and never gets to) decide who a prefix belongs to.
func TestBMPStoreReportsAnnouncedPrefixesTenantStamped(t *testing.T) {
	store := bmp.NewStore(func() time.Time { return time.Now().UTC() }, 8, 64)
	got := bmpApplyAnnounce(t, store, "s1", "acme", "dev-1", "192.0.2.0/24", "8.8.8.0/24")
	if len(got) != 2 {
		t.Fatalf("Applied.Announced = %d rows, want 2", len(got))
	}
	for _, a := range got {
		if a.TenantID != "acme" || a.DeviceID != "dev-1" {
			t.Fatalf("announcement not stamped from the session: %+v", a)
		}
		if a.At.IsZero() || a.PeerAddr == "" {
			t.Fatalf("announcement missing peer/time: %+v", a)
		}
	}
	// A WITHDRAWAL is not an announcement: a bogon sighting claims a prefix was
	// announced, and reporting a withdrawal would invert that claim.
	if err := store.Open("s2", "acme", "dev-1", "203.0.113.9:40001"); err != nil {
		t.Fatal(err)
	}
	msg := bmpAnnounce(t, "198.51.100.7", 64500, "192.0.2.0/24")
	msg.Update.Withdrawn, msg.Update.Announced = msg.Update.Announced, nil
	applied := store.Apply("s2", msg)
	if len(applied.Announced) != 0 {
		t.Fatalf("a withdrawal was reported as an announcement: %+v", applied.Announced)
	}
}

// End to end: a BMP update carrying the RFC 5737 documentation prefix produces
// a sighting with its block and reason; a routable prefix produces none.
func TestBMPAnnouncementBecomesABogonSighting(t *testing.T) {
	s := bgpWatchTestServer(t, true)
	store := bmp.NewStore(func() time.Time { return time.Now().UTC() }, 8, 64)

	s.bgpWatchNoteBMPAnnounce(bmpApplyAnnounce(t, store, "s1", "acme", "dev-1",
		"192.0.2.0/24", // RFC 5737 TEST-NET-1 — a bogon
		"8.8.8.0/24",   // globally routable — not a bogon
	))

	sightings, err := s.bgpWatchEval.Sightings("acme", 50)
	if err != nil {
		t.Fatalf("Sightings(acme): %v", err)
	}
	if len(sightings) != 1 {
		t.Fatalf("want exactly the bogon sighting, got %d: %+v", len(sightings), sightings)
	}
	got := sightings[0]
	if got.Prefix != "192.0.2.0/24" {
		t.Fatalf("sighting prefix = %q", got.Prefix)
	}
	if got.Entry.Block == "" || got.Entry.Reason == "" {
		t.Fatalf("sighting carries no block/reason — the page could not say WHY: %+v", got.Entry)
	}
	if got.Source != "bmp" {
		t.Fatalf("source = %q, want bmp (the periodic sweep writes the same key)", got.Source)
	}
	if got.Peer == "" || got.LastSeen.IsZero() {
		t.Fatalf("sighting missing peer/last_seen: %+v", got)
	}
	// The same announcement seen twice is ONE sighting, not two: the immediate
	// path and the evaluator's sweep both write, and they must not double-count.
	s.bgpWatchNoteBMPAnnounce(bmpApplyAnnounce(t, store, "s2", "acme", "dev-1", "192.0.2.0/24"))
	again, err := s.bgpWatchEval.Sightings("acme", 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 1 {
		t.Fatalf("re-announcement duplicated the sighting: %+v", again)
	}
	if again[0].Count < 2 {
		t.Fatalf("re-announcement did not bump the count: %+v", again[0])
	}
}

// §3a: one tenant's sightings are invisible to another, and an announcement
// whose session resolved to no tenant is dropped rather than pooled.
func TestBMPSightingsAreTenantScoped(t *testing.T) {
	s := bgpWatchTestServer(t, true)
	store := bmp.NewStore(func() time.Time { return time.Now().UTC() }, 8, 64)

	s.bgpWatchNoteBMPAnnounce(bmpApplyAnnounce(t, store, "a1", "acme", "dev-a", "192.0.2.0/24"))
	s.bgpWatchNoteBMPAnnounce(bmpApplyAnnounce(t, store, "g1", "globex", "dev-g", "198.18.0.0/24"))

	acme, err := s.bgpWatchEval.Sightings("acme", 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, sg := range acme {
		if sg.Prefix == "198.18.0.0/24" {
			t.Fatalf("CROSS-TENANT LEAK: acme sees globex's sighting: %+v", acme)
		}
	}
	gx, err := s.bgpWatchEval.Sightings("globex", 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, sg := range gx {
		if sg.Prefix == "192.0.2.0/24" {
			t.Fatalf("CROSS-TENANT LEAK: globex sees acme's sighting: %+v", gx)
		}
	}

	// An unattributed row is DROPPED. It can only arise from a wiring bug (the
	// receiver refuses a session it cannot attribute), and the safe answer is
	// to record nothing rather than to invent an owner.
	before := len(acme)
	s.bgpWatchNoteBMPAnnounce([]bmp.AnnouncedPrefix{
		{TenantID: "", DeviceID: "d", PeerAddr: "198.51.100.7", Prefix: netip.MustParsePrefix("192.0.2.0/24"), At: time.Now().UTC()},
		{TenantID: "*", DeviceID: "d", PeerAddr: "198.51.100.7", Prefix: netip.MustParsePrefix("192.0.2.0/24"), At: time.Now().UTC()},
	})
	after, err := s.bgpWatchEval.Sightings("acme", 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != before {
		t.Fatalf("an untenanted announcement was recorded: %+v", after)
	}
}

// The near-live feed ring's observer registers a bogon the moment a poll lands,
// skips withdrawals, and is tenant-scoped by the poller that produced it.
func TestFeedUpdatesBecomeBogonSightings(t *testing.T) {
	s := bgpWatchTestServer(t, true)
	now := time.Now().UTC()

	s.bgpWatchNoteFeedUpdates("acme", []bgpdepth.Update{
		{Type: "A", Prefix: "192.0.2.0/24", Peer: "rrc00", Origin: 64500, Time: now},
		{Type: "A", Prefix: "8.8.8.0/24", Peer: "rrc00", Time: now},
		{Type: "W", Prefix: "198.18.0.0/24", Peer: "rrc00", Time: now},
	})

	rows, err := s.bgpWatchEval.Sightings("acme", 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("want exactly the announced bogon, got %+v", rows)
	}
	if rows[0].Prefix != "192.0.2.0/24" || rows[0].Source != "feed" {
		t.Fatalf("sighting = %+v, want the feed-sourced 192.0.2.0/24", rows[0])
	}
	if rows[0].Origin != 64500 {
		t.Fatalf("feed sightings carry the origin ASN; got %d", rows[0].Origin)
	}
	// A non-concrete tenant records nothing.
	for _, tenant := range []string{"", "  ", "*"} {
		s.bgpWatchNoteFeedUpdates(tenant, []bgpdepth.Update{
			{Type: "A", Prefix: "198.18.0.0/24", Peer: "rrc00", Time: now},
		})
	}
	if again, _ := s.bgpWatchEval.Sightings("acme", 50); len(again) != 1 {
		t.Fatalf("an unscoped feed update landed somewhere: %+v", again)
	}
}

// With the evaluator off, both bridges are inert — no panic, no work, and no
// pretence that a sighting register exists.
func TestSightingBridgesAreInertWithoutTheEvaluator(t *testing.T) {
	s := bgpWatchTestServer(t, false)
	s.bgpWatchNoteBMPAnnounce([]bmp.AnnouncedPrefix{
		{TenantID: "acme", Prefix: netip.MustParsePrefix("192.0.2.0/24"), At: time.Now().UTC()},
	})
	s.bgpWatchNoteFeedUpdates("acme", []bgpdepth.Update{
		{Type: "A", Prefix: "192.0.2.0/24", Time: time.Now().UTC()},
	})
}

// A watched prefix that is a bogon is flagged on the watchlist response with
// NO evaluator running — the documented purpose of API.LookupPrefix, which
// until now had no caller at all. Bogon-ness is a fact about the address space:
// no network call, no tick, no store.
func TestWatchlistFlagsWatchedBogonsWithoutTheEvaluator(t *testing.T) {
	s := bgpWatchTestServer(t, false)
	if s.bgpWatchEval != nil {
		t.Fatal("this test is about the evaluator being OFF")
	}
	out := map[string]any{}
	s.bgpWatchAnnotateWatchlist(out, []bgpWatchEntry{
		{Resource: "192.0.2.0/24", Kind: "prefix"}, // RFC 5737 — a bogon
		{Resource: "8.8.8.0/24", Kind: "prefix"},   // routable
		{Resource: "AS64500", Kind: "asn"},         // not a prefix at all
	}, "acme", false)

	flagged, ok := out["watched_bogons"].(map[string]bgpwatch.BogonEntry)
	if !ok {
		t.Fatalf("watched_bogons missing or mistyped: %#v", out["watched_bogons"])
	}
	if len(flagged) != 1 {
		t.Fatalf("watched_bogons = %v, want only the RFC 5737 prefix", flagged)
	}
	entry, ok := flagged["192.0.2.0/24"]
	if !ok || entry.Block == "" || entry.Reason == "" {
		t.Fatalf("the flag carries no block/reason to show the operator: %+v", flagged)
	}
	// The honest "not evaluating" note still rides alongside it — a bogon flag
	// is not a claim that anything else was checked.
	if _, ok := out["incidents_note"]; !ok {
		t.Fatal("the evaluator-off note disappeared")
	}
}
