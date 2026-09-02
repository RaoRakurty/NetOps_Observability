package igpmon

// pure_test.go — the module's pure core: protocol vocabulary, the two state
// decoders, the SQL builder, the identifier/cursor validators and the
// event↔live merge. These are the parts an operator's verdict is computed
// from, so each one is pinned by a table rather than exercised incidentally
// through a handler.

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestProtoFrom(t *testing.T) {
	cases := []struct {
		in   string
		want Proto
		ok   bool
	}{
		{"ospf", ProtoOSPF, true},
		{"OSPF", ProtoOSPF, true},
		{"  isis ", ProtoISIS, true},
		{"IsIs", ProtoISIS, true},
		{"", "", false},
		{"bgp", "", false},
		{"ospfv3", "", false},
		{"is-is", "", false}, // unknown spellings are REFUSED, never defaulted
	}
	for _, c := range cases {
		got, ok := ProtoFrom(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("ProtoFrom(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestProtoVocabulary(t *testing.T) {
	cases := []struct {
		p                            Proto
		kind, adj, lsdb, peer, level string
	}{
		{ProtoOSPF, "ospf_adjacency_change", "device_ospf_nbr_state", "device_ospf_lsdb_count", "neighbor", ""},
		{ProtoISIS, "isis_adjacency_change", "device_isis_adj_state", "device_isis_lsp_count", "isis_neighbor", ""},
	}
	for _, c := range cases {
		if got := c.p.Kind(); got != c.kind {
			t.Errorf("%s.Kind() = %q, want %q", c.p, got, c.kind)
		}
		if got := c.p.AdjMetric(); got != c.adj {
			t.Errorf("%s.AdjMetric() = %q, want %q", c.p, got, c.adj)
		}
		if got := c.p.LSDBMetric(); got != c.lsdb {
			t.Errorf("%s.LSDBMetric() = %q, want %q", c.p, got, c.lsdb)
		}
		if got := c.p.PeerLabel(); got != c.peer {
			t.Errorf("%s.PeerLabel() = %q, want %q", c.p, got, c.peer)
		}
	}
}

// TestStateDecoders pins BOTH MIB vocabularies. A wrong decode here renders a
// down adjacency as healthy, which is the whole failure this module exists to
// prevent — so every defined numeric, and the undefined ones, are asserted.
func TestStateDecoders(t *testing.T) {
	ospf := []struct {
		v    float64
		name string
		up   bool
	}{
		{1, "down", false}, {2, "attempt", false}, {3, "init", false}, {4, "twoWay", false},
		{5, "exchangeStart", false}, {6, "exchange", false}, {7, "loading", false},
		{8, "full", true},
		{0, "unknown", false}, {9, "unknown", false}, {-1, "unknown", false}, {8.9, "full", true},
	}
	for _, c := range ospf {
		if got := ProtoOSPF.stateName(c.v); got != c.name {
			t.Errorf("ospf stateName(%v) = %q, want %q", c.v, got, c.name)
		}
		if got := ProtoOSPF.isUp(c.v); got != c.up {
			t.Errorf("ospf isUp(%v) = %v, want %v", c.v, got, c.up)
		}
	}
	isis := []struct {
		v    float64
		name string
		up   bool
	}{
		{1, "down", false}, {2, "init", false}, {3, "up", true}, {4, "failed", false},
		{0, "unknown", false}, {5, "unknown", false}, {-3, "unknown", false},
	}
	for _, c := range isis {
		if got := ProtoISIS.stateName(c.v); got != c.name {
			t.Errorf("isis stateName(%v) = %q, want %q", c.v, got, c.name)
		}
		if got := ProtoISIS.isUp(c.v); got != c.up {
			t.Errorf("isis isUp(%v) = %v, want %v", c.v, got, c.up)
		}
	}
	// "unknown" is NEVER rounded up to healthy on either protocol.
	for _, p := range []Proto{ProtoOSPF, ProtoISIS} {
		if p.isUp(99) {
			t.Errorf("%s: an undefined state value decoded as UP", p)
		}
	}
}

func TestScopeReadsNothing(t *testing.T) {
	for _, s := range []string{"", "   ", "__none__", " __none__ "} {
		if !scopeReadsNothing(s) {
			t.Errorf("scopeReadsNothing(%q) = false, want true (fail closed)", s)
		}
	}
	for _, s := range []string{"acme", "__all__", "globex"} {
		if scopeReadsNothing(s) {
			t.Errorf("scopeReadsNothing(%q) = true, want false", s)
		}
	}
}

func TestCHTokenDropsInjectionCharacters(t *testing.T) {
	cases := []struct{ in, want string }{
		{"acme-core", "acme-core"},
		{"spine1.dc1", "spine1.dc1"},
		{"a_b:c/d-e.f", "a_b:c/d-e.f"},
		{"acme'; DROP TABLE netops.corr_signals; --", "acmeDROPTABLEnetops.corr_signals--"},
		{`back\slash`, "backslash"},
		{"tab\there", "tabhere"},
		{"", ""},
		{"   ", ""},
	}
	for _, c := range cases {
		if got := chToken(c.in); got != c.want {
			t.Errorf("chToken(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	long := strings.Repeat("a", 300)
	if got := chToken(long); len(got) != 128 {
		t.Errorf("chToken did not bound length: got %d chars", len(got))
	}
	// A quote can never survive into an interpolated literal.
	for _, bad := range []string{"'", `"`, "`", `\`, ";", "(", ")", " "} {
		if strings.Contains(chToken("x"+bad+"y"), bad) {
			t.Errorf("chToken kept %q", bad)
		}
	}
}

func TestCHList(t *testing.T) {
	if got := chList(nil); got != "" {
		t.Errorf("chList(nil) = %q, want empty", got)
	}
	if got := chList([]string{"'", "  "}); got != "" {
		t.Errorf("chList of unusable tokens = %q, want empty", got)
	}
	if got := chList([]string{"a", "a", "b"}); got != "'a','b'" {
		t.Errorf("chList dedup = %q, want 'a','b'", got)
	}
}

func TestCursorRoundTripAndRejection(t *testing.T) {
	const sid = "0f8fad5b-d9cb-469f-a165-70867728950e"
	enc := encodeCursor(1756814400000, sid)
	ms, got, ok := decodeCursor(enc)
	if !ok || ms != 1756814400000 || got != sid {
		t.Fatalf("round trip = (%d,%q,%v)", ms, got, ok)
	}
	bad := []string{
		"",                          // empty
		"!!!not-base64!!!",          // not base64
		b64("nopipe"),               // no separator
		b64("abc|" + sid),           // non-numeric millis
		b64("-1|" + sid),            // negative millis
		b64("1|not-a-uuid"),         // signal_id shape
		b64("1|0f8fad5bd9cb469fa1"), // too short
	}
	for _, c := range bad {
		if _, _, ok := decodeCursor(c); ok {
			t.Errorf("decodeCursor(%q) accepted a malformed cursor", c)
		}
	}
}

func TestIsUUIDToken(t *testing.T) {
	good := []string{"0f8fad5b-d9cb-469f-a165-70867728950e", "0F8FAD5B-D9CB-469F-A165-70867728950E"}
	for _, g := range good {
		if !isUUIDToken(g) {
			t.Errorf("isUUIDToken(%q) = false", g)
		}
	}
	bad := []string{
		"", "short",
		"0f8fad5bxd9cb-469f-a165-70867728950e", // dash in the wrong place
		"0f8fad5b-d9cb-469f-a165-70867728950g", // non-hex
		"0f8fad5b-d9cb-469f-a165-70867728950",  // 35 chars
	}
	for _, b := range bad {
		if isUUIDToken(b) {
			t.Errorf("isUUIDToken(%q) = true", b)
		}
	}
}

// TestEventsSQL pins the shape of the read: both tables, the same WHERE on each
// arm, the bounded fetch and the keyset predicate. A silently-dropped arm makes
// a timeline short; a silently-dropped predicate makes it unbounded.
func TestEventsSQL(t *testing.T) {
	sql := eventsSQL(EventQuery{
		Kind:     "isis_adjacency_change",
		Devices:  []string{"leaf1", "leaf1", "spine1'"},
		SinceMS:  1756814400000,
		CursorMS: 1756900000000,
		CursorID: "0f8fad5b-d9cb-469f-a165-70867728950e",
		Limit:    50,
	})
	for _, want := range []string{
		"kind = 'isis_adjacency_change'",
		"entity_type = 'device'",
		"ts >= fromUnixTimestamp64Milli(toInt64(1756814400000))",
		"entity_id IN ('leaf1','spine1')",
		"(toUnixTimestamp64Milli(ts), toString(signal_id)) < (toInt64(1756900000000), '0f8fad5b-d9cb-469f-a165-70867728950e')",
		"FROM " + tableSignals + " WHERE",
		"FROM " + tableArchive + " WHERE",
		"UNION ALL",
		"ORDER BY ts_ms DESC, signal_id DESC LIMIT 100 FORMAT JSON",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("eventsSQL missing %q\ngot: %s", want, sql)
		}
	}
	if strings.Contains(sql, "'spine1''") || strings.Count(sql, "'")%2 != 0 {
		t.Errorf("eventsSQL has an unbalanced quote — injection surface: %s", sql)
	}
	// Both UNION arms carry the SAME predicate: a filter on one arm only is a
	// silently short timeline.
	if got := strings.Count(sql, "kind = 'isis_adjacency_change'"); got != 2 {
		t.Errorf("kind predicate appears %d times, want 2 (one per UNION arm)", got)
	}

	// No cursor and no devices → neither predicate appears.
	plain := eventsSQL(EventQuery{Kind: "ospf_adjacency_change", SinceMS: 1, Limit: 10})
	if strings.Contains(plain, "entity_id IN") || strings.Contains(plain, "toString(signal_id)) <") {
		t.Errorf("optional predicates leaked into the plain query: %s", plain)
	}
	if !strings.Contains(plain, "LIMIT 20 ") {
		t.Errorf("over-fetch is not limit*2: %s", plain)
	}
	// The over-fetch is itself bounded, independent of the caller's limit.
	if !strings.Contains(eventsSQL(EventQuery{Kind: "x", Limit: 9000}), "LIMIT 4000 ") {
		t.Error("the raw fetch ceiling (maxFetchRows) is not applied")
	}
}

func TestNormalizeEventState(t *testing.T) {
	cases := map[string]string{
		"up": "up", "UP": "up", " Up ": "up",
		"down": "down", "DOWN": "down",
		"": "unknown", "full": "unknown", "flapping": "unknown", "1": "unknown",
	}
	for in, want := range cases {
		if got := normalizeEventState(in); got != want {
			t.Errorf("normalizeEventState(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCellDecoders(t *testing.T) {
	if got := cellString("x"); got != "x" {
		t.Errorf("cellString(string) = %q", got)
	}
	if got := cellString(nil); got != "" {
		t.Errorf("cellString(nil) = %q", got)
	}
	if got := cellString(float64(12)); got != "12" {
		t.Errorf("cellString(float64) = %q", got)
	}
	if got := cellString(true); got != "true" {
		t.Errorf("cellString(bool) = %q", got)
	}
	// 64-bit integers arrive QUOTED from ClickHouse FORMAT JSON.
	if got := cellInt("1756814400000"); got != 1756814400000 {
		t.Errorf("cellInt(quoted) = %d", got)
	}
	if got := cellInt(float64(42)); got != 42 {
		t.Errorf("cellInt(float64) = %d", got)
	}
	for _, bad := range []any{nil, "abc", true} {
		if got := cellInt(bad); got != 0 {
			t.Errorf("cellInt(%v) = %d, want 0", bad, got)
		}
	}
}

func TestPromQuoteAndSelector(t *testing.T) {
	if got := promQuote("spine1.dc1"); got != `spine1\\.dc1` {
		t.Errorf("promQuote = %q", got)
	}
	if got := deviceSelector(nil); got != "" {
		t.Errorf("deviceSelector(nil) = %q, want empty (fleet-wide, bounded by extra_filters)", got)
	}
	if got := deviceSelector([]string{"'", ""}); got != "" {
		t.Errorf("deviceSelector of unusable ids = %q", got)
	}
	if got := deviceSelector([]string{"a", "a", "b"}); got != `{device=~"a|b"}` {
		t.Errorf("deviceSelector = %q", got)
	}
	if got := seriesQuery("device_isis_adj_state", []string{"leaf1"}); got != `device_isis_adj_state{device=~"leaf1"}` {
		t.Errorf("seriesQuery = %q", got)
	}
}

func TestSourceLabel(t *testing.T) {
	cases := []struct {
		c    Coverage
		want string
	}{
		{Coverage{Events: true, LiveSeries: true}, "events+live_series"},
		{Coverage{Events: true}, "events"},
		{Coverage{LiveSeries: true}, "live_series"},
		{Coverage{}, "none"},
		{Coverage{LSDB: true}, "none"}, // LSDB alone is not an adjacency source
	}
	for _, c := range cases {
		if got := sourceLabel(c.c); got != c.want {
			t.Errorf("sourceLabel(%+v) = %q, want %q", c.c, got, c.want)
		}
	}
}

// TestHonestNotesNameTheAbsentSource — the notes are the product here: they must
// name the metric and the transport, so "not collected" cannot read as "healthy".
func TestHonestNotesNameTheAbsentSource(t *testing.T) {
	for _, p := range []Proto{ProtoOSPF, ProtoISIS} {
		n := lsdbNote(p)
		if !strings.Contains(n, p.LSDBMetric()) || !strings.Contains(n, "not reported rather than reported as zero") {
			t.Errorf("%s lsdbNote is not honest: %q", p, n)
		}
		s := noSeriesNote(p)
		if !strings.Contains(s, p.AdjMetric()) || !strings.Contains(s, "syslog/trap events only") {
			t.Errorf("%s noSeriesNote is not honest: %q", p, s)
		}
	}
	if !strings.Contains(noSeriesNote(ProtoOSPF), "SNMP-owned") {
		t.Error("the OSPF note must name why no live series exists")
	}
	if !strings.Contains(noSeriesNote(ProtoISIS), "gNMI") {
		t.Error("the IS-IS note must name the transport that carries the series")
	}
}

func TestSortStrings(t *testing.T) {
	v := []string{"L2", "L1", "L2", "L1"}
	sortStrings(v)
	want := []string{"L1", "L1", "L2", "L2"}
	for i := range want {
		if v[i] != want[i] {
			t.Fatalf("sortStrings = %v, want %v", v, want)
		}
	}
	sortStrings(nil)        // must not panic
	sortStrings([]string{}) // must not panic
}

// ── merge ───────────────────────────────────────────────────────────────────

func ev(ms int64, id, dev, peer, state string) Event {
	return Event{
		TSMillis: ms, TS: time.UnixMilli(ms).UTC().Format(time.RFC3339Nano),
		SignalID: id, Device: dev, Peer: peer, State: state, Source: "syslog", Severity: "warn",
	}
}

func TestMergeAdjacenciesBothSources(t *testing.T) {
	live := []LiveAdj{
		{Device: "leaf1", Peer: "0000.0000.0002", IfName: "ethernet-1/1", Level: "L2", VRF: "default", State: "up", Up: true, Value: 3},
	}
	events := []Event{
		ev(3000, "id3", "leaf1", "0000.0000.0002", "up"),
		ev(2000, "id2", "leaf1", "0000.0000.0002", "down"),
		ev(1000, "id1", "leaf1", "0000.0000.0002", "unknown"),
	}
	got := MergeAdjacencies(live, events, 0)
	if len(got) != 1 {
		t.Fatalf("want one adjacency, got %d", len(got))
	}
	a := got[0]
	if a.StateSource != "live_series" {
		t.Errorf("state_source = %q, want live_series (the present beats the last thing we were told)", a.StateSource)
	}
	if a.CurrentState == nil || *a.CurrentState != "up" || a.Up == nil || !*a.Up {
		t.Errorf("live state not carried: %+v", a)
	}
	if a.Level != "L2" || a.VRF != "default" || a.IfName != "ethernet-1/1" {
		t.Errorf("live labels not carried: %+v", a)
	}
	if a.Changes != 3 || a.UpEvents != 1 || a.DownEvents != 1 || a.Flaps != 1 {
		t.Errorf("counts = changes %d up %d down %d flaps %d", a.Changes, a.UpEvents, a.DownEvents, a.Flaps)
	}
	if a.LastChange != events[0].TS {
		t.Errorf("last_change = %q, want the NEWEST event %q", a.LastChange, events[0].TS)
	}
	if len(a.Timeline) != 3 || a.Timeline[0].SignalID != "id3" || a.Timeline[2].SignalID != "id1" {
		t.Errorf("timeline is not newest-first: %+v", a.Timeline)
	}
}

func TestMergeAdjacenciesEventsOnlyNeverClaimsUp(t *testing.T) {
	got := MergeAdjacencies(nil, []Event{ev(2000, "b", "r1", "10.0.0.2", "up")}, 0)
	if len(got) != 1 {
		t.Fatalf("want one adjacency, got %d", len(got))
	}
	a := got[0]
	if a.StateSource != "events" {
		t.Errorf("state_source = %q, want events", a.StateSource)
	}
	if a.CurrentState == nil || *a.CurrentState != "up" {
		t.Errorf("current_state not taken from the newest event: %+v", a)
	}
	// The load-bearing assertion: an event-only adjacency is NOT evidence that
	// the adjacency is up right now, so `up` stays null.
	if a.Up != nil {
		t.Errorf("up = %v, want null for an event-only adjacency", *a.Up)
	}
}

func TestMergeAdjacenciesLiveOnlyHasEmptyTimeline(t *testing.T) {
	got := MergeAdjacencies([]LiveAdj{{Device: "leaf1", Peer: "p", State: "down", Up: false, Value: 1}}, nil, 10)
	if len(got) != 1 {
		t.Fatalf("want one adjacency, got %d", len(got))
	}
	a := got[0]
	if a.Timeline == nil || len(a.Timeline) != 0 {
		t.Errorf("timeline = %+v, want an EMPTY (non-nil) list, not a fabricated one", a.Timeline)
	}
	if a.LastChange != "" || a.Changes != 0 || a.Flaps != 0 {
		t.Errorf("live-only adjacency invented history: %+v", a)
	}
	if a.Up == nil || *a.Up {
		t.Errorf("live down state not carried: %+v", a)
	}
}

func TestMergeAdjacenciesOrderingCapAndIfnameFallback(t *testing.T) {
	events := []Event{
		ev(9000, "e1", "b-dev", "p2", "down"),
		ev(8000, "e2", "a-dev", "p1", "down"),
		ev(7000, "e3", "a-dev", "p1", "up"),
	}
	events[1].IfName = "Gi0/1"
	got := MergeAdjacencies(nil, events, 1)
	if len(got) != 2 {
		t.Fatalf("want two adjacencies, got %d", len(got))
	}
	if got[0].Device != "a-dev" || got[1].Device != "b-dev" {
		t.Errorf("not sorted by (device, peer): %+v", got)
	}
	if got[0].IfName != "Gi0/1" {
		t.Errorf("ifname fallback from the event did not apply: %q", got[0].IfName)
	}
	if len(got[0].Timeline) != 1 || got[0].Timeline[0].SignalID != "e2" {
		t.Errorf("timeline cap not applied newest-first: %+v", got[0].Timeline)
	}
	if got[0].Changes != 2 {
		t.Errorf("the cap must bound the TIMELINE, not the counts: changes = %d", got[0].Changes)
	}
}

func TestMergeAdjacenciesEmpty(t *testing.T) {
	if got := MergeAdjacencies(nil, nil, 10); len(got) != 0 {
		t.Errorf("MergeAdjacencies(nil,nil) = %+v, want empty", got)
	}
}

// ── summarize ───────────────────────────────────────────────────────────────

func TestSummarizeLiveCountsAreNullWithoutASeries(t *testing.T) {
	events := []Event{ev(5000, "s1", "r1", "p", "down")}
	got := Summarize([]LiveAdj{{Device: "r1", Peer: "p", Up: false}}, events, false)
	if len(got) != 1 {
		t.Fatalf("want one device, got %d", len(got))
	}
	if got[0].Adjacencies != nil || got[0].DownAdjacencies != nil {
		t.Fatalf("live counts must be NULL when no live series backed them: %+v", got[0])
	}
	if got[0].Flaps != 1 || got[0].Changes != 1 || got[0].DownEvents != 1 {
		t.Errorf("event counts wrong: %+v", got[0])
	}
}

func TestSummarizeLiveCountsWhenAvailable(t *testing.T) {
	live := []LiveAdj{
		{Device: "r1", Peer: "a", Up: true},
		{Device: "r1", Peer: "b", Up: false},
		{Device: "r2", Peer: "c", Up: true},
	}
	got := Summarize(live, nil, true)
	byDev := map[string]DeviceSummary{}
	for _, d := range got {
		byDev[d.Device] = d
	}
	r1 := byDev["r1"]
	if r1.Adjacencies == nil || *r1.Adjacencies != 2 || r1.DownAdjacencies == nil || *r1.DownAdjacencies != 1 {
		t.Fatalf("r1 live counts wrong: %+v", r1)
	}
	r2 := byDev["r2"]
	if r2.DownAdjacencies == nil || *r2.DownAdjacencies != 0 {
		t.Fatalf("r2 down count wrong: %+v", r2)
	}
}

func TestSummarizeOrderingWorstFirst(t *testing.T) {
	events := []Event{
		ev(9000, "a", "quiet", "p", "up"),
		ev(8000, "b", "noisy", "p", "down"),
		ev(7000, "c", "noisy", "p", "down"),
		ev(6000, "d", "recent", "p", "down"),
	}
	got := Summarize(nil, events, false)
	if len(got) != 3 {
		t.Fatalf("want 3 devices, got %d", len(got))
	}
	if got[0].Device != "noisy" {
		t.Errorf("worst-first broken: %q leads", got[0].Device)
	}
	if got[1].Device != "recent" {
		t.Errorf("tie-break on recency broken: %+v", got)
	}
}

func TestSummarizeEmpty(t *testing.T) {
	if got := Summarize(nil, nil, true); len(got) != 0 {
		t.Errorf("Summarize(nil,nil) = %+v, want empty", got)
	}
}

// ── stability ───────────────────────────────────────────────────────────────

func TestStabilityScore(t *testing.T) {
	cases := []struct {
		flaps, seconds int
		rate, score    float64
		basisHas       string
	}{
		{0, 3600, 0, 100, "0 adjacency down-transitions over 1h"},
		{1, 3600, 1, 50, "1 adjacency down-transition over 1h"},
		{3, 3600, 3, 25, "3 adjacency down-transitions over 1h"},
		{12, 86400, 0.5, 66.7, "12 adjacency down-transitions over 24h"},
		// A zero-length window cannot divide: the basis falls back to one hour
		// rather than producing an infinite rate.
		{0, 0, 0, 100, "0 adjacency down-transitions over 1h"},
	}
	for _, c := range cases {
		got := stabilityScore(c.flaps, c.seconds)
		if got.FlapsPerHour != c.rate {
			t.Errorf("flaps=%d window=%ds → rate %v, want %v", c.flaps, c.seconds, got.FlapsPerHour, c.rate)
		}
		if got.Score != c.score {
			t.Errorf("flaps=%d window=%ds → score %v, want %v", c.flaps, c.seconds, got.Score, c.score)
		}
		if !strings.Contains(got.Basis, c.basisHas) {
			t.Errorf("basis = %q, want it to contain %q", got.Basis, c.basisHas)
		}
		if !strings.Contains(got.Basis, "counted from syslog/trap adjacency-change events") {
			t.Errorf("the basis must name where the number came from: %q", got.Basis)
		}
	}
	// Monotonic, no cliff: more flaps never scores better.
	prev := 101.0
	for f := 0; f < 40; f++ {
		s := stabilityScore(f, 3600).Score
		if s > prev {
			t.Fatalf("score is not monotonic at %d flaps: %v > %v", f, s, prev)
		}
		prev = s
	}
}

func TestSmallFormatHelpers(t *testing.T) {
	if got := plural(1, "one", "many"); got != "1 one" {
		t.Errorf("plural(1) = %q", got)
	}
	if got := plural(0, "one", "many"); got != "0 many" {
		t.Errorf("plural(0) = %q", got)
	}
	if got := plural(2, "one", "many"); got != "2 many" {
		t.Errorf("plural(2) = %q", got)
	}
	for in, want := range map[int]string{0: "0", 7: "7", 42: "42", -13: "-13", 1000000: "1000000"} {
		if got := itoa(in); got != want {
			t.Errorf("itoa(%d) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[float64]string{0: "0", 1: "1", 1.5: "1.5", 24: "24", 0.4: "0.4", -1.5: "-1.5"} {
		if got := trimFloat(in); got != want {
			t.Errorf("trimFloat(%v) = %q, want %q", in, got, want)
		}
	}
	// A fraction that rounds up must carry into the whole part, not print ".10".
	if got := formatFloat1(1.96); got != "2.0" {
		t.Errorf("formatFloat1(1.96) = %q, want 2.0", got)
	}
	if got := formatFloat1(-1.96); got != "-2.0" {
		t.Errorf("formatFloat1(-1.96) = %q, want -2.0", got)
	}
}

// ── construction ────────────────────────────────────────────────────────────

// TestNewFailsClosedOnIncompleteDeps — a half-wired module must not return a
// handler set that reads unscoped.
func TestNewFailsClosedOnIncompleteDeps(t *testing.T) {
	if _, err := New(Deps{}); err == nil {
		t.Fatal("New(empty Deps) returned no error")
	} else {
		for _, want := range []string{"Authz", "Scope", "CHQuery", "ScopeFilters", "VMQuery", "CanSee", "LookupDevice"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the error must name the missing field %q: %v", want, err)
			}
		}
	}
	full := Deps{
		Now:          time.Now,
		Authz:        func(http.ResponseWriter, *http.Request, Gate) (Principal, bool) { return Principal{}, false },
		LookupDevice: func(string) (Device, bool) { return Device{}, false },
		CanSee:       func(Device, Principal) bool { return false },
		Scope:        func(*http.Request) string { return "__none__" },
		CHQuery:      func(context.Context, string, string) ([]map[string]any, error) { return nil, nil },
		ScopeFilters: func(*http.Request, Principal) []string { return nil },
		VMQuery:      func(context.Context, string, []string) ([]Sample, error) { return nil, nil },
		WriteJSON:    func(http.ResponseWriter, int, any) {},
		WriteError:   func(http.ResponseWriter, int, error) {},
		LogWarn:      func(string, map[string]any) {},
	}
	api, err := New(full)
	if err != nil || api == nil {
		t.Fatalf("New(complete Deps) = (%v, %v)", api, err)
	}
	if api.Metrics() != nil {
		t.Error("Metrics() must be nil when none was injected")
	}
	var nilAPI *API
	if nilAPI.Metrics() != nil {
		t.Error("Metrics() on a nil API must be nil, not a panic")
	}
	// Dropping ONE required field is still refused.
	one := full
	one.Scope = nil
	if _, err := New(one); err == nil || !strings.Contains(err.Error(), "Scope") {
		t.Fatalf("New without Scope = %v, want an error naming Scope", err)
	}
}

// b64 renders a raw cursor payload the way encodeCursor would, so a malformed
// PAYLOAD (rather than malformed base64) can be tested.
func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
