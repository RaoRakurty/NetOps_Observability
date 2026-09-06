// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// bmp_deps_test.go — the CLAUDE.md §3a rule-5 cross-org test for the BMP
// receiver subtree (internal/bmp), exercised through the REAL wiring: the
// module is assembled by s.buildBMP() itself, so the gate under test is the
// production s.bmpAuthz mapping and the session-to-tenant attribution is the
// production s.bmpResolveDevice over the shared inventory. A fixture that
// re-implemented either would prove nothing about the deployed surface.
//
// Proven here:
//   - tenant A cannot list tenant B's BMP sessions, updates or stats — on any
//     of the three registered routes;
//   - a FILTER (?prefix=, ?peer=, ?session=) narrows within the caller's scope
//     and can never be used to reach across it, even when both tenants hold the
//     identical prefix;
//   - ?as_tenant= into another org is ignored for a non-owner;
//   - the platform owner is the ONLY principal that reads cross-tenant, and a
//     tenant admin holding full administration:admin is NOT that principal;
//   - an unauthenticated caller is refused before any store is touched;
//   - a BMP connection from an address that resolves to no device is REJECTED
//     and stored nowhere — never admitted as tenant "" — and a device row with
//     no tenant is refused for the same reason;
//   - the tenant is stamped from the INVENTORY, never from anything on the wire.

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/bmp"
	"netops/backend/internal/discovery"
	"netops/backend/models"
)

// bmpFixture is a server with two orgs' devices and the PRODUCTION bmp module
// built on top of it.
type bmpFixture struct {
	t   *testing.T
	s   *server
	api *bmp.API
}

func newBMPFixture(t *testing.T) *bmpFixture {
	t.Helper()
	t.Setenv(bmp.EnvListen, "127.0.0.1:0") // never bind the real port in a test
	roles, err := newRoleStore(t.TempDir() + "/roles.json")
	if err != nil {
		t.Fatalf("roleStore: %v", err)
	}
	d := discovery.NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: "acme-core", Name: "acme-core", Address: "192.0.2.1", TenantID: "acme"})
	d.Upsert(models.Device{ID: "globex-core", Name: "gx-edge", Address: "198.51.100.1", TenantID: "globex"})
	d.Upsert(models.Device{ID: "shared-dns", Name: "shared-dns", Address: "203.0.113.1"}) // platform-owned, no tenant

	s := &server{roles: roles, discovery: d, workers: &workerGroup{}}
	api, err := s.buildBMP()
	if err != nil {
		t.Fatalf("buildBMP: %v", err)
	}
	if api == nil {
		t.Fatal("buildBMP returned a nil API")
	}
	s.bmpAPI = api
	f := &bmpFixture{t: t, s: s, api: api}
	f.seed()
	return f
}

// seed loads one session per org, with the SAME prefix in both so a filter that
// crossed the boundary would be visible.
func (f *bmpFixture) seed() {
	f.t.Helper()
	st := f.api.Store()
	for _, sess := range []struct{ id, tenant, device, addr string }{
		{"bmp-1", "acme", "acme-core", "192.0.2.1:45000"},
		{"bmp-2", "globex", "globex-core", "198.51.100.1:45000"},
	} {
		if err := st.Open(sess.id, sess.tenant, sess.device, sess.addr); err != nil {
			f.t.Fatalf("open %s: %v", sess.id, err)
		}
	}
	st.Apply("bmp-1", bmpAnnounce(f.t, "10.10.0.1", 64512, "10.0.0.0/8"))
	st.Apply("bmp-1", bmpAnnounce(f.t, "10.10.0.1", 64512, "192.168.7.0/24"))
	st.Apply("bmp-2", bmpAnnounce(f.t, "10.20.0.1", 65001, "10.0.0.0/8"))
	st.Apply("bmp-2", bmpAnnounce(f.t, "10.20.0.1", 65001, "172.16.0.0/12"))
}

// bmpAnnounce builds a Route Monitoring frame announcing one prefix. The bytes
// are assembled here rather than imported from the subpackage's test helpers,
// because those are not exported — which keeps this file an INDEPENDENT witness
// to the wire format.
func bmpAnnounce(t *testing.T, peer string, as uint32, cidr string) *bmp.Message {
	t.Helper()
	be16 := func(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }
	be32 := func(v uint32) []byte { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }

	// per-peer header (42 octets)
	ph := []byte{0, 0}
	ph = append(ph, make([]byte, 8)...) // distinguisher
	pa := netip.MustParseAddr(peer).As4()
	ph = append(ph, make([]byte, 12)...)
	ph = append(ph, pa[:]...)
	ph = append(ph, be32(as)...)
	ph = append(ph, 10, 0, 0, 1)         // BGP ID
	ph = append(ph, be32(1700000000)...) // timestamp sec
	ph = append(ph, be32(0)...)          // timestamp usec

	// path attributes
	nh := []byte{0x40, 3, 4, 192, 0, 2, 254}
	origin := []byte{0x40, 1, 1, 0}
	attrs := append(append([]byte{}, origin...), nh...)

	// NLRI
	p := netip.MustParsePrefix(cidr)
	n := (p.Bits() + 7) / 8
	a4 := p.Addr().As4()
	nlri := append([]byte{byte(p.Bits())}, a4[:n]...)

	body := append([]byte{}, be16(0)...) // withdrawn routes length
	body = append(body, be16(uint16(len(attrs)))...)
	body = append(body, attrs...)
	body = append(body, nlri...)

	// BGP header
	bgp := make([]byte, 16)
	for i := range bgp {
		bgp[i] = 0xFF
	}
	bgp = append(bgp, be16(uint16(19+len(body)))...)
	bgp = append(bgp, 2) // UPDATE
	bgp = append(bgp, body...)

	payload := append(append([]byte{}, ph...), bgp...)
	frame := []byte{3}
	frame = append(frame, be32(uint32(6+len(payload)))...)
	frame = append(frame, 0) // Route Monitoring
	frame = append(frame, payload...)

	msg, err := bmp.ParseMessage(frame)
	if err != nil {
		t.Fatalf("the test's own frame does not parse: %v", err)
	}
	return msg
}

// get runs one request through the module's real dispatcher with real claims.
func (f *bmpFixture) get(path string, claims jwtClaims) *httptest.ResponseRecorder {
	f.t.Helper()
	w := httptest.NewRecorder()
	f.api.Handler()(w, req(http.MethodGet, path, "", claims))
	return w
}

// bmpRoutes names all three registered routes LITERALLY. They are spelled out
// rather than composed so this file is the searchable proof, for the §3a
// route-isolation coverage guard and for a human, that every one of them was
// exercised cross-tenant here:
//
//	/api/bgp/bmp/sessions  /api/bgp/bmp/updates  /api/bgp/bmp/stats
var bmpRoutes = []string{
	"/api/bgp/bmp/sessions",
	"/api/bgp/bmp/updates",
	"/api/bgp/bmp/stats",
}

// TestBMPEveryRegisteredRouteIsOwnTenantOnly walks all three routes: the
// caller sees its own session and NOTHING of the other org's, on every one.
func TestBMPEveryRegisteredRouteIsOwnTenantOnly(t *testing.T) {
	f := newBMPFixture(t)
	for _, route := range bmpRoutes {
		w := f.get(route, acme())
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s (acme) = %d (%s)", route, w.Code, w.Body.String())
		}
		body := w.Body.String()
		for _, foreign := range []string{"globex-core", "gx-edge", "bmp-2", "10.20.0.1", "172.16.0.0/12"} {
			if strings.Contains(body, foreign) {
				t.Errorf("CROSS-TENANT LEAK on %s — acme saw %q: %s", route, foreign, body)
			}
		}
		// And the mirror image, so the test cannot pass by returning nothing.
		g := f.get(route, globex())
		if g.Code != http.StatusOK {
			t.Fatalf("GET %s (globex) = %d", route, g.Code)
		}
		gb := g.Body.String()
		for _, foreign := range []string{"acme-core", "bmp-1", "10.10.0.1", "192.168.7.0/24"} {
			if strings.Contains(gb, foreign) {
				t.Errorf("CROSS-TENANT LEAK on %s — globex saw %q: %s", route, foreign, gb)
			}
		}
	}
}

func TestBMPSessionsAndUpdatesAreOwnOnlyLists(t *testing.T) {
	f := newBMPFixture(t)
	countOf := func(w *httptest.ResponseRecorder) float64 {
		t.Helper()
		var body struct {
			Count float64 `json:"count"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode %q: %v", w.Body.String(), err)
		}
		return body.Count
	}
	if got := countOf(f.get("/api/bgp/bmp/sessions", acme())); got != 1 {
		t.Fatalf("acme sessions = %v, want exactly its own 1", got)
	}
	if got := countOf(f.get("/api/bgp/bmp/updates", acme())); got != 2 {
		t.Fatalf("acme updates = %v, want its own 2", got)
	}
	if got := countOf(f.get("/api/bgp/bmp/sessions", globex())); got != 1 {
		t.Fatalf("globex sessions = %v", got)
	}
	// A third org with no BMP session at all sees an EMPTY feed, not someone
	// else's.
	initech := jwtClaims{Sub: "i@initech", Role: RoleOperator, Tenant: "initech"}
	for _, route := range []string{"/api/bgp/bmp/sessions", "/api/bgp/bmp/updates"} {
		w := f.get(route, initech)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s (initech) = %d", route, w.Code)
		}
		if got := countOf(w); got != 0 {
			t.Fatalf("GET %s for a session-less org = %v rows, want 0: %s", route, got, w.Body.String())
		}
	}
}

func TestBMPFiltersCannotReachAcrossTheTenantBoundary(t *testing.T) {
	f := newBMPFixture(t)
	// BOTH orgs hold 10.0.0.0/8, so a filter that crossed the boundary would
	// return two rows instead of one.
	var body struct {
		Count   float64 `json:"count"`
		Updates []struct {
			SessionID string `json:"session_id"`
			DeviceID  string `json:"device_id"`
		} `json:"updates"`
	}
	w := f.get("/api/bgp/bmp/updates?prefix=10.0.0.0/8", acme())
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Count != 1 {
		t.Fatalf("the shared prefix returned %v rows to acme, want its own 1: %s", body.Count, w.Body.String())
	}
	if body.Updates[0].DeviceID != "acme-core" {
		t.Fatalf("row = %+v", body.Updates[0])
	}
	// Naming another org's session id, peer or prefix returns NOTHING — not a
	// 403 that would confirm the id exists.
	for _, q := range []string{
		"?session=bmp-2",
		"?peer=10.20.0.1",
		"?prefix=172.16.0.0/12",
	} {
		w := f.get("/api/bgp/bmp/updates"+q, acme())
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want a 200 with no rows (never an existence oracle)", q, w.Code)
		}
		if !strings.Contains(w.Body.String(), `"count":0`) {
			t.Fatalf("GET %s reached another org: %s", q, w.Body.String())
		}
	}
}

func TestBMPAsTenantIntoAnotherOrgIsIgnoredForANonOwner(t *testing.T) {
	f := newBMPFixture(t)
	for _, route := range bmpRoutes {
		w := f.get(route+"?as_tenant=globex", acme())
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s?as_tenant=globex = %d (%s)", route, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "globex-core") || strings.Contains(w.Body.String(), "bmp-2") {
			t.Fatalf("as_tenant into another org WIDENED scope on %s: %s", route, w.Body.String())
		}
	}
	// An ORG admin holding full administration:admin inside its own org is
	// still not a cross-tenant principal (§3a rule 3).
	admin := jwtClaims{Sub: "a@acme", Role: RoleOrgAdmin, Tenant: "acme"}
	w := f.get("/api/bgp/bmp/sessions?as_tenant=globex", admin)
	if strings.Contains(w.Body.String(), "globex-core") {
		t.Fatalf("a tenant admin read cross-tenant: %s", w.Body.String())
	}
}

func TestBMPPlatformOwnerIsTheOnlyCrossTenantReader(t *testing.T) {
	f := newBMPFixture(t)
	w := f.get("/api/bgp/bmp/sessions", superA())
	if w.Code != http.StatusOK {
		t.Fatalf("owner sessions = %d (%s)", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "acme-core") || !strings.Contains(body, "globex-core") {
		t.Fatalf("the platform owner must see BOTH orgs: %s", body)
	}
}

func TestBMPRoutesAreGatedBeforeAnyRead(t *testing.T) {
	f := newBMPFixture(t)
	// UNAUTHENTICATED is "no claims in the request context at all" — the shape
	// withAuth produces when a token is missing or invalid. requirePerm answers
	// 401 before the store is ever consulted.
	for _, route := range bmpRoutes {
		w := httptest.NewRecorder()
		f.api.Handler()(w, httptest.NewRequest(http.MethodGet, route, nil))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("GET %s unauthenticated = %d, want 401 (%s)", route, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "acme-core") || strings.Contains(w.Body.String(), "10.0.0.0/8") {
			t.Fatalf("GET %s leaked data while refusing: %s", route, w.Body.String())
		}
	}
}

// TestBMPPrincipalWithNoTenantReadsNothing pins the DEFAULT-CLOSED half of the
// scope rule: a principal that authenticates but carries no tenant and no
// cross-tenant grant is not "everyone", it is "no one". This is the property
// that decides what an anomalous claim set sees, and it belongs to this module
// (the store enforces it) rather than to the auth middleware.
func TestBMPPrincipalWithNoTenantReadsNothing(t *testing.T) {
	f := newBMPFixture(t)
	tenantless := jwtClaims{Sub: "nobody", Role: RoleReadOnly}
	for _, route := range bmpRoutes {
		w := f.get(route, tenantless)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d (%s)", route, w.Code, w.Body.String())
		}
		body := w.Body.String()
		for _, owned := range []string{"acme-core", "globex-core", "bmp-1", "bmp-2", "10.0.0.0/8", "172.16.0.0/12"} {
			if strings.Contains(body, owned) {
				t.Fatalf("a tenant-less principal read %q on %s — the scope rule must be default-CLOSED: %s", owned, route, body)
			}
		}
	}
}

func TestBMPUnsupportedGateIsRefused(t *testing.T) {
	f := newBMPFixture(t)
	w := httptest.NewRecorder()
	if _, ok := f.s.bmpAuthz(w, req(http.MethodGet, "/x", "", acme()), bmp.Gate(99)); ok {
		t.Fatal("an unknown gate must never authorize")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("unknown gate = %d, want 403", w.Code)
	}
}

// ── §3a: session attribution comes from the INVENTORY, never the wire ───────

func TestBMPResolveDeviceStampsTheTenantFromTheInventory(t *testing.T) {
	f := newBMPFixture(t)
	cases := []struct {
		addr           string
		wantDev, wantT string
		wantOK         bool
	}{
		{"192.0.2.1", "acme-core", "acme", true},
		{"198.51.100.1", "globex-core", "globex", true},
		// A device row with NO tenant is platform-owned inventory. Admitting it
		// would pool a customer's routing table into the global bucket.
		{"203.0.113.1", "", "", false},
		// Nothing in the inventory: refused outright.
		{"10.99.99.99", "", "", false},
		{"2001:db8::1", "", "", false},
		// The IPv4-mapped form of a known address still resolves — a router
		// arriving over a dual-stack socket is the same router.
		{"::ffff:192.0.2.1", "acme-core", "acme", true},
	}
	for _, tc := range cases {
		dev, tenant, ok := f.s.bmpResolveDevice(netip.MustParseAddr(tc.addr))
		if ok != tc.wantOK || dev != tc.wantDev || tenant != tc.wantT {
			t.Errorf("resolve(%s) = (%q, %q, %v), want (%q, %q, %v)",
				tc.addr, dev, tenant, ok, tc.wantDev, tc.wantT, tc.wantOK)
		}
	}
	// With no inventory at all, everything is refused rather than defaulted.
	empty := &server{}
	if _, _, ok := empty.bmpResolveDevice(netip.MustParseAddr("192.0.2.1")); ok {
		t.Fatal("a server with no inventory must attribute nothing")
	}
}

// TestBMPUnknownSourceConnectionIsRejectedAndStoredNowhere drives a REAL TCP
// connection into the production listener. The loopback source resolves to no
// device, so the session must be closed and stored nowhere — the §3a refusal
// that keeps an unattributable feed out of tenant "".
func TestBMPUnknownSourceConnectionIsRejectedAndStoredNowhere(t *testing.T) {
	f := newBMPFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.api.Run(ctx)
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the BMP listener did not stop on cancellation")
		}
	}()

	addr := ""
	for deadline := time.Now().Add(5 * time.Second); addr == ""; {
		addr = f.api.Listener().Addr()
		if addr == "" {
			if time.Now().After(deadline) {
				t.Fatal("listener never bound")
			}
			time.Sleep(time.Millisecond)
		}
	}
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()

	// A refused connection is CLOSED: the read returns rather than blocking.
	if derr := c.SetReadDeadline(time.Now().Add(5 * time.Second)); derr != nil {
		t.Fatal(derr)
	}
	if _, rerr := c.Read(make([]byte, 1)); rerr == nil {
		t.Fatal("an unattributable source was NOT disconnected")
	}
	// Nothing was stored — under any tenant, including the empty one.
	got := f.api.Store().Sessions("", true)
	if len(got) != 2 {
		t.Fatalf("session count changed to %d — the rejected connection was stored", len(got))
	}
	for _, v := range got {
		if v.TenantOf() == "" {
			t.Fatalf("a session was stored with no tenant: %+v", v)
		}
	}
}

func TestBMPBuildIsDormantWithoutTheFlag(t *testing.T) {
	// A nil API is what a flag-off deployment holds: every route 404s, the
	// metrics writer emits nothing, and starting the worker is a no-op.
	s := &server{workers: &workerGroup{}}
	w := httptest.NewRecorder()
	s.bmpAPI.Handler()(w, req(http.MethodGet, "/api/bgp/bmp/sessions", "", acme()))
	if w.Code != http.StatusNotFound {
		t.Fatalf("flag-off route = %d, want 404", w.Code)
	}
	var sb strings.Builder
	s.bmpAPI.Metrics().Write(&sb)
	if sb.Len() != 0 {
		t.Fatalf("a dormant module emitted metrics: %q", sb.String())
	}
	// The launch site is main.go's BMP block, registered on the drain group.
	// Running that exact closure against the dormant (nil) API must be a no-op:
	// no panic, no port, and a clean drain.
	s.workers.start("bmp-receiver", func() { s.bmpAPI.Run(context.Background()) })
	if stuck := s.workers.drain(5 * time.Second); len(stuck) > 0 {
		t.Fatalf("dormant BMP worker still running: %v — a flag-off module must start nothing", stuck)
	}
}

// The receiver must be launched as a TRACKED worker, so shutdown waits for it
// instead of reporting success while the listener is still serving a feed.
// (The shutdown drift guard counts untracked launches; this names the worker.)
func TestBMPReceiverIsLaunchedAsATrackedWorker(t *testing.T) {
	src := mainSource(t)
	if !strings.Contains(src, `workers.start("bmp-receiver"`) {
		t.Error(`main.go no longer launches the BMP receiver via workers.start("bmp-receiver", ...) — ` +
			"an untracked listener is abandoned mid-feed on SIGTERM")
	}
}
