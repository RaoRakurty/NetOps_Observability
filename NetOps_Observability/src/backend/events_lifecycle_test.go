package main

import (
	"net"
	"sync"
	"testing"
	"time"
)

// events_lifecycle_test.go — regression cover for the WebSocket hub's lifetime
// rules: a disconnecting client must never be able to panic the process, and
// the per-tick fan-out must not scale with the number of sockets.

// newTestClient builds a registered client backed by a real (in-memory) conn so
// close() has something to close.
func newTestClient(t *testing.T, h *Hub, claims jwtClaims, buf int) (*wsClient, net.Conn) {
	t.Helper()
	srvConn, peer := net.Pipe()
	c := &wsClient{
		conn:   srvConn,
		send:   make(chan []byte, buf),
		done:   make(chan struct{}),
		claims: claims,
	}
	if !h.register(c) {
		t.Fatal("register refused unexpectedly")
	}
	return c, peer
}

// The failure this guards: the read pump used to close(c.send) on ANY read
// error — i.e. on an ordinary browser tab close — while broadcasters still held
// that channel from the hub map. A send on a closed channel panics even inside
// a select with a default, and nothing recovers it, so one closed tab took the
// whole API down. A panic anywhere below fails this test by killing it.
func TestTabCloseDuringBroadcastDoesNotPanic(t *testing.T) {
	h := newHubWithLimit(0)
	const clients, rounds = 16, 200

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Broadcasters, hammering both fan-out paths for the whole test.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				h.Broadcast(map[string]any{"type": "telemetry", "data": map[string]any{"value": 1}})
				h.BroadcastFiltered(func(jwtClaims) []map[string]any {
					return []map[string]any{{"type": "metric_update", "data": MetricTile{Title: "Devices", Value: "1"}}}
				})
			}
		}()
	}

	// Connect/disconnect churn: each client is torn down from a "read pump"
	// goroutine (c.close, holding no hub lock) while the hub is mid-fan-out,
	// with unregister racing behind it exactly as the handler's defer does.
	for r := 0; r < rounds; r++ {
		var conns []net.Conn
		var cs []*wsClient
		for i := 0; i < clients; i++ {
			// Tiny buffers so the drop path is exercised too.
			c, peer := newTestClient(t, h, jwtClaims{Sub: "u", Role: RoleOperator, Tenant: "acme"}, 1)
			cs = append(cs, c)
			conns = append(conns, peer)
		}
		var churn sync.WaitGroup
		for _, c := range cs {
			churn.Add(2)
			go func(c *wsClient) { defer churn.Done(); c.close() }(c)       // read pump
			go func(c *wsClient) { defer churn.Done(); h.unregister(c) }(c) // handler defer
		}
		churn.Wait()
		for _, p := range conns {
			_ = p.Close()
		}
	}

	close(stop)
	wg.Wait()

	if n := h.Count(); n != 0 {
		t.Fatalf("clients leaked: %d still registered", n)
	}
}

// A closed client must not receive further frames, and delivering to it must be
// harmless (this is the same invariant as above, asserted directly).
func TestDeliverToClosedClientIsSafe(t *testing.T) {
	h := newHubWithLimit(0)
	c, peer := newTestClient(t, h, jwtClaims{Sub: "u", Tenant: "acme"}, 4)
	defer peer.Close()

	c.close()
	c.close() // idempotent: sync.Once
	h.Broadcast(map[string]any{"type": "telemetry"})

	select {
	case msg := <-c.send:
		t.Fatalf("closed client received %q", msg)
	default:
	}
}

func TestHubRefusesClientsPastCap(t *testing.T) {
	h := newHubWithLimit(2)
	for i := 0; i < 2; i++ {
		c, peer := newTestClient(t, h, jwtClaims{Sub: "u", Tenant: "acme"}, 1)
		defer peer.Close()
		defer h.unregister(c)
	}
	if !h.atCapacity() {
		t.Fatal("hub should report capacity reached")
	}
	over := &wsClient{conn: nil, send: make(chan []byte, 1), done: make(chan struct{})}
	if h.register(over) {
		t.Fatal("hub admitted a client past the cap")
	}
	if h.Count() != 2 {
		t.Fatalf("count = %d, want 2", h.Count())
	}
}

// The per-tick payload is expensive (a full fleet + alert scan). It must be
// built once per distinct tenant scope, not once per socket, or N dashboards
// multiply backend CPU by N.
func TestBroadcastFilteredBuildsOncePerScope(t *testing.T) {
	tests := []struct {
		name      string
		claims    []jwtClaims
		wantBuild int
	}{
		{
			name: "many sockets, one tenant",
			claims: []jwtClaims{
				{Sub: "a", Role: RoleOperator, Tenant: "acme"},
				{Sub: "b", Role: RoleOperator, Tenant: "acme"},
				{Sub: "c", Role: RoleReadOnly, Tenant: "acme"},
			},
			wantBuild: 1,
		},
		{
			name: "two tenants",
			claims: []jwtClaims{
				{Sub: "a", Role: RoleOperator, Tenant: "acme"},
				{Sub: "b", Role: RoleOperator, Tenant: "globex"},
				{Sub: "c", Role: RoleOperator, Tenant: "acme"},
			},
			wantBuild: 2,
		},
		{
			name: "platform owner is its own scope",
			claims: []jwtClaims{
				{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal},
				{Sub: "a", Role: RoleOperator, Tenant: "acme"},
			},
			wantBuild: 2,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHubWithLimit(0)
			var cs []*wsClient
			for _, cl := range tc.claims {
				c, peer := newTestClient(t, h, cl, 8)
				defer peer.Close()
				cs = append(cs, c)
			}
			var builds int
			var seen []string
			h.BroadcastFiltered(func(c jwtClaims) []map[string]any {
				builds++
				seen = append(seen, c.Tenant)
				return []map[string]any{{"type": "metric_update", "tenant": c.Tenant}}
			})
			if builds != tc.wantBuild {
				t.Fatalf("build called %d times (%v), want %d", builds, seen, tc.wantBuild)
			}
			// Every client still gets exactly one frame.
			for i, c := range cs {
				select {
				case <-c.send:
				default:
					t.Fatalf("client %d (%s) got no frame", i, tc.claims[i].Tenant)
				}
			}
		})
	}
}

// Two clients of the SAME tenant share a payload; a different tenant must never
// receive it. Guards the memoization key against becoming a cross-tenant leak.
func TestBroadcastFilteredKeepsTenantsSeparate(t *testing.T) {
	h := newHubWithLimit(0)
	acme, p1 := newTestClient(t, h, jwtClaims{Sub: "a", Role: RoleOperator, Tenant: "acme"}, 8)
	defer p1.Close()
	globex, p2 := newTestClient(t, h, jwtClaims{Sub: "g", Role: RoleOperator, Tenant: "globex"}, 8)
	defer p2.Close()

	h.BroadcastFiltered(func(c jwtClaims) []map[string]any {
		if c.Tenant != "acme" {
			return nil
		}
		return []map[string]any{{"secret": "acme-only"}}
	})

	select {
	case <-acme.send:
	default:
		t.Fatal("acme client received nothing")
	}
	select {
	case msg := <-globex.send:
		t.Fatalf("cross-tenant leak: globex received %q", msg)
	default:
	}
}

// A client that cannot keep up loses frames — bounded queue, by design — but
// the loss must be counted, not silent (§10).
func TestSlowClientDropsAreCounted(t *testing.T) {
	h := newHubWithLimit(0)
	c, peer := newTestClient(t, h, jwtClaims{Sub: "slow", Tenant: "acme"}, 1)
	defer peer.Close()
	defer h.unregister(c)

	for i := 0; i < 5; i++ {
		h.Broadcast(map[string]any{"type": "telemetry", "data": i})
	}
	if got := h.Dropped(); got != 4 {
		t.Fatalf("dropped = %d, want 4 (buffer of 1, 5 frames)", got)
	}
	if got := c.dropped.Load(); got != 4 {
		t.Fatalf("per-client dropped = %d, want 4", got)
	}
}

// The read pump must tear the client down on a peer disconnect — and only via
// done, so the write pump exits without ever observing a closed send channel.
func TestReadPumpClosesClientOnPeerHangup(t *testing.T) {
	h := newHubWithLimit(0)
	c, peer := newTestClient(t, h, jwtClaims{Sub: "u", Tenant: "acme"}, 4)
	defer h.unregister(c)

	go discardIncoming(c.conn, c)
	_ = peer.Close() // browser tab closes

	select {
	case <-c.done:
	case <-time.After(2 * time.Second):
		t.Fatal("read pump did not close the client after peer hangup")
	}
	// Broadcasting after the hangup, with the client still in the hub map, is
	// the exact race that used to panic.
	h.Broadcast(map[string]any{"type": "telemetry"})
}

// Oversized/garbage frames from a client are refused rather than trusted: we
// expect no client→server payloads at all.
func TestReadPumpRejectsOversizedFrame(t *testing.T) {
	h := newHubWithLimit(0)
	c, peer := newTestClient(t, h, jwtClaims{Sub: "u", Tenant: "acme"}, 4)
	defer h.unregister(c)

	go discardIncoming(c.conn, c)
	// FIN|binary, masked, 64-bit length of 2^40 bytes.
	frame := []byte{0x82, 0xff, 0, 0, 1, 0, 0, 0, 0, 0}
	go func() {
		_, _ = peer.Write(frame)
		_ = peer.Close()
	}()

	select {
	case <-c.done:
	case <-time.After(2 * time.Second):
		t.Fatal("read pump accepted an absurd frame length")
	}
}
