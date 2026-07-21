package main

import (
	"bufio"
	"crypto/sha1" // #nosec G505 -- RFC 6455 §4.2.2: WebSocket accept-key is SHA-1; protocol-mandated
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// events.go — WebSocket pub/sub for live dashboard updates.
//
// The protocol is RFC 6455 (text frames only, no fragmentation, no
// compression). We implement just enough server-side to push JSON
// events to browsers — no client-to-server messages are expected, so
// we don't even unmask incoming frames.
//
// Wire-level messages broadcast to subscribers:
//
//   { "type": "metric_update", "data": { "title": "Devices", "value": "42", "trend": "+3" } }
//   { "type": "alert",         "data": <models.Alert>                                       }
//   { "type": "telemetry",     "data": { "value": 87 }                                      }
//
// Authentication: the standard /api/auth bearer token is required, but
// browsers can't set Authorization on WebSocket — so the client sends
// `?token=<jwt>` and the auth middleware accepts that for this route.

const wsMagic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

const (
	// Keepalive: we send a ping every wsPingInterval and require ANY frame
	// (browsers auto-reply pong, RFC 6455 §5.5.3) inside wsReadTimeout. Without
	// it a half-open peer — laptop lid closed, NAT entry expired — is only reaped
	// after the TCP retransmit timeout, minutes later, while the hub keeps
	// building and buffering frames for it. The read deadline also matters now
	// that the HTTP server sets a ReadTimeout: the hijacked conn inherits that
	// deadline, so the read pump MUST manage its own or the socket dies on the
	// server's request-read clock.
	wsPingInterval = 30 * time.Second
	wsReadTimeout  = 90 * time.Second

	// We expect NO client→server payloads. Anything larger than this is either a
	// broken client or an attempt to make us buffer/skip an absurd amount, so the
	// connection is dropped rather than trusted (§3).
	wsMaxFramePayload = 1 << 20 // 1 MiB

	// Default ceiling on concurrent sockets. Each one multiplies the per-tick
	// broadcast cost, so an unbounded count is a latency-amplification DoS.
	// Raise with WS_MAX_CLIENTS; the cap is never off in production.
	wsDefaultMaxClients = 512
)

// ----------------------------------------------------------------------------
// Hub — tracks connected clients and fans out broadcasts.
// ----------------------------------------------------------------------------

type wsClient struct {
	conn    net.Conn
	send    chan []byte
	done    chan struct{}
	once    sync.Once
	dropped atomic.Uint64 // frames discarded because this client's buffer was full
	claims  jwtClaims     // the principal that opened the socket; gates tenant-sensitive frames
}

// close tears the client down exactly once.
//
// It deliberately does NOT close c.send. Broadcasters hold that channel while
// the client is still in h.clients, and a send on a closed channel panics even
// inside a select with a default — so closing it here (from the READ pump, with
// no hub lock held) turned an ordinary browser tab close into a process-wide
// crash. Only c.done is closed: senders check it, the write pump exits on it,
// and the buffered channel is garbage-collected with the client.
func (c *wsClient) close() {
	c.once.Do(func() {
		close(c.done)
		_ = c.conn.Close()
	})
}

// closed reports whether the client has been torn down.
func (c *wsClient) closed() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

type Hub struct {
	mu      sync.RWMutex
	clients map[*wsClient]bool
	max     int           // 0 = unbounded
	dropped atomic.Uint64 // frames dropped hub-wide (slow clients)
}

func NewHub() *Hub {
	return newHubWithLimit(envInt("WS_MAX_CLIENTS", wsDefaultMaxClients))
}

func newHubWithLimit(max int) *Hub {
	if max < 0 {
		max = 0
	}
	return &Hub{clients: make(map[*wsClient]bool), max: max}
}

// register admits a client, or refuses it when the hub is at capacity. The
// caller must drop the connection on false — accepting past the cap lets N
// sockets multiply the per-tick broadcast cost without bound.
func (h *Hub) register(c *wsClient) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.max > 0 && len(h.clients) >= h.max {
		return false
	}
	h.clients[c] = true
	return true
}

func (h *Hub) unregister(c *wsClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.clients, c)
	// Closed unconditionally: a client refused at the cap, or one already
	// removed, must still be torn down. close() is idempotent.
	c.close()
}

// snapshot copies the client set so fan-out (marshalling, per-tenant payload
// building, channel sends) happens with NO hub lock held. Holding the lock
// across that work starved register/unregister, which need the write lock.
func (h *Hub) snapshot() []*wsClient {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]*wsClient, 0, len(h.clients))
	for c := range h.clients {
		out = append(out, c)
	}
	return out
}

// deliver queues one frame for one client without ever blocking the hub. A slow
// client loses frames (bounded queue, §9) but is counted and logged rather than
// silently skipped (§10).
func (h *Hub) deliver(c *wsClient, data []byte) {
	if c.closed() {
		return
	}
	select {
	case c.send <- data:
	case <-c.done:
	default:
		h.dropped.Add(1)
		if c.dropped.Add(1) == 1 {
			logWarn("events", "websocket send buffer full, dropping frames", map[string]any{
				"tenant": c.claims.Tenant,
				"sub":    c.claims.Sub,
			})
		}
	}
}

// Dropped returns the total number of frames discarded because a client could
// not keep up. Monotonic; exported for the metrics endpoint.
func (h *Hub) Dropped() uint64 { return h.dropped.Load() }

// Broadcast marshals msg to JSON and pushes a frame to every connected client.
func (h *Hub) Broadcast(msg map[string]any) {
	data, err := json.Marshal(msg)
	if err != nil {
		logError("events", "broadcast marshal", errf(err))
		return
	}
	for _, c := range h.snapshot() {
		h.deliver(c, data)
	}
}

// BroadcastFiltered fans out a PER-SCOPE set of frames: build(claims) returns
// the messages to send a principal with that claims scope (nil/empty to skip
// it). Use this for tenant-sensitive payloads (dashboard tiles, alerts) so one
// tenant never receives another's data over the shared socket.
//
// build is invoked ONCE PER DISTINCT SCOPE, not once per socket: the builders
// here derive visibility solely from principalTenant(claims) (see
// broadcastScopeKey), and each one is a full fleet + alert scan. Calling it per
// socket made backend CPU scale with the number of open dashboards — 200 tabs
// on one tenant meant 200 identical fleet scans every 5 seconds.
func (h *Hub) BroadcastFiltered(build func(claims jwtClaims) []map[string]any) {
	clients := h.snapshot()
	frames := make(map[string][][]byte, 4)
	for _, c := range clients {
		key := broadcastScopeKey(c.claims)
		data, built := frames[key]
		if !built {
			for _, msg := range build(c.claims) {
				b, err := json.Marshal(msg)
				if err != nil {
					logError("events", "broadcast marshal", errf(err))
					continue
				}
				data = append(data, b)
			}
			frames[key] = data
		}
		for _, b := range data {
			h.deliver(c, b)
		}
	}
}

// broadcastScopeKey collapses a principal to the scope that fully determines the
// frames it may receive. Every tenant-sensitive builder resolves visibility
// through principalTenant (visibleDevices / visibleDeviceIDs / alertVisibleTo),
// so two clients with the same (tenant, cross) pair are entitled to byte-
// identical payloads — and nothing else may share a payload. Widening this key
// (e.g. keying on role) would be a cross-tenant leak, so it stays derived from
// the same function the request-path filters use.
func broadcastScopeKey(c jwtClaims) string {
	tenant, cross := principalTenant(c)
	if cross {
		return "cross:*"
	}
	return "tenant:" + tenant
}

func (h *Hub) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// atCapacity is an advisory pre-check for the HTTP handler; register() is the
// authoritative one.
func (h *Hub) atCapacity() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.max > 0 && len(h.clients) >= h.max
}

// ----------------------------------------------------------------------------
// HTTP handler: upgrade and serve.
// ----------------------------------------------------------------------------

// wsOriginAllowed defends WebSocket upgrades against Cross-Site WebSocket
// Hijacking (SR-006). WS handshakes are exempt from the same-origin policy and
// CORS, so a malicious page could open a socket to our event feed using a token
// it observed. Browsers always send Origin on a WS handshake, so: a present
// Origin MUST be same-origin (matches the request Host) or explicitly
// allowlisted (CORS_ALLOWED_ORIGINS). A missing Origin is a non-browser client
// (CLI/agent) which can't be a CSWSH victim and still needs a valid token.
func wsOriginAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	return corsAllowedOrigins()[origin]
}

func (s *server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return
	}
	if !wsOriginAllowed(r) {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return
	}
	// Refuse at capacity BEFORE hijacking, so the client gets a real HTTP status
	// instead of a socket that opens and dies. register() re-checks under the
	// lock and is the authoritative gate.
	if s.hub.atCapacity() {
		w.Header().Set("Retry-After", "5")
		http.Error(w, "too many websocket clients", http.StatusServiceUnavailable)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "server doesn't support connection hijack", http.StatusInternalServerError)
		return
	}
	conn, brw, err := hijacker.Hijack()
	if err != nil {
		return
	}

	// Send 101 Switching Protocols.
	h := sha1.New() // #nosec G401 -- RFC 6455 WebSocket Sec-WebSocket-Accept hash; protocol-mandated
	_, _ = h.Write([]byte(key + wsMagic))
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := brw.WriteString(resp); err != nil {
		_ = conn.Close()
		return
	}
	if err := brw.Flush(); err != nil {
		_ = conn.Close()
		return
	}

	claims, _ := userFrom(r.Context())
	client := &wsClient{
		conn:   conn,
		send:   make(chan []byte, 64),
		done:   make(chan struct{}),
		claims: claims,
	}
	if !s.hub.register(client) {
		logWarn("events", "websocket client refused: hub at capacity", map[string]any{
			"remote":  conn.RemoteAddr().String(),
			"clients": s.hub.Count(),
		})
		_ = conn.Close()
		return
	}
	defer s.hub.unregister(client)

	logInfo("events", "client connected", map[string]any{
		"remote":  conn.RemoteAddr().String(),
		"clients": s.hub.Count(),
	})

	// Read pump — we don't expect client messages, but we need to detect
	// the connection closing. Drain incoming frames silently.
	safeGo("ws-read-pump", func() { discardIncoming(conn, client) })

	// Write pump in this goroutine — exits when the client is torn down.
	ping := time.NewTicker(wsPingInterval)
	defer ping.Stop()
	for {
		select {
		case <-client.done:
			return
		case <-ping.C:
			if err := writePingFrame(conn); err != nil {
				return
			}
		case msg := <-client.send:
			if err := writeTextFrame(conn, msg); err != nil {
				return
			}
		}
	}
}

func discardIncoming(conn net.Conn, c *wsClient) {
	br := bufio.NewReader(conn)
	for {
		// Bound how long we'll wait for the peer. Refreshed per frame, and the
		// peer's automatic pong to our ping is enough to keep it alive, so a
		// half-open connection is reaped in ~wsReadTimeout instead of never.
		if err := conn.SetReadDeadline(time.Now().Add(wsReadTimeout)); err != nil {
			c.close()
			return
		}
		// Each frame: read 2 bytes (FIN+opcode, masked+length), then
		// length, then mask key, then payload. We discard everything;
		// a close frame (opcode 0x8) ends the loop. ReadFull, not Read: a
		// short read would silently misalign every subsequent frame.
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(br, hdr); err != nil {
			c.close()
			return
		}
		opcode := hdr[0] & 0x0f
		masked := hdr[1]&0x80 != 0
		plen := int(hdr[1] & 0x7f)

		switch plen {
		case 126:
			ext := make([]byte, 2)
			if _, err := io.ReadFull(br, ext); err != nil {
				c.close()
				return
			}
			plen = int(ext[0])<<8 | int(ext[1])
		case 127:
			ext := make([]byte, 8)
			if _, err := io.ReadFull(br, ext); err != nil {
				c.close()
				return
			}
			plen = 0
			for _, b := range ext {
				// Reject before the shift can overflow int into a negative
				// length; we never accept a payload this large anyway.
				if plen > wsMaxFramePayload {
					c.close()
					return
				}
				plen = plen<<8 | int(b)
			}
		}
		if plen < 0 || plen > wsMaxFramePayload {
			c.close()
			return
		}
		if masked {
			mask := make([]byte, 4)
			if _, err := io.ReadFull(br, mask); err != nil {
				c.close()
				return
			}
		}
		if plen > 0 {
			// Skip payload.
			if _, err := br.Discard(plen); err != nil {
				c.close()
				return
			}
		}
		if opcode == 0x8 { // close
			c.close()
			return
		}
	}
}

// writePingFrame emits an empty ping. The peer's pong refreshes the read
// deadline in discardIncoming, which is how a half-open socket gets detected.
func writePingFrame(conn net.Conn) error {
	if err := conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	_, err := conn.Write([]byte{0x89, 0x00})
	return err
}

// writeTextFrame emits a single, unfragmented, unmasked text frame.
func writeTextFrame(conn net.Conn, payload []byte) error {
	n := len(payload)
	var header []byte
	switch {
	case n <= 125:
		header = []byte{0x81, byte(n)}
	case n <= 65535:
		header = []byte{0x81, 126, byte(n >> 8), byte(n)}
	default:
		header = []byte{
			0x81, 127,
			byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32),
			byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n),
		}
	}
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(header); err != nil {
		return err
	}
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	return nil
}
