package main

import (
	"bufio"
	"crypto/sha1" // #nosec G505 -- RFC 6455 §4.2.2: WebSocket accept-key is SHA-1; protocol-mandated
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
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

// ----------------------------------------------------------------------------
// Hub — tracks connected clients and fans out broadcasts.
// ----------------------------------------------------------------------------

type wsClient struct {
	conn   net.Conn
	send   chan []byte
	done   chan struct{}
	once   sync.Once
	claims jwtClaims // the principal that opened the socket; gates tenant-sensitive frames
}

func (c *wsClient) close() {
	c.once.Do(func() {
		close(c.done)
		close(c.send)
		_ = c.conn.Close()
	})
}

type Hub struct {
	mu      sync.RWMutex
	clients map[*wsClient]bool
}

func NewHub() *Hub {
	return &Hub{clients: make(map[*wsClient]bool)}
}

func (h *Hub) register(c *wsClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[c] = true
}

func (h *Hub) unregister(c *wsClient) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.clients[c]; ok {
		delete(h.clients, c)
		c.close()
	}
}

// Broadcast marshals msg to JSON and pushes a frame to every connected
// client. Slow clients are silently skipped (their send buffer is full)
// rather than blocking the whole hub.
func (h *Hub) Broadcast(msg map[string]any) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.clients {
		select {
		case c.send <- data:
		default:
			// drop: client is too slow
		}
	}
}

// BroadcastFiltered fans out a PER-CLIENT set of frames: build(claims) returns
// the messages to send that specific client (nil/empty to skip it). Use this for
// tenant-sensitive payloads (dashboard tiles, alerts) so one tenant never
// receives another's data over the shared socket. Slow clients are dropped, as
// in Broadcast.
func (h *Hub) BroadcastFiltered(build func(claims jwtClaims) []map[string]any) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.clients {
		for _, msg := range build(c.claims) {
			data, err := json.Marshal(msg)
			if err != nil {
				continue
			}
			select {
			case c.send <- data:
			default:
				// drop: client is too slow
			}
		}
	}
}

func (h *Hub) Count() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
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
	s.hub.register(client)
	defer s.hub.unregister(client)

	logInfo("events", "client connected", map[string]any{
		"remote":  conn.RemoteAddr().String(),
		"clients": s.hub.Count(),
	})

	// Read pump — we don't expect client messages, but we need to detect
	// the connection closing. Drain incoming frames silently.
	go discardIncoming(conn, client)

	// Write pump in this goroutine — exits when client.send is closed.
	for {
		select {
		case <-client.done:
			return
		case msg, ok := <-client.send:
			if !ok {
				return
			}
			if err := writeTextFrame(conn, msg); err != nil {
				return
			}
		}
	}
}

func discardIncoming(conn net.Conn, c *wsClient) {
	br := bufio.NewReader(conn)
	for {
		// Each frame: read 2 bytes (FIN+opcode, masked+length), then
		// length, then mask key, then payload. We discard everything;
		// a close frame (opcode 0x8) ends the loop.
		hdr := make([]byte, 2)
		if _, err := br.Read(hdr); err != nil {
			c.close()
			return
		}
		opcode := hdr[0] & 0x0f
		masked := hdr[1]&0x80 != 0
		plen := int(hdr[1] & 0x7f)

		switch plen {
		case 126:
			ext := make([]byte, 2)
			if _, err := br.Read(ext); err != nil {
				c.close()
				return
			}
			plen = int(ext[0])<<8 | int(ext[1])
		case 127:
			ext := make([]byte, 8)
			if _, err := br.Read(ext); err != nil {
				c.close()
				return
			}
			plen = 0
			for _, b := range ext {
				plen = plen<<8 | int(b)
			}
		}
		if masked {
			mask := make([]byte, 4)
			if _, err := br.Read(mask); err != nil {
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
