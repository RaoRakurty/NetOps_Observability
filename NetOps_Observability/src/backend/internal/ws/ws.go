// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package ws is the platform's hand-rolled RFC 6455 WebSocket codec
// (Phase-2 W1.10, extracted from device_ssh.go): handshake-by-hijack upgrade,
// masked-frame reads with ping/pong and size bounds, and locked binary/JSON
// writes. Bidirectional — the server→client-only push in events.go predates it
// and still carries its own writer (dedup is a follow-on).
//
// Zero trust at the boundary (SR-006): Upgrade takes the caller's
// origin-allowlist predicate and DENIES browser cross-origin handshakes when
// the predicate is nil (same-origin only) — the caller cannot forget the check.
package ws

import (
	"bufio"
	"crypto/sha1" // #nosec G505 -- RFC 6455 Sec-WebSocket-Accept hash; protocol-mandated
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Magic is the RFC 6455 §4.2.2 GUID every Sec-WebSocket-Accept is derived from.
const Magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// OriginAllowed is the default cross-origin gate: a present Origin must be
// same-origin with the request Host or in the caller's allowlist; a missing
// Origin is a non-browser client (no CSWSH exposure). Fail closed on garbage.
func OriginAllowed(r *http.Request, allowlist map[string]bool) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false // unparseable Origin — deny (fail closed, SR-006)
	}
	if u.Host == "" {
		return false // an Origin with no host can never match r.Host — deny
	}
	if strings.EqualFold(u.Host, r.Host) {
		return true
	}
	return allowlist[origin]
}

const (
	opCont   = 0x0
	OpText   = 0x1
	OpBinary = 0x2
	OpClose  = 0x8
	opPing   = 0x9
	opPong   = 0xA
)

type Conn struct {
	conn   net.Conn
	br     *bufio.Reader
	wmu    sync.Mutex
	closed chan struct{}
	once   sync.Once
}

// SetReadDeadline bounds the next read (the connect-handshake timeout).
func (c *Conn) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }

// Closed is closed when the connection is torn down (select-able).
func (c *Conn) Closed() <-chan struct{} { return c.closed }

func (c *Conn) Close() {
	c.once.Do(func() {
		close(c.closed)
		_ = c.conn.Close() // best-effort: nothing actionable on close failure
	})
}

// wsAcceptKey computes the RFC 6455 §4.2.2 Sec-WebSocket-Accept value. Magic
// is defined in events.go (same package).
func AcceptKey(key string) string {
	h := sha1.New()                     // #nosec G401 -- RFC 6455 Sec-WebSocket-Accept hash; protocol-mandated
	_, _ = h.Write([]byte(key + Magic)) // hash.Write never fails
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// wsUpgrade performs the RFC 6455 handshake by hijacking the connection (same
// accept-key dance as events.go) and returns a bidirectional conn.
func Upgrade(w http.ResponseWriter, r *http.Request, allowOrigin func(*http.Request) bool) (*Conn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return nil, errors.New("not a websocket request")
	}
	// SR-006: reject cross-origin WS handshakes (CSWSH). Shared with the
	// /api/events upgrade; see wsOriginAllowed in events.go.
	if allowOrigin == nil {
		allowOrigin = func(r *http.Request) bool { return OriginAllowed(r, nil) }
	}
	if !allowOrigin(r) {
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return nil, errors.New("forbidden origin")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing Sec-WebSocket-Key", http.StatusBadRequest)
		return nil, errors.New("missing key")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack support", http.StatusInternalServerError)
		return nil, errors.New("no hijacker")
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	accept := AcceptKey(key)
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := brw.WriteString(resp); err != nil {
		_ = conn.Close() // best-effort: handshake failed; tearing down
		return nil, err
	}
	if err := brw.Flush(); err != nil {
		_ = conn.Close() // best-effort: handshake failed; tearing down
		return nil, err
	}
	return &Conn{conn: conn, br: bufio.NewReader(conn), closed: make(chan struct{})}, nil
}

// readMessage returns the next complete application message (text or binary),
// transparently reassembling fragments and answering ping with pong. A close
// frame returns op=OpClose. Payloads are capped to guard memory.
func (c *Conn) ReadMessage() (op byte, payload []byte, err error) {
	const maxMessage = 1 << 20 // 1 MiB per message — keystrokes are tiny
	var msg []byte
	var firstOp byte
	for {
		fin, opcode, data, rerr := c.readFrame()
		if rerr != nil {
			return 0, nil, rerr
		}
		switch opcode {
		case opPing:
			_ = c.writeFrame(opPong, data) // best-effort: a failed pong surfaces as the peer's timeout
			continue
		case opPong:
			continue
		case OpClose:
			return OpClose, nil, nil
		case OpText, OpBinary:
			firstOp = opcode
			msg = append(msg, data...)
		case opCont:
			msg = append(msg, data...)
		}
		if len(msg) > maxMessage {
			return 0, nil, errors.New("ws message too large")
		}
		if fin {
			return firstOp, msg, nil
		}
	}
}

// readFrame reads one (possibly partial) frame, unmasking the payload.
func (c *Conn) readFrame() (fin bool, opcode byte, payload []byte, err error) {
	h := make([]byte, 2)
	if _, err = io.ReadFull(c.br, h); err != nil {
		return
	}
	fin = h[0]&0x80 != 0
	opcode = h[0] & 0x0f
	masked := h[1]&0x80 != 0
	n := int64(h[1] & 0x7f)
	switch n {
	case 126:
		ext := make([]byte, 2)
		if _, err = io.ReadFull(c.br, ext); err != nil {
			return
		}
		n = int64(ext[0])<<8 | int64(ext[1])
	case 127:
		ext := make([]byte, 8)
		if _, err = io.ReadFull(c.br, ext); err != nil {
			return
		}
		n = 0
		for _, b := range ext {
			n = n<<8 | int64(b)
		}
	}
	if n < 0 || n > (1<<20) {
		return false, 0, nil, errors.New("ws frame too large")
	}
	var mask []byte
	if masked {
		mask = make([]byte, 4)
		if _, err = io.ReadFull(c.br, mask); err != nil {
			return
		}
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(c.br, payload); err != nil {
		return
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i&3]
		}
	}
	return fin, opcode, payload, nil
}

func (c *Conn) WriteBinary(p []byte) error { return c.writeFrame(OpBinary, p) }

func (c *Conn) WriteJSON(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.writeFrame(OpText, b)
}

// writeFrame writes a single unfragmented, unmasked server frame.
func (c *Conn) writeFrame(opcode byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	n := len(payload)
	var hdr []byte
	b0 := 0x80 | opcode // FIN + opcode
	switch {
	case n <= 125:
		hdr = []byte{b0, byte(n)}
	case n <= 65535:
		hdr = []byte{b0, 126, byte(n >> 8), byte(n)}
	default:
		hdr = []byte{b0, 127,
			byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32),
			byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second)) // best-effort: a failed deadline set surfaces as a read/write error
	if _, err := c.conn.Write(hdr); err != nil {
		return err
	}
	if _, err := c.conn.Write(payload); err != nil {
		return err
	}
	return nil
}
