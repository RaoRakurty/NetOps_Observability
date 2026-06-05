package main

// device_ssh.go — opt-in, zero-trust SSH-over-WebSocket gateway for the
// Infrastructure → Devices page. The browser runs an xterm.js terminal; this
// handler bridges it to a real SSH session on the target device.
//
// Security posture (CLAUDE.md §3/§8/§9):
//   - Dormant unless FEATURE_DEVICE_SSH=true (a 404 otherwise — don't reveal it).
//   - Authenticated by the normal JWT (over ?token= since browsers can't set an
//     Authorization header on a WebSocket), then authorized: the caller must be
//     able to SEE the device (tenant/visibility) AND hold an operator/admin role.
//     Read-only principals and API-key machine clients are refused.
//   - SSH credentials are supplied per-connection by the operator and are NEVER
//     persisted — the operator authenticates to the device as themselves, which
//     also gives honest audit attribution. (A stored-SSH-credential vault keyed
//     off credential_ref is a clean future add; the SNMP cred store today only
//     holds SNMP secrets.)
//   - Host keys are verified TOFU: the first key seen for an address is recorded;
//     a later mismatch is refused (possible MITM) — never blindly accepted.
//   - Bounded IO: dial timeout, idle timeout, and a hard max session duration.
//   - Audited: SSH_OPEN / SSH_CLOSE events (actor, device, tenant, fingerprint,
//     bytes, duration). Session CONTENT (keystrokes/output) is never logged.

import (
	"bufio"
	"context"
	"crypto/sha1" // #nosec G505 -- RFC 6455 §4.2.2 WebSocket accept-key is SHA-1; protocol-mandated
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"netops/backend/models"

	"golang.org/x/crypto/ssh"
)

// ---- tunables (env-overridable; all fail safe to sane bounds) ---------------

func sshDialTimeout() time.Duration { return secEnvDuration("DEVICE_SSH_DIAL_TIMEOUT_SEC", 10, 1, 60) }
func sshIdleTimeout() time.Duration {
	return secEnvDuration("DEVICE_SSH_IDLE_TIMEOUT_SEC", 900, 30, 7200)
}
func sshMaxSession() time.Duration {
	return secEnvDuration("DEVICE_SSH_MAX_SESSION_SEC", 3600, 60, 86400)
}

// secEnvDuration reads a positive integer-seconds env var, clamped to [min,max].
func secEnvDuration(key string, def, lo, hi int) time.Duration {
	v := def
	if s := strings.TrimSpace(os.Getenv(key)); s != "" {
		if n, err := parseIntStrict(s); err == nil {
			v = n
		}
	}
	if v < lo {
		v = lo
	}
	if v > hi {
		v = hi
	}
	return time.Duration(v) * time.Second
}

// ---- host-key TOFU store ----------------------------------------------------

// sshHostStore persists the first SSH host-key fingerprint seen per address and
// refuses a later change (trust on first use). Backed by the same kvBackend as
// the other small config stores; bounded (one row per device address).
type sshHostStore struct {
	mu     sync.Mutex
	path   string
	hosts  map[string]string // address -> "SHA256:base64" fingerprint
	loaded bool
}

func newSSHHostStore(path string) *sshHostStore {
	if path == "" {
		path = "/data/ssh_known_hosts.json"
	}
	s := &sshHostStore{path: path, hosts: map[string]string{}}
	if b, err := kvLoad(path); err == nil {
		_ = json.Unmarshal(b, &s.hosts)
	}
	s.loaded = true
	return s
}

// check implements TOFU. Returns (firstSeen, ok): ok=false means a recorded
// fingerprint exists and DIFFERS (refuse the connection). firstSeen=true means
// the key was just recorded (surface it to the operator).
func (s *sshHostStore) check(addr, fp string) (firstSeen, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, exists := s.hosts[addr]
	if exists {
		return false, prev == fp
	}
	s.hosts[addr] = fp
	if b, err := json.MarshalIndent(s.hosts, "", "  "); err == nil {
		_ = kvSave(s.path, b)
	}
	return true, true
}

func sshFingerprint(key ssh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// ---- connect request (first client frame) -----------------------------------

type sshConnectReq struct {
	Username   string `json:"username"`
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
	Port       int    `json:"port,omitempty"`
	Cols       int    `json:"cols,omitempty"`
	Rows       int    `json:"rows,omitempty"`
}

// ---- handler ----------------------------------------------------------------

// sshRoleAllowed gates the gateway to write-capable human roles. SSH into a
// device is an operator action; read-only principals (and machine API keys,
// whose role is derived from scopes) are refused.
func sshRoleAllowed(role string) bool {
	return role == RoleOperator || isSuperAdminRole(role)
}

// handleDeviceSSH upgrades to a WebSocket and bridges it to an SSH shell on the
// device named in the path: GET /api/devices/{id}/ssh.
func (s *server) handleDeviceSSH(w http.ResponseWriter, r *http.Request) {
	if os.Getenv("FEATURE_DEVICE_SSH") != "true" {
		http.NotFound(w, r) // dormant: don't disclose the capability
		return
	}
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/devices/"), "/ssh")
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("authentication required"))
		return
	}
	if strings.HasPrefix(claims.Sub, "apikey:") || !sshRoleAllowed(claims.Role) {
		writeError(w, http.StatusForbidden, errors.New("device SSH requires an operator or admin session"))
		return
	}
	tenant, cross := principalTenant(claims)
	dev, found := s.discovery.Get(id)
	if !found || !canSeeDevice(dev, tenant, cross) {
		http.NotFound(w, r) // out-of-tenant: don't reveal existence
		return
	}
	if strings.TrimSpace(dev.Address) == "" {
		writeError(w, http.StatusBadRequest, errors.New("device has no address"))
		return
	}

	ws, err := wsUpgrade(w, r)
	if err != nil {
		return // wsUpgrade already wrote the error if it could
	}
	defer ws.close()

	s.bridgeSSH(ws, claims, tenant, cross, dev)
}

// bridgeSSH performs the connect handshake, dials SSH, and pumps bytes both ways
// until either side closes or a bound (idle/max) is hit. It owns the audit
// open/close pair.
func (s *server) bridgeSSH(ws *wsConn, claims jwtClaims, tenant string, cross bool, dev models.Device) {
	// First frame: the connect request (creds + initial window). Bounded read.
	_ = ws.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	op, payload, err := ws.readMessage()
	if err != nil || op == wsOpClose {
		return
	}
	var req sshConnectReq
	if err := json.Unmarshal(payload, &req); err != nil || strings.TrimSpace(req.Username) == "" {
		_ = ws.writeJSON(map[string]any{"type": "error", "message": "first message must be a JSON connect request with a username"})
		return
	}
	if req.Password == "" && req.PrivateKey == "" {
		_ = ws.writeJSON(map[string]any{"type": "error", "message": "a password or private key is required"})
		return
	}
	port := req.Port
	if port <= 0 || port > 65535 {
		port = 22
	}
	cols, rows := clampDim(req.Cols, 80), clampDim(req.Rows, 24)

	var auth []ssh.AuthMethod
	if req.PrivateKey != "" {
		signer, perr := parsePrivateKey(req.PrivateKey, req.Passphrase)
		if perr != nil {
			_ = ws.writeJSON(map[string]any{"type": "error", "message": "invalid private key: " + perr.Error()})
			return
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if req.Password != "" {
		auth = append(auth, ssh.Password(req.Password))
	}

	addr := net.JoinHostPort(dev.Address, fmt.Sprintf("%d", port))
	start := time.Now().UTC()
	var hostFP string
	hostKeyCB := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		hostFP = sshFingerprint(key)
		first, okHost := s.sshHosts.check(dev.Address, hostFP)
		if !okHost {
			return fmt.Errorf("host key mismatch for %s (possible MITM) — recorded fingerprint differs", dev.Address)
		}
		_ = ws.writeJSON(map[string]any{"type": "hostkey", "fingerprint": hostFP, "first_seen": first})
		return nil
	}

	cfg := &ssh.ClientConfig{
		User:            req.Username,
		Auth:            auth,
		HostKeyCallback: hostKeyCB,
		Timeout:         sshDialTimeout(),
	}

	conn, err := net.DialTimeout("tcp", addr, sshDialTimeout())
	if err != nil {
		_ = ws.writeJSON(map[string]any{"type": "error", "message": "connect failed: " + err.Error()})
		return
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		_ = ws.writeJSON(map[string]any{"type": "error", "message": "ssh handshake failed: " + err.Error()})
		s.audit.Record(s.sshAudit(claims, tenant, cross, dev, hostFP, "deny", 0, 0))
		return
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		_ = ws.writeJSON(map[string]any{"type": "error", "message": "session open failed: " + err.Error()})
		return
	}
	defer session.Close()

	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := session.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		_ = ws.writeJSON(map[string]any{"type": "error", "message": "pty request failed: " + err.Error()})
		return
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return
	}
	// Frame device output straight back to the browser as binary.
	counter := &byteCounter{}
	session.Stdout = &wsBinWriter{ws: ws, n: counter}
	session.Stderr = &wsBinWriter{ws: ws, n: counter}
	if err := session.Shell(); err != nil {
		_ = ws.writeJSON(map[string]any{"type": "error", "message": "shell start failed: " + err.Error()})
		return
	}

	s.audit.Record(s.sshAudit(claims, tenant, cross, dev, hostFP, "allow", 0, 0))
	logInfo("device.ssh", "session opened", map[string]any{
		"actor": claims.Sub, "tenant": tenant, "device": dev.ID, "address": dev.Address, "fingerprint": hostFP,
	})

	// Bounds: hard max-session + idle. The idle timer is reset on any client
	// frame or device output; firing closes the WS, which unblocks both pumps.
	ctx, cancel := context.WithTimeout(context.Background(), sshMaxSession())
	defer cancel()
	idle := time.AfterFunc(sshIdleTimeout(), func() {
		_ = ws.writeJSON(map[string]any{"type": "status", "message": "session idle timeout"})
		ws.close()
	})
	defer idle.Stop()
	counter.onWrite = func() { idle.Reset(sshIdleTimeout()) }

	// Client → device pump (own goroutine). Binary frames = stdin; text frames =
	// control JSON (resize). Exits on close/EOF, then closes the session.
	go func() {
		defer session.Close()
		for {
			_ = ws.conn.SetReadDeadline(time.Now().Add(sshIdleTimeout() + 30*time.Second))
			op, data, rerr := ws.readMessage()
			if rerr != nil || op == wsOpClose {
				return
			}
			idle.Reset(sshIdleTimeout())
			switch op {
			case wsOpBinary:
				if _, werr := stdin.Write(data); werr != nil {
					return
				}
			case wsOpText:
				var ctl struct {
					Type string `json:"type"`
					Cols int    `json:"cols"`
					Rows int    `json:"rows"`
				}
				if json.Unmarshal(data, &ctl) == nil && ctl.Type == "resize" {
					_ = session.WindowChange(clampDim(ctl.Rows, 24), clampDim(ctl.Cols, 80))
				}
			}
		}
	}()

	// Wait for the shell to exit, the context (max session), or a closed WS.
	done := make(chan struct{})
	go func() { _ = session.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		_ = ws.writeJSON(map[string]any{"type": "status", "message": "max session duration reached"})
	case <-ws.closed:
	}

	dur := int(time.Now().UTC().Sub(start).Seconds())
	s.audit.Record(s.sshAudit(claims, tenant, cross, dev, hostFP, "close", counter.total(), dur))
	logInfo("device.ssh", "session closed", map[string]any{
		"actor": claims.Sub, "device": dev.ID, "bytes_out": counter.total(), "duration_s": dur,
	})
}

func (s *server) sshAudit(claims jwtClaims, tenant string, cross bool, dev models.Device, fp, decision string, bytesOut, durSec int) AuditEvent {
	method := "SSH_OPEN"
	switch decision {
	case "close":
		method = "SSH_CLOSE"
	case "deny":
		method = "SSH_DENY"
	}
	return AuditEvent{
		Time: time.Now().UTC(), Actor: claims.Sub, Tenant: tenant, Cross: cross,
		Method: method, Path: "/api/devices/" + dev.ID + "/ssh", Decision: decision,
		Detail: map[string]any{
			"device": dev.ID, "address": dev.Address, "host_fingerprint": fp,
			"bytes_out": bytesOut, "duration_s": durSec,
		},
	}
}

func parsePrivateKey(pem, passphrase string) (ssh.Signer, error) {
	if passphrase != "" {
		return ssh.ParsePrivateKeyWithPassphrase([]byte(pem), []byte(passphrase))
	}
	return ssh.ParsePrivateKey([]byte(pem))
}

func clampDim(v, def int) int {
	if v <= 0 {
		return def
	}
	if v > 1000 {
		return 1000
	}
	return v
}

// ---- byte counter + framed writer ------------------------------------------

type byteCounter struct {
	mu      sync.Mutex
	n       int
	onWrite func()
}

func (c *byteCounter) add(n int) {
	c.mu.Lock()
	c.n += n
	cb := c.onWrite
	c.mu.Unlock()
	if cb != nil {
		cb()
	}
}
func (c *byteCounter) total() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

type wsBinWriter struct {
	ws *wsConn
	n  *byteCounter
}

func (w *wsBinWriter) Write(p []byte) (int, error) {
	if err := w.ws.writeBinary(p); err != nil {
		return 0, err
	}
	w.n.add(len(p))
	return len(p), nil
}

// ---- minimal bidirectional RFC 6455 WebSocket ------------------------------
//
// The events.go hub is server→client text-only and never unmasks; a terminal is
// bidirectional binary, so this is a fuller (still small) implementation:
// fragmentation reassembly, client-frame unmasking, ping/pong, close.

const (
	wsOpCont   = 0x0
	wsOpText   = 0x1
	wsOpBinary = 0x2
	wsOpClose  = 0x8
	wsOpPing   = 0x9
	wsOpPong   = 0xA
)

type wsConn struct {
	conn   net.Conn
	br     *bufio.Reader
	wmu    sync.Mutex
	closed chan struct{}
	once   sync.Once
}

func (c *wsConn) close() {
	c.once.Do(func() {
		close(c.closed)
		_ = c.conn.Close()
	})
}

// wsAcceptKey computes the RFC 6455 §4.2.2 Sec-WebSocket-Accept value. wsMagic
// is defined in events.go (same package).
func wsAcceptKey(key string) string {
	h := sha1.New() // #nosec G401 -- RFC 6455 Sec-WebSocket-Accept hash; protocol-mandated
	_, _ = h.Write([]byte(key + wsMagic))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// wsUpgrade performs the RFC 6455 handshake by hijacking the connection (same
// accept-key dance as events.go) and returns a bidirectional conn.
func wsUpgrade(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "websocket upgrade required", http.StatusBadRequest)
		return nil, errors.New("not a websocket request")
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
	accept := wsAcceptKey(key)
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := brw.WriteString(resp); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := brw.Flush(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &wsConn{conn: conn, br: bufio.NewReader(conn), closed: make(chan struct{})}, nil
}

// readMessage returns the next complete application message (text or binary),
// transparently reassembling fragments and answering ping with pong. A close
// frame returns op=wsOpClose. Payloads are capped to guard memory.
func (c *wsConn) readMessage() (op byte, payload []byte, err error) {
	const maxMessage = 1 << 20 // 1 MiB per message — keystrokes are tiny
	var msg []byte
	var firstOp byte
	for {
		fin, opcode, data, rerr := c.readFrame()
		if rerr != nil {
			return 0, nil, rerr
		}
		switch opcode {
		case wsOpPing:
			_ = c.writeFrame(wsOpPong, data)
			continue
		case wsOpPong:
			continue
		case wsOpClose:
			return wsOpClose, nil, nil
		case wsOpText, wsOpBinary:
			firstOp = opcode
			msg = append(msg, data...)
		case wsOpCont:
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
func (c *wsConn) readFrame() (fin bool, opcode byte, payload []byte, err error) {
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

func (c *wsConn) writeBinary(p []byte) error { return c.writeFrame(wsOpBinary, p) }

func (c *wsConn) writeJSON(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.writeFrame(wsOpText, b)
}

// writeFrame writes a single unfragmented, unmasked server frame.
func (c *wsConn) writeFrame(opcode byte, payload []byte) error {
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
	_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.conn.Write(hdr); err != nil {
		return err
	}
	if _, err := c.conn.Write(payload); err != nil {
		return err
	}
	return nil
}
