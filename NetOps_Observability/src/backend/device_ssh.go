// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// device_ssh.go — opt-in, zero-trust SSH-over-WebSocket gateway for the
// Infrastructure → Devices page. The browser runs an xterm.js terminal; this
// handler bridges it to a real SSH session on the target device.
//
// Security posture (CLAUDE.md §3/§8/§9):
//   - Dormant unless FEATURE_DEVICE_SSH=true (a 404 otherwise — don't reveal it).
//   - Authenticated by a ONE-TIME WebSocket ticket (internal/wsticket): the
//     browser POSTs /api/devices/{id}/ssh-ticket over ordinary authenticated
//     HTTPS and opens the socket with ?ticket=<opaque, ~30s, single-use,
//     scope-bound>. The session JWT never enters a URL — it used to ride
//     ?token= and was written verbatim into the nginx access log. Then
//     authorized (at BOTH issuance and connect, via one shared primitive): the
//     caller must be able to SEE the device (tenant/visibility) AND hold an
//     operator/admin role. Read-only principals and API-key machine clients
//     are refused.
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
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"netops/backend/internal/platformdb"
	"os"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/ws"
	"netops/backend/internal/wsticket"
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

// ---- host-key TOFU store ----------------------------------------------------

// sshHostStore persists the first SSH host-key fingerprint seen per address and
// refuses a later change (trust on first use). Backed by the same platformdb.Backend as
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
	if b, err := platformdb.Load(path); err == nil {
		_ = json.Unmarshal(b, &s.hosts) // best-effort: corrupt state file starts from defaults
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
		if serr := platformdb.Save(s.path, b); serr != nil {
			// A TOFU pin that fails to persist re-trusts WHATEVER key the host
			// presents after a restart — a silent MITM window. Loudly visible.
			logError("device-ssh", "host-key pin not persisted; TOFU trust resets on restart", map[string]any{
				"err": serr.Error()})
		}
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

// authorizeDeviceSSH is THE single authorization primitive for the SSH gateway.
// Ticket issuance and WebSocket redemption both call it, so the two paths can
// never drift — the ticket endpoint cannot become a weaker door than the socket
// it opens. It writes the HTTP error and returns ok=false on refusal.
//
// Order matters and mirrors the original handler: feature gate (404, do not
// disclose a dormant capability) → id shape → authenticated principal → role
// (api-key principals are refused outright; SSH is a human operator action) →
// tenant visibility (404, never reveal another tenant's device) → usable
// address.
func (s *server) authorizeDeviceSSH(w http.ResponseWriter, r *http.Request, suffix string) (id string, claims jwtClaims, tenant string, cross bool, dev models.Device, ok bool) {
	if os.Getenv("FEATURE_DEVICE_SSH") != "true" {
		http.NotFound(w, r) // dormant: don't disclose the capability
		return
	}
	id = strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/devices/"), suffix)
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	claims, found := userFrom(r.Context())
	if !found {
		writeError(w, http.StatusUnauthorized, errors.New("authentication required"))
		return
	}
	if strings.HasPrefix(claims.Sub, "apikey:") || !sshRoleAllowed(claims.Role) {
		writeError(w, http.StatusForbidden, errors.New("device SSH requires an operator or admin session"))
		return
	}
	tenant, cross = principalTenant(claims)
	dev, found = s.discovery.Get(id)
	if !found || !canSeeDevice(dev, tenant, cross) {
		http.NotFound(w, r) // out-of-tenant: don't reveal existence
		return
	}
	if strings.TrimSpace(dev.Address) == "" {
		writeError(w, http.StatusBadRequest, errors.New("device has no address"))
		return
	}
	return id, claims, tenant, cross, dev, true
}

// handleDeviceSSHTicket mints a one-time WebSocket ticket:
// POST /api/devices/{id}/ssh-ticket.
//
// This is an ORDINARY authenticated HTTPS request, so the session credential
// rides the Authorization header where it belongs and never reaches a URL. The
// browser then opens the WebSocket with ?ticket=<opaque>, which is single-use,
// device/tenant/user/purpose-bound and expires in ~30s — worthless in a log.
//
// Full SSH authorization runs HERE, not only at connect: a caller who may not
// SSH must not be able to obtain a ticket at all.
func (s *server) handleDeviceSSHTicket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id, claims, tenant, _, _, ok := s.authorizeDeviceSSH(w, r, "/ssh-ticket")
	if !ok {
		return
	}
	raw, err := s.wsTickets.Issue(wsticket.Ticket{
		TenantID: tenant, UserID: claims.Sub, Role: claims.Role,
		DeviceID: id, Purpose: wsticket.PurposeDeviceSSH,
	}, time.Now())
	if err != nil {
		// Capacity refusal is a real condition, not silence (§16.1 in spirit).
		logWarn("device-ssh", "ws ticket not issued", map[string]any{
			"device_id": id, "tenant": tenant, "error": err.Error()})
		writeError(w, http.StatusServiceUnavailable, errors.New("too many terminal sessions starting — retry shortly"))
		return
	}
	// Fingerprint only — the raw ticket is a credential and never enters a log.
	logInfo("device-ssh", "ws ticket issued", map[string]any{
		"device_id": id, "tenant": tenant, "user": claims.Sub,
		"purpose": wsticket.PurposeDeviceSSH, "ticket_fp": wsticket.Fingerprint(raw)})
	writeJSON(w, http.StatusOK, map[string]any{
		"ticket": raw, "expires_in_seconds": int(wsticket.TTL.Seconds()),
	})
}

// handleDeviceSSH upgrades to a WebSocket and bridges it to an SSH shell on the
// device named in the path: GET /api/devices/{id}/ssh?ticket=<one-time ticket>.
//
// The ticket was already consumed by withAuth (which is where the request's
// principal comes from). What remains here is the scope check that binds the
// ticket to THIS device, plus the same authorization the issuer applied — the
// ticket is a transport credential, never a substitute for authorization.
func (s *server) handleDeviceSSH(w http.ResponseWriter, r *http.Request) {
	id, claims, tenant, cross, dev, ok := s.authorizeDeviceSSH(w, r, "/ssh")
	if !ok {
		return
	}
	// Ticket scope: the consumed ticket must have been minted for this device
	// and this purpose. A ticket for device-A presented at device-B is refused
	// even though both are visible to the caller.
	if tkt, seen := wsTicketFrom(r.Context()); seen {
		if tkt.DeviceID != id || tkt.Purpose != wsticket.PurposeDeviceSSH {
			logWarn("device-ssh", "ws ticket scope mismatch", map[string]any{
				"device_id": id, "ticket_device_id": tkt.DeviceID,
				"purpose": tkt.Purpose, "tenant": tenant})
			writeError(w, http.StatusForbidden, errors.New("ticket is not valid for this device"))
			return
		}
	} else if r.URL.Query().Get("ticket") != "" {
		// A ticket was supplied but did not survive redemption (expired, already
		// used, or unknown). Never fall through to another credential.
		writeError(w, http.StatusUnauthorized, errors.New("websocket ticket invalid, expired or already used"))
		return
	}

	conn, err := ws.Upgrade(w, r, wsOriginAllowed)
	if err != nil {
		return // wsUpgrade already wrote the error if it could
	}
	defer conn.Close()

	s.bridgeSSH(conn, claims, tenant, cross, dev)
}

// bridgeSSH performs the connect handshake, dials SSH, and pumps bytes both ways
// until either side closes or a bound (idle/max) is hit. It owns the audit
// open/close pair.
func (s *server) bridgeSSH(sock *ws.Conn, claims jwtClaims, tenant string, cross bool, dev models.Device) {
	// First frame: the connect request (creds + initial window). Bounded read.
	_ = sock.SetReadDeadline(time.Now().Add(60 * time.Second)) // best-effort: a failed deadline set surfaces as a read/write error
	op, payload, err := sock.ReadMessage()
	if err != nil || op == ws.OpClose {
		return
	}
	var req sshConnectReq
	if err := json.Unmarshal(payload, &req); err != nil || strings.TrimSpace(req.Username) == "" {
		_ = sock.WriteJSON(map[string]any{"type": "error", "message": "first message must be a JSON connect request with a username"}) // best-effort: error report to a client that may be gone
		return
	}
	if req.Password == "" && req.PrivateKey == "" {
		_ = sock.WriteJSON(map[string]any{"type": "error", "message": "a password or private key is required"}) // best-effort: error report to a client that may be gone
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
			_ = sock.WriteJSON(map[string]any{"type": "error", "message": "invalid private key: " + perr.Error()}) // best-effort: error report to a client that may be gone
			return
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if req.Password != "" {
		// Offer BOTH password and keyboard-interactive with the same secret. The
		// ssh client only attempts a configured method if its name is in the
		// server's advertised list, and many network devices (Arista EOS, Cisco,
		// Juniper, …) accept ONLY keyboard-interactive — offering password alone
		// leaves "none" the only attempted method ("no supported methods remain").
		auth = append(auth, ssh.Password(req.Password))
		auth = append(auth, ssh.KeyboardInteractive(
			func(_, _ string, questions []string, _ []bool) ([]string, error) {
				// Replay the one password for each prompt the device sends.
				answers := make([]string, len(questions))
				for i := range questions {
					answers[i] = req.Password
				}
				return answers, nil
			}))
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
		_ = sock.WriteJSON(map[string]any{"type": "hostkey", "fingerprint": hostFP, "first_seen": first}) // best-effort: informational frame; the session proceeds
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
		_ = sock.WriteJSON(map[string]any{"type": "error", "message": "connect failed: " + err.Error()}) // best-effort: error report to a client that may be gone
		return
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()                                                                                       // best-effort: nothing actionable on close failure
		_ = sock.WriteJSON(map[string]any{"type": "error", "message": "ssh handshake failed: " + err.Error()}) // best-effort: error report to a client that may be gone
		s.audit.Record(s.sshAudit(claims, tenant, cross, dev, hostFP, "deny", 0, 0))
		return
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		_ = sock.WriteJSON(map[string]any{"type": "error", "message": "session open failed: " + err.Error()}) // best-effort: error report to a client that may be gone
		return
	}
	defer session.Close()

	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := session.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		_ = sock.WriteJSON(map[string]any{"type": "error", "message": "pty request failed: " + err.Error()}) // best-effort: error report to a client that may be gone
		return
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return
	}
	// Frame device output straight back to the browser as binary.
	counter := &byteCounter{}
	session.Stdout = &wsBinWriter{sock: sock, n: counter}
	session.Stderr = &wsBinWriter{sock: sock, n: counter}
	if err := session.Shell(); err != nil {
		_ = sock.WriteJSON(map[string]any{"type": "error", "message": "shell start failed: " + err.Error()}) // best-effort: error report to a client that may be gone
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
		_ = sock.WriteJSON(map[string]any{"type": "status", "message": "session idle timeout"}) // best-effort: status frame; teardown follows
		sock.Close()
	})
	defer idle.Stop()
	counter.onWrite = func() { idle.Reset(sshIdleTimeout()) }

	// Client → device pump (own goroutine). Binary frames = stdin; text frames =
	// control JSON (resize). Exits on close/EOF, then closes the session.
	go func() {
		defer session.Close()
		for {
			_ = sock.SetReadDeadline(time.Now().Add(sshIdleTimeout() + 30*time.Second)) // best-effort: a failed deadline set surfaces as a read/write error
			op, data, rerr := sock.ReadMessage()
			if rerr != nil || op == ws.OpClose {
				return
			}
			idle.Reset(sshIdleTimeout())
			switch op {
			case ws.OpBinary:
				if _, werr := stdin.Write(data); werr != nil {
					return
				}
			case ws.OpText:
				var ctl struct {
					Type string `json:"type"`
					Cols int    `json:"cols"`
					Rows int    `json:"rows"`
				}
				if json.Unmarshal(data, &ctl) == nil && ctl.Type == "resize" {
					_ = session.WindowChange(clampDim(ctl.Rows, 24), clampDim(ctl.Cols, 80)) // best-effort: a failed resize keeps the old PTY size
				}
			}
		}
	}()

	// Wait for the shell to exit, the context (max session), or a closed WS.
	done := make(chan struct{})
	go func() { _ = session.Wait(); close(done) }() // discard: teardown: the exit status is not needed
	select {
	case <-done:
	case <-ctx.Done():
		_ = sock.WriteJSON(map[string]any{"type": "status", "message": "max session duration reached"}) // best-effort: status frame; teardown follows
	case <-sock.Closed():
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
	sock *ws.Conn
	n    *byteCounter
}

func (w *wsBinWriter) Write(p []byte) (int, error) {
	if err := w.sock.WriteBinary(p); err != nil {
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

// wsTicketCtxKey carries the redeemed WebSocket ticket from withAuth (which
// consumes it) to the handler (which checks its scope). Distinct from
// userCtxKey so a ticket can never be mistaken for a session principal.
type wsTicketKey struct{}

var wsTicketCtxKey = wsTicketKey{}

// wsTicketFrom returns the ticket redeemed for this request, if any.
func wsTicketFrom(ctx context.Context) (wsticket.Ticket, bool) {
	t, ok := ctx.Value(wsTicketCtxKey).(wsticket.Ticket)
	return t, ok
}
