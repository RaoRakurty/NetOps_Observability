package protocoldiag

// sshgw.go — the LIVE command source: one read-only `show` over the platform's
// SSH gateway.
//
// This is NOT a second SSH implementation. It is the SAME vendored, audited
// client the operator terminal and the config-capture path use
// (golang.org/x/crypto/ssh, CLAUDE.md §6 allowlist), configured with the SAME
// host-key custody: HostKeyCheck is INJECTED and production binds it to
// device_ssh.go's trust-on-first-use pinned fingerprint store, so a device whose
// key changed is refused HERE for exactly the same reason, and with exactly the
// same evidence, as it would be refused in the terminal. There is no
// InsecureIgnoreHostKey anywhere in this file and no code path that proceeds on
// a mismatch.
//
// It mirrors internal/configstore/sshgw.go deliberately — the differences are
// only the ones diagnostics require, and every one of them NARROWS the surface:
//
//   - a single non-interactive `exec` of ONE command from the CLOSED per-vendor
//     table (commandtable.go), never a shell and never a caller-supplied string;
//   - no PTY and no stdin — the session cannot be typed into;
//   - a hard byte cap on the response (§9) enforced by the writer itself, so a
//     device that streams forever is cut off rather than filling memory;
//   - a context deadline pushed onto the socket, so it can break a stuck
//     handshake or read rather than only wrapping the call.
//
// The Gateway interface is what keeps CI offline: every test in this package
// injects a fake session and no test ever opens a socket.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// DefaultDialTimeout bounds the TCP dial + SSH handshake (§9).
	DefaultDialTimeout = 10 * time.Second
	// DefaultCommandTimeout bounds ONE command end to end. A `show` that has not
	// answered within this window is a failed probe, not a reason to hang the
	// operator's collection.
	DefaultCommandTimeout = 30 * time.Second
	// MaxOutputBytes is the hard ceiling on ONE command's captured output (§9).
	// A diagnostics `show` is kilobytes; this is generous headroom, not a target.
	MaxOutputBytes = 512 << 10
)

var (
	// ErrNoAddress is a device with nothing to dial.
	ErrNoAddress = errors.New("protocoldiag: device has no address")
	// ErrTooLarge is the output-cap refusal.
	ErrTooLarge = errors.New("protocoldiag: command output exceeded the size cap")
	// ErrCommandNotInTable is the closed-table refusal: a command that the
	// catalog could not have rendered for this device's dialect is never run,
	// even when it is a perfectly valid read-only `show` (§8 least privilege).
	ErrCommandNotInTable = errors.New("protocoldiag: command is not in the closed per-vendor command table")
	// ErrDeviceBusy is the one-in-flight-per-device refusal.
	ErrDeviceBusy = errors.New("protocoldiag: a diagnostics command is already running on this device")
)

// Credential is the least-privilege diagnostics identity: a READ-ONLY account
// whose command set is the `show` class, never an enable/config-capable one.
//
// It is fetched per command through an injected function so the secret is held
// for the life of one session and never cached on a struct — and it is never
// logged, never audited and never returned by any handler (§8).
type Credential struct {
	Username   string
	Password   string
	PrivateKey string
	Passphrase string
}

// Gateway runs ONE already-validated read-only command on one device. Injecting
// it is what lets the whole collect path be tested with no network, and what
// keeps this package from holding ambient authority to reach devices (§5).
type Gateway interface {
	Run(ctx context.Context, dev Device, command string, maxBytes int64) (string, error)
}

// SSHGateway is the production Gateway.
type SSHGateway struct {
	// Credentials yields the diagnostics identity for a device. Required.
	Credentials func(ctx context.Context, dev Device) (Credential, error)
	// HostKeyCheck implements trust-on-first-use against the PLATFORM's pinned
	// fingerprint store. It returns (firstSeen, ok); ok=false means a recorded
	// fingerprint exists and DIFFERS — a possible MITM, and the command is
	// refused. Required: a nil check is a fail-closed error, never a bypass.
	HostKeyCheck func(addr, fingerprint string) (firstSeen, ok bool)
	// Dial opens the TCP connection. Optional: nil uses a bounded net.Dialer.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// DialTimeout bounds the dial + handshake; <= 0 uses DefaultDialTimeout.
	DialTimeout time.Duration
	// Port is the default SSH port when the device carries none.
	Port int
	// OnHostKey is an optional observability hook (first-seen pins are worth a
	// log line). It never decides anything.
	OnHostKey func(dev Device, fingerprint string, firstSeen bool)
}

// Run implements Gateway.
func (g *SSHGateway) Run(ctx context.Context, dev Device, command string, maxBytes int64) (string, error) {
	if g.Credentials == nil {
		return "", errors.New("protocoldiag: no diagnostics credentials configured")
	}
	if g.HostKeyCheck == nil {
		// Fail CLOSED. An absent host-key policy is not "trust everything".
		return "", errors.New("protocoldiag: no host-key verification configured — refusing to connect")
	}
	if dev.Address == "" {
		return "", ErrNoAddress
	}
	if maxBytes <= 0 || maxBytes > MaxOutputBytes {
		maxBytes = MaxOutputBytes
	}
	timeout := g.DialTimeout
	if timeout <= 0 {
		timeout = DefaultDialTimeout
	}
	port := dev.Port
	if port <= 0 {
		port = g.Port
	}
	if port <= 0 || port > 65535 {
		port = 22
	}
	addr := net.JoinHostPort(dev.Address, strconv.Itoa(port))

	cred, err := g.Credentials(ctx, dev)
	if err != nil {
		return "", fmt.Errorf("diagnostics credentials unavailable: %w", err)
	}
	if cred.Username == "" || (cred.Password == "" && cred.PrivateKey == "") {
		return "", errors.New("protocoldiag: diagnostics credentials are incomplete")
	}
	auth, err := sshAuthMethods(cred)
	if err != nil {
		return "", err
	}

	cfg := &ssh.ClientConfig{
		User: cred.Username,
		Auth: auth,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fp := Fingerprint(key)
			first, ok := g.HostKeyCheck(dev.Address, fp)
			if !ok {
				return fmt.Errorf("host key mismatch for %s (possible MITM) — recorded fingerprint differs", dev.Address)
			}
			if g.OnHostKey != nil {
				g.OnHostKey(dev, fp, first)
			}
			return nil
		},
		Timeout: timeout,
	}

	dial := g.Dial
	if dial == nil {
		d := &net.Dialer{Timeout: timeout}
		dial = d.DialContext
	}
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("connect: %w", err)
	}
	// A context deadline must be able to break a stuck handshake or read, so it
	// is pushed onto the socket rather than only wrapping the call (§9).
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl) // best-effort: an unsupported deadline still leaves the ctx watchdog below
	}
	closed := make(chan struct{})
	defer close(closed)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close() // unblocks any in-flight read/write
		case <-closed:
		}
	}()

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close() // best-effort: the handshake already failed
		return "", fmt.Errorf("ssh handshake: %w", err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("ssh session: %w", err)
	}
	defer session.Close()

	// No PTY and no stdin: this session can be read from, never typed into.
	out := &capWriter{max: maxBytes}
	session.Stdout = out
	session.Stderr = io.Discard // device chatter is not diagnostic output
	if err := session.Run(command); err != nil {
		if out.overflow {
			return "", ErrTooLarge
		}
		// A non-zero exit is an honest per-command failure. The collector records
		// it on that command and continues — it never invents output.
		return "", fmt.Errorf("command %q failed: %w", command, err)
	}
	if out.overflow {
		return "", ErrTooLarge
	}
	return out.String(), nil
}

// sshAuthMethods builds the offered SSH auth methods. Password is ALSO offered
// as keyboard-interactive because many network operating systems advertise only
// that method — the same reasoning (and the same fix) as the operator gateway.
func sshAuthMethods(cred Credential) ([]ssh.AuthMethod, error) {
	var auth []ssh.AuthMethod
	if cred.PrivateKey != "" {
		signer, err := parseSSHKey(cred.PrivateKey, cred.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("invalid diagnostics private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	}
	if cred.Password != "" {
		pw := cred.Password
		auth = append(auth, ssh.Password(pw))
		auth = append(auth, ssh.KeyboardInteractive(
			func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					answers[i] = pw
				}
				return answers, nil
			}))
	}
	if len(auth) == 0 {
		return nil, errors.New("protocoldiag: no usable diagnostics credential")
	}
	return auth, nil
}

func parseSSHKey(pem, passphrase string) (ssh.Signer, error) {
	if passphrase != "" {
		return ssh.ParsePrivateKeyWithPassphrase([]byte(pem), []byte(passphrase))
	}
	return ssh.ParsePrivateKey([]byte(pem))
}

// Fingerprint renders a host key the way the operator gateway records it, so all
// three paths compare the SAME string against the SAME pin.
func Fingerprint(key ssh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// capWriter is the byte cap (§9): it accepts up to max bytes and then refuses,
// so an endlessly-streaming device cannot grow the process's heap.
type capWriter struct {
	max      int64
	n        int64
	buf      []byte
	overflow bool
}

func (c *capWriter) Write(p []byte) (int, error) {
	if c.overflow {
		return 0, ErrTooLarge
	}
	if c.n+int64(len(p)) > c.max {
		c.overflow = true
		return 0, ErrTooLarge
	}
	c.buf = append(c.buf, p...)
	c.n += int64(len(p))
	return len(p), nil
}

func (c *capWriter) String() string { return string(c.buf) }

var _ Gateway = (*SSHGateway)(nil)
