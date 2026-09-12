// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bmp

// listener.go — the TCP receiver.
//
// The shape is deliberately boring, because this is the one surface an
// unauthenticated remote party can reach:
//
//	accept → resolve the source against the inventory (REJECT if unknown)
//	       → bounded per-connection reader with two deadlines
//	       → parse one frame → fold it into the store → repeat
//
// Nothing here allocates on a peer-supplied length, nothing blocks without a
// deadline, and no failure path is silent: every rejection, parse error and
// disconnect increments a counter and (for session-level events) writes ONE
// structured log line. Frame CONTENTS are never logged — a BMP feed carries a
// customer's routing table.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// receiverState is the receiver's OWN account of whether it is listening. It
// exists because "the routes are registered" and "a router can reach us" are
// two different facts, and the read API used to report the first as if it were
// the second: after the accept loop returned, the listener was closed for the
// process lifetime while every response still said receiver_enabled: true and
// told the operator to go and configure a router.
type receiverState int32

const (
	// receiverIdle — built, but Run has not bound yet. This is also the state of
	// a module whose Run is never called, which is what the read-surface tests
	// hold; it is not a failure and is not reported as one.
	receiverIdle receiverState = iota
	// receiverListening — a bound socket is accepting.
	receiverListening
	// receiverStopped — the context was cancelled. The process is going down.
	receiverStopped
	// receiverFailed — the bind was refused, or the accept loop died. NOTHING
	// will be received until the process is restarted, and every read says so.
	receiverFailed
)

// Listener terminates BMP sessions and folds them into a Store.
type Listener struct {
	deps  Deps
	store *Store

	mu       sync.Mutex
	ln       net.Listener
	seq      atomic.Uint64
	liveConn atomic.Int64

	state  atomic.Int32   // receiverState
	reason atomic.Value   // string: why it is not listening
	rnd    func() float64 // backoff jitter
}

// NewListener builds the receiver over an already-validated Deps.
func NewListener(d Deps, store *Store) *Listener {
	// #nosec G404 -- jitter for a retry backoff, not a security decision: this
	// value never authenticates, authorizes, seeds a key or names a resource
	// (the bgpwatch.NewEvaluator precedent).
	rng := rand.New(rand.NewSource(d.Now().UnixNano()))
	var mu sync.Mutex
	return &Listener{deps: d, store: store,
		rnd: func() float64 { mu.Lock(); defer mu.Unlock(); return rng.Float64() }}
}

// setState records what the receiver is doing and why, so a read can report it
// instead of guessing.
func (l *Listener) setState(st receiverState, reason string) {
	l.reason.Store(reason)
	l.state.Store(int32(st))
}

// Down reports whether the receiver is NOT listening, and why. It is false for
// a receiver that has simply not been started (a read-only assembly), because
// that is not a failure to report to an operator.
func (l *Listener) Down() (bool, string) {
	if l == nil {
		return false, ""
	}
	switch receiverState(l.state.Load()) {
	case receiverStopped, receiverFailed:
		reason, _ := l.reason.Load().(string)
		return true, reason
	case receiverIdle, receiverListening:
		return false, ""
	default:
		return false, ""
	}
}

// acceptBackoff grows the pause between retries, jittered, and caps it.
func (l *Listener) acceptBackoff(prev time.Duration) time.Duration {
	next := prev * 2
	if next < AcceptBackoff {
		next = AcceptBackoff
	}
	if next > MaxAcceptBackoff {
		next = MaxAcceptBackoff
	}
	jitter := 1.0
	if l.rnd != nil {
		jitter = 0.75 + 0.5*l.rnd()
	}
	return time.Duration(float64(next) * jitter)
}

// acceptOutcome is the decision about ONE accept() failure. It is a value
// rather than a branch inside the loop so the rule can be tested directly: a
// receiver's behaviour under fd exhaustion is not something to find out in
// production.
type acceptOutcome struct {
	// Retry says whether the loop keeps going, after Wait.
	Retry bool
	Wait  time.Duration
	// Log and Reason are filled in only when Retry is false: the log line for
	// the operator's console, and the sentence every read response carries.
	Log    string
	Reason string
}

// classifyAcceptFailure decides what one accept() failure means. retries is how
// many CONSECUTIVE transient failures have already been ridden out, prev the
// last pause.
func (l *Listener) classifyAcceptFailure(err error, retries int, prev time.Duration) acceptOutcome {
	if !transientAcceptError(err) {
		return acceptOutcome{
			Log:    "BMP receiver stopped accepting and will NOT recover — NO router feed will be received until the platform is restarted",
			Reason: "The BMP receiver stopped accepting connections and cannot recover, so no router feed is being received. Restart the platform.",
		}
	}
	if retries >= MaxAcceptRetries {
		return acceptOutcome{
			Log:    "BMP receiver could not accept a connection after repeated retries — NO router feed will be received until the platform is restarted",
			Reason: "The BMP receiver has been unable to accept connections for a sustained period, which usually means the platform has run out of file descriptors. No router feed is being received. Restart the platform.",
		}
	}
	return acceptOutcome{Retry: true, Wait: l.acceptBackoff(prev)}
}

// transientAcceptError reports whether an accept() failure is one the receiver
// can ride out. The kernel errors below mean "not right now" — a file-descriptor
// or buffer ceiling, a connection the peer aborted between SYN and accept, a
// signal — and they clear on their own. Everything else (a closed or revoked
// socket, an unrecognised failure) is treated as PERMANENT, because a receiver
// that quietly retries a socket it can never accept on again is a receiver that
// is down while claiming to be up.
//
// The old test was `net.Error.Timeout()`, and it was DEAD CODE: no deadline is
// ever set on this listener, so Accept never returns a timeout. It is kept in
// the set anyway, ahead of the errno checks, because a future deadline would be
// a transient condition and this is where that answer belongs.
func transientAcceptError(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	for _, errno := range []syscall.Errno{
		syscall.EMFILE,  // this process is out of file descriptors
		syscall.ENFILE,  // the machine is out of file descriptors
		syscall.ENOBUFS, // no buffer space
		syscall.ENOMEM,  // no memory for the socket
		syscall.ECONNABORTED,
		syscall.EINTR,
	} {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}

// Run binds the listen address and serves until ctx is cancelled. It is the
// tracked-worker entry point: it returns only when the context is done or the
// bind fails, and it closes every live connection on the way out.
//
// A bind failure is LOUD and terminal for the module: the operator asked for a
// BMP receiver, and a receiver that silently never bound would look exactly
// like a network where no router has been configured yet.
func (l *Listener) Run(ctx context.Context) {
	addr := l.deps.ListenAddr
	if addr == "" {
		addr = DefaultListen
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		l.deps.LogError("BMP receiver could not bind — NO router feed will be received", map[string]any{
			"listen": addr,
			"error":  err.Error(),
		})
		l.setState(receiverFailed, "The BMP receiver could not bind "+addr+", so no router feed is being received. Restart the platform once the address is free.")
		return
	}
	l.mu.Lock()
	l.ln = ln
	l.mu.Unlock()
	l.setState(receiverListening, "")
	l.deps.LogInfo("BMP receiver listening", map[string]any{"listen": addr})

	// Closing the listener is what unblocks Accept on cancellation.
	stop := make(chan struct{})
	var closeOnce sync.Once
	shutdown := func() {
		closeOnce.Do(func() {
			close(stop)
			// A receiver that failed keeps that reason; a clean stop replaces an
			// idle/listening state with the honest "not listening any more".
			if receiverState(l.state.Load()) != receiverFailed {
				l.setState(receiverStopped, "The BMP receiver has shut down, so no router feed is being received.")
			}
			if cerr := ln.Close(); cerr != nil {
				l.deps.LogWarn("BMP listener close failed", map[string]any{"error": cerr.Error()})
			}
		})
	}
	go func() {
		<-ctx.Done()
		shutdown()
	}()
	defer shutdown()

	var conns sync.WaitGroup
	defer conns.Wait()

	// Consecutive transient accept failures. A successful accept resets both,
	// so a single EMFILE spike costs one backoff and nothing else.
	retries, backoff := 0, time.Duration(0)
	for {
		conn, aerr := ln.Accept()
		if aerr != nil {
			select {
			case <-stop:
				return
			default:
			}
			l.deps.Metrics.Session(OutcomeAcceptFailed)
			out := l.classifyAcceptFailure(aerr, retries, backoff)
			if !out.Retry {
				// Die LOUDLY, and tell the READS, so the API stops offering a
				// receiver that is not there (§10: no silent failures).
				l.deps.LogError(out.Log, map[string]any{
					"listen":  addr,
					"error":   aerr.Error(),
					"retries": retries,
				})
				l.setState(receiverFailed, out.Reason)
				return
			}
			retries++
			backoff = out.Wait
			// One line PER RETRY is bounded by MaxAcceptRetries, and the backoff
			// spreads them, so a wedged listener is visible without becoming the
			// log volume it is reporting on.
			l.deps.LogWarn("BMP accept failed — retrying", map[string]any{
				"listen":  addr,
				"error":   aerr.Error(),
				"retry":   retries,
				"backoff": backoff.String(),
			})
			select {
			case <-stop:
				return
			case <-time.After(backoff):
				continue
			}
		}
		retries, backoff = 0, 0
		if l.liveConn.Load() >= int64(l.maxConns()) {
			l.deps.Metrics.Session(OutcomeAtCapacity)
			l.deps.LogWarn("BMP connection refused — receiver at its connection ceiling", map[string]any{
				"remote": remoteHost(conn),
				"max":    l.maxConns(),
			})
			closeQuietly(conn)
			continue
		}
		l.liveConn.Add(1)
		conns.Add(1)
		go func() {
			defer conns.Done()
			defer l.liveConn.Add(-1)
			l.serve(ctx, conn)
		}()
	}
}

func (l *Listener) maxConns() int {
	if l.deps.MaxConnections > 0 {
		return l.deps.MaxConnections
	}
	return MaxConnections
}

// Addr reports the bound address (useful to tests that bind :0). It returns ""
// before Run has bound.
func (l *Listener) Addr() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ln == nil {
		return ""
	}
	return l.ln.Addr().String()
}

func closeQuietly(c net.Conn) { _ = c.Close() } // the peer is being refused; a close error changes nothing

// remoteHost renders a connection's remote address for a log field.
func remoteHost(c net.Conn) string {
	if c == nil || c.RemoteAddr() == nil {
		return ""
	}
	return c.RemoteAddr().String()
}

// serve runs ONE BMP session: attribute it, then read frames until the peer
// stops, misbehaves, or the context is cancelled.
func (l *Listener) serve(ctx context.Context, conn net.Conn) {
	defer closeQuietly(conn)

	remote := remoteHost(conn)
	ap, aerr := netip.ParseAddrPort(remote)
	if aerr != nil {
		l.deps.Metrics.Session(OutcomeBadAddress)
		l.deps.LogWarn("BMP connection refused — unusable remote address", map[string]any{"remote": remote})
		return
	}
	addr := ap.Addr().Unmap()

	// §3a: the tenant comes from the INVENTORY, never from the wire. A source we
	// cannot attribute is closed, not admitted as tenant "".
	deviceID, tenant, ok := l.deps.ResolveDevice(addr)
	if !ok || tenant == "" {
		l.deps.Metrics.Session(OutcomeUnknownSource)
		l.deps.LogWarn("BMP connection refused — source address is not a known device", map[string]any{
			"remote_ip": addr.String(),
		})
		return
	}

	id := "bmp-" + strconv.FormatUint(l.seq.Add(1), 10)
	if err := l.store.Open(id, tenant, deviceID, remote); err != nil {
		l.deps.Metrics.Session(OutcomeAtCapacity)
		l.deps.LogWarn("BMP connection refused — session store is at capacity", map[string]any{
			"device": deviceID,
			"error":  err.Error(),
		})
		return
	}
	l.deps.Metrics.Session(OutcomeAccepted)
	l.deps.Metrics.SessionOpened()
	l.deps.LogInfo("BMP session up", map[string]any{
		"session": id,
		"device":  deviceID,
		"tenant":  tenant,
	})

	// Cancellation reaches a blocked read by closing the socket.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			closeQuietly(conn)
		case <-done:
		}
	}()

	reason := l.readLoop(conn, id)

	l.store.Close(id, reason)
	l.deps.Metrics.SessionClosed()
	l.deps.LogInfo("BMP session down", map[string]any{
		"session": id,
		"device":  deviceID,
		"tenant":  tenant,
		"reason":  reason,
	})
}

// readLoop consumes frames until the session ends, returning the operator-
// readable reason it ended.
func (l *Listener) readLoop(conn net.Conn, id string) string {
	br := bufio.NewReaderSize(conn, 64*1024)
	hdr := make([]byte, CommonHeaderLen)
	// One reusable frame buffer per session, grown at most to MaxMessageSize.
	// It is never sized from a peer-supplied length beyond that ceiling.
	body := make([]byte, 0, 8*1024)

	idle := l.idleTimeout()
	msgTimeout := l.messageTimeout()

	for {
		if err := conn.SetReadDeadline(l.deps.Now().Add(idle)); err != nil {
			l.deps.Metrics.ParseError(StageRead)
			return "set read deadline failed"
		}
		if _, err := io.ReadFull(br, hdr); err != nil {
			if errors.Is(err, io.EOF) {
				return "peer closed"
			}
			if errors.Is(err, io.ErrUnexpectedEOF) {
				l.deps.Metrics.ParseError(StageHeader)
				return "truncated common header"
			}
			l.deps.Metrics.ParseError(StageRead)
			return readEndReason(err)
		}
		h, err := ParseHeader(hdr)
		if err != nil {
			// A bad header means the stream is desynchronized: there is no safe
			// resynchronization point in BMP, so the session is dropped rather
			// than read on as garbage.
			stage := StageHeader
			if errors.Is(err, ErrLength) {
				stage = StageOversize
			}
			l.deps.Metrics.ParseError(stage)
			l.store.RecordParseError(id)
			return "malformed common header: " + err.Error()
		}
		rest := int(h.Length) - CommonHeaderLen
		if cap(body) < rest {
			body = make([]byte, rest)
		}
		body = body[:rest]
		if rest > 0 {
			if derr := conn.SetReadDeadline(l.deps.Now().Add(msgTimeout)); derr != nil {
				l.deps.Metrics.ParseError(StageRead)
				return "set read deadline failed"
			}
			if _, rerr := io.ReadFull(br, body); rerr != nil {
				l.deps.Metrics.ParseError(StageRead)
				l.store.RecordParseError(id)
				return readEndReason(rerr)
			}
		}
		frame := make([]byte, 0, CommonHeaderLen+rest)
		frame = append(frame, hdr...)
		frame = append(frame, body...)

		msg, perr := ParseMessage(frame)
		if perr != nil {
			// ONE frame is skipped; the session continues. This is the case the
			// counters exist for — a feed with parse errors is not a healthy
			// feed, and the session view says so.
			l.deps.Metrics.ParseError(StageMessage)
			l.deps.Metrics.Message(h.Type)
			l.store.RecordParseError(id)
			continue
		}
		l.deps.Metrics.Message(h.Type)
		if !decodable(h.Type) {
			l.deps.Metrics.Unsupported(KindMessageType, 1)
		}
		applied := l.store.Apply(id, msg)
		if l.deps.OnAnnounce != nil && len(applied.Announced) > 0 {
			// Outside the store lock, on this session's own goroutine: an
			// observer that misbehaves degrades one feed, never the store.
			l.deps.OnAnnounce(applied.Announced)
		}
		l.deps.Metrics.UpdatesStored(applied.StoredUpdates)
		l.deps.Metrics.UpdatesDropped(applied.DroppedUpdates)
		l.deps.Metrics.Unsupported(KindAddressFamily, applied.UnsupportedFamilies)
		l.deps.Metrics.Unsupported(KindPathAttribute, applied.UnknownAttributes)

		if msg.Termination != nil {
			return terminationReason(msg.Termination)
		}
	}
}

// decodable reports whether this receiver actually interprets a message type.
func decodable(t MsgType) bool {
	switch t {
	case MsgRouteMonitoring, MsgStatisticsReport, MsgPeerDown, MsgPeerUp, MsgInitiation, MsgTermination:
		return true
	default:
		return false
	}
}

// terminationReason renders RFC 7854 §4.5 reason codes.
func terminationReason(t *Termination) string {
	if t == nil || !t.HasReason {
		return "router terminated the session"
	}
	switch t.ReasonCode {
	case 0:
		return "router terminated: administratively closed"
	case 1:
		return "router terminated: unspecified reason"
	case 2:
		return "router terminated: out of resources"
	case 3:
		return "router terminated: redundant connection"
	case 4:
		return "router terminated: permanently administratively closed"
	default:
		return "router terminated: reason code " + strconv.FormatUint(uint64(t.ReasonCode), 10)
	}
}

// readEndReason turns a read failure into an operator-readable phrase without
// leaking socket internals into the session record.
func readEndReason(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "peer stalled past the read deadline"
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "peer closed mid-message"
	}
	if errors.Is(err, net.ErrClosed) {
		return "receiver shutting down"
	}
	return fmt.Sprintf("read failed: %v", err)
}

func (l *Listener) idleTimeout() time.Duration {
	if l.deps.IdleTimeout > 0 {
		return l.deps.IdleTimeout
	}
	return IdleTimeout
}

func (l *Listener) messageTimeout() time.Duration {
	if l.deps.MessageTimeout > 0 {
		return l.deps.MessageTimeout
	}
	return MessageTimeout
}
