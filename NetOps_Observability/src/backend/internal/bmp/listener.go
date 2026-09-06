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
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Listener terminates BMP sessions and folds them into a Store.
type Listener struct {
	deps  Deps
	store *Store

	mu       sync.Mutex
	ln       net.Listener
	seq      atomic.Uint64
	liveConn atomic.Int64
}

// NewListener builds the receiver over an already-validated Deps.
func NewListener(d Deps, store *Store) *Listener {
	return &Listener{deps: d, store: store}
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
		return
	}
	l.mu.Lock()
	l.ln = ln
	l.mu.Unlock()
	l.deps.LogInfo("BMP receiver listening", map[string]any{"listen": addr})

	// Closing the listener is what unblocks Accept on cancellation.
	stop := make(chan struct{})
	var closeOnce sync.Once
	shutdown := func() {
		closeOnce.Do(func() {
			close(stop)
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

	for {
		conn, aerr := ln.Accept()
		if aerr != nil {
			select {
			case <-stop:
				return
			default:
			}
			var ne net.Error
			if errors.As(aerr, &ne) && ne.Timeout() {
				// A transient accept failure must not spin the CPU.
				select {
				case <-stop:
					return
				case <-time.After(AcceptBackoff):
					continue
				}
			}
			l.deps.LogWarn("BMP accept failed", map[string]any{"error": aerr.Error()})
			return
		}
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
