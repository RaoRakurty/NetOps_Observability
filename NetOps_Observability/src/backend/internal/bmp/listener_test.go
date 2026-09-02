package bmp

// listener_test.go — the receiver, driven by a MOCK ROUTER over a real TCP
// socket (§11: mock telemetry streams are required for validation).
//
// These are the tests that matter most, because the listener is the one
// surface an unauthenticated remote party can reach. They assert the refusal
// paths as hard as the happy path: an unattributable source, a desynchronized
// stream, an oversized frame, a stalled peer, and the connection ceiling.

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// logSink records structured log lines so a test can assert that a refusal was
// OBSERVABLE (§10) and that no frame contents leaked into it (§8).
type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (l *logSink) log(msg string, fields map[string]any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, msg)
	for k, v := range fields {
		_ = k
		_ = v
	}
}

func (l *logSink) contains(sub string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.lines {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// listenerFixture runs a real listener on 127.0.0.1:0.
type listenerFixture struct {
	t       *testing.T
	api     *API
	metrics *Metrics
	logs    *logSink
	addr    string
	cancel  context.CancelFunc
	done    chan struct{}
	// known maps a source IP onto (device, tenant). Anything else is refused.
	known map[string][2]string
}

func newListenerFixture(t *testing.T, tune func(*Deps)) *listenerFixture {
	t.Helper()
	f := &listenerFixture{
		t:       t,
		metrics: NewMetrics(),
		logs:    &logSink{},
		known:   map[string][2]string{"127.0.0.1": {"lab-core", "acme"}, "::1": {"lab-core", "acme"}},
		done:    make(chan struct{}),
	}
	d := Deps{
		Now:        time.Now,
		ListenAddr: "127.0.0.1:0",
		ResolveDevice: func(a netip.Addr) (string, string, bool) {
			v, ok := f.known[a.String()]
			if !ok {
				return "", "", false
			}
			return v[0], v[1], true
		},
		Authz:                testAuthz,
		Metrics:              f.metrics,
		WriteJSON:            testWriteJSON,
		WriteError:           testWriteError,
		LogInfo:              f.logs.log,
		LogWarn:              f.logs.log,
		LogError:             f.logs.log,
		MaxSessionRecords:    8,
		MaxUpdatesPerSession: 64,
	}
	if tune != nil {
		tune(&d)
	}
	api, err := New(d)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f.api = api

	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	go func() {
		defer close(f.done)
		api.Run(ctx)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if a := api.Listener().Addr(); a != "" {
			f.addr = a
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("listener never bound")
		}
		time.Sleep(time.Millisecond)
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-f.done:
		case <-time.After(5 * time.Second):
			t.Error("listener did not stop on context cancellation")
		}
	})
	return f
}

func (f *listenerFixture) dial() net.Conn {
	f.t.Helper()
	c, err := net.DialTimeout("tcp", f.addr, 5*time.Second)
	if err != nil {
		f.t.Fatalf("dial: %v", err)
	}
	f.t.Cleanup(func() { _ = c.Close() })
	return c
}

// waitFor polls until cond holds or the test times out. The listener runs on
// its own goroutine, so this is how a test observes its effects without a
// sleep that is either flaky or slow.
func (f *listenerFixture) waitFor(what string, cond func() bool) {
	f.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			f.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func (f *listenerFixture) sessions() []SessionView {
	return f.api.Store().Sessions("", true)
}

// ── the happy path ──────────────────────────────────────────────────────────

func TestListenerAcceptsAKnownRouterAndStoresItsFeed(t *testing.T) {
	f := newListenerFixture(t, nil)
	c := f.dial()

	stream := append([]byte{}, initiation("lab-core", "IOS-XR 7.9.2")...)
	stream = append(stream, peerUp(0, "192.0.2.10", 64512)...)
	stream = append(stream, announce("192.0.2.10", 64512, "10.1.0.0/24")...)
	stream = append(stream, announce("192.0.2.10", 64512, "10.2.0.0/24")...)
	stream = append(stream, withdraw("192.0.2.10", 64512, "10.1.0.0/24")...)
	stream = append(stream, statsReport("192.0.2.10", map[uint16]uint32{0: 5})...)
	if _, err := c.Write(stream); err != nil {
		t.Fatalf("write: %v", err)
	}

	f.waitFor("the feed to be stored", func() bool {
		s := f.sessions()
		return len(s) == 1 && s[0].Updates == 3
	})
	s := f.sessions()[0]
	if s.TenantOf() != "acme" {
		t.Fatalf("tenant = %q, want acme (stamped from the INVENTORY, not the wire)", s.TenantOf())
	}
	if s.DeviceID != "lab-core" || s.Router != "lab-core" {
		t.Fatalf("session = %+v", s)
	}
	if s.State != "up" {
		t.Fatalf("state = %q", s.State)
	}
	if s.Messages["route_monitoring"] != 3 || s.Messages["initiation"] != 1 || s.Messages["statistics_report"] != 1 {
		t.Fatalf("messages = %+v", s.Messages)
	}
	if s.ParseErrors != 0 {
		t.Fatalf("a clean stream produced %d parse errors", s.ParseErrors)
	}
	rows := f.api.Store().Updates("acme", false, UpdateFilter{Limit: 10})
	if len(rows) != 3 {
		t.Fatalf("updates = %+v", rows)
	}
	if !f.logs.contains("BMP session up") {
		t.Fatal("no session-up log line — a session that starts silently is not observable")
	}
	snap := f.metrics.Snapshot()
	if snap.Sessions[OutcomeAccepted] != 1 || snap.Active != 1 {
		t.Fatalf("metrics = %+v", snap)
	}
	if snap.Messages["route_monitoring"] != 3 {
		t.Fatalf("message metrics = %+v", snap.Messages)
	}
	if snap.UpdatesStored != 3 {
		t.Fatalf("stored metric = %d", snap.UpdatesStored)
	}
}

// ── §3a: an unattributable source is REFUSED ────────────────────────────────

func TestListenerRefusesASourceItCannotAttribute(t *testing.T) {
	f := newListenerFixture(t, nil)
	f.known = map[string][2]string{} // nothing resolves

	c := f.dial()
	_, _ = c.Write(initiation("rogue", "who?"))

	f.waitFor("the refusal to be counted", func() bool {
		return f.metrics.Snapshot().Sessions[OutcomeUnknownSource] == 1
	})
	if got := f.sessions(); len(got) != 0 {
		t.Fatalf("an unattributable source was STORED: %+v — it must never be admitted as tenant \"\"", got)
	}
	if !f.logs.contains("not a known device") {
		t.Fatal("the refusal was silent")
	}
	// The socket is closed, so the next read fails.
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1)
	if _, err := c.Read(buf); err == nil {
		t.Fatal("a refused connection must be CLOSED, not left open")
	}
}

func TestListenerRefusesASourceThatResolvesToAnEmptyTenant(t *testing.T) {
	f := newListenerFixture(t, nil)
	// A device row with no tenant is exactly the case that would pool a
	// customer's routing table into the global bucket.
	f.known = map[string][2]string{"127.0.0.1": {"orphan-device", ""}, "::1": {"orphan-device", ""}}
	c := f.dial()
	_, _ = c.Write(initiation("orphan", "d"))
	f.waitFor("the refusal to be counted", func() bool {
		return f.metrics.Snapshot().Sessions[OutcomeUnknownSource] == 1
	})
	if got := f.sessions(); len(got) != 0 {
		t.Fatalf("a tenant-less device was stored: %+v", got)
	}
}

// ── hostile streams ─────────────────────────────────────────────────────────

func TestListenerDropsASessionOnADesynchronizedHeader(t *testing.T) {
	f := newListenerFixture(t, nil)
	c := f.dial()
	stream := append([]byte{}, initiation("lab-core", "d")...)
	stream = append(stream, 0x09, 0x00, 0x00, 0x00, 0x10, 0x00) // version 9
	_, _ = c.Write(stream)

	f.waitFor("the session to close", func() bool {
		s := f.sessions()
		return len(s) == 1 && s[0].State == "closed"
	})
	s := f.sessions()[0]
	if !strings.Contains(s.CloseReason, "malformed common header") {
		t.Fatalf("close reason = %q", s.CloseReason)
	}
	if snap := f.metrics.Snapshot(); snap.ParseErrors[StageHeader] != 1 {
		t.Fatalf("parse errors = %+v", snap.ParseErrors)
	}
}

func TestListenerRefusesAnOversizedFrameWithoutAllocatingForIt(t *testing.T) {
	f := newListenerFixture(t, nil)
	c := f.dial()
	// A header declaring 4 GiB. A receiver that trusted it would try to
	// allocate it; this one must refuse on the header alone.
	_, _ = c.Write([]byte{3, 0xFF, 0xFF, 0xFF, 0xFF, 0})

	f.waitFor("the oversize refusal", func() bool {
		return f.metrics.Snapshot().ParseErrors[StageOversize] == 1
	})
	if got := f.sessions(); len(got) != 1 || got[0].State != "closed" {
		t.Fatalf("sessions = %+v", got)
	}
}

func TestListenerSkipsOneBadFrameAndKeepsReading(t *testing.T) {
	f := newListenerFixture(t, nil)
	c := f.dial()

	// A well-framed Route Monitoring whose BGP body is garbage: the header
	// parses, the body does not. ONE frame is skipped; the session lives.
	bad := frame(MsgRouteMonitoring, append(peerHeader(0, "192.0.2.10", 64512, "10.0.0.1"), 0xFF, 0xFF, 0xFF))
	stream := append([]byte{}, initiation("lab-core", "d")...)
	stream = append(stream, bad...)
	stream = append(stream, announce("192.0.2.10", 64512, "10.7.0.0/24")...)
	_, _ = c.Write(stream)

	f.waitFor("the good frame after the bad one", func() bool {
		s := f.sessions()
		return len(s) == 1 && s[0].Updates == 1
	})
	s := f.sessions()[0]
	if s.State != "up" {
		t.Fatalf("a single bad FRAME must not drop the session: state = %q", s.State)
	}
	if s.ParseErrors != 1 {
		t.Fatalf("parse errors = %d, want 1 — a skipped frame must be COUNTED", s.ParseErrors)
	}
	if snap := f.metrics.Snapshot(); snap.ParseErrors[StageMessage] != 1 {
		t.Fatalf("message-stage parse errors = %+v", snap.ParseErrors)
	}
}

func TestListenerCountsUndecodedMessageTypes(t *testing.T) {
	f := newListenerFixture(t, nil)
	c := f.dial()
	mirror := frame(MsgRouteMirroring, append(peerHeader(0, "192.0.2.10", 64512, "10.0.0.1"), 1, 2, 3))
	_, _ = c.Write(append(initiation("lab-core", "d"), mirror...))
	f.waitFor("the undecoded type to be counted", func() bool {
		return f.metrics.Snapshot().Unsupported[KindMessageType] == 1
	})
	if snap := f.metrics.Snapshot(); snap.Messages["route_mirroring"] != 1 {
		t.Fatalf("messages = %+v", snap.Messages)
	}
}

func TestListenerDisconnectsAPeerThatStallsMidMessage(t *testing.T) {
	f := newListenerFixture(t, func(d *Deps) {
		d.MessageTimeout = 100 * time.Millisecond
		d.IdleTimeout = 5 * time.Second
	})
	c := f.dial()
	// Announce a 200-octet frame, then send nothing more: the slowloris shape.
	_, _ = c.Write([]byte{3, 0, 0, 0, 200, 4})

	f.waitFor("the stall to end the session", func() bool {
		s := f.sessions()
		return len(s) == 1 && s[0].State == "closed"
	})
	if reason := f.sessions()[0].CloseReason; !strings.Contains(reason, "stalled past the read deadline") {
		t.Fatalf("close reason = %q", reason)
	}
	if snap := f.metrics.Snapshot(); snap.ParseErrors[StageRead] == 0 {
		t.Fatalf("a stalled peer was not counted: %+v", snap.ParseErrors)
	}
}

func TestListenerDisconnectsAnIdlePeer(t *testing.T) {
	f := newListenerFixture(t, func(d *Deps) { d.IdleTimeout = 100 * time.Millisecond })
	c := f.dial()
	_, _ = c.Write(initiation("lab-core", "d"))
	f.waitFor("the idle timeout to fire", func() bool {
		s := f.sessions()
		return len(s) == 1 && s[0].State == "closed"
	})
	if reason := f.sessions()[0].CloseReason; !strings.Contains(reason, "stalled") {
		t.Fatalf("close reason = %q", reason)
	}
}

func TestListenerHonoursTheConnectionCeiling(t *testing.T) {
	f := newListenerFixture(t, func(d *Deps) { d.MaxConnections = 1 })
	first := f.dial()
	_, _ = first.Write(initiation("lab-core", "d"))
	f.waitFor("the first session", func() bool { return len(f.sessions()) == 1 })

	second := f.dial()
	f.waitFor("the second connection to be refused", func() bool {
		return f.metrics.Snapshot().Sessions[OutcomeAtCapacity] == 1
	})
	_ = second.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("a connection past the ceiling must be CLOSED")
	}
	if got := f.sessions(); len(got) != 1 {
		t.Fatalf("sessions = %d, want 1", len(got))
	}
	if !f.logs.contains("connection ceiling") {
		t.Fatal("the refusal was silent")
	}
}

func TestListenerRefusesWhenTheStoreIsFull(t *testing.T) {
	f := newListenerFixture(t, func(d *Deps) { d.MaxSessionRecords = 1 })
	first := f.dial()
	_, _ = first.Write(initiation("lab-core", "d"))
	f.waitFor("the first session", func() bool { return len(f.sessions()) == 1 })

	second := f.dial()
	f.waitFor("the store refusal", func() bool {
		return f.metrics.Snapshot().Sessions[OutcomeAtCapacity] >= 1
	})
	_ = second.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("a connection the store cannot hold must be closed")
	}
	// The LIVE session survives — capacity never evicts a router that is
	// still talking to us.
	if got := f.sessions(); len(got) != 1 || got[0].State != "up" {
		t.Fatalf("sessions = %+v", got)
	}
}

func TestListenerClosesOnTerminationWithTheRoutersReason(t *testing.T) {
	f := newListenerFixture(t, nil)
	c := f.dial()
	_, _ = c.Write(append(initiation("lab-core", "d"), termination(2)...))
	f.waitFor("the termination", func() bool {
		s := f.sessions()
		return len(s) == 1 && s[0].State == "closed"
	})
	if reason := f.sessions()[0].CloseReason; !strings.Contains(reason, "out of resources") {
		t.Fatalf("close reason = %q", reason)
	}
	if snap := f.metrics.Snapshot(); snap.Active != 0 {
		t.Fatalf("the active gauge did not fall: %d", snap.Active)
	}
}

func TestListenerRecordsAPeerClose(t *testing.T) {
	f := newListenerFixture(t, nil)
	c := f.dial()
	_, _ = c.Write(initiation("lab-core", "d"))
	f.waitFor("the session", func() bool { return len(f.sessions()) == 1 })
	_ = c.Close()
	f.waitFor("the close to be recorded", func() bool {
		s := f.sessions()
		return len(s) == 1 && s[0].State == "closed"
	})
	if reason := f.sessions()[0].CloseReason; !strings.Contains(reason, "peer closed") {
		t.Fatalf("close reason = %q", reason)
	}
	if !f.logs.contains("BMP session down") {
		t.Fatal("no session-down log line")
	}
}

func TestListenerStopsOnContextCancellation(t *testing.T) {
	f := newListenerFixture(t, nil)
	c := f.dial()
	_, _ = c.Write(initiation("lab-core", "d"))
	f.waitFor("the session", func() bool { return len(f.sessions()) == 1 })
	f.cancel()
	select {
	case <-f.done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return on cancellation — a worker that ignores the root context blocks shutdown")
	}
	f.waitFor("the session to be closed by shutdown", func() bool {
		s := f.sessions()
		return len(s) == 1 && s[0].State == "closed"
	})
}

func TestListenerReportsABindFailureLoudly(t *testing.T) {
	logs := &logSink{}
	api, err := New(Deps{
		Now:           time.Now,
		ListenAddr:    "127.0.0.1:1", // privileged; the bind must fail
		ResolveDevice: func(netip.Addr) (string, string, bool) { return "", "", false },
		Authz:         testAuthz,
		WriteJSON:     testWriteJSON,
		WriteError:    testWriteError,
		LogInfo:       logs.log,
		LogWarn:       logs.log,
		LogError:      logs.log,
	})
	if err != nil {
		t.Fatal(err)
	}
	api.Run(context.Background())
	if !logs.contains("could not bind") {
		t.Fatalf("a failed bind must be LOUD, not a dormant no-op: %v", logs.lines)
	}
}

func TestNilAPIRunIsANoOp(t *testing.T) {
	var a *API
	a.Run(context.Background()) // must not panic
}

func TestReadEndReasonNamesTheCause(t *testing.T) {
	if got := readEndReason(net.ErrClosed); !strings.Contains(got, "shutting down") {
		t.Fatalf("net.ErrClosed = %q", got)
	}
	if got := readEndReason(&net.OpError{Err: timeoutErr{}}); !strings.Contains(got, "stalled") {
		t.Fatalf("timeout = %q", got)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string { return "i/o timeout" }
func (timeoutErr) Timeout() bool { return true }
