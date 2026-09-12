// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bmp

// receiver_liveness_test.go — what happens when accept() fails, and what the
// read API says about it afterwards.
//
// The old loop retried only on a net.Error with Timeout(). No deadline is ever
// set on this listener, so that branch could never be reached: EVERY accept
// failure, including an EMFILE spike that would have cleared on its own, logged
// one warning and returned. The deferred shutdown then closed the socket for
// the rest of the process lifetime while every read still answered
// receiver_enabled: true and told the operator to go and configure a router.

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"
)

// opErr wraps an errno the way the runtime hands one back from accept().
func opErr(errno syscall.Errno) error {
	return &net.OpError{Op: "accept", Net: "tcp", Err: errno}
}

// TestTransientAcceptErrorsAreRetriedAndPermanentOnesAreNot pins the
// classification. An fd or buffer ceiling clears on its own; a closed socket
// never does.
func TestTransientAcceptErrorsAreRetriedAndPermanentOnesAreNot(t *testing.T) {
	transient := []error{
		opErr(syscall.EMFILE),
		opErr(syscall.ENFILE),
		opErr(syscall.ENOBUFS),
		opErr(syscall.ENOMEM),
		opErr(syscall.ECONNABORTED),
		opErr(syscall.EINTR),
	}
	for _, err := range transient {
		if !transientAcceptError(err) {
			t.Errorf("transientAcceptError(%v) = false — a receiver must ride this out, not die on it", err)
		}
	}
	permanent := []error{
		net.ErrClosed,
		&net.OpError{Op: "accept", Net: "tcp", Err: net.ErrClosed},
		opErr(syscall.EINVAL),
		opErr(syscall.EBADF),
	}
	for _, err := range permanent {
		if transientAcceptError(err) {
			t.Errorf("transientAcceptError(%v) = true — retrying a socket that will never accept again hides a dead receiver", err)
		}
	}
}

// TestAcceptFailureBacksOffThenGivesUpLoudly is the §9 half: bounded retries
// with a growing, jittered, capped pause, and then an honest death.
func TestAcceptFailureBacksOffThenGivesUpLoudly(t *testing.T) {
	l := NewListener(Deps{Now: time.Now}, nil)

	// A permanent error is never retried, whatever the retry count.
	if out := l.classifyAcceptFailure(net.ErrClosed, 0, 0); out.Retry {
		t.Fatal("a permanent accept error was scheduled for retry")
	} else if out.Reason == "" || out.Log == "" {
		t.Fatalf("a permanent accept failure said nothing to the operator: %+v", out)
	}

	// A transient one is retried, and the pause grows and is capped.
	var wait time.Duration
	for i := 0; i < MaxAcceptRetries; i++ {
		out := l.classifyAcceptFailure(opErr(syscall.EMFILE), i, wait)
		if !out.Retry {
			t.Fatalf("retry %d of %d gave up on a transient error", i, MaxAcceptRetries)
		}
		if out.Wait <= 0 {
			t.Fatalf("retry %d scheduled a zero pause — that is a CPU spin", i)
		}
		if out.Wait > MaxAcceptBackoff*2 {
			t.Fatalf("retry %d pause %v is unbounded (cap %v)", i, out.Wait, MaxAcceptBackoff)
		}
		wait = out.Wait
	}
	if wait < AcceptBackoff {
		t.Fatalf("the backoff never grew past the first pause: %v", wait)
	}

	// And it does not retry forever.
	out := l.classifyAcceptFailure(opErr(syscall.EMFILE), MaxAcceptRetries, wait)
	if out.Retry {
		t.Fatalf("the receiver retried past MaxAcceptRetries=%d — a receiver broken for hours must stop claiming to work", MaxAcceptRetries)
	}
	if out.Reason == "" {
		t.Fatal("giving up said nothing an operator could act on")
	}
}

// TestAPortDroppedUnderTheReceiverStopsTheStatusClaimingItIsUp is the honesty
// half, end to end: the accept loop dies on a permanent error and every read
// then reports the receiver as DOWN, with a sentence naming what to do.
func TestAPortDroppedUnderTheReceiverStopsTheStatusClaimingItIsUp(t *testing.T) {
	f := newListenerFixture(t, nil)

	// Before: the receiver is up and says so.
	if down, _ := f.api.Listener().Down(); down {
		t.Fatal("a freshly bound receiver reports itself down")
	}
	if !coverageReceiverEnabled(t, f) {
		t.Fatal("a listening receiver reported receiver_enabled: false")
	}

	// Close the bound socket from underneath the accept loop, exactly the way a
	// permanent accept failure presents. Nothing else is cancelled, so this is
	// the loop's own decision.
	ln := f.api.Listener()
	ln.mu.Lock()
	raw := ln.ln
	ln.mu.Unlock()
	if raw == nil {
		t.Fatal("the fixture's listener is not bound")
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close the bound socket: %v", err)
	}

	// The loop returns rather than spinning.
	select {
	case <-f.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the accept loop did not return after a permanent accept failure")
	}

	down, why := f.api.Listener().Down()
	if !down {
		t.Fatal("the receiver died and still reports itself as listening")
	}
	if why == "" {
		t.Fatal("the receiver reported itself down with no reason an operator could act on")
	}
	if !f.logs.contains("NO router feed will be received") {
		t.Fatalf("the death was not LOUD: %v", f.logs.lines)
	}

	// And the read API stops claiming a receiver that is not there.
	if coverageReceiverEnabled(t, f) {
		t.Fatal("the API still reports receiver_enabled: true after the receiver died")
	}
	body := coverageOf(t, f)
	notes, _ := body["notes"].([]any)
	if len(notes) == 0 {
		t.Fatalf("no note explains the dead receiver: %v", body)
	}
	if complete, _ := body["complete"].(bool); complete {
		t.Fatal("a feed nothing can reach was reported as complete")
	}
}

func coverageOf(t *testing.T, f *listenerFixture) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/bgp/bmp/stats", nil)
	r.Header.Set("X-Test-Cross", "1")
	f.api.Handler()(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET stats = %d (%s)", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	cov, ok := body["coverage"].(map[string]any)
	if !ok {
		t.Fatalf("no coverage block: %s", w.Body.String())
	}
	return cov
}

func coverageReceiverEnabled(t *testing.T, f *listenerFixture) bool {
	t.Helper()
	on, _ := coverageOf(t, f)["receiver_enabled"].(bool)
	return on
}
