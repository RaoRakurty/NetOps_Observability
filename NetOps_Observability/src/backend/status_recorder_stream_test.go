// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A streamed response must reach the client through the logging + audit
// wrappers: http.ResponseController's Flush and SetWriteDeadline have to find
// the real connection (statusRecorder.Unwrap). Proven over a real socket —
// the first line arrives while the handler is still running.
func TestStreamingPassesThroughTheMiddleware(t *testing.T) {
	release := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		if err := rc.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Errorf("SetWriteDeadline did not reach the connection: %v", err)
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("first\n")) // discard: a write failure fails the read below
		if err := rc.Flush(); err != nil {
			t.Errorf("Flush did not reach the connection: %v", err)
		}
		<-release
		_, _ = w.Write([]byte("second\n")) // discard: same
	})
	srv := httptest.NewServer(withLogging(&statusRecorderProbe{h}))
	defer srv.Close()
	defer close(release) // unblock the handler whatever happens below (runs before srv.Close)
	type got struct {
		line string
		err  error
	}
	first := make(chan got, 1)
	go func() {
		// The whole request runs here: without a flush even the response
		// headers are held back, so http.Get itself would block.
		resp, err := http.Get(srv.URL)
		if err != nil {
			first <- got{"", err}
			return
		}
		defer resp.Body.Close()
		line, err := bufio.NewReader(resp.Body).ReadString('\n')
		first <- got{line, err}
	}()
	select {
	case g := <-first:
		if g.err != nil || strings.TrimSpace(g.line) != "first" {
			t.Fatalf("first line: %q %v", g.line, g.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the first line did not arrive while the handler was still running — the response is buffered (statusRecorder.Unwrap missing?)")
	}
}

// statusRecorderProbe wraps once more in a statusRecorder, as withAudit does,
// so the chain under test is logging → audit-shaped recorder → handler.
type statusRecorderProbe struct{ next http.Handler }

func (p *statusRecorderProbe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.next.ServeHTTP(&statusRecorder{ResponseWriter: w, status: http.StatusOK}, r)
}
