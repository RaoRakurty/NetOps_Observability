// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package notify

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// Text is the platform route's SMS sender. Every request goes to an httptest
// server — never Twilio.
func TestTwilioTextWireShapeAndBounds(t *testing.T) {
	var (
		mu    sync.Mutex
		paths []string
		forms []url.Values
		users []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body) // test fake
		f, _ := url.ParseQuery(string(b))
		u, _, _ := r.BasicAuth()
		mu.Lock()
		paths, forms, users = append(paths, r.URL.Path), append(forms, f), append(users, u)
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	sid := "AC" + strings.Repeat("b2", 16)
	tw := NewTwilio(sid, "placeholder-"+strings.Repeat("y", 16), "+14155550199", "+14155550100,+14155550101").WithEndpoint(srv.URL + "/")
	if err := tw.Text(strings.Repeat("é", 400)); err != nil {
		t.Fatalf("Text: %v", err)
	}
	if len(forms) != 2 {
		t.Fatalf("one request per recipient, got %d", len(forms))
	}
	for i, f := range forms {
		if paths[i] != "/2010-04-01/Accounts/"+sid+"/Messages.json" || users[i] != sid {
			t.Fatalf("request %d: path %q user %q", i, paths[i], users[i])
		}
		if n := len([]rune(f.Get("Body"))); n != maxSMSText {
			t.Fatalf("an SMS is bounded to one segment: %d runes", n)
		}
	}
}

// A failure is TYPED and carries no provider body (it can echo account detail
// and destination numbers).
func TestTwilioTextTypedErrorWithoutProviderBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"message":"secret account detail +14155550100"}`) // test fake
	}))
	defer srv.Close()
	tw := NewTwilio("AC"+strings.Repeat("c3", 16), "placeholder-"+strings.Repeat("z", 16), "+14155550199", "+14155550100").WithEndpoint(srv.URL)
	err := tw.Text("hello")
	var se *TwilioStatusError
	if !errors.As(err, &se) || se.Status != 429 || !se.RateLimited() || !se.Retryable() || se.RetryDelay() != 7*time.Second {
		t.Fatalf("typed error: %#v", err)
	}
	if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "+1415") {
		t.Fatalf("provider body leaked: %v", err)
	}
	for _, c := range []struct {
		st                   int
		auth, retry, limited bool
	}{{401, true, false, false}, {403, true, false, false}, {400, false, false, false}, {500, false, true, false}} {
		e := &TwilioStatusError{Status: c.st}
		if e.AuthRejected() != c.auth || e.Retryable() != c.retry || e.RateLimited() != c.limited {
			t.Errorf("status %d classification wrong", c.st)
		}
	}
}

func TestTwilioTextRefusesIncompleteConfig(t *testing.T) {
	if err := NewTwilio("", "", "", "").Text("x"); err == nil {
		t.Fatal("an incomplete sender must refuse")
	}
	if err := NewTwilio("AC1", "t", "+1", "").Text("x"); err == nil {
		t.Fatal("no recipients must refuse")
	}
}
