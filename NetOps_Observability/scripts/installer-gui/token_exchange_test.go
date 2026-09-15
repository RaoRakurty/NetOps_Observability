// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// One-time token exchange only on POST (FMEA 2026-09-15 §3.1 G8, TRACKER 315).
// Any bare GET of the printed link — a chat client's link preview, a browser
// prefetch, a proxy scanner — used to burn the token, and the operator's real
// click then met "another setup session is already active". A GET now renders
// a landing page with a Continue button; only its POST exchanges the token.
package main

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
)

func noRedirectClient(t *testing.T, base *http.Client) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Transport: base.Transport,
		Jar:       jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func TestTokenIsExchangedOnlyByPost(t *testing.T) {
	_, ts := newTestServer(t, &fakeRunner{})

	// A link preview (twice, as chat clients do) sees a landing page and burns nothing.
	preview := ts.Client()
	for i := 0; i < 2; i++ {
		res, err := preview.Get(ts.URL + "/?t=tok123")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("GET of the printed link #%d: got %d, want the 200 landing page", i+1, res.StatusCode)
		}
		for _, c := range res.Cookies() {
			if c.Name == "cx_setup" {
				t.Fatalf("GET #%d issued a session cookie — a link preview would burn the token", i+1)
			}
		}
		page := string(body)
		if !strings.Contains(page, `method="post"`) || !strings.Contains(page, `action="/session"`) {
			t.Fatalf("landing page has no POST form to /session:\n%s", page)
		}
		if strings.Contains(page, "<script") {
			t.Fatal("the landing page must work without script")
		}
		if got := res.Header.Get("Referrer-Policy"); got != "no-referrer" {
			t.Fatalf("landing page Referrer-Policy = %q, want no-referrer (the URL carries the token)", got)
		}
		if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self'") ||
			!strings.Contains(csp, "default-src 'none'") {
			t.Fatalf("landing page CSP = %q", csp)
		}
	}

	// The API never exchanges a token from the query string.
	res, err := preview.Get(ts.URL + "/api/state?t=tok123")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("GET /api/state?t=: got %d, want 403", res.StatusCode)
	}

	// The operator's Continue click exchanges it.
	c := noRedirectClient(t, ts.Client())
	res, err = c.PostForm(ts.URL+"/session", url.Values{"t": {"tok123"}})
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/" {
		t.Fatalf("POST /session: got %d Location=%q, want 303 to /", res.StatusCode, res.Header.Get("Location"))
	}
	res, err = c.Get(ts.URL + "/api/state")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("session after POST exchange: got %d, want 200", res.StatusCode)
	}

	// A second exchange while that session lives is still refused (H2)...
	other := noRedirectClient(t, ts.Client())
	res, err = other.PostForm(ts.URL+"/session", url.Values{"t": {"tok123"}})
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusConflict {
		t.Fatalf("second POST exchange: got %d, want 409", res.StatusCode)
	}
	// ...and a wrong token is forbidden.
	res, err = other.PostForm(ts.URL+"/session", url.Values{"t": {"nope"}})
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("POST /session with a wrong token: got %d, want 403", res.StatusCode)
	}
}

func TestLandingPageNeedsTheToken(t *testing.T) {
	_, ts := newTestServer(t, &fakeRunner{})
	for _, u := range []string{"/", "/?t=wrong"} {
		res, err := ts.Client().Get(ts.URL + u)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusForbidden {
			t.Fatalf("GET %s: got %d, want 403", u, res.StatusCode)
		}
	}
}
