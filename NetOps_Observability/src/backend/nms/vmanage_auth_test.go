// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// vManage has two login flows in the field. 2026-10-17 (lab, vManage 20.6.1):
// the connector only knew /jwt/login, which 20.x does not serve, so every poll
// failed. These tests pin the fallback and — as importantly — that a refused
// login is reported as one, never retried through the other flow.

type fakeVManage struct {
	jwt         int    // status for /jwt/login; 0 = 404
	goodPass    string // the password /j_security_check accepts
	xsrf        string
	jwtCalls    int
	formCalls   int
	tokenCookie string
}

func (f *fakeVManage) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/jwt/login":
		f.jwtCalls++
		if f.jwt == http.StatusOK {
			_, _ = w.Write([]byte(`{"token":"jwt-1"}`))
			return
		}
		st := f.jwt
		if st == 0 {
			st = http.StatusNotFound
		}
		w.WriteHeader(st)
	case "/j_security_check":
		f.formCalls++
		_ = r.ParseForm()
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.PostForm.Get("j_username") != "admin" || r.PostForm.Get("j_password") != f.goodPass {
			_, _ = w.Write([]byte("<html><body>login</body></html>")) // 20.x answers 200 + the login page
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "sess-42"})
	case "/dataservice/client/token":
		f.tokenCookie = r.Header.Get("Cookie")
		if f.tokenCookie != "JSESSIONID=sess-42" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(f.xsrf))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func authAgainst(t *testing.T, f *fakeVManage, pass string) (Session, error) {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return VManageAuth{}.Authenticate(context.Background(), srv.URL+"/", Credentials{Username: "admin", Password: pass}, srv.Client())
}

func TestVManageJWTStillPreferred(t *testing.T) {
	f := &fakeVManage{jwt: http.StatusOK}
	s, err := authAgainst(t, f, "x")
	if err != nil {
		t.Fatal(err)
	}
	if s.Header.Get("Authorization") != "Bearer jwt-1" || f.formCalls != 0 {
		t.Fatalf("JWT flow not used: %v formCalls=%d", s.Header, f.formCalls)
	}
}

func TestVManage20xFallsBackToSessionLogin(t *testing.T) {
	for _, st := range []int{http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusNotImplemented} {
		f := &fakeVManage{jwt: st, goodPass: "cisco", xsrf: "xsrf-tok-9\n"}
		s, err := authAgainst(t, f, "cisco")
		if err != nil {
			t.Fatalf("status %d: %v", st, err)
		}
		if s.Header.Get("Cookie") != "JSESSIONID=sess-42" || s.Header.Get("X-XSRF-TOKEN") != "xsrf-tok-9" {
			t.Fatalf("status %d: session headers %v", st, s.Header)
		}
		if s.Header.Get("Authorization") != "" || s.ExpiresAt.IsZero() {
			t.Fatalf("status %d: wrong session shape %+v", st, s)
		}
	}
}

func TestVManageRejectedSessionLoginSaysCredentials(t *testing.T) {
	f := &fakeVManage{goodPass: "cisco", xsrf: "t"}
	_, err := authAgainst(t, f, "wrong")
	if err == nil || !strings.Contains(err.Error(), "username and password") {
		t.Fatalf("want a credentials error, got %v", err)
	}
}

func TestVManageRefusedJWTNeverFallsBack(t *testing.T) {
	for _, st := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusInternalServerError} {
		f := &fakeVManage{jwt: st, goodPass: "cisco", xsrf: "t"}
		if _, err := authAgainst(t, f, "cisco"); err == nil {
			t.Fatalf("status %d: refused JWT login must fail", st)
		}
		if f.formCalls != 0 {
			t.Fatalf("status %d: a refused JWT login must not try the session flow", st)
		}
	}
}

func TestVManageSessionLoginRejectsAMissingOrHostileXSRFToken(t *testing.T) {
	for _, tok := range []string{"", "<html>nope</html>", "a b"} {
		f := &fakeVManage{goodPass: "cisco", xsrf: tok}
		if _, err := authAgainst(t, f, "cisco"); err == nil {
			t.Fatalf("token %q accepted", tok)
		}
	}
}
