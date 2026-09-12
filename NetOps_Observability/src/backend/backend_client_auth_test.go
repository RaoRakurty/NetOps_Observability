// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// SEC-010: URL-userinfo credentials must become an Authorization header at
// the shared transport, with the userinfo stripped from the wire request —
// and requests without userinfo must pass through untouched.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestBackendClientAppliesURLUserinfoAsBasicAuth(t *testing.T) {
	var gotAuth, gotUser string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotUser = r.URL.User.String() // must be empty — userinfo never hits the wire
		w.WriteHeader(200)
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	u.User = url.UserPassword("svc-api", "sekret")
	resp, err := backendHTTPClient(5 * time.Second).Get(u.String())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	wantUser, wantPass, ok := (&http.Request{Header: http.Header{"Authorization": []string{gotAuth}}}).BasicAuth()
	if !ok || wantUser != "svc-api" || wantPass != "sekret" {
		t.Fatalf("Authorization = %q — want basic svc-api:sekret", gotAuth)
	}
	if gotUser != "" {
		t.Fatalf("userinfo leaked to the wire: %q", gotUser)
	}
}

func TestBackendClientNoUserinfoPassthrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a := r.Header.Get("Authorization"); a != "" {
			t.Errorf("unexpected Authorization header %q on a credential-less URL", a)
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	resp, err := backendHTTPClient(5 * time.Second).Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
}
