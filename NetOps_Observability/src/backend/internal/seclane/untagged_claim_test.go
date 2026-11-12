// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package seclane

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Tracker 370: the security lane's device-log source claims an UNTAGGED syslog
// document only through identities no other owner holds. The composition root
// supplies those (Deps.UntaggedClaims); the source intersects them with the
// devices it scans, and claims nothing when no source is wired.

func claimTestSource(claims func(string) ([]string, []string), capture *[]byte) *osLogSource {
	return &osLogSource{
		search: func(_, _ string, body any) (*http.Response, error) {
			b, err := json.Marshal(body)
			if err != nil {
				return nil, err
			}
			*capture = b
			return &http.Response{StatusCode: http.StatusOK,
				Body: io.NopCloser(bytes.NewReader([]byte(`{"hits":{"hits":[]}}`)))}, nil
		},
		claims: claims,
		tenant: "acme",
		devices: []Device{
			{ID: "acme-1", Name: "core-rtr-1", Address: "10.0.0.1", TenantID: "acme"}, // shared with another owner
			{ID: "acme-2", Name: "acme-edge", Address: "10.1.0.2", TenantID: "acme"},
		},
		since: time.Unix(0, 0),
		until: time.Unix(60, 0),
	}
}

func TestLogSourceClaimsOnlyUnambiguousIdentities(t *testing.T) {
	var body []byte
	// The root says: core-rtr-1 / 10.0.0.1 are ambiguous; "other-dev" is acme's
	// but not a scanned (monitored) device, so the intersection drops it too.
	src := claimTestSource(func(tenant string) ([]string, []string) {
		if tenant != "acme" {
			t.Errorf("claims asked for tenant %q", tenant)
		}
		return []string{"acme-1", "acme-2", "acme-edge", "other-dev"}, []string{"10.1.0.2"}
	}, &body)
	keys, addrs := src.claimIdentities()
	if strings.Join(keys, ",") != "acme-1,acme-2,acme-edge" || strings.Join(addrs, ",") != "10.1.0.2" {
		t.Fatalf("claim = keys %v addrs %v", keys, addrs)
	}
	if _, err := src.LogEvents(t.Context()); err != nil {
		t.Fatalf("LogEvents: %v", err)
	}
	for _, leak := range []string{`"core-rtr-1"`, `"10.0.0.1"`, `"other-dev"`} {
		if bytes.Contains(body, []byte(leak)) {
			t.Errorf("the syslog query claims %s, which another owner also holds:\n%s", leak, body)
		}
	}
	if !bytes.Contains(body, []byte(`"acme-edge"`)) {
		t.Errorf("the query lost acme's own key:\n%s", body)
	}
}

func TestLogSourceClaimsNothingWithoutAClaimSource(t *testing.T) {
	var body []byte
	src := claimTestSource(nil, &body)
	if keys, addrs := src.claimIdentities(); keys != nil || addrs != nil {
		t.Fatalf("no claim source must claim nothing: %v %v", keys, addrs)
	}
	if _, err := src.LogEvents(t.Context()); err != nil {
		t.Fatalf("LogEvents: %v", err)
	}
	for _, leak := range []string{`"core-rtr-1"`, `"acme-edge"`, `"10.0.0.1"`} {
		if bytes.Contains(body, []byte(leak)) {
			t.Errorf("default-closed: the query must not claim %s:\n%s", leak, body)
		}
	}
	if !bytes.Contains(body, []byte(`"tenant_id":"acme"`)) {
		t.Errorf("the tenant's own stamped documents must still be read:\n%s", body)
	}
}
