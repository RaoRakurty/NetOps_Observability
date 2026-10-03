// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package experience

// change_redact_test.go — tracker 337 N-D3: a change's before/after leaves
// /api/dem/changes (and every derived view that carries changes) through the
// injected redactor, exactly as /api/changes does. The real redactor is wired in
// package main and asserted end to end in dem_experience_isolation_test.go; here
// a deterministic stub proves the module applies it on every read path, leaves
// every other field intact, never mutates the stored record, and fails closed.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// testSecret is the one string testRedact masks.
const testSecret = "hunter2"

// testRedact is a deterministic stand-in for ai.RedactSecrets.
func testRedact(v string) string { return strings.ReplaceAll(v, testSecret, "***") }

const redactFixtureBody = `{"type":"CONFIG_CHANGE","object":"edge-fw-1","object_kind":"device",` +
	`"summary":"rotated the admin credential","app":"checkout","site":"dc1",` +
	`"before":"username admin password hunter2","after":"username admin vlan 20"}`

func assertRedactedChange(t *testing.T, where string, c ChangeEvent) {
	t.Helper()
	if strings.Contains(c.Before, testSecret) || strings.Contains(c.After, testSecret) {
		t.Fatalf("%s: a secret came back raw: before=%q after=%q", where, c.Before, c.After)
	}
	if c.Before != "username admin password ***" {
		t.Fatalf("%s: before was not redacted in place: %q", where, c.Before)
	}
	// Non-secret content is untouched — the value with no secret, and every
	// other field.
	if c.After != "username admin vlan 20" {
		t.Fatalf("%s: a non-secret after value was altered: %q", where, c.After)
	}
	if c.Object != "edge-fw-1" || c.ObjectKind != "device" || c.Summary != "rotated the admin credential" ||
		c.App != "checkout" || c.Site != "dc1" || c.Type != ChangeConfig || c.TenantID != "acme" || c.Actor != "operator" {
		t.Fatalf("%s: a non-secret field was altered: %+v", where, c)
	}
}

func TestDEMChangeValuesAreRedactedOnEveryReadPath(t *testing.T) {
	api, _ := newTestAPI(t, nil)

	// 1. The record echo.
	code, body := call(t, api.HandleChanges, http.MethodPost, "/api/dem/changes", redactFixtureBody, nil)
	if code != http.StatusCreated {
		t.Fatalf("record: %d %s", code, body)
	}
	var made ChangeEvent
	if err := json.Unmarshal(body, &made); err != nil {
		t.Fatal(err)
	}
	assertRedactedChange(t, "POST echo", made)
	if strings.Contains(string(body), testSecret) {
		t.Fatalf("POST echo body carries the secret: %s", body)
	}

	// 2. The list.
	code, body = call(t, api.HandleChanges, http.MethodGet, "/api/dem/changes", "", nil)
	if code != http.StatusOK {
		t.Fatalf("list: %d %s", code, body)
	}
	if strings.Contains(string(body), testSecret) {
		t.Fatalf("GET /api/dem/changes carries the secret: %s", body)
	}
	var feed struct {
		Changes []ChangeEvent `json:"changes"`
	}
	if err := json.Unmarshal(body, &feed); err != nil {
		t.Fatal(err)
	}
	if len(feed.Changes) != 1 {
		t.Fatalf("list returned %d changes, want 1", len(feed.Changes))
	}
	assertRedactedChange(t, "GET list", feed.Changes[0])

	// 3. The overview (the assembly every derived view and the investigator
	// packet is built from).
	code, body = call(t, api.HandleOverview, http.MethodGet, "/api/dem/overview", "", nil)
	if code != http.StatusOK {
		t.Fatalf("overview: %d %s", code, body)
	}
	if strings.Contains(string(body), testSecret) {
		t.Fatalf("GET /api/dem/overview carries the secret: %s", body)
	}
	var ov OverviewResponse
	if err := json.Unmarshal(body, &ov); err != nil {
		t.Fatal(err)
	}
	if len(ov.Changes) != 1 {
		t.Fatalf("overview returned %d changes, want 1", len(ov.Changes))
	}
	assertRedactedChange(t, "overview", ov.Changes[0])

	// 4. The STORED record is untouched: redaction is a property of what leaves
	// over the API, never a rewrite of the immutable ledger.
	stored, err := api.deps.Store.ListChanges(context.Background(), "acme", ChangeQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || stored[0].Before != "username admin password hunter2" {
		t.Fatalf("the stored record was mutated by a read: %+v", stored)
	}

	// 5. A repeat of the same record echoes a row that is still redacted.
	code, body = call(t, api.HandleChanges, http.MethodPost, "/api/dem/changes", redactFixtureBody, nil)
	if code != http.StatusCreated {
		t.Fatalf("repeat record: %d %s", code, body)
	}
	if strings.Contains(string(body), testSecret) {
		t.Fatalf("a repeated record echoed the secret: %s", body)
	}
}

func TestNewAPIRefusesAMissingRedactor(t *testing.T) {
	policy, err := EmbeddedScorePolicy()
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewAPI(Deps{
		Authz:      nil, // also missing; the error must still name Redact
		Store:      newTestFileStore(""),
		Targets:    &memCatalogue{},
		Policy:     policy,
		Now:        nil,
		WriteJSON:  func(http.ResponseWriter, int, any) {},
		WriteError: func(http.ResponseWriter, int, error) {},
		LogWarn:    func(string, map[string]any) {},
	})
	if err == nil || !strings.Contains(err.Error(), "Redact") {
		t.Fatalf("NewAPI accepted Deps with no Redact: %v", err)
	}
}

func TestRedactChangeValuesFailsClosedAndCopies(t *testing.T) {
	if got := RedactChangeValue("password hunter2", nil); got != ChangeValueWithheld {
		t.Fatalf("a nil redactor returned %q, want the value withheld", got)
	}
	if got := RedactChangeValue("", nil); got != "" {
		t.Fatalf("an empty value became %q", got)
	}
	if redactChangeValues(nil, testRedact) != nil {
		t.Fatal("a nil slice did not stay nil")
	}
	in := []ChangeEvent{{ID: "c1", Before: "secret hunter2", After: "x"}}
	out := redactChangeValues(in, testRedact)
	if out[0].Before != "secret ***" || out[0].After != "x" || out[0].ID != "c1" {
		t.Fatalf("redacted copy wrong: %+v", out[0])
	}
	if in[0].Before != "secret hunter2" {
		t.Fatal("redactChangeValues mutated its input")
	}
}
