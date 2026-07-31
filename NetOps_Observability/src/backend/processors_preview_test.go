package backend

// processors_preview_test.go — end-to-end reproduction of what an operator
// actually does in the UI: clone a managed rule, then run the preview. The
// report "before and after show the same thing" has to be reproducible through
// the REAL handlers (auth, tenant derivation, store, simulator) before it can
// be believed or fixed.

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"netops/backend/processors"
)

func TestManagedRuleCloneThenPreviewRedacts(t *testing.T) {
	srv, s := newTestServerState(t)
	s.processors = processors.NewFileStore(filepath.Join(t.TempDir(), "p.json"))

	// The platform owner — the account an evaluator is logged in as.
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// 1. Clone the email detector into syslog, exactly as the modal does.
	st, body := do(t, srv, "POST", "/api/pipeline/processors/clone", admin, map[string]any{
		"managed_rule_id": "email", "lane": "syslog", "field": "",
	})
	if st != 201 {
		t.Fatalf("clone: %d %s", st, body)
	}
	var cloned processors.Processor
	if err := json.Unmarshal(body, &cloned); err != nil {
		t.Fatal(err)
	}
	t.Logf("cloned: tenant=%q field=%q type=%s enabled=%v", cloned.TenantID, cloned.Field, cloned.Type, cloned.Enabled)

	// 2. Preview the wizard's default syslog sample, which contains an email.
	sample := map[string]any{
		"message":  "login failure for jsmith@example.org from 10.1.2.3",
		"hostname": "edge-fw-01",
		"severity": "warning",
	}
	st, body = do(t, srv, "POST", "/api/pipeline/processors/preview", admin, map[string]any{
		"lane": "syslog", "event": sample,
	})
	if st != 200 {
		t.Fatalf("preview: %d %s", st, body)
	}
	var res struct {
		Original map[string]any       `json:"original"`
		Event    map[string]any       `json:"event"`
		Applied  []processors.Applied `json:"applied"`
		Dropped  bool                 `json:"dropped"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		t.Fatal(err)
	}

	// THE ASSERTION THE BUG REPORT IS ABOUT: after must differ from before.
	if len(res.Applied) == 0 {
		t.Fatalf("the cloned detector did not fire — this is the \"before and after look identical\" report.\n"+
			"cloned rule: %+v\npreview response: %s", cloned, body)
	}
	msg, _ := res.Event["message"].(string)
	if msg == sample["message"] {
		t.Fatalf("message was not redacted: %q (applied=%+v)", msg, res.Applied)
	}
	t.Logf("redacted to: %q", msg)

	// A DRAFT — the rule an operator is typing in the wizard, not yet saved —
	// must show its effect. Without this the wizard's step 4 showed "before"
	// and "after" identical for the very rule being written, which is what the
	// "preview does nothing" report was really about.
	st, body = do(t, srv, "POST", "/api/pipeline/processors/preview", admin, map[string]any{
		"lane":  "applogs",
		"event": map[string]any{"card": "4111111111111111", "note": "keep me"},
		"processor": map[string]any{
			"type": "mask", "field": "card", "keep_last": 4, "lane": "applogs",
		},
	})
	if st != 200 {
		t.Fatalf("draft preview: %d %s", st, body)
	}
	var draftRes struct {
		Event   map[string]any       `json:"event"`
		Applied []processors.Applied `json:"applied"`
	}
	if err := json.Unmarshal(body, &draftRes); err != nil {
		t.Fatal(err)
	}
	if len(draftRes.Applied) == 0 {
		t.Fatalf("an unsaved draft must appear in its own preview: %s", body)
	}
	if got, _ := draftRes.Event["card"].(string); got != "************1111" {
		t.Fatalf("draft mask must apply: %q", got)
	}
	if draftRes.Event["note"] != "keep me" {
		t.Fatal("the draft must not touch unrelated fields")
	}

	// An INVALID draft is refused with a clear reason rather than silently
	// previewing nothing.
	st, _ = do(t, srv, "POST", "/api/pipeline/processors/preview", admin, map[string]any{
		"lane": "syslog", "event": map[string]any{"a": "b"},
		"processor": map[string]any{"type": "mask", "field": "tenant_id"},
	})
	if st != 400 {
		t.Fatalf("an invalid draft must 400, got %d", st)
	}
}
