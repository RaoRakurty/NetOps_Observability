package main

import (
	"netops/backend/notify"
	"path/filepath"
	"testing"
)

func TestContactPointValidation(t *testing.T) {
	cases := []struct {
		name    string
		in      ContactPoint
		wantErr bool
	}{
		{"email ok", ContactPoint{Name: "NOC", Type: "email", Email: []string{"a@x.io", "b@x.io"}}, false},
		{"email needs address", ContactPoint{Name: "NOC", Type: "email"}, true},
		{"email bad address", ContactPoint{Name: "NOC", Type: "email", Email: []string{"not-an-email"}}, true},
		{"slack ok", ContactPoint{Name: "ops", Type: "slack", Target: "https://hooks.slack.com/x"}, false},
		{"slack needs target", ContactPoint{Name: "ops", Type: "slack"}, true},
		{"name required", ContactPoint{Type: "email", Email: []string{"a@x.io"}}, true},
		{"unknown type", ContactPoint{Name: "x", Type: "carrier-pigeon"}, true},
	}
	for _, c := range cases {
		_, err := notify.ValidateContactPoint(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err=%v, wantErr=%v", c.name, err, c.wantErr)
		}
	}

	// De-dupes addresses (case-insensitive) and drops the unused Target.
	got, err := notify.ValidateContactPoint(ContactPoint{Name: "NOC", Type: "EMAIL", Email: []string{"a@x.io", "A@X.io", "b@x.io"}, Target: "ignored"})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if len(got.Email) != 2 || got.Target != "" || got.Type != "email" {
		t.Errorf("normalize wrong: %+v", got)
	}
}

func TestContactPointStoreCRUDAndResolve(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "cp.json")
	s, err := newContactPointStore(storePath)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	acme, err := s.Upsert(ContactPoint{TenantID: "acme", Name: "Acme NOC", Type: "email", Email: []string{"noc@acme.io"}, Enabled: true})
	if err != nil {
		t.Fatalf("upsert acme: %v", err)
	}
	if acme.ID == "" {
		t.Fatal("expected an id to be minted")
	}
	globex, _ := s.Upsert(ContactPoint{TenantID: "globex", Name: "Globex", Type: "email", Email: []string{"team@globex.io"}, Enabled: true})
	disabled, _ := s.Upsert(ContactPoint{TenantID: "acme", Name: "Old", Type: "email", Email: []string{"old@acme.io"}, Enabled: false})

	// Update round-trips.
	if _, err := s.Upsert(ContactPoint{ID: acme.ID, TenantID: "acme", Name: "Acme NOC", Type: "email", Email: []string{"noc@acme.io", "lead@acme.io"}, Enabled: true}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if g, _ := s.Get(acme.ID); len(g.Email) != 2 {
		t.Errorf("update not persisted: %+v", g)
	}

	// Reload through the backend.
	s2, _ := newContactPointStore(storePath)
	if _, ok := s2.Get(acme.ID); !ok {
		t.Error("reloaded store should see the acme point")
	}

	// resolveEmailRecipients: tenant-scoped, dedup, skip disabled + other tenants.
	got := s.ResolveEmailRecipients([]string{acme.ID, globex.ID, disabled.ID}, "acme", false)
	if len(got) != 2 { // acme's two addresses; globex hidden, disabled skipped
		t.Errorf("acme scope resolve = %v, want 2 acme addrs", got)
	}
	// Platform owner ('*') sees across tenants.
	if all := s.ResolveEmailRecipients([]string{acme.ID, globex.ID}, "", true); len(all) != 3 {
		t.Errorf("platform resolve = %v, want 3", all)
	}

	if err := s.Delete(globex.ID); err != nil {
		t.Errorf("delete: %v", err)
	}
	if _, ok := s.Get(globex.ID); ok {
		t.Error("globex should be gone")
	}
}
