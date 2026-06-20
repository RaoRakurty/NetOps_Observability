package main

import "testing"

func TestNormalizeIsolationMode(t *testing.T) {
	cases := []struct {
		in   string
		want IsolationMode
		err  bool
	}{
		{"", IsolationShared, false},
		{"shared", IsolationShared, false},
		{"DEDICATED_SCHEMA", IsolationDedicatedSchema, false},
		{"dedicated_db", IsolationDedicatedDB, false},
		{" dedicated_cluster ", IsolationDedicatedCluster, false},
		{"bogus", "", true},
	}
	for _, c := range cases {
		got, err := normalizeIsolationMode(c.in)
		if (err != nil) != c.err {
			t.Errorf("normalize(%q) err=%v, want err=%v", c.in, err, c.err)
		}
		if !c.err && got != c.want {
			t.Errorf("normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestTenantCreateIsolationMode(t *testing.T) {
	s, err := newTenantStore(t.TempDir() + "/tenants.json")
	if err != nil {
		t.Fatal(err)
	}
	// default → shared
	def, err := s.Create("Acme", "", "", "", "")
	if err != nil || def.IsolationMode != IsolationShared {
		t.Fatalf("default isolation = %q (err %v), want shared", def.IsolationMode, err)
	}
	if def.OrgID != OrgGlobal {
		t.Errorf("blank org should default to Global, got %q", def.OrgID)
	}
	// explicit dedicated mode persisted
	ded, err := s.Create("Globex", "", "", "dedicated_db", "")
	if err != nil || ded.IsolationMode != IsolationDedicatedDB {
		t.Fatalf("dedicated isolation = %q (err %v)", ded.IsolationMode, err)
	}
	// invalid rejected
	if _, err := s.Create("Initech", "", "", "bogus", ""); err == nil {
		t.Error("invalid isolation_mode should be rejected")
	}
	// the seeded global tenant is shared
	if g, ok := s.Get(TenantGlobal); !ok || g.IsolationMode != IsolationShared {
		t.Errorf("global tenant isolation = %q, want shared", g.IsolationMode)
	}
}

func TestSharedRouterAlwaysShared(t *testing.T) {
	// A tenant flagged for dedicated infra still resolves to shared until that
	// infra is provisioned (intent vs reality).
	got := sharedRouter{}.BackendFor(Tenant{ID: "globex", IsolationMode: IsolationDedicatedCluster})
	if got.Mode != IsolationShared {
		t.Errorf("sharedRouter resolved %q, want shared", got.Mode)
	}
}
