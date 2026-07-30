package rbac

import (
	"path/filepath"
	"testing"
)

// TestCompileRoleRules: the compiled rule bundle faithfully reflects the grid —
// every module with level>none becomes an allow rule with the right actions, and
// none-level modules produce no rule.
func TestCompileRoleRules(t *testing.T) {
	perms := map[string]int{
		"alerts":         LevelWrite, // ack alerts
		"infrastructure": LevelRead,  // view devices, not modify
		"administration": LevelNone,  // no admin
	}
	rules := compileRoleRules(perms)
	got := map[string][]string{}
	for _, r := range rules {
		if r.Effect != EffectAllow {
			t.Errorf("expected allow effect, got %q", r.Effect)
		}
		got[r.ResourceType] = r.Actions
	}
	if _, ok := got["administration"]; ok {
		t.Error("none-level module must not produce a rule")
	}
	if a := got["alerts"]; len(a) != 2 || a[0] != "view" || a[1] != "write" {
		t.Errorf("alerts write rule = %v, want [view write]", a)
	}
	if a := got["infrastructure"]; len(a) != 1 || a[0] != "view" {
		t.Errorf("infrastructure read rule = %v, want [view]", a)
	}
}

// TestRolesExposeRules: List() attaches the compiled bundle to every role.
func TestRolesExposeRules(t *testing.T) {
	rs, err := NewRoleStore(filepath.Join(t.TempDir(), "roles.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs.List() {
		if len(r.Permissions) == 0 {
			continue
		}
		// operator/super-admin/etc. all have at least one non-none module → rules.
		if hasAnyLevel(r.Permissions) && len(r.Rules) == 0 {
			t.Errorf("role %q should expose compiled rules", r.ID)
		}
	}
}

func hasAnyLevel(p map[string]int) bool {
	for _, v := range p {
		if v > LevelNone {
			return true
		}
	}
	return false
}

// TestCustomRoleSandbox: a custom role cannot grant administration:admin (the
// escalation vector), but operational grids are accepted.
func TestCustomRoleSandbox(t *testing.T) {
	rs, err := NewRoleStore(filepath.Join(t.TempDir(), "roles.json"))
	if err != nil {
		t.Fatal(err)
	}
	// rejected: administration admin
	if _, err := rs.Upsert(Role{Name: "shadow-admin", Permissions: map[string]int{"administration": LevelAdmin}}); err == nil {
		t.Error("custom role granting administration:admin must be rejected")
	}
	// accepted: a focused operational role (ack alerts, view devices)
	r, err := rs.Upsert(Role{Name: "alert-handler", Permissions: map[string]int{"alerts": LevelWrite, "infrastructure": LevelRead}})
	if err != nil {
		t.Fatalf("operational custom role should be accepted: %v", err)
	}
	if r.Builtin {
		t.Error("custom role must not be builtin")
	}
	// the persisted role exposes its compiled rules on read
	got, _ := rs.Get(r.ID)
	if got.Permissions["alerts"] != LevelWrite {
		t.Errorf("custom role grid not persisted: %+v", got.Permissions)
	}
}

// TestBindingPrincipalType: machine principals carry their type; default is user.
func TestBindingPrincipalType(t *testing.T) {
	bs, err := NewBindingStore(filepath.Join(t.TempDir(), "rb.json"))
	if err != nil {
		t.Fatal(err)
	}
	u, err := bs.Add(RoleBinding{PrincipalID: "alice", RoleID: "operator", ScopeID: ScopeTenant("acme")})
	if err != nil {
		t.Fatal(err)
	}
	if u.PrincipalType != PrincipalUser {
		t.Errorf("default principal type = %q, want user", u.PrincipalType)
	}
	svc, err := bs.Add(RoleBinding{PrincipalID: "collector-1", PrincipalType: PrincipalAgent, RoleID: "api-client", ScopeID: ScopeTenant("acme")})
	if err != nil {
		t.Fatal(err)
	}
	if svc.PrincipalType != PrincipalAgent {
		t.Errorf("agent principal type = %q, want agent", svc.PrincipalType)
	}
}
