package rbac

import (
	"netops/backend/internal/platformdb"
	"path/filepath"
	"testing"
)

// TestBuiltinPolicyRoles pins the Auditor + API-Client policy roles (#16.5):
// Auditor reads everything incl. the audit trail but never writes; API-Client is
// a tighter machine identity (operational read only, no reports/administration).
func TestBuiltinPolicyRoles(t *testing.T) {
	roles := map[string]Role{}
	for _, r := range builtinRoles() {
		roles[r.ID] = r
	}

	aud, ok := roles[RoleAuditor]
	if !ok || !aud.Builtin {
		t.Fatal("auditor must be a built-in role")
	}
	if aud.Permissions["administration"] != LevelRead {
		t.Errorf("auditor administration = %d, want read", aud.Permissions["administration"])
	}
	for mod, lvl := range aud.Permissions {
		if lvl > LevelRead {
			t.Errorf("auditor must never exceed read; %s = %d", mod, lvl)
		}
	}

	api, ok := roles[RoleAPIClient]
	if !ok || !api.Builtin {
		t.Fatal("api-client must be a built-in role")
	}
	if api.Permissions["reports"] != LevelNone || api.Permissions["administration"] != LevelNone {
		t.Errorf("api-client must not see reports/administration: %+v", api.Permissions)
	}
	if api.Permissions["alerts"] != LevelRead || api.Permissions["infrastructure"] != LevelRead {
		t.Errorf("api-client should read operational data: %+v", api.Permissions)
	}
}

// TestPolicyRolesSeededAndEnforced confirms the store seeds the new built-ins and
// that Allows enforces their grids.
func TestPolicyRolesSeededAndEnforced(t *testing.T) {
	t.Cleanup(platformdb.SwapBackendForTest(platformdb.FileKV{}))
	rs, err := NewRoleStore(filepath.Join(t.TempDir(), "roles.json"))
	if err != nil {
		t.Fatalf("NewRoleStore: %v", err)
	}
	// Auditor: reads administration, cannot write it.
	if !rs.Allows(RoleAuditor, "administration", LevelRead) {
		t.Error("auditor should read administration (audit trail)")
	}
	if rs.Allows(RoleAuditor, "alerts", LevelWrite) {
		t.Error("auditor must not write")
	}
	// API-Client: reads alerts, blocked from reports + administration.
	if !rs.Allows(RoleAPIClient, "alerts", LevelRead) {
		t.Error("api-client should read alerts")
	}
	if rs.Allows(RoleAPIClient, "reports", LevelRead) || rs.Allows(RoleAPIClient, "administration", LevelRead) {
		t.Error("api-client must not read reports/administration")
	}
	// Built-ins are protected.
	if _, err := rs.Upsert(Role{ID: RoleAuditor, Name: "Auditor"}); err == nil {
		t.Error("overwriting a built-in role must fail")
	}
}
