package backend

import (
	"netops/backend/internal/users"
	"path/filepath"
	"testing"
)

// A configured MAX_USERS cap must block both create paths once reached, while an
// unset/zero cap means unlimited (default behavior).
func TestUserLimitEnforced(t *testing.T) {
	d := userDeps()
	d.MaxUsers = 2 // simulate MAX_USERS=2
	us, err := users.NewFileStore(filepath.Join(t.TempDir(), "users.json"), d)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	if _, err := us.Create("alice", "Passw0rd!2345", RoleReadOnly); err != nil {
		t.Fatalf("1st user should succeed: %v", err)
	}
	if _, err := us.CreateFull(User{Username: "bob", Role: RoleReadOnly}, "Passw0rd!2345"); err != nil {
		t.Fatalf("2nd user should succeed: %v", err)
	}
	// 3rd exceeds the cap — both entry points must refuse.
	if _, err := us.Create("carol", "Passw0rd!2345", RoleReadOnly); err == nil {
		t.Error("Create past the cap must fail")
	}
	if _, err := us.CreateFull(User{Username: "dave", Role: RoleReadOnly}, "Passw0rd!2345"); err == nil {
		t.Error("CreateFull past the cap must fail")
	}
	if got := len(us.List("", true)); got != 2 {
		t.Errorf("store should hold exactly the cap (2), got %d", got)
	}

	// Federated provisioning is exempt so SSO never locks out at the cap.
	if _, err := us.UpsertFederated("ext-user", "e@x.com", "Ext", RoleReadOnly, "oidc", ""); err != nil {
		t.Errorf("federated provisioning should bypass the cap: %v", err)
	}
}

func TestUserLimitUnlimitedByDefault(t *testing.T) {
	us, err := users.NewFileStore(filepath.Join(t.TempDir(), "users.json"), userDeps())
	if err != nil {
		t.Fatalf("newUserStore: %v", err)
	}
	// userDeps() reads MAX_USERS from env — unset in tests, so the cap is 0
	// (unlimited); the loop below proves the behavior.
	for i := 0; i < 25; i++ {
		if _, err := us.Create("u"+itoa(i), "Passw0rd!2345", RoleReadOnly); err != nil {
			t.Fatalf("unlimited store should accept user %d: %v", i, err)
		}
	}
}

func itoa(n int) string { return string(rune('a'+n%26)) + string(rune('0'+n/26)) }
