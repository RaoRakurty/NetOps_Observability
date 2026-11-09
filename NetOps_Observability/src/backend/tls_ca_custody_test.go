// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"netops/backend/internal/vault"
)

// newTestCA builds a caManager over an in-memory vault and temp CA blobs.
func newTestCA(t *testing.T) *caManager {
	t.Helper()
	withTempCAKeys(t)
	v, err := vault.NewWithProvider(context.Background(), &memSealing{}, &memVaultStore{data: map[string][]byte{}},
		func(string, string, map[string]any) {})
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	m, err := loadOrCreateCA(v, "netops")
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	m.ttl = time.Hour
	return m
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}

// TestAdminKeyIsNeverWidened: the admin DN bypasses every role and index check.
// Whatever the environment says about OTHER keys, including a dev-mode 0644, its
// key is 0600 in a 0700 directory. This is the owner's custody decision.
func TestAdminKeyIsNeverWidened(t *testing.T) {
	for _, tc := range []struct{ name, mode, dev string }{
		{"mode unset", "", ""},
		{"group read for the service keys", "0640", ""},
		{"world readable under the dev escape hatch", "0644", "true"},
		{"everything open under the dev escape hatch", "0777", "true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestCA(t)
			dir := filepath.Join(t.TempDir(), "admin")
			t.Setenv("TLS_OS_ADMIN_CERT_DIR", dir)
			t.Setenv("TLS_SERVICE_KEY_MODE", tc.mode)
			t.Setenv("ALLOW_DEV_SECRETS", tc.dev)
			if err := m.provisionFromEnv(); err != nil {
				t.Fatalf("provision: %v", err)
			}
			if got := fileMode(t, filepath.Join(dir, "admin.key")); got != 0o600 {
				t.Fatalf("admin.key mode = %04o, want 0600", got)
			}
			if got := fileMode(t, dir); got != 0o700 {
				t.Fatalf("admin dir mode = %04o, want 0700", got)
			}
			if got := fileMode(t, filepath.Join(dir, "admin.crt")); got != 0o644 {
				t.Fatalf("admin.crt mode = %04o, want 0644 (public material)", got)
			}
		})
	}
}

// TestAdminKeyTightensOnAnExistingWideInstall: every TLS install before this
// change holds admin.key at 0644 in a 0755 directory. The next boot must repair
// both, not only new installs.
func TestAdminKeyTightensOnAnExistingWideInstall(t *testing.T) {
	m := newTestCA(t)
	dir := filepath.Join(t.TempDir(), "admin")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil { // the umask may have narrowed it
		t.Fatal(err)
	}
	old := filepath.Join(dir, "admin.key")
	if err := os.WriteFile(old, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(old, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TLS_OS_ADMIN_CERT_DIR", dir)
	if err := m.provisionFromEnv(); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if got := fileMode(t, old); got != 0o600 {
		t.Fatalf("admin.key mode = %04o after re-issue, want 0600", got)
	}
	if got := fileMode(t, dir); got != 0o700 {
		t.Fatalf("admin dir mode = %04o after re-issue, want 0700", got)
	}
}

// TestProvisionFailsWhenTheAdminDirCannotBeSecured: a failure to secure the
// directory must stop the mint, never leave a key in a directory of unknown
// mode (§16.1). A regular file where the directory should be is the portable way
// to force that error without root.
func TestProvisionFailsWhenTheAdminDirCannotBeSecured(t *testing.T) {
	m := newTestCA(t)
	parent := t.TempDir()
	blocker := filepath.Join(parent, "admin")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TLS_OS_ADMIN_CERT_DIR", blocker)
	if err := m.provisionFromEnv(); err == nil {
		t.Fatal("provision succeeded although the admin dir could not be created")
	}
}
