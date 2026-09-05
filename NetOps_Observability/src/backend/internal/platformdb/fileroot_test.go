package platformdb

// fileroot_test.go — the CI tls-boot leg's find (2026-08-12): store keys are
// documented as absolute paths ("/data/users.json"), but the vault's wrapped-
// keys key is the BARE "secrets_wrapped_keys.json". On the FILE backend that
// resolved against the process CWD — /home/nonroot in the distroless image,
// unwritable — so sealing custody could not persist on ANY file-backend
// deployment, and a fresh `install.py --tls` on the file backend (the
// installer default until tracker 245 made it postgres) could mint
// nothing. Nobody saw it earlier because every TLS deployment to date ran the
// Postgres backend, where the bare key is a ROW KEY (and must STAY bare —
// re-keying would orphan the existing custody row: the swtpm-incident class).
//
// The fix: FileKV resolves RELATIVE keys against a configurable root; absolute
// keys and the PG backend are untouched.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileBackendResolvesBareKeysAgainstTheRoot(t *testing.T) {
	dir := t.TempDir()
	prev := fileRoot
	SetFileRoot(dir)
	t.Cleanup(func() { fileRoot = prev })

	f := FileKV{}
	if err := f.Save("secrets_wrapped_keys.json", []byte(`{"v":1}`)); err != nil {
		t.Fatalf("save bare key: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "secrets_wrapped_keys.json")); err != nil {
		t.Fatalf("bare key did not land under the file root: %v — it went to the "+
			"process CWD, which is the distroless /home/nonroot failure (F: CI tls-boot)", err)
	}
	got, err := f.Load("secrets_wrapped_keys.json")
	if err != nil || string(got) != `{"v":1}` {
		t.Fatalf("load bare key: %v %q", err, got)
	}
}

func TestFileBackendLeavesAbsoluteKeysAlone(t *testing.T) {
	dir := t.TempDir()
	prev := fileRoot
	SetFileRoot(filepath.Join(dir, "root"))
	t.Cleanup(func() { fileRoot = prev })

	abs := filepath.Join(dir, "users.json")
	f := FileKV{}
	if err := f.Save(abs, []byte("x")); err != nil {
		t.Fatalf("save absolute: %v", err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("absolute key was rerouted under the root: %v", err)
	}
}

func TestNoRootKeepsLegacyRelativeBehavior(t *testing.T) {
	prev := fileRoot
	SetFileRoot("")
	t.Cleanup(func() { fileRoot = prev })
	// With no root configured (tests, default build), a bare key stays
	// CWD-relative — the pre-fix behavior, preserved so nothing outside the
	// container contract changes.
	f := FileKV{}
	if err := f.Save("fileroot_probe.json", []byte("y")); err != nil {
		t.Fatalf("save: %v", err)
	}
	t.Cleanup(func() { os.Remove("fileroot_probe.json") })
	if _, err := os.Stat("fileroot_probe.json"); err != nil {
		t.Fatalf("no-root bare key should be CWD-relative: %v", err)
	}
}
