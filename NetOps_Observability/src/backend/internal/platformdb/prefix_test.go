package platformdb

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// prefix_test.go — the FileKV half of the optional per-record capability
// (PrefixBackend). The PG half lives in prefix_pg_test.go (build-tagged
// pgintegration). Contract under test: LoadPrefix returns every committed
// record under a prefix keyed by the ORIGINAL key; an absent subtree is an
// empty store, not an error; in-flight ".tmp" temporaries are invisible;
// Delete is idempotent; relative keys respect the file root.

func TestFileKVPrefixRoundTrip(t *testing.T) {
	dir := t.TempDir()
	f := FileKV{}
	prefix := filepath.Join(dir, "devices.json.d") + "/"
	keys := map[string]string{
		prefix + "manual/aaa":     `{"id":"a"}`,
		prefix + "manual/bbb":     `{"id":"b"}`,
		prefix + "suppressed/ccc": `{"id":"c"}`,
		prefix + "migrated":       `{}`,
	}
	for k, v := range keys {
		if err := f.Save(k, []byte(v)); err != nil {
			t.Fatalf("save %s: %v", k, err)
		}
	}
	// A neighbour OUTSIDE the prefix must not leak in.
	outside := filepath.Join(dir, "devices.jsonX")
	if err := f.Save(outside, []byte("x")); err != nil {
		t.Fatal(err)
	}

	got, err := f.LoadPrefix(prefix)
	if err != nil {
		t.Fatalf("LoadPrefix: %v", err)
	}
	if len(got) != len(keys) {
		t.Fatalf("LoadPrefix returned %d records, want %d: %v", len(got), len(keys), got)
	}
	for k, v := range keys {
		if string(got[k]) != v {
			t.Fatalf("record %s = %q, want %q (keys must round-trip in their ORIGINAL form)", k, got[k], v)
		}
	}
}

func TestFileKVPrefixAbsentSubtreeIsEmptyNotError(t *testing.T) {
	f := FileKV{}
	got, err := f.LoadPrefix(filepath.Join(t.TempDir(), "never-written.json.d") + "/")
	if err != nil {
		t.Fatalf("an absent prefix subtree is a fresh store, got error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("absent subtree returned %d records", len(got))
	}
}

func TestFileKVPrefixSkipsInFlightTemporaries(t *testing.T) {
	dir := t.TempDir()
	f := FileKV{}
	prefix := filepath.Join(dir, "s.d") + "/"
	if err := f.Save(prefix+"manual/aaa", []byte("ok")); err != nil {
		t.Fatal(err)
	}
	// A crashed Save leaves its temp file behind; it was never committed and
	// must never surface as a record.
	if err := os.WriteFile(prefix+"manual/bbb.tmp", []byte("torn"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := f.LoadPrefix(prefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("a torn .tmp write surfaced as a committed record: %v", got)
	}
}

func TestFileKVDeleteIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	f := FileKV{}
	key := filepath.Join(dir, "s.d", "manual", "aaa")
	if err := f.Save(key, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := f.Delete(key); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := f.Load(key); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted key still loads: %v", err)
	}
	if err := f.Delete(key); err != nil {
		t.Fatalf("deleting an absent key must be a no-op, got: %v", err)
	}
}

func TestFileKVPrefixRespectsFileRoot(t *testing.T) {
	dir := t.TempDir()
	prev := fileRoot
	SetFileRoot(dir)
	t.Cleanup(func() { fileRoot = prev })

	f := FileKV{}
	if err := f.Save("devices.json.d/manual/aaa", []byte("v")); err != nil {
		t.Fatal(err)
	}
	got, err := f.LoadPrefix("devices.json.d/")
	if err != nil {
		t.Fatal(err)
	}
	// Keys come back UNRESOLVED (the caller's form), while the bytes landed
	// under the root — the same contract Load/Save honour.
	if string(got["devices.json.d/manual/aaa"]) != "v" {
		t.Fatalf("relative-key record did not round-trip through the file root: %v", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "devices.json.d", "manual", "aaa")); err != nil {
		t.Fatalf("record did not land under the file root: %v", err)
	}
	if err := f.Delete("devices.json.d/manual/aaa"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "devices.json.d", "manual", "aaa")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("relative-key delete missed the rooted file: %v", err)
	}
}

func TestEscapeLikeNeutralizesMetacharacters(t *testing.T) {
	cases := map[string]string{
		`plain/prefix/`:   `plain/prefix/`,
		`p_x%y\z`:         `p\_x\%y\\z`,
		`/data/d.json.d/`: `/data/d.json.d/`,
	}
	for in, want := range cases {
		if got := escapeLike(in); got != want {
			t.Errorf("escapeLike(%q) = %q, want %q", in, got, want)
		}
	}
}
