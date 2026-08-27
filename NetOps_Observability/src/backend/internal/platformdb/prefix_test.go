package platformdb

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// --- Parallel LoadPrefix (bounded worker pool) -----------------------------
// These cover the GA-scale boot fix: the per-file reads now run on a bounded
// pool instead of one syscall at a time. Semantics must be byte-for-byte the
// same as the serial walk — the tests below pin scale parity, error
// propagation, empty subtrees, and merge-race correctness.

func TestFileKVPrefixScaleParity(t *testing.T) {
	dir := t.TempDir()
	f := FileKV{}
	prefix := filepath.Join(dir, "devices.json.d") + "/"

	// 50,000 committed records under the prefix. Completing inside the default
	// `go test` timeout is itself the proof the load is no longer serial-slow.
	const n = 50000
	for i := 0; i < n; i++ {
		// Spread across nested subdirs so WalkDir descends, like the real store.
		key := fmt.Sprintf("%sbucket%02d/rec%05d", prefix, i%64, i)
		if err := f.Save(key, []byte(fmt.Sprintf("v%d", i))); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	// A sibling prefix that shares the parent dir but must NOT be returned.
	sibPrefix := filepath.Join(dir, "devices.json.OTHER") + "/"
	if err := f.Save(sibPrefix+"nope", []byte("sibling")); err != nil {
		t.Fatal(err)
	}
	// A neighbour whose path is a string-prefix of nothing we want.
	if err := f.Save(filepath.Join(dir, "devices.jsonX"), []byte("x")); err != nil {
		t.Fatal(err)
	}
	// An in-flight temporary that must be skipped.
	if err := os.WriteFile(prefix+"bucket00/rec00000.tmp", []byte("torn"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A nested empty subdir (WalkDir must not surface it as a record).
	if err := os.MkdirAll(prefix+"emptybucket/deeper", 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := f.LoadPrefix(prefix)
	if err != nil {
		t.Fatalf("LoadPrefix: %v", err)
	}
	if len(got) != n {
		t.Fatalf("LoadPrefix returned %d records, want %d", len(got), n)
	}
	for i := 0; i < n; i++ {
		key := fmt.Sprintf("%sbucket%02d/rec%05d", prefix, i%64, i)
		want := fmt.Sprintf("v%d", i)
		if string(got[key]) != want {
			t.Fatalf("record %s = %q, want %q", key, got[key], want)
		}
	}
	// Sibling prefix and .tmp excluded.
	for k := range got {
		if strings.HasPrefix(k, sibPrefix) {
			t.Fatalf("sibling-prefix record leaked in: %s", k)
		}
		if strings.HasSuffix(k, ".tmp") {
			t.Fatalf(".tmp temporary surfaced as a record: %s", k)
		}
	}
}

func TestFileKVPrefixPropagatesReadError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod-based unreadable file is not enforced for root")
	}
	dir := t.TempDir()
	f := FileKV{}
	prefix := filepath.Join(dir, "s.d") + "/"
	for i := 0; i < 8; i++ {
		if err := f.Save(fmt.Sprintf("%srec%d", prefix, i), []byte("ok")); err != nil {
			t.Fatal(err)
		}
	}
	// Force a read error: an unreadable committed file (mode 000). fs.ReadFile
	// through the root FS opens it and fails with EACCES.
	bad := prefix + "unreadable"
	if err := f.Save(bad, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bad, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(bad, 0o600) })
	// If the environment still lets us read it (some CI overlay FSes ignore
	// mode bits), skip rather than assert a false negative.
	if _, err := os.ReadFile(bad); err == nil {
		t.Skip("filesystem does not enforce chmod 000; cannot create an unreadable entry")
	}

	_, err := f.LoadPrefix(prefix)
	if err == nil {
		t.Fatal("LoadPrefix must return an error when a committed file is unreadable")
	}
	if !strings.Contains(err.Error(), "scan prefix") {
		t.Fatalf("error not wrapped as a scan failure: %v", err)
	}
}

func TestFileKVPrefixEmptyMissingSubtree(t *testing.T) {
	f := FileKV{}
	got, err := f.LoadPrefix(filepath.Join(t.TempDir(), "absent.d") + "/")
	if err != nil {
		t.Fatalf("missing subtree must be (empty map, nil), got err: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("missing subtree must be an empty non-nil map, got: %#v", got)
	}
}

func TestFileKVPrefixConcurrencyMergeIsStable(t *testing.T) {
	dir := t.TempDir()
	f := FileKV{}
	prefix := filepath.Join(dir, "c.d") + "/"
	const n = 2000
	want := make(map[string]string, n)
	for i := 0; i < n; i++ {
		key := fmt.Sprintf("%sb%03d/rec%04d", prefix, i%37, i)
		val := fmt.Sprintf("val-%d", i)
		want[key] = val
		if err := f.Save(key, []byte(val)); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	// Repeat the concurrent load many times: a merge race (lost or duplicated
	// entry) would show up as a wrong count or wrong value on some iteration,
	// even though -race is unavailable here.
	for iter := 0; iter < 20; iter++ {
		got, err := f.LoadPrefix(prefix)
		if err != nil {
			t.Fatalf("iter %d: LoadPrefix: %v", iter, err)
		}
		if len(got) != n {
			t.Fatalf("iter %d: got %d records, want %d", iter, len(got), n)
		}
		for k, v := range want {
			if string(got[k]) != v {
				t.Fatalf("iter %d: record %s = %q, want %q", iter, k, got[k], v)
			}
		}
	}
}
