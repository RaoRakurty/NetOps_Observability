//go:build pgintegration

package platformdb

import (
	"context"
	"errors"
	"os"
	"testing"
)

// prefix_pg_test.go — the PGStore half of the PrefixBackend capability, against
// a real PostgreSQL (build-tagged pgintegration; the CI pg-integration job
// runs it with DATABASE_URL_TEST set — see .github/workflows/backend-ci.yml).
//
// Contract under test, mirroring prefix_test.go's FileKV half:
//   - per-record keys land as app_kv blob rows (their hex basenames never
//     match the rowSpecs registry, so they take the blob path);
//   - LoadPrefix returns exactly the rows under the prefix, keyed verbatim;
//   - LIKE metacharacters in a prefix match LITERALLY (escaping), so
//     "a_b/" can never sweep in "aXb/" rows;
//   - Delete is idempotent and absent-key Load stays os.ErrNotExist.

func TestPGPrefixBackendConformance(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres prefix-capability test")
	}
	ctx := context.Background()
	ps, err := NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("NewPGStore: %v", err)
	}
	defer ps.DB().Close()

	// The wiring seam: the PG backend must advertise the capability.
	var b Backend = ps
	pb, ok := b.(PrefixBackend)
	if !ok {
		t.Fatal("PGStore does not implement PrefixBackend — the device store would silently fall back to O(N²) blob writes")
	}

	const prefix = "/data/devices.json.d/"
	records := map[string]string{
		prefix + "manual/aaa111":     `{"id":"a"}`,
		prefix + "manual/bbb222":     `{"id":"b"}`,
		prefix + "suppressed/ccc333": `{"id":"c","deleted_at":"2026-06-01T00:00:00Z"}`,
		prefix + "migrated":          `{"migrated_at":"2026-06-01T00:00:00Z"}`,
	}
	for k, v := range records {
		if err := pb.Save(k, []byte(v)); err != nil {
			t.Fatalf("save %s: %v", k, err)
		}
	}
	// Rows OUTSIDE the prefix must not leak in.
	if err := pb.Save("/data/devices.jsonX/manual/zzz", []byte("outside")); err != nil {
		t.Fatal(err)
	}

	got, err := pb.LoadPrefix(prefix)
	if err != nil {
		t.Fatalf("LoadPrefix: %v", err)
	}
	if len(got) != len(records) {
		t.Fatalf("LoadPrefix returned %d rows, want %d: %v", len(got), len(records), got)
	}
	for k, v := range records {
		if string(got[k]) != v {
			t.Fatalf("row %s = %q, want %q (verbatim round-trip)", k, got[k], v)
		}
	}

	// Upsert semantics: re-Save overwrites in place (no duplicate rows).
	if err := pb.Save(prefix+"manual/aaa111", []byte(`{"id":"a","v":2}`)); err != nil {
		t.Fatal(err)
	}
	got, err = pb.LoadPrefix(prefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(records) || string(got[prefix+"manual/aaa111"]) != `{"id":"a","v":2}` {
		t.Fatalf("re-Save did not upsert in place: %v", got)
	}

	// Delete: row gone, absent Load is os.ErrNotExist, re-Delete is a no-op.
	if err := pb.Delete(prefix + "manual/bbb222"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := pb.Load(prefix + "manual/bbb222"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted row still loads (err=%v)", err)
	}
	if err := pb.Delete(prefix + "manual/bbb222"); err != nil {
		t.Fatalf("deleting an absent row must be a no-op, got: %v", err)
	}
	if got, err = pb.LoadPrefix(prefix); err != nil || len(got) != len(records)-1 {
		t.Fatalf("after delete: rows=%d err=%v, want %d", len(got), err, len(records)-1)
	}
}

// TestPGPrefixEscapingMatchesLiterally: a prefix containing LIKE
// metacharacters must match itself only. Without ESCAPE handling, "_" matches
// ANY character and "a_b/" would sweep in "aXb/" rows — a cross-store bleed.
// (Keys are server-generated, so this is defence in depth; still pinned.)
func TestPGPrefixEscapingMatchesLiterally(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres prefix-capability test")
	}
	ctx := context.Background()
	ps, err := NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("NewPGStore: %v", err)
	}
	defer ps.DB().Close()

	if err := ps.Save("/data/a_b.d/k1", []byte("underscore")); err != nil {
		t.Fatal(err)
	}
	if err := ps.Save("/data/aXb.d/k1", []byte("wildcard-bait")); err != nil {
		t.Fatal(err)
	}
	if err := ps.Save(`/data/a\b.d/k1`, []byte("backslash")); err != nil {
		t.Fatal(err)
	}

	got, err := ps.LoadPrefix("/data/a_b.d/")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || string(got["/data/a_b.d/k1"]) != "underscore" {
		t.Fatalf("underscore prefix matched non-literally: %v", got)
	}
	got, err = ps.LoadPrefix(`/data/a\b.d/`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || string(got[`/data/a\b.d/k1`]) != "backslash" {
		t.Fatalf("backslash prefix matched non-literally: %v", got)
	}
}
