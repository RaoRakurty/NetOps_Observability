package platformdb

import (
	"context"
	"errors"
	"os"
	"testing"
)

// The backend kind must always match the backend that is actually active: the
// selectors decide what a registry can do from Kind(), so a kind that lags
// behind `active` would re-open exactly the tracker-245 confusion.

func TestKindTracksTheActiveBackend(t *testing.T) {
	t.Cleanup(UseFile)

	UseFile()
	if Kind() != KindFile {
		t.Fatalf("Kind()=%q after UseFile", Kind())
	}
	if _, ok := ActivePG(); ok {
		t.Fatal("the file backend must not present itself as postgres")
	}

	UseMemory()
	if Kind() != KindMemory {
		t.Fatalf("Kind()=%q after UseMemory", Kind())
	}
	if IsPersistent(Kind()) {
		t.Fatal("the memory backend must never report itself as persistent")
	}

	UseFile()
	if Kind() != KindFile || !IsPersistent(Kind()) {
		t.Fatalf("Kind()=%q after returning to the file backend", Kind())
	}
}

// A failed Postgres selection must leave the previous backend untouched: the
// caller aborts the boot, and nothing silently continues on files or RAM.
func TestUsePostgresFailureDoesNotSwitchBackends(t *testing.T) {
	t.Cleanup(UseFile)
	UseFile()
	if err := UsePostgres(context.Background(), ""); err == nil {
		t.Fatal("an empty DSN must be an error")
	}
	if Kind() != KindFile {
		t.Fatalf("a failed postgres selection changed the backend to %q", Kind())
	}
}

func TestMemKVRoundTripsAndIsolatesCopies(t *testing.T) {
	t.Cleanup(UseFile)
	UseMemory()

	if _, err := Load("/data/missing.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an absent key must report os.ErrNotExist (the Backend contract), got %v", err)
	}
	payload := []byte(`[{"id":"a"}]`)
	if err := Save("/data/things.json", payload); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := Load("/data/things.json")
	if err != nil || string(got) != `[{"id":"a"}]` {
		t.Fatalf("load: %q %v", got, err)
	}
	// The store must hold its own copy: mutating the caller's slice afterwards
	// cannot rewrite stored state.
	payload[2] = 'X'
	got, _ = Load("/data/things.json")
	if string(got) != `[{"id":"a"}]` {
		t.Fatalf("stored bytes aliased the caller's slice: %q", got)
	}
	got[2] = 'Y'
	got2, _ := Load("/data/things.json")
	if string(got2) != `[{"id":"a"}]` {
		t.Fatalf("returned bytes aliased stored state: %q", got2)
	}
}

func TestMemKVPrefixCapability(t *testing.T) {
	t.Cleanup(UseFile)
	UseMemory()
	pb, ok := ActivePrefix()
	if !ok {
		t.Fatal("the memory backend must offer the per-record capability like the two production backends")
	}
	for _, k := range []string{"/data/devices.json.d/a", "/data/devices.json.d/b", "/data/other.json"} {
		if err := pb.Save(k, []byte(`{}`)); err != nil {
			t.Fatalf("save %s: %v", k, err)
		}
	}
	recs, err := pb.LoadPrefix("/data/devices.json.d/")
	if err != nil || len(recs) != 2 {
		t.Fatalf("LoadPrefix: %d records, err %v", len(recs), err)
	}
	if err := pb.Delete("/data/devices.json.d/a"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := pb.Delete("/data/devices.json.d/a"); err != nil {
		t.Fatalf("deleting an absent record must be idempotent: %v", err)
	}
	if recs, _ = pb.LoadPrefix("/data/devices.json.d/"); len(recs) != 1 {
		t.Fatalf("after delete: %d records", len(recs))
	}
}

func TestHealthOnNonPostgresBackends(t *testing.T) {
	t.Cleanup(func() { UseFile(); SetFileRoot("") })

	UseMemory()
	if ok, reason := Health(context.Background()); !ok || reason != "" {
		t.Fatalf("memory backend health: %v %q", ok, reason)
	}

	UseFile()
	SetFileRoot(t.TempDir())
	if ok, _ := Health(context.Background()); !ok {
		t.Fatal("an existing data root must read healthy")
	}
	SetFileRoot("/nonexistent-data-root-for-tracker-245")
	ok, reason := Health(context.Background())
	if ok || reason == "" {
		t.Fatal("a missing data volume must be reported, not assumed healthy")
	}
}
