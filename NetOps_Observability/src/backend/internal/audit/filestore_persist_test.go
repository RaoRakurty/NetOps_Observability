package audit

// filestore_persist_test.go — D-11. The live api logged, on repeat:
//
//	{"component":"audit","error":"rename /data/audit.json.tmp /data/audit.json:
//	 no such file or directory","msg":"audit trail not persisted; events survive
//	 in memory only"}
//
// Record runs on essentially every authenticated request, so FileStore is the
// heaviest concurrent writer of a single kv key in the process. Two defects
// combined: FileKV.Save's FIXED temp path (fixed in platformdb) and record()
// marshalling under mu but Saving OUTSIDE it, which let an OLDER snapshot land
// after a newer one. Net effect: the trail — including the Iris `ai` tool lines
// and the `sensitive`-tagged protocol-diagnostics rows — did not survive an api
// restart on STORE_BACKEND=file.
//
// These tests drive a REAL FileKV over a temp dir and prove the trail reloads
// into a NEW FileStore (the "survives restart" proof), and that the reloaded
// trail is still tenant-scoped (CLAUDE.md §3a rule 5).

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"netops/backend/internal/platformdb"
)

func TestFileStoreConcurrentRecordsAllSurviveARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	kv := platformdb.FileKV{}

	s, err := NewFileStore(path, kv)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	const goroutines, perGoroutine = 16, 25
	const want = goroutines * perGoroutine
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				s.Record(Event{
					Actor:    fmt.Sprintf("actor-%d", g),
					Tenant:   "acme",
					Method:   "POST",
					Path:     fmt.Sprintf("/api/x/%d/%d", g, i),
					Status:   200,
					Decision: "allow",
				})
			}
		}(g)
	}
	wg.Wait()

	if got := s.Count("acme", false, Query{}); got != want {
		t.Fatalf("in-memory ring holds %d events, want %d", got, want)
	}

	// Restart: a NEW store over the SAME path sees only what was PERSISTED.
	reloaded, err := NewFileStore(path, kv)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := reloaded.Count("acme", false, Query{}); got != want {
		t.Fatalf("reloaded trail holds %d of %d events — writes were lost between "+
			"the temp-file rename race and the out-of-order snapshot Save (D-11)", got, want)
	}

	// Every recorded path is present exactly once: no snapshot regression
	// silently truncated the tail.
	seen := map[string]int{}
	page, err := reloaded.List("acme", false, Query{Limit: MaxQueryLimit})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, e := range page {
		seen[e.Path]++
	}
	for g := 0; g < goroutines; g++ {
		for i := 0; i < perGoroutine; i++ {
			p := fmt.Sprintf("/api/x/%d/%d", g, i)
			if seen[p] != 1 {
				t.Fatalf("event %s appears %d times in the reloaded trail, want 1", p, seen[p])
			}
		}
	}
}

// CLAUDE.md §3a rule 5: the isolation test ships with the feature. A reloaded
// trail must scope exactly like a live one — a restart must not turn the audit
// read into a cross-tenant leak.
func TestReloadedFileStoreIsTenantScoped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.json")
	kv := platformdb.FileKV{}

	s, err := NewFileStore(path, kv)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	const aCount, bCount = 7, 5
	for i := 0; i < aCount; i++ {
		s.Record(Event{Actor: "alice", Tenant: "tenant-a", Method: "GET", Path: "/api/a", Status: 200, Decision: "allow"})
	}
	for i := 0; i < bCount; i++ {
		s.Record(Event{Actor: "bob", Tenant: "tenant-b", Method: "GET", Path: "/api/b", Status: 200, Decision: "allow"})
	}

	reloaded, err := NewFileStore(path, kv)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}

	// Scoped principal of tenant-a: own rows ONLY.
	aPage, err := reloaded.List("tenant-a", false, Query{Limit: MaxQueryLimit})
	if err != nil {
		t.Fatalf("list as tenant-a: %v", err)
	}
	if len(aPage) != aCount {
		t.Fatalf("tenant-a sees %d rows, want %d", len(aPage), aCount)
	}
	for _, e := range aPage {
		if e.Tenant != "tenant-a" {
			t.Fatalf("CROSS-TENANT LEAK: tenant-a's page carries a %q row (%s)", e.Tenant, e.Path)
		}
	}
	if got := reloaded.Count("tenant-a", false, Query{}); got != len(aPage) {
		t.Fatalf("Count(%d) disagrees with List(%d) for tenant-a", got, len(aPage))
	}

	// Scoped principal of tenant-b: symmetric.
	bPage, err := reloaded.List("tenant-b", false, Query{Limit: MaxQueryLimit})
	if err != nil {
		t.Fatalf("list as tenant-b: %v", err)
	}
	if len(bPage) != bCount {
		t.Fatalf("tenant-b sees %d rows, want %d", len(bPage), bCount)
	}
	for _, e := range bPage {
		if e.Tenant != "tenant-b" {
			t.Fatalf("CROSS-TENANT LEAK: tenant-b's page carries a %q row (%s)", e.Tenant, e.Path)
		}
	}
	if got := reloaded.Count("tenant-b", false, Query{}); got != len(bPage) {
		t.Fatalf("Count(%d) disagrees with List(%d) for tenant-b", got, len(bPage))
	}

	// The platform owner (cross) sees both.
	all, err := reloaded.List("", true, Query{Limit: MaxQueryLimit})
	if err != nil {
		t.Fatalf("cross list: %v", err)
	}
	if len(all) != aCount+bCount {
		t.Fatalf("cross-tenant read sees %d rows, want %d", len(all), aCount+bCount)
	}
	if got := reloaded.Count("", true, Query{}); got != len(all) {
		t.Fatalf("cross Count(%d) disagrees with List(%d)", got, len(all))
	}

	// An unknown tenant sees nothing — default-closed.
	none, err := reloaded.List("tenant-c", false, Query{Limit: MaxQueryLimit})
	if err != nil {
		t.Fatalf("list as tenant-c: %v", err)
	}
	if len(none) != 0 {
		t.Fatalf("an unrelated tenant sees %d rows, want 0", len(none))
	}
}
