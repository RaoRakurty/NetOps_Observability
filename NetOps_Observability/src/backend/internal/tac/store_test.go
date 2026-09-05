package tac

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testStore(t *testing.T, opts ...StoreOption) (*Store, string) {
	t.Helper()
	root := t.TempDir()
	s, err := NewStore(filepath.Join(root, "tac"), opts...)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return s, filepath.Join(root, "tac")
}

func fixtureBundle(t *testing.T) *Bundle {
	t.Helper()
	b, err := BuildBundle(t.Context(), fixtureBundleInput(t), nil, fixedClock())
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	return b
}

// TestStoreIsTenantKeyed — one tenant's bundle is not reachable under another's
// key, and the two answers are indistinguishable.
func TestStoreIsTenantKeyed(t *testing.T) {
	s, root := testStore(t)
	b := fixtureBundle(t)
	meta, err := s.Put("tenant-a", "inc-1", b)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, _, err := s.Get("tenant-a", "inc-1", meta.Name); err != nil {
		t.Fatalf("own read: %v", err)
	}
	if _, _, err := s.Get("tenant-b", "inc-1", meta.Name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a foreign tenant read returned %v, want ErrNotFound", err)
	}
	if _, _, err := s.Get("tenant-b", "inc-1", "correlix-tac-nothing-here.zip"); !errors.Is(err, ErrNotFound) {
		t.Fatal("an absent bundle and a foreign one must answer identically")
	}
	list, _ := s.List("tenant-b", "inc-1")
	if len(list) != 0 {
		t.Fatal("a foreign tenant's listing is not empty")
	}
	// The tenant is a path segment, not a filter.
	if _, err := os.Stat(filepath.Join(root, "tenant-a", "inc-1", meta.Name)); err != nil {
		t.Fatalf("bundle is not under the tenant path: %v", err)
	}
}

// TestStorePermissions — 0700 directories, 0600 files.
func TestStorePermissions(t *testing.T) {
	s, root := testStore(t)
	b := fixtureBundle(t)
	meta, _ := s.Put("t1", "inc-1", b)
	di, err := os.Stat(filepath.Join(root, "t1", "inc-1"))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode = %v, want 0700", di.Mode().Perm())
	}
	fi, err := os.Stat(filepath.Join(root, "t1", "inc-1", meta.Name))
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %v, want 0600", fi.Mode().Perm())
	}
}

// TestStoreRefusesUnsafeKeys — traversal never becomes a path.
func TestStoreRefusesUnsafeKeys(t *testing.T) {
	s, _ := testStore(t)
	b := fixtureBundle(t)
	for _, tc := range []struct{ tenant, incident string }{
		{"../etc", "inc"},
		{"t1", "../../etc"},
		{"t1", "inc/../.."},
		{"", "inc"},
		{"t1", ""},
		{"t/1", "inc"},
		{strings.Repeat("t", 200), "inc"},
	} {
		if _, err := s.Put(tc.tenant, tc.incident, b); !errors.Is(err, ErrBadKey) {
			t.Errorf("Put(%q,%q) returned %v, want ErrBadKey", tc.tenant, tc.incident, err)
		}
	}
	// A bundle name that is not a bundle name is refused on both sides.
	bad := *b
	bad.Name = "../../../etc/passwd"
	if _, err := s.Put("t1", "inc", &bad); !errors.Is(err, ErrBadKey) {
		t.Fatalf("an unsafe bundle name was accepted: %v", err)
	}
	if _, _, err := s.Get("t1", "inc", "../../etc/passwd"); !errors.Is(err, ErrNotFound) {
		t.Fatal("an unsafe read name was not refused")
	}
}

// TestStoreRetentionByCount.
func TestStoreRetentionByCount(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	s, _ := testStore(t, WithRetention(3, time.Hour), WithStoreClock(func() time.Time { return now }))
	base := fixtureBundle(t)
	for i := 0; i < 6; i++ {
		b := *base
		b.Name = "correlix-tac-inc-core1-bgp-session-" + itoaTAC(i) + ".zip"
		// Each write is one minute later, so the prune order is deterministic
		// and independent of the filesystem's timestamp resolution.
		now = now.Add(time.Minute)
		if _, err := s.Put("t1", "inc-1", &b); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	list, err := s.List("t1", "inc-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("retention kept %d bundles, want 3", len(list))
	}
}

// TestStoreRetentionByAge.
func TestStoreRetentionByAge(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	_ = clock
	cur := now.Add(-48 * time.Hour)
	s, _ := testStore(t, WithRetention(10, time.Hour), WithStoreClock(func() time.Time { return cur }))
	b := fixtureBundle(t)
	meta, err := s.Put("t1", "inc-1", b)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	// Time moves past the retention window; the next write prunes.
	cur = now
	second := *b
	second.Name = "correlix-tac-inc-core1-bgp-session-2.zip"
	if _, err := s.Put("t1", "inc-1", &second); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, _, err := s.Get("t1", "inc-1", meta.Name); !errors.Is(err, ErrNotFound) {
		t.Fatal("a bundle past the retention age was not pruned")
	}
}

// TestStoreListIsNewestFirst.
func TestStoreListIsNewestFirst(t *testing.T) {
	s, _ := testStore(t)
	base := fixtureBundle(t)
	for i := 0; i < 3; i++ {
		b := *base
		b.Name = "correlix-tac-inc-core1-bgp-session-" + itoaTAC(i) + ".zip"
		if _, err := s.Put("t1", "inc-1", &b); err != nil {
			t.Fatalf("put: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	list, _ := s.List("t1", "inc-1")
	if len(list) != 3 {
		t.Fatalf("list = %d", len(list))
	}
	for i := 1; i < len(list); i++ {
		if list[i-1].CreatedAt.Before(list[i].CreatedAt) {
			t.Fatal("listing is not newest-first")
		}
	}
}
