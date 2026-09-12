// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pipedebug

// bundle_member_bound_test.go — the in-memory bundle bound must refuse an
// oversized member BEFORE it is allocated, not after.
//
// The bound used to be checked on a running total that was only updated once
// os.ReadFile had already pulled the whole member into memory. The refusal was
// therefore correct and useless: a single multi-gigabyte file under the debug
// root (which the documented CLI `logs` flow mounts from the host) was read in
// full into a 512 MiB api container and only then declined. The test measures
// the heap the writer actually consumes, because the ERROR alone was already
// right on the broken code — the allocation is the defect.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// hugeMemberBytes is deliberately far above MaxBundleBytes so the difference
// between "refused on stat" and "refused after reading" is unmistakable in the
// allocation counter. The file is sparse: it costs no disk.
const hugeMemberBytes = 256 << 20

func writeSparse(t *testing.T, path string, size int64) {
	t.Helper()
	f, err := os.Create(path) // #nosec G304 -- test-owned path under t.TempDir()
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	if err := f.Truncate(size); err != nil {
		_ = f.Close()
		t.Fatalf("truncate %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if info.Size() != size {
		t.Fatalf("fixture %s reports %d bytes, want %d", path, info.Size(), size)
	}
}

func TestAnOversizedMemberIsRefusedWithoutBeingRead(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "sess-20260101T000000Z-aaaaaaaa")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "summary.txt"), []byte("small\n"), 0o600); err != nil {
		t.Fatalf("write summary: %v", err)
	}
	writeSparse(t, filepath.Join(dir, "zz-oversized.log"), hugeMemberBytes)

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var buf bytes.Buffer
	_, err := WriteBundleTar(&buf, []string{dir}, MaxBundleBytes)
	runtime.ReadMemStats(&after)

	var tooLarge ErrBundleTooLarge
	if !errors.As(err, &tooLarge) {
		t.Fatalf("WriteBundleTar err = %v, want ErrBundleTooLarge", err)
	}
	if tooLarge.Limit != MaxBundleBytes {
		t.Errorf("refusal names limit %d, want %d", tooLarge.Limit, MaxBundleBytes)
	}
	if tooLarge.Bytes < hugeMemberBytes {
		t.Errorf("refusal names %d bytes, want at least the member's own %d", tooLarge.Bytes, hugeMemberBytes)
	}

	// TotalAlloc is cumulative and GC-independent: it is the number of heap
	// bytes this call asked for. Reading the member would move it by at least
	// the member's size; refusing on stat moves it by a few kilobytes.
	const allowed = 32 << 20
	if grew := after.TotalAlloc - before.TotalAlloc; grew > allowed {
		t.Fatalf("the writer allocated %d bytes for a member it refused (allowed %d, member is %d) — the bound is being checked AFTER the read",
			grew, allowed, int64(hugeMemberBytes))
	}
}

// TestAMemberThatFitsIsStillBundled guards the fix from over-refusing: the
// size gate must reject only what genuinely does not fit in what is left.
func TestAMemberThatFitsIsStillBundled(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "sess-20260101T000000Z-bbbbbbbb")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body := bytes.Repeat([]byte("x"), 4096)
	if err := os.WriteFile(filepath.Join(dir, "api.log"), body, 0o600); err != nil {
		t.Fatalf("write member: %v", err)
	}
	var buf bytes.Buffer
	sums, err := WriteBundleTar(&buf, []string{dir}, MaxBundleBytes)
	if err != nil {
		t.Fatalf("WriteBundleTar: %v", err)
	}
	if !bytes.Contains([]byte(sums), []byte("api.log")) {
		t.Fatalf("SHA256SUMS does not name the member that fits:\n%s", sums)
	}
}

// TestTheUnboundedPathStillReadsEveryMember pins the CLI's on-disk contract:
// limit 0 means unbounded, and the size gate must not fire there.
func TestTheUnboundedPathStillReadsEveryMember(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "sess-20260101T000000Z-cccccccc")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body := bytes.Repeat([]byte("y"), 1<<20)
	if err := os.WriteFile(filepath.Join(dir, "kafka.log"), body, 0o600); err != nil {
		t.Fatalf("write member: %v", err)
	}
	var buf bytes.Buffer
	sums, err := WriteBundleTar(&buf, []string{dir}, 0)
	if err != nil {
		t.Fatalf("WriteBundleTar unbounded: %v", err)
	}
	if !bytes.Contains([]byte(sums), []byte("kafka.log")) {
		t.Fatalf("SHA256SUMS does not name the member:\n%s", sums)
	}
}
