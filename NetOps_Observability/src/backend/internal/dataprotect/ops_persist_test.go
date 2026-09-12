// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package dataprotect

import (
	"os"
	"path/filepath"
	"testing"
)

// blockDirWrites makes `dir` read-only so the next WriteFileAtomic fails at its
// temp-file creation, the way a full or read-only volume does. Reads still
// work, so the history already on disk stays visible.
func blockDirWrites(t *testing.T, dir string) func() {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root: a read-only directory does not block writes")
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("blocking %s: %v", dir, err)
	}
	restore := func() {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatalf("unblocking %s: %v", dir, err)
		}
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	return restore
}

// TestBeginWhosePersistFailsLosesNoDurableHistory settles tracker 282's
// dataprotect entry. The ring registers the operation in memory and only then
// tries to persist, which reads like the mutate-then-flush shape that lost rows
// elsewhere. It is not: begin only ever PREPENDS, so the ring after a failed
// persist is a state the next successful persist would have reached anyway.
// Nothing on disk is dropped by the failure, and the operation the caller is
// about to run stays visible to a poller — which is the whole reason the ring
// registers first and reports the persist error through the log instead of
// refusing the operation.
func TestBeginWhosePersistFailsLosesNoDurableHistory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ops.json")
	ring := &opsRing{path: path}

	first, conflict, ok := ring.begin(OpKindSnapshotCreate, "alice", OperationTarget{Snapshot: "snap-1"})
	if !ok {
		t.Fatalf("begin(create) refused, conflict=%q", conflict)
	}
	ring.finish(first.ID, func(o *Operation) { o.State = OpStateSucceeded })

	restore := blockDirWrites(t, dir)
	second, conflict, ok := ring.begin(OpKindSnapshotVerify, "bob", OperationTarget{Snapshot: "snap-1"})
	if !ok {
		t.Fatalf("begin(verify) refused with the write path broken, conflict=%q — it must never refuse an operation because the history could not be written", conflict)
	}
	// The running operation is visible even though its registration was not
	// persisted: a poller asking about the id it was just handed gets an answer.
	if _, found := ring.get(second.ID); !found {
		t.Fatal("the operation the caller is running is not in the ring")
	}
	if _, found := ring.get(first.ID); !found {
		t.Fatal("in memory: the earlier successful operation was dropped by a failed persist")
	}
	restore()

	ring.finish(second.ID, func(o *Operation) { o.State = OpStateFailed })

	reloaded := &opsRing{path: path}
	byID := map[string]Operation{}
	for _, op := range reloaded.list() {
		byID[op.ID] = op
	}
	if got, found := byID[first.ID]; !found || got.State != OpStateSucceeded {
		t.Fatalf("on disk: the earlier successful operation reads %+v, want it present and succeeded", got)
	}
	if got, found := byID[second.ID]; !found || got.State != OpStateFailed {
		t.Fatalf("on disk: the operation whose registration failed to persist reads %+v, want it present and failed", got)
	}
}
