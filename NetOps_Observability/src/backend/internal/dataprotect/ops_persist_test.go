// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package dataprotect

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// TestAFailureBurstDoesNotEvictTheSuccessfulHistory settles the last open entry
// on tracker 282. The ring is the only record of what was done to the snapshot
// repository, and it was one plain newest-first queue shared by both outcomes:
// operations that failed in MILLISECONDS — an automation retrying a delete
// against a repository answering 502 — cost a full slot each, so a burst of
// them evicted every create and restore that had actually landed.
//
// Before the fix this test observed 0 of the 500 successful operations left in
// the ring after 500 immediate failures. The forensic question the ring exists
// to answer had no answer at exactly the moment it was being asked.
func TestAFailureBurstDoesNotEvictTheSuccessfulHistory(t *testing.T) {
	ring := &opsRing{} // memory only: this is about eviction, not persistence

	succeeded := map[string]bool{}
	for i := 0; i < OperationsCapacity; i++ {
		op, conflict, ok := ring.begin(OpKindSnapshotCreate, "alice", OperationTarget{Snapshot: "snap"})
		if !ok {
			t.Fatalf("begin #%d refused, conflict=%q", i, conflict)
		}
		ring.finish(op.ID, func(o *Operation) { o.State = OpStateSucceeded })
		succeeded[op.ID] = true
	}
	if got := len(ring.list()); got != OperationsCapacity {
		t.Fatalf("the ring holds %d successful operations, want it full at %d", got, OperationsCapacity)
	}

	for i := 0; i < OperationsCapacity; i++ {
		op, conflict, ok := ring.begin(OpKindSnapshotDelete, "automation", OperationTarget{Snapshot: "snap"})
		if !ok {
			t.Fatalf("begin(delete) #%d refused, conflict=%q", i, conflict)
		}
		ring.finish(op.ID, func(o *Operation) {
			o.State, o.Error = OpStateFailed, "repository answered 502"
		})
	}

	list := ring.list()
	if len(list) > OperationsCapacity {
		t.Fatalf("the ring grew to %d, want it bounded at %d", len(list), OperationsCapacity)
	}
	kept, failures := 0, 0
	for _, op := range list {
		if succeeded[op.ID] {
			kept++
		}
		if op.State == OpStateFailed {
			failures++
		}
	}
	// One ring slot always belongs to the operation in flight, which has no
	// outcome yet, so a settled class floors one below the reserve.
	if want := operationsOutcomeReserve - 1; kept < want {
		t.Fatalf("%d of %d successful operations survived a burst of %d immediate failures, want at least %d — a failure burst must not erase what actually happened to the repository",
			kept, OperationsCapacity, OperationsCapacity, want)
	}
	if failures == 0 {
		t.Fatal("the burst left no failure in the ring at all — the failures are history too")
	}
}

// TestASuccessBurstDoesNotEvictTheFailureHistory is the symmetric half: the
// share is a floor for BOTH outcomes, so a run of routine nightly successes
// cannot bury the failed restores an operator is trying to explain.
func TestASuccessBurstDoesNotEvictTheFailureHistory(t *testing.T) {
	ring := &opsRing{}

	failed := map[string]bool{}
	for i := 0; i < OperationsCapacity; i++ {
		op, _, ok := ring.begin(OpKindSnapshotRestore, "alice", OperationTarget{Snapshot: "snap"})
		if !ok {
			t.Fatalf("begin(restore) #%d refused", i)
		}
		ring.finish(op.ID, func(o *Operation) { o.State, o.Error = OpStateFailed, "blob tree missing" })
		failed[op.ID] = true
	}
	for i := 0; i < OperationsCapacity; i++ {
		op, _, ok := ring.begin(OpKindSnapshotCreate, "system", OperationTarget{Snapshot: "snap"})
		if !ok {
			t.Fatalf("begin(create) #%d refused", i)
		}
		ring.finish(op.ID, func(o *Operation) { o.State = OpStateSucceeded })
	}

	kept := 0
	for _, op := range ring.list() {
		if failed[op.ID] {
			kept++
		}
	}
	if want := operationsOutcomeReserve - 1; kept < want {
		t.Fatalf("%d failed operations survived a burst of %d successes, want at least %d",
			kept, OperationsCapacity, want)
	}
}

// TestTrimOperationsKeepsTheRingNewestFirst pins the ordering contract the whole
// surface reads on: whichever class gives up slots, it gives up its OLDEST, and
// what is left is still newest-first.
func TestTrimOperationsKeepsTheRingNewestFirst(t *testing.T) {
	ops := make([]Operation, 0, OperationsCapacity+10)
	for i := 0; i < OperationsCapacity+10; i++ {
		state := OpStateSucceeded
		if i%2 == 0 {
			state = OpStateFailed
		}
		ops = append(ops, Operation{ID: "op-" + strconv.Itoa(i), State: state})
	}
	got := trimOperations(ops)
	if len(got) != OperationsCapacity {
		t.Fatalf("trim left %d, want %d", len(got), OperationsCapacity)
	}
	// Ids were minted newest-first (index 0 is newest), so the surviving ids must
	// stay in ascending index order.
	prev := -1
	for _, op := range got {
		n, err := strconv.Atoi(strings.TrimPrefix(op.ID, "op-"))
		if err != nil {
			t.Fatalf("unexpected id %q", op.ID)
		}
		if n <= prev {
			t.Fatalf("id %d came after %d — the trim reordered the ring", n, prev)
		}
		prev = n
	}
}
