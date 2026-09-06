// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package dataprotect

// ops_test.go — the snapshot surface's own behaviour, tested against the
// module directly.
//
// THREE THINGS ARE UNDER TEST, matching the three ways this surface could hurt
// someone:
//
//  1. THE GRAMMARS. Everything a browser can send is matched against a closed
//     grammar before it reaches a repository path — including the path-traversal
//     shapes (`../..`, `a/b`) that a name-shaped string could otherwise smuggle
//     into a URL.
//
//  2. THE OPERATIONS. One slot, a persisted ring, and an operation that was in
//     flight when the process died must never read as "still running".
//
//  3. THE PROBE. It must actually restore, actually compare counts, and ALWAYS
//     delete its temporary index — including when the comparison fails and
//     including when the delete itself fails (which must surface in Detail, not
//     vanish).
//
// The GATE is not tested here: it is injected, and the integrator's own route
// tests assert that the platform-admin gate refuses a tenant admin BEFORE any
// OpenSearch call. There is deliberately NO org-isolation test either — this is
// platform-global plumbing, not tenant data (CLAUDE.md §3a rule 3).

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ── 1. the grammars ─────────────────────────────────────────────────────────

func TestSnapshotNameGrammarRefusesTraversal(t *testing.T) {
	h := newHarness(t, newOSStub())

	// Every one of these is a name-SHAPED string that must never reach a
	// repository path. `../..` and `a/b` are the traversal cases; the rest are
	// the shapes a permissive check would let slip.
	bad := []string{
		"../..", "a/b", "../../etc/passwd", "netops-daily/../x", "UPPER",
		"", " ", "-leading-dash", ".dotfile", "name with space", "name?query=1",
		"name#frag", "name%2e%2e", "x" + strings.Repeat("y", 200),
	}
	for _, name := range bad {
		st, b := h.do(t, "POST", "/api/system/backup/snapshots/delete",
			map[string]any{"snapshot": name, "confirm": name})
		if st != 400 {
			t.Errorf("delete %q: got %d, want 400 (%s)", name, st, b)
		}
		st, b = h.do(t, "POST", "/api/system/backup/snapshots/restore", map[string]any{"snapshot": name})
		if st != 400 {
			t.Errorf("restore %q: got %d, want 400 (%s)", name, st, b)
		}
	}
	if h.stub.sent("../") {
		t.Fatal("a traversal string reached OpenSearch")
	}
}

func TestSnapshotDeleteUnknownSnapshotIs404(t *testing.T) {
	h := newHarness(t, newOSStub())
	// Grammar-valid but absent from the repository.
	st, b := h.do(t, "POST", "/api/system/backup/snapshots/delete",
		map[string]any{"snapshot": "netops-daily-1999-01-01", "confirm": "netops-daily-1999-01-01"})
	if st != 404 {
		t.Fatalf("unknown snapshot: %d %s", st, b)
	}
	if !strings.Contains(string(b), "no such snapshot in repository netops-fs") {
		t.Errorf("the 404 must name the repository it looked in: %s", b)
	}
}

func TestSnapshotDeleteRequiresTypeToConfirm(t *testing.T) {
	h := newHarness(t, newOSStub())
	const name = "netops-daily-2026-09-02"

	// No confirm at all.
	st, b := h.do(t, "POST", "/api/system/backup/snapshots/delete", map[string]any{"snapshot": name})
	if st != 400 || !strings.Contains(string(b), "confirm must equal") {
		t.Errorf("missing confirm: %d %s", st, b)
	}
	// Mismatched confirm.
	st, b = h.do(t, "POST", "/api/system/backup/snapshots/delete",
		map[string]any{"snapshot": name, "confirm": name + "x"})
	if st != 400 {
		t.Errorf("mismatched confirm: %d %s", st, b)
	}
	if h.stub.sent("DELETE /_snapshot/netops-fs/") {
		t.Fatal("an unconfirmed delete already reached OpenSearch")
	}

	// Matching confirm: 202 and the upstream DELETE is actually issued.
	st, b = h.do(t, "POST", "/api/system/backup/snapshots/delete",
		map[string]any{"snapshot": name, "confirm": name})
	if st != 202 {
		t.Fatalf("confirmed delete: %d %s", st, b)
	}
	h.waitForOperation(t, h.operationFrom(t, b).ID)
	if !h.stub.sent("DELETE /_snapshot/netops-fs/" + name) {
		t.Error("the confirmed delete never issued the upstream DELETE")
	}
}

func TestSnapshotRestoreModesAndPrefix(t *testing.T) {
	h := newHarness(t, newOSStub())
	const name = "netops-daily-2026-09-02"

	// Bad mode.
	if st, _ := h.do(t, "POST", "/api/system/backup/snapshots/restore",
		map[string]any{"snapshot": name, "mode": "obliterate"}); st != 400 {
		t.Errorf("bad mode must 400, got %d", st)
	}
	// Bad prefix — anything outside the granted restored-* namespace.
	for _, prefix := range []string{"netops-", "restored", "restored-../x", "restored-UP", "x-restored-"} {
		if st, _ := h.do(t, "POST", "/api/system/backup/snapshots/restore",
			map[string]any{"snapshot": name, "rename_prefix": prefix}); st != 400 {
			t.Errorf("prefix %q must 400, got %d", prefix, st)
		}
	}
	// An index not present in the snapshot, named in the error.
	st, b := h.do(t, "POST", "/api/system/backup/snapshots/restore",
		map[string]any{"snapshot": name, "indices": []string{"netops-flows-1999.01.01"}})
	if st != 400 || !strings.Contains(string(b), "netops-flows-1999.01.01") {
		t.Errorf("unknown index: %d %s", st, b)
	}
	// A malformed index name.
	if st, _ = h.do(t, "POST", "/api/system/backup/snapshots/restore",
		map[string]any{"snapshot": name, "indices": []string{"a/b"}}); st != 400 {
		t.Errorf("bad index name must 400, got %d", st)
	}
	// in_place without confirm.
	st, b = h.do(t, "POST", "/api/system/backup/snapshots/restore",
		map[string]any{"snapshot": name, "mode": "in_place"})
	if st != 400 || !strings.Contains(string(b), "type-to-confirm") {
		t.Errorf("in_place without confirm: %d %s", st, b)
	}

	// The DEFAULT is renamed, and it issues rename_pattern/rename_replacement
	// with the validated prefix.
	st, b = h.do(t, "POST", "/api/system/backup/snapshots/restore",
		map[string]any{"snapshot": name, "indices": []string{"netops-syslog-2026.09.02"}})
	if st != 202 {
		t.Fatalf("default restore: %d %s", st, b)
	}
	op := h.operationFrom(t, b)
	if op.Target.Mode != RestoreModeRenamed || op.Target.RenamePrefix != DefaultRestorePrefix {
		t.Errorf("default mode/prefix: %+v", op.Target)
	}
	final := h.waitForOperation(t, op.ID)
	if final.State != OpStateSucceeded {
		t.Fatalf("restore state %s: %s", final.State, final.Error)
	}
	body := h.stub.body("POST /_snapshot/netops-fs/" + name + "/_restore")
	if body == nil {
		t.Fatal("no restore body captured")
	}
	if body["rename_pattern"] != "(.+)" || body["rename_replacement"] != "restored-$1" {
		t.Errorf("rename not applied: %v", body)
	}
	if body["indices"] != "netops-syslog-2026.09.02" {
		t.Errorf("indices not applied: %v", body["indices"])
	}
	if got, _ := body["include_global_state"].(bool); got {
		t.Error("include_global_state must be false")
	}
	if len(final.RestoredIndices) != 1 || final.RestoredIndices[0] != "restored-netops-syslog-2026.09.02" {
		t.Errorf("restored_indices: %v", final.RestoredIndices)
	}
}

func TestSnapshotRestoreInPlaceClosesAndReopens(t *testing.T) {
	h := newHarness(t, newOSStub())
	const name = "netops-daily-2026-09-02"

	st, b := h.do(t, "POST", "/api/system/backup/snapshots/restore", map[string]any{
		"snapshot": name, "mode": "in_place", "confirm": name,
		"indices": []string{"netops-syslog-2026.09.02"},
	})
	if st != 202 {
		t.Fatalf("in_place restore: %d %s", st, b)
	}
	op := h.waitForOperation(t, h.operationFrom(t, b).ID)
	if op.State != OpStateSucceeded {
		t.Fatalf("in_place state %s: %s", op.State, op.Error)
	}
	if !h.stub.sent("POST /netops-syslog-2026.09.02/_close") {
		t.Error("in_place must CLOSE the target index first — OpenSearch refuses to restore over an open index")
	}
	if !h.stub.sent("POST /netops-syslog-2026.09.02/_open") {
		t.Error("in_place must REOPEN the index — leaving it closed silently is the failure mode this guards")
	}
	if body := h.stub.body("POST /_snapshot/netops-fs/" + name + "/_restore"); body["rename_pattern"] != nil {
		t.Errorf("in_place must not rename: %v", body)
	}
}

func TestSnapshotRestoreFailureReopensAndSaysSo(t *testing.T) {
	stub := newOSStub()
	stub.failRestore = true
	h := newHarness(t, stub)
	const name = "netops-daily-2026-09-02"

	st, b := h.do(t, "POST", "/api/system/backup/snapshots/restore", map[string]any{
		"snapshot": name, "mode": "in_place", "confirm": name,
		"indices": []string{"netops-syslog-2026.09.02"},
	})
	if st != 202 {
		t.Fatalf("in_place restore: %d %s", st, b)
	}
	op := h.waitForOperation(t, h.operationFrom(t, b).ID)
	if op.State != OpStateFailed {
		t.Fatalf("state %s, want failed", op.State)
	}
	if !strings.Contains(op.Error, "restore step failed") {
		t.Errorf("the failing STEP must be named: %q", op.Error)
	}
	if !strings.Contains(op.Error, "reopened successfully") {
		t.Errorf("the reopen outcome must be recorded — an index left closed silently is the worst case: %q", op.Error)
	}
	// The upstream failure text must survive into the error: the 2026-08-27
	// window was diagnosable ONLY from the body, not the status line.
	if !strings.Contains(op.Error, "repository_missing_exception") {
		t.Errorf("the cluster's own reason must be carried, not thrown away: %q", op.Error)
	}
}

func TestSnapshotCreateGeneratesItsOwnName(t *testing.T) {
	h := newHarness(t, newOSStub())

	// A client-supplied name is simply not in the contract — anything it sends
	// is ignored, and the generated name matches the closed grammar.
	st, b := h.do(t, "POST", "/api/system/backup/snapshots/create",
		map[string]any{"note": "before the upgrade", "snapshot": "../evil"})
	if st != 202 {
		t.Fatalf("create: %d %s", st, b)
	}
	op := h.operationFrom(t, b)
	if !strings.HasPrefix(op.Target.Snapshot, "netops-manual-") {
		t.Errorf("generated name: %q", op.Target.Snapshot)
	}
	if !ValidSnapshotName(op.Target.Snapshot) {
		t.Errorf("generated name violates its own grammar: %q", op.Target.Snapshot)
	}
	if strings.Contains(op.Target.Snapshot, "evil") {
		t.Fatal("a client-supplied name leaked into the generated one")
	}
	h.waitForOperation(t, op.ID)
	if !h.stub.sent("PUT /_snapshot/netops-fs/" + op.Target.Snapshot) {
		t.Error("the create never issued the upstream PUT")
	}

	// Note bounds.
	if st, _ = h.do(t, "POST", "/api/system/backup/snapshots/create",
		map[string]any{"note": strings.Repeat("x", 201)}); st != 400 {
		t.Errorf("over-long note must 400, got %d", st)
	}
	if st, _ = h.do(t, "POST", "/api/system/backup/snapshots/create",
		map[string]any{"note": "line\nbreak"}); st != 400 {
		t.Errorf("control char in note must 400, got %d", st)
	}
}

// ── 2. operations ───────────────────────────────────────────────────────────

func TestOperationsPollableAndUnknownIs404(t *testing.T) {
	h := newHarness(t, newOSStub())

	st, b := h.do(t, "POST", "/api/system/backup/snapshots/create", map[string]any{})
	if st != 202 {
		t.Fatalf("create: %d %s", st, b)
	}
	op := h.operationFrom(t, b)
	if !ValidOperationID(op.ID) {
		t.Fatalf("operation id %q does not match its own grammar", op.ID)
	}
	st, b = h.do(t, "GET", "/api/system/backup/operations/"+op.ID, nil)
	if st != 200 {
		t.Fatalf("poll: %d %s", st, b)
	}
	var polled Operation
	if err := json.Unmarshal(b, &polled); err != nil || polled.ID != op.ID {
		t.Fatalf("polled operation: %v %s", err, b)
	}
	h.waitForOperation(t, op.ID)
	for _, bad := range []string{"op-zzzz", "../../etc/passwd", "op-00112233445566778899", ""} {
		if st, _ = h.do(t, "GET", "/api/system/backup/operations/"+bad, nil); st != 404 {
			t.Errorf("unknown id %q: got %d, want 404", bad, st)
		}
	}
	// The list carries the ring capacity and the restart caveat.
	st, b = h.do(t, "GET", "/api/system/backup/operations", nil)
	if st != 200 {
		t.Fatalf("list: %d %s", st, b)
	}
	var list OperationListView
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatalf("list decode: %v", err)
	}
	if list.Capacity != OperationsCapacity || len(list.Operations) == 0 {
		t.Errorf("list: capacity %d, %d operations", list.Capacity, len(list.Operations))
	}
	if !strings.Contains(list.Detail, "survive an api restart") || !strings.Contains(list.Detail, "beyond the cap are gone") {
		t.Errorf("the list must state exactly what survives a restart and what does not: %q", list.Detail)
	}
}

func TestSecondOperationWhileOneRunsIs409(t *testing.T) {
	stub := newOSStub()
	stub.blockRestore = make(chan struct{})
	h := newHarness(t, stub)
	const name = "netops-daily-2026-09-02"

	st, b := h.do(t, "POST", "/api/system/backup/snapshots/restore", map[string]any{"snapshot": name})
	if st != 202 {
		t.Fatalf("first restore: %d %s", st, b)
	}
	first := h.operationFrom(t, b)

	// A second long operation while the first holds the slot.
	st, b = h.do(t, "POST", "/api/system/backup/snapshots/verify", map[string]any{})
	if st != 409 {
		t.Fatalf("second operation: got %d, want 409 (%s)", st, b)
	}
	if !strings.Contains(string(b), first.ID) {
		t.Errorf("the 409 must name the operation holding the slot: %s", b)
	}
	close(stub.blockRestore)
	h.waitForOperation(t, first.ID)

	// The slot is released once it ends.
	if st, b = h.do(t, "POST", "/api/system/backup/snapshots/create", map[string]any{}); st != 202 {
		t.Fatalf("after release: %d %s", st, b)
	}
	h.waitForOperation(t, h.operationFrom(t, b).ID)
}

// TestOperationHistorySurvivesARestart — the ring is the incident record. A
// 50-entry in-memory ring that dies with the process cannot answer "what was
// done to the repository during the window", which is the whole reason this
// surface exists.
func TestOperationHistorySurvivesARestart(t *testing.T) {
	h := newHarness(t, newOSStub())

	st, b := h.do(t, "POST", "/api/system/backup/snapshots/create", map[string]any{"note": "pre-upgrade"})
	if st != 202 {
		t.Fatalf("create: %d %s", st, b)
	}
	op := h.operationFrom(t, b)
	h.waitForOperation(t, op.ID)

	// A SECOND service over the same file is the restart: nothing is shared in
	// memory, so anything it can see came off disk.
	restarted := New(Deps{OpsFile: h.dir + "/snapshot_operations.json"})
	found := false
	for _, o := range restarted.Operations() {
		if o.ID == op.ID {
			found = true
			if o.State != OpStateSucceeded || o.Actor != "admin" {
				t.Errorf("restored operation lost fidelity: %+v", o)
			}
		}
	}
	if !found {
		t.Fatalf("operation %s did not survive the restart", op.ID)
	}

	// An operation that was RUNNING when the process died must not read as
	// still running — a restart is not a completion.
	crashed := `[{"id":"op-00000000deadbeef","kind":"snapshot_restore","state":"running","actor":"admin",` +
		`"started_at":"2026-09-03T01:00:00Z","ended_at":null,"target":{"snapshot":"netops-daily-2026-09-02"}}]`
	if err := os.WriteFile(h.dir+"/snapshot_operations.json", []byte(crashed), 0o600); err != nil {
		t.Fatalf("seed crashed history: %v", err)
	}
	afterCrash := New(Deps{OpsFile: h.dir + "/snapshot_operations.json"})
	ops := afterCrash.Operations()
	if len(ops) != 1 {
		t.Fatalf("expected the seeded operation, got %d", len(ops))
	}
	if ops[0].State != OpStateFailed {
		t.Errorf("an in-flight operation must be reported failed after a restart, got %q", ops[0].State)
	}
	if !strings.Contains(ops[0].Error, "outcome is UNKNOWN") {
		t.Errorf("the unknown outcome must be stated, not implied: %q", ops[0].Error)
	}
	if ops[0].EndedAt == nil {
		t.Error("a terminal operation must carry an end time")
	}
	// And the slot is free — a crashed operation must not wedge the surface.
	if st, b = h.do(t, "POST", "/api/system/backup/snapshots/create", map[string]any{}); st != 202 {
		t.Fatalf("a restart must not leave the operation slot held: %d %s", st, b)
	}
	h.waitForOperation(t, h.operationFrom(t, b).ID)
}

// ── 3. the probe ────────────────────────────────────────────────────────────

func TestRestorabilityProbeHappyPath(t *testing.T) {
	h := newHarness(t, newOSStub())

	res, err := h.svc.RunRestorabilityProbe(t.Context(), "", func(string) {})
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	// The SMALLEST live index wins (syslog: 42 docs vs flows: 900).
	if res.Index != "netops-syslog-2026.09.02" {
		t.Errorf("probed index %q — the smallest by live doc count must be chosen", res.Index)
	}
	if res.TempIndex != "probe-netops-syslog-2026.09.02" {
		t.Errorf("temp index: %q", res.TempIndex)
	}
	if res.SourceDocs != 42 || res.RestoredDocs != 42 || !res.Match {
		t.Errorf("counts: source=%d restored=%d match=%v", res.SourceDocs, res.RestoredDocs, res.Match)
	}
	if !res.TempDeleted {
		t.Error("temp index must be deleted")
	}
	if !h.stub.sent("DELETE /probe-netops-syslog-2026.09.02") {
		t.Error("the probe never issued the temp-index DELETE")
	}
	body := h.stub.body("POST /_snapshot/netops-fs/netops-daily-2026-09-02/_restore")
	if body["rename_replacement"] != "probe-$1" {
		t.Errorf("probe restore must rename into probe-*: %v", body)
	}
}

func TestRestorabilityProbeMismatchIsNotAMatch(t *testing.T) {
	stub := newOSStub()
	stub.probeCount = 41 // one doc short of the live source
	h := newHarness(t, stub)

	res, err := h.svc.RunRestorabilityProbe(t.Context(), "", func(string) {})
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.Match {
		t.Fatal("41 restored docs against 42 live docs is NOT a match")
	}
	if !res.TempDeleted || !h.stub.sent("DELETE /probe-netops-syslog-2026.09.02") {
		t.Error("a mismatching probe must still delete its temp index")
	}
	if !strings.Contains(res.Detail, "41") || !strings.Contains(res.Detail, "42") {
		t.Errorf("the detail must carry both counts: %q", res.Detail)
	}
}

func TestRestorabilityProbeCleanupFailureSurfaces(t *testing.T) {
	stub := newOSStub()
	stub.failDeleteTemp = true
	h := newHarness(t, stub)

	res, err := h.svc.RunRestorabilityProbe(t.Context(), "", func(string) {})
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.TempDeleted {
		t.Error("TempDeleted must be false when the delete failed")
	}
	if !strings.Contains(res.Detail, "could NOT be deleted") {
		t.Errorf("a failed cleanup must surface in Detail, never be swallowed: %q", res.Detail)
	}
	if !h.stub.sent("DELETE /probe-netops-syslog-2026.09.02") {
		t.Error("the DELETE must still be ATTEMPTED")
	}
}

func TestRestorabilityProbeWithNoLiveIndexIsUnverifiable(t *testing.T) {
	stub := newOSStub()
	stub.liveDocs = map[string]int64{} // nothing from the snapshot still exists
	h := newHarness(t, stub)

	res, err := h.svc.RunRestorabilityProbe(t.Context(), "", func(string) {})
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if res.SourceDocs != -1 {
		t.Errorf("SourceDocs must be -1 when there is no comparable source, got %d", res.SourceDocs)
	}
	if res.Match {
		t.Fatal("UNVERIFIABLE IS NOT VERIFIED — Match must be false")
	}
	if !strings.Contains(res.Detail, "could not be compared") {
		t.Errorf("detail must explain why: %q", res.Detail)
	}
	// The smallest by SNAPSHOT SIZE (syslog: 10 bytes vs flows: 999).
	if res.Index != "netops-syslog-2026.09.02" {
		t.Errorf("fallback picked %q", res.Index)
	}
}

func TestVerifyOperationRecordsTheVerdict(t *testing.T) {
	h := newHarness(t, newOSStub())

	st, b := h.do(t, "POST", "/api/system/backup/snapshots/verify", map[string]any{})
	if st != 202 {
		t.Fatalf("verify: %d %s", st, b)
	}
	op := h.waitForOperation(t, h.operationFrom(t, b).ID)
	if op.State != OpStateSucceeded {
		t.Fatalf("verify state %s: %s", op.State, op.Error)
	}
	if op.Verify == nil || !op.Verify.Match {
		t.Fatalf("the operation must carry the VerifyResult: %+v", op.Verify)
	}

	// The verdict is persisted and shows up on the list view.
	st, b = h.do(t, "GET", "/api/system/backup/snapshots/list", nil)
	if st != 200 {
		t.Fatalf("list: %d %s", st, b)
	}
	var list SnapshotListView
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatalf("list decode: %v", err)
	}
	var probed, unprobed *SnapshotView
	for i := range list.Snapshots {
		switch list.Snapshots[i].Name {
		case "netops-daily-2026-09-02":
			probed = &list.Snapshots[i]
		case "netops-daily-2026-09-01":
			unprobed = &list.Snapshots[i]
		}
	}
	if probed == nil || probed.RestorableVerified == nil || !*probed.RestorableVerified {
		t.Fatalf("the probed snapshot must report verified=true: %+v", probed)
	}
	if unprobed == nil || unprobed.RestorableVerified != nil {
		t.Fatalf("an unprobed snapshot must report null, not false: %+v", unprobed)
	}
	if !strings.Contains(unprobed.RestorableDetail, "never probed") {
		t.Errorf("never-probed detail: %q", unprobed.RestorableDetail)
	}
	// The PARTIAL snapshot's shard failure reason must survive to the GUI.
	if len(unprobed.Failures) != 1 || !strings.Contains(unprobed.Failures[0].Reason, "NoSuchFileException") {
		t.Errorf("shard failure reasons must be carried: %+v", unprobed.Failures)
	}
	// And the metric cache moved with it.
	if restorable, at, _ := h.svc.Metrics().Snapshot(); !restorable || at.IsZero() {
		t.Errorf("the probe metric cache was not updated: restorable=%v at=%v", restorable, at)
	}
}

// ── 4. list view shape ──────────────────────────────────────────────────────

func TestSnapshotListShapeAndLimits(t *testing.T) {
	h := newHarness(t, newOSStub())

	for _, bad := range []string{"0", "201", "-1", "abc"} {
		if st, _ := h.do(t, "GET", "/api/system/backup/snapshots/list?limit="+bad, nil); st != 400 {
			t.Errorf("limit=%s must 400, got %d", bad, st)
		}
	}
	st, b := h.do(t, "GET", "/api/system/backup/snapshots/list?limit=1", nil)
	if st != 200 {
		t.Fatalf("list: %d %s", st, b)
	}
	var list SnapshotListView
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list.Snapshots) != 1 || list.Total != 2 {
		t.Errorf("limit not applied: %d shown, total %d", len(list.Snapshots), list.Total)
	}
	if list.Snapshots[0].Name != "netops-daily-2026-09-02" {
		t.Errorf("newest first: %q", list.Snapshots[0].Name)
	}
	if list.Snapshots[0].SizeBytes != nil {
		t.Error("size must be null without ?sizes=1")
	}
	if list.Snapshots[0].SizeDetail == "" {
		t.Error("a null size needs a sibling detail (the honesty rule)")
	}
	if !list.Repository.Registered || list.Repository.Verified != nil {
		t.Errorf("repository: %+v", list.Repository)
	}
	if list.Repository.VerifiedDetail == "" {
		t.Error("a null verified needs a sibling detail")
	}

	// ?sizes=1 measures.
	st, b = h.do(t, "GET", "/api/system/backup/snapshots/list?sizes=1", nil)
	if st != 200 {
		t.Fatalf("sized list: %d %s", st, b)
	}
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if list.Snapshots[0].SizeBytes == nil || *list.Snapshots[0].SizeBytes != 12345 {
		t.Errorf("sizes=1 must measure: %+v", list.Snapshots[0].SizeBytes)
	}
}

// ── 5. audit ────────────────────────────────────────────────────────────────

func TestSnapshotWritesAreAuditedOnBothOutcomes(t *testing.T) {
	h := newHarness(t, newOSStub())

	// DENY: a delete without the confirm token.
	if st, _ := h.do(t, "POST", "/api/system/backup/snapshots/delete",
		map[string]any{"snapshot": "netops-daily-2026-09-02"}); st != 400 {
		t.Fatal("expected the unconfirmed delete to be refused")
	}
	// ALLOW: a create.
	st, b := h.do(t, "POST", "/api/system/backup/snapshots/create", map[string]any{"note": "pre-upgrade"})
	if st != 202 {
		t.Fatalf("create: %d %s", st, b)
	}
	h.waitForOperation(t, h.operationFrom(t, b).ID)

	var sawDeny, sawAllow bool
	for _, e := range h.audit.all() {
		if e.Detail == nil {
			continue
		}
		action, _ := e.Detail["action"].(string)
		if action == "snapshot_delete" && e.Decision == "deny" {
			sawDeny = true
		}
		if action == "snapshot_create" && e.Decision == "allow" {
			sawAllow = true
			if _, ok := e.Detail["operation"]; !ok {
				t.Error("an accepted operation must be attributable to its id in the audit trail")
			}
			if e.Actor != "admin" {
				t.Errorf("the audited actor must be the authenticated subject, got %q", e.Actor)
			}
		}
	}
	if !sawDeny {
		t.Error("a REFUSED snapshot write was not audited — an unrecorded refusal is indistinguishable from one that never happened")
	}
	if !sawAllow {
		t.Error("an ACCEPTED snapshot write was not audited")
	}
}

// ── 6. metrics ──────────────────────────────────────────────────────────────

func TestSnapshotRestorabilityMetrics(t *testing.T) {
	verifiedAt := time.Date(2026, 9, 3, 1, 45, 0, 0, time.UTC)
	successAt := time.Date(2026, 9, 3, 1, 30, 0, 0, time.UTC)

	cases := []struct {
		name      string
		probeOn   bool
		apply     func(m *Metrics)
		wantLines []string
	}{
		{
			name:    "never probed",
			probeOn: true,
			apply:   func(m *Metrics) { m.setLastSuccess(successAt) },
			wantLines: []string{
				`netops_opensearch_snapshot_restorable{repo="netops-fs"} 0`,
				`netops_opensearch_snapshot_restorable_verified_timestamp_seconds{repo="netops-fs"} 0`,
				`netops_opensearch_snapshot_probe_enabled{repo="netops-fs"} 1`,
				`netops_opensearch_snapshot_last_success_timestamp_seconds{repo="netops-fs"} ` + strconv.FormatInt(successAt.Unix(), 10),
			},
		},
		{
			name:    "verified",
			probeOn: true,
			apply: func(m *Metrics) {
				m.setLastSuccess(successAt)
				m.setVerdict(true, verifiedAt)
			},
			wantLines: []string{
				`netops_opensearch_snapshot_restorable{repo="netops-fs"} 1`,
				`netops_opensearch_snapshot_restorable_verified_timestamp_seconds{repo="netops-fs"} ` + strconv.FormatInt(verifiedAt.Unix(), 10),
				`netops_opensearch_snapshot_probe_enabled{repo="netops-fs"} 1`,
			},
		},
		{
			name:    "probe disabled",
			probeOn: false,
			apply:   func(m *Metrics) { m.setVerdict(false, time.Time{}) },
			wantLines: []string{
				`netops_opensearch_snapshot_restorable{repo="netops-fs"} 0`,
				`netops_opensearch_snapshot_probe_enabled{repo="netops-fs"} 0`,
				`netops_opensearch_snapshot_last_success_timestamp_seconds{repo="netops-fs"} 0`,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newMetrics(DefaultRepository, tc.probeOn)
			tc.apply(m)
			var sb strings.Builder
			m.Write(&sb)
			out := sb.String()
			for _, want := range tc.wantLines {
				if !strings.Contains(out, want) {
					t.Errorf("missing %q in:\n%s", want, out)
				}
			}
			for _, help := range []string{
				"# HELP netops_opensearch_snapshot_restorable ",
				"# TYPE netops_opensearch_snapshot_restorable gauge",
				"# TYPE netops_opensearch_snapshot_probe_enabled gauge",
				"# TYPE netops_opensearch_snapshot_last_success_timestamp_seconds gauge",
				"# TYPE netops_opensearch_snapshot_restorable_verified_timestamp_seconds gauge",
			} {
				if !strings.Contains(out, help) {
					t.Errorf("missing %q", help)
				}
			}
		})
	}
}

// ── 7. the worker's decision logic ──────────────────────────────────────────

func TestProbeTickProbesTheNewestUnprobedSuccess(t *testing.T) {
	h := newHarness(t, newOSStub())

	var last time.Time
	h.svc.ProbeTick(t.Context(), 24*time.Hour, &last)
	if !h.stub.sent("DELETE /probe-netops-syslog-2026.09.02") {
		t.Fatal("the first tick must probe the newest unprobed SUCCESS snapshot")
	}
	restorable, at, lastSuccess := h.svc.Metrics().Snapshot()
	if !restorable || at.IsZero() || lastSuccess.IsZero() {
		t.Errorf("cache after a passing probe: %v %v %v", restorable, at, lastSuccess)
	}

	// A second tick must NOT re-probe an already-probed snapshot.
	before := h.stub.hitCount()
	h.svc.ProbeTick(t.Context(), 24*time.Hour, &last)
	if h.stub.hitCount() > before+6 { // the tick still reads the inventory
		t.Error("an already-probed snapshot must not be probed again")
	}
}

func TestProbeTickHonoursTheKillSwitch(t *testing.T) {
	h := newHarness(t, newOSStub(), func(d *Deps) { d.ProbeEnabled = false })

	var last time.Time
	h.svc.ProbeTick(t.Context(), 24*time.Hour, &last)
	if h.stub.sent("/_restore") {
		t.Fatal("ProbeEnabled=false must stop the probe entirely")
	}
	// And the metric must say NOT PROVEN rather than fabricate a pass.
	if restorable, _, _ := h.svc.Metrics().Snapshot(); restorable {
		t.Error("a disabled probe must never report restorable=1")
	}
}

// ── 8. repository headroom ──────────────────────────────────────────────────

// TestRepositoryHeadroomSources — "how many restore points fit" is the
// retention arithmetic behind the incident, and it is unanswerable without
// free/total bytes. Two sources, in order, and an honest null when neither
// works.
func TestRepositoryHeadroomSources(t *testing.T) {
	t.Run("statfs on a mounted repository path", func(t *testing.T) {
		stub := newOSStub()
		stub.repoLocation = t.TempDir() // a path the "container" really has
		h := newHarness(t, stub)
		v := h.svc.RepositoryView(t.Context())
		if v.DiskFreeBytes == nil || v.DiskTotalBytes == nil {
			t.Fatalf("a mounted path must be measured: %+v", v)
		}
		if *v.DiskTotalBytes <= 0 || *v.DiskFreeBytes < 0 || *v.DiskFreeBytes > *v.DiskTotalBytes {
			t.Errorf("implausible headroom: free=%d total=%d", *v.DiskFreeBytes, *v.DiskTotalBytes)
		}
		if !strings.Contains(v.DiskDetail, "statfs") {
			t.Errorf("the source must be stated: %q", v.DiskDetail)
		}
	})

	t.Run("falls back to OpenSearch node fs stats", func(t *testing.T) {
		stub := newOSStub()
		stub.repoLocation = "/definitely-not-mounted-in-this-container"
		stub.nodesFS = &[2]int64{1 << 40, 1 << 39}
		h := newHarness(t, stub)
		v := h.svc.RepositoryView(t.Context())
		if v.DiskTotalBytes == nil || *v.DiskTotalBytes != 1<<40 || v.DiskFreeBytes == nil || *v.DiskFreeBytes != 1<<39 {
			t.Fatalf("node fs stats not used: %+v", v)
		}
		if !strings.Contains(v.DiskDetail, "_nodes/stats/fs") {
			t.Errorf("the fallback must say it is NOT the repository path: %q", v.DiskDetail)
		}
	})

	t.Run("null with a reason when neither source works", func(t *testing.T) {
		stub := newOSStub()
		stub.repoLocation = "/definitely-not-mounted-in-this-container"
		h := newHarness(t, stub) // the stub 403s _nodes/stats/fs, like a role without cluster:monitor
		v := h.svc.RepositoryView(t.Context())
		if v.DiskFreeBytes != nil || v.DiskTotalBytes != nil {
			t.Fatalf("an unmeasurable headroom must be null, never guessed: %+v", v)
		}
		if !strings.Contains(v.DiskDetail, "does not mount") || !strings.Contains(v.DiskDetail, "host") {
			t.Errorf("the detail must say why it is null and where the number can be got: %q", v.DiskDetail)
		}
	})
}
