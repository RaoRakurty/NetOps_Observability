// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package dataprotect

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"netops/backend/internal/platformdb"
)

// ops.go — snapshot INVENTORY, snapshot MANAGEMENT and the restorability PROBE,
// plus the bounded async operation runner they all return.
//
// WHY THIS EXISTS (2026-08-27): the netops-fs repository's blob tree was
// deleted out from under a registered repository. OpenSearch kept answering
// with a policy, a schedule and a list of restore points for seven days, and
// every one of those restore points was unrestorable. Nothing in the product
// could tell the difference, because nothing ever tried to restore one.
//
// So the design law here is: A BACKUP THAT HAS NEVER BEEN RESTORED IS NOT A
// PROVEN BACKUP. `restorable_verified` is nil until a probe has actually
// restored a real index out of a real snapshot and compared its doc count to
// the live source, and the metric that vmalert watches reports 0 — "not proven
// restorable" — for "never probed" exactly as it does for "probe failed".
//
// ZERO TRUST (§3). Everything a browser can send is matched against a CLOSED
// grammar before it is allowed anywhere near a repository path:
//   - a snapshot name must match snapshotNameRe AND already exist in the
//     repository (a name that merely parses is still a 404);
//   - an index name must match restoreIndexRe AND be present in that
//     snapshot's own index list;
//   - a rename prefix must match restorePrefixRe, which is scoped to the
//     `restored-` namespace the OpenSearch role actually grants;
//   - a create takes NO client-supplied name at all — it is generated here.
// Nothing is ever interpolated into a URL before it has passed one of those.
//
// ISOLATION (§3a rule 3): every route in this package is platform-GLOBAL
// plumbing behind the injected Gate and is classified "platform" in
// route_isolation_test.go. There is deliberately NO org-isolation test: this
// surface returns no tenant data — it returns the platform's own backup
// posture, which a tenant admin must never see or touch at all.

const (
	// snapshotFailureCap bounds the per-snapshot shard-failure list a response
	// carries. A snapshot of a large cluster can fail thousands of shards; the
	// GUI needs the reasons, not an unbounded payload (§9 bounded everything).
	snapshotFailureCap = 25

	// DefaultRestorePrefix is the namespace a renamed restore lands in. The
	// OpenSearch role grants indices_all on `restored-*` and `probe-*` and
	// nothing else, so a restore cannot overwrite a live index except through
	// the explicitly-confirmed in_place path.
	DefaultRestorePrefix = "restored-"

	// probeIndexPrefix is the disposable namespace the restorability probe
	// restores into. Always deleted afterwards.
	probeIndexPrefix = "probe-"

	// OperationsCapacity is the operation ring size (newest first). Sized to
	// OUTLIVE ONE INCIDENT, not one session: the question this surface has to
	// answer after the fact is "what was done to the repository, by whom, in
	// the window" — a ring that wraps in an afternoon cannot answer it.
	OperationsCapacity = 500

	// snapshotNoteMax bounds the free-text note a create may carry into the
	// audit trail.
	snapshotNoteMax = 200

	// snapshotRestoreMaxIndices bounds an explicit index list on a restore.
	snapshotRestoreMaxIndices = 200

	// SnapshotNeverProbedDetail is the honest answer for a restore point no
	// probe has ever touched. It is NOT "fine".
	SnapshotNeverProbedDetail = "never probed — a backup that has never been restored is not a proven backup"

	// snapshotVerdictCap bounds the persisted probe-verdict file.
	snapshotVerdictCap = 100
)

// Per-kind operation timeouts. The goroutine NEVER uses the request context —
// that context dies with the HTTP response, which would cancel a multi-hour
// restore the instant the browser tab closed (§9 all IO has a timeout, and the
// timeout has to be the operation's, not the poller's).
const (
	snapshotCreateTimeout  = 2 * time.Hour
	snapshotRestoreTimeout = 2 * time.Hour
	snapshotVerifyTimeout  = 30 * time.Minute
	snapshotDeleteTimeout  = 15 * time.Minute
)

// Closed grammars. Compiled once; immutable (the pushTokenRe/cronFieldRe idiom
// already established in config.go).
var (
	// snapshotNameRe is the OpenSearch snapshot-name grammar, narrowed. No
	// slash, no dot-dot, no uppercase, no wildcard: `../..` and `a/b` are
	// rejected by construction rather than by a blocklist.
	snapshotNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)
	// restoreIndexRe is the index-name grammar (no `:` — index names cannot
	// carry one, and allowing it would admit a remote-cluster reference).
	restoreIndexRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,254}$`)
	// restorePrefixRe pins a rename prefix INSIDE the namespace the role
	// grants. Anything else would 403 at the store anyway; refusing it here
	// turns a confusing upstream 403 into an honest 400.
	restorePrefixRe = regexp.MustCompile(`^restored-[a-z0-9-]{0,24}$`)
	// operationIDRe is the opaque operation id shape (contract: Operation.ID).
	operationIDRe = regexp.MustCompile(`^op-[0-9a-f]{16}$`)
)

// ValidSnapshotName reports whether name matches the closed snapshot grammar.
// Exported so an integration test can assert a GENERATED name against the same
// grammar the handlers enforce, without the regexp itself escaping the package.
func ValidSnapshotName(name string) bool { return snapshotNameRe.MatchString(name) }

// ValidOperationID reports whether id matches the opaque operation-id shape.
func ValidOperationID(id string) bool { return operationIDRe.MatchString(id) }

// ── the operation ring ──────────────────────────────────────────────────────

// opsRing is the bounded, persisted operation register. It is a VALUE field on
// *Service (no package-level state, §5) and its zero value is usable, so a
// service built without an explicit construction step still answers honestly
// instead of nil-panicking.
//
// Concurrency policy: ONE slot. Create, restore, verify and delete all
// serialise through `running`. A second request while one is in flight is a
// 409 naming the operation that holds the slot — never a queue (§9 bounded)
// and never two restores racing over the same index namespace.
type opsRing struct {
	mu      sync.Mutex
	ops     []Operation // newest first, capped at OperationsCapacity
	running string      // id of the in-flight operation; "" = idle
	loaded  bool        // the on-disk history has been read
	path    string      // where the history is persisted ("" = memory only)
	log     Logger
	now     func() time.Time
}

func (r *opsRing) logger() Logger {
	if r.log == nil {
		return nopLogger{}
	}
	return r.log
}

func (r *opsRing) clock() time.Time {
	if r.now == nil {
		return time.Now()
	}
	return r.now()
}

// loadLocked reads the persisted history once.
//
// Any operation still marked `running` in the file was in flight when the
// process died. It is transitioned to FAILED with that stated plainly: a
// restart is not a completion, and an operation frozen at "running" forever
// would read as "still working" to every poller (§10).
func (r *opsRing) loadLocked() {
	if r.loaded {
		return
	}
	r.loaded, r.ops = true, nil
	if r.path == "" {
		return
	}
	// #nosec G304 -- `path` is Deps.OpsFile: a deployment-owned env var
	// (SNAPSHOT_OPS_FILE) with a fixed default under the api's own /data mount.
	// It is never reachable from a request body, a query string or a snapshot
	// name — every client-supplied string on this surface is validated against a
	// closed grammar before it is used at all, and none of them reaches here.
	// Same shape and same justification as NewFileConfigStore's read of
	// SYSTEM_BACKUP_FILE in config.go.
	b, err := os.ReadFile(r.path)
	if err != nil {
		if !os.IsNotExist(err) {
			r.logger().Warn("backup.ops", "snapshot operation history unreadable — starting from an empty history",
				map[string]any{"error": err.Error()})
		}
		return
	}
	var ops []Operation
	if err := json.Unmarshal(b, &ops); err != nil {
		r.logger().Warn("backup.ops", "snapshot operation history corrupt — starting from an empty history",
			map[string]any{"error": err.Error()})
		return
	}
	now := r.clock().UTC()
	for i := range ops {
		if ops[i].State != OpStateRunning {
			continue
		}
		ops[i].State = OpStateFailed
		if ops[i].EndedAt == nil {
			ended := now
			ops[i].EndedAt = &ended
		}
		ops[i].Error = strings.TrimSpace(ops[i].Error + " the api restarted while this operation was in flight, " +
			"so its outcome is UNKNOWN — check the snapshot list for what actually landed")
	}
	if len(ops) > OperationsCapacity {
		ops = ops[:OperationsCapacity]
	}
	r.ops = ops
}

// persistLocked writes the history atomically (tmp + rename, 0600), the same
// discipline as the verify file. It RETURNS the error rather than swallowing
// it: a persist that cannot fail leaves its caller unable to tell anyone the
// write never landed (the F-62/F-63/F-78 class).
//
// Callers deliberately do not FAIL the operation on a persist error — losing
// the history is bad, refusing to take a backup because the history could not
// be written would be worse — but they must LOG it, which is why the error has
// to come back out at all.
func (r *opsRing) persistLocked() error {
	if r.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(r.ops, "", "  ")
	if err != nil {
		return err
	}
	return platformdb.WriteFileAtomic(r.path, b, 0o600)
}

// logPersistFailure is the single place the ring reports a lost history, so the
// two call sites cannot drift on the wording an operator greps for.
func (r *opsRing) logPersistFailure(err error) {
	if err == nil {
		return
	}
	r.logger().Error("backup.ops", "snapshot operation history could not be persisted — it will NOT survive an api restart",
		map[string]any{"path": r.path, "error": err.Error()})
}

// begin claims the single slot and registers a running Operation. ok=false
// returns the id of the operation that holds the slot (the 409 body).
func (r *opsRing) begin(kind, actor string, target OperationTarget) (Operation, string, bool) {
	id, err := newOperationID()
	if err != nil {
		// A failure of crypto/rand is not a "try again later" — it is a broken
		// platform, and an operation with a guessable id is worse than none.
		return Operation{}, "", false
	}
	op := Operation{
		ID: id, Kind: kind, State: OpStateRunning, Actor: actor,
		StartedAt: r.clock().UTC(), Target: target,
		Progress: "accepted",
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.loadLocked()
	if r.running != "" {
		return Operation{}, r.running, false
	}
	r.running = id
	r.ops = append([]Operation{op}, r.ops...)
	if len(r.ops) > OperationsCapacity {
		r.ops = r.ops[:OperationsCapacity]
	}
	r.logPersistFailure(r.persistLocked())
	return op, "", true
}

// update mutates one operation in place under the lock.
func (r *opsRing) update(id string, fn func(*Operation)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.ops {
		if r.ops[i].ID == id {
			fn(&r.ops[i])
			return
		}
	}
}

// finish ends an operation and RELEASES the slot. It is called from exactly one
// deferred site per operation, so a panicking operation cannot wedge the slot.
func (r *opsRing) finish(id string, fn func(*Operation)) {
	now := r.clock().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.ops {
		if r.ops[i].ID == id {
			r.ops[i].EndedAt = &now
			fn(&r.ops[i])
		}
	}
	if r.running == id {
		r.running = ""
	}
	r.logPersistFailure(r.persistLocked())
}

// get returns one operation by id.
func (r *opsRing) get(id string) (Operation, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.loadLocked()
	for _, op := range r.ops {
		if op.ID == id {
			return op, true
		}
	}
	return Operation{}, false
}

// list returns a copy of the ring, newest first, never nil.
func (r *opsRing) list() []Operation {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.loadLocked()
	out := make([]Operation, len(r.ops))
	copy(out, r.ops)
	return out
}

// Operations returns the operation register, newest first, never nil.
func (s *Service) Operations() []Operation { return s.ops.list() }

// OperationByID returns one operation.
func (s *Service) OperationByID(id string) (Operation, bool) { return s.ops.get(id) }

// newOperationID mints an opaque id from crypto/rand (never math/rand: an
// operation id is a handle a poller quotes back, and a guessable one is a
// cross-request handle).
func newOperationID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "op-" + hex.EncodeToString(b[:]), nil
}

// runOperation executes one operation body with its OWN context (never the
// request's), a per-kind deadline, panic recovery and a single terminal
// transition. §10: no silent failures — a panic ends the operation `failed`
// with the panic named, it never disappears.
func (s *Service) runOperation(id string, timeout time.Duration, body func(ctx context.Context, progress func(string)) error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	progress := func(msg string) {
		s.ops.update(id, func(op *Operation) { op.Progress = msg })
	}
	var runErr error
	defer func() {
		if rec := recover(); rec != nil {
			runErr = fmt.Errorf("operation panicked: %v", rec)
			s.deps.Log.Error("backup.ops", "snapshot operation panicked", map[string]any{
				"operation": id, "panic": fmt.Sprint(rec),
			})
		}
		s.ops.finish(id, func(op *Operation) {
			if runErr != nil {
				op.State = OpStateFailed
				op.Error = runErr.Error()
				return
			}
			op.State = OpStateSucceeded
		})
	}()
	runErr = body(ctx, progress)
}

// ── OpenSearch snapshot plumbing ────────────────────────────────────────────

// osSnapshotDoc is the subset of one `_snapshot/<repo>/_all` entry we render.
type osSnapshotDoc struct {
	Snapshot    string   `json:"snapshot"`
	State       string   `json:"state"`
	Indices     []string `json:"indices"`
	StartTimeMs int64    `json:"start_time_in_millis"`
	EndTimeMs   int64    `json:"end_time_in_millis"`
	DurationMs  int64    `json:"duration_in_millis"`
	Shards      struct {
		Total      int `json:"total"`
		Failed     int `json:"failed"`
		Successful int `json:"successful"`
	} `json:"shards"`
	Failures []struct {
		Index   string `json:"index"`
		ShardID int    `json:"shard_id"`
		Reason  string `json:"reason"`
	} `json:"failures"`
}

// fetchSnapshots reads the whole repository inventory, newest first.
func (s *Service) fetchSnapshots(ctx context.Context) ([]osSnapshotDoc, error) {
	var body struct {
		Snapshots []osSnapshotDoc `json:"snapshots"`
	}
	if err := s.osDo(ctx, http.MethodGet,
		"/_snapshot/"+s.repo()+"/_all", nil, &body, 30*time.Second); err != nil {
		return nil, err
	}
	out := body.Snapshots
	sort.SliceStable(out, func(i, j int) bool { return out[i].StartTimeMs > out[j].StartTimeMs })
	return out, nil
}

// findSnapshot resolves a CLIENT-SUPPLIED name against the repository. A name
// that merely matches the grammar is not a name that exists: unknown → 404, and
// the caller never gets to name a path segment we did not first read back.
func (s *Service) findSnapshot(ctx context.Context, name string) (osSnapshotDoc, error) {
	docs, err := s.fetchSnapshots(ctx)
	if err != nil {
		return osSnapshotDoc{}, err
	}
	for _, d := range docs {
		if d.Snapshot == name {
			return d, nil
		}
	}
	return osSnapshotDoc{}, &snapshotNotFoundError{repo: s.repo()}
}

// newestSuccessSnapshot picks the newest SUCCESS restore point.
func newestSuccessSnapshot(docs []osSnapshotDoc) (osSnapshotDoc, bool) {
	var best osSnapshotDoc
	found := false
	for _, d := range docs {
		if d.State != "SUCCESS" {
			continue
		}
		if !found || d.EndTimeMs > best.EndTimeMs {
			best, found = d, true
		}
	}
	return best, found
}

// snapshotNotFoundError is the verdict for a grammar-valid snapshot name that
// is not present in the repository. It is a TYPE, not a package-level sentinel,
// because its message names the CONFIGURED repository — which is injected.
type snapshotNotFoundError struct{ repo string }

func (e *snapshotNotFoundError) Error() string { return "no such snapshot in repository " + e.repo }

// isSnapshotNotFound reports whether err is that verdict, so a handler can turn
// it into a 404 while every other failure stays a 502.
func isSnapshotNotFound(err error) bool {
	var e *snapshotNotFoundError
	return errors.As(err, &e)
}

var (
	errBadSnapshotName  = jsonError("snapshot must match ^[a-z0-9][a-z0-9._:-]{0,127}$ — no slashes, no path segments, no wildcards")
	errBadRestorePrefix = jsonError("rename_prefix must match ^restored-[a-z0-9-]{0,24}$ — restores are confined to the restored-* namespace")
	errBadRestoreMode   = jsonError(`mode must be "", "renamed" or "in_place"`)
)

// ── the persisted probe verdict ─────────────────────────────────────────────

// snapshotVerdict is one probe outcome, keyed by snapshot name.
type snapshotVerdict struct {
	Verified bool      `json:"verified"`
	At       time.Time `json:"at"`
	Detail   string    `json:"detail"`
}

// verdictStore persists probe verdicts next to the backup intent. It is a
// VALUE field on *Service: zero value usable, no package-level state, and the
// file path is injected so a test can point it somewhere writable.
type verdictStore struct {
	mu   sync.Mutex
	path string
	log  Logger
}

func (v *verdictStore) logger() Logger {
	if v.log == nil {
		return nopLogger{}
	}
	return v.log
}

// all returns the recorded verdicts. A missing or corrupt file reads as EMPTY —
// which renders as "never probed", the honest answer, never as "verified".
func (v *verdictStore) all() map[string]snapshotVerdict {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.readLocked()
}

func (v *verdictStore) readLocked() map[string]snapshotVerdict {
	out := map[string]snapshotVerdict{}
	if v.path == "" {
		return out
	}
	// #nosec G304 -- deployment-owned path (SNAPSHOT_VERIFY_FILE), resolved once
	// by the integrator; no request-supplied string reaches it.
	b, err := os.ReadFile(v.path)
	if err != nil {
		return out
	}
	if err := json.Unmarshal(b, &out); err != nil {
		v.logger().Warn("backup.ops", "snapshot verify file unreadable — every snapshot will report never-probed",
			map[string]any{"error": err.Error()})
		return map[string]snapshotVerdict{}
	}
	return out
}

// record stores one verdict, trimming to the newest snapshotVerdictCap entries.
func (v *verdictStore) record(name string, rec snapshotVerdict) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.path == "" {
		return jsonError("no snapshot verify file is configured on this server")
	}
	all := v.readLocked()
	all[name] = rec
	if len(all) > snapshotVerdictCap {
		type kv struct {
			k string
			t time.Time
		}
		rows := make([]kv, 0, len(all))
		for k, r := range all {
			rows = append(rows, kv{k, r.At})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].t.After(rows[j].t) })
		trimmed := map[string]snapshotVerdict{}
		for _, row := range rows[:snapshotVerdictCap] {
			trimmed[row.k] = all[row.k]
		}
		all = trimmed
	}
	b, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return err
	}
	return platformdb.WriteFileAtomic(v.path, b, 0o600)
}

// ── the restorability probe ─────────────────────────────────────────────────

// RunRestorabilityProbe is the whole point of this file. It RESTORES a real
// index out of a real snapshot into a disposable namespace and compares the doc
// count against the live source. "The restore call returned 200" is not
// evidence; matching counts are.
//
// The temp index is ALWAYS deleted (deferred), and a cleanup that fails is
// recorded in Detail — never swallowed (§16.1's spirit: a script that hides an
// error is worse than one that fails).
// The results are NAMED on purpose: the deferred cleanup records TempDeleted
// and appends to Detail, and a deferred write to an unnamed result is silently
// discarded — which would have made the cleanup outcome unreportable, the exact
// class of silent failure this file exists to end.
func (s *Service) RunRestorabilityProbe(ctx context.Context, snapshot string, progress func(string)) (res VerifyResult, err error) {
	started := s.now()
	res = VerifyResult{Snapshot: snapshot, SourceDocs: -1, RestoredDocs: -1}

	// 1. Resolve the snapshot.
	docs, err := s.fetchSnapshots(ctx)
	if err != nil {
		return res, err
	}
	var doc osSnapshotDoc
	if snapshot == "" {
		ok := false
		if doc, ok = newestSuccessSnapshot(docs); !ok {
			return res, jsonError("no SUCCESS snapshot exists")
		}
	} else {
		found := false
		for _, d := range docs {
			if d.Snapshot == snapshot {
				doc, found = d, true
				break
			}
		}
		if !found {
			return res, &snapshotNotFoundError{repo: s.repo()}
		}
	}
	res.Snapshot = doc.Snapshot
	if len(doc.Indices) == 0 {
		return res, jsonError("snapshot " + doc.Snapshot + " contains no indices — there is nothing to restore")
	}

	// 2. Pick the SMALLEST index by LIVE doc count, preferring one that still
	//    exists live so the comparison is meaningful.
	//
	//    Deliberately one _cat call for every live index rather than
	//    /_cat/indices/<name>: _cat 404s the whole request when ANY named index
	//    is missing, and "the snapshot's indices no longer exist live" is
	//    exactly the case this step has to handle rather than crash on.
	progress("choosing the smallest index in " + doc.Snapshot)
	live, liveErr := s.liveDocCounts(ctx)
	idx, sourceDocs := "", int64(-1)
	for _, name := range doc.Indices {
		n, ok := live[name]
		if !ok {
			continue
		}
		if idx == "" || n < sourceDocs {
			idx, sourceDocs = name, n
		}
	}
	if idx == "" {
		// NOTHING in the snapshot still exists live. Restore the smallest by
		// SNAPSHOT SIZE instead, and be explicit that the result is
		// unverifiable — unverifiable is NOT verified.
		smallest, sizeErr := s.smallestIndexBySnapshotSize(ctx, doc)
		if sizeErr != nil {
			return res, sizeErr
		}
		idx = smallest
		res.Detail = "none of this snapshot's indices still exists live, so the restored doc count could not be compared to a source"
		if liveErr != nil {
			res.Detail += " (live index list unreadable: " + liveErr.Error() + ")"
		}
	}
	res.Index = idx
	res.SourceDocs = sourceDocs
	temp := probeIndexPrefix + idx
	res.TempIndex = temp

	// 5 (registered FIRST so an early return still cleans up). The probe index
	// is disposable by construction, but leaving one behind would grow the
	// cluster silently, so the delete is unconditional and its failure is
	// reported rather than dropped.
	defer func() {
		if err := s.osDo(context.WithoutCancel(ctx), http.MethodDelete, "/"+temp,
			nil, nil, 60*time.Second); err != nil {
			res.TempDeleted = false
			res.Detail = strings.TrimSpace(res.Detail + " temp index " + temp +
				" could NOT be deleted: " + err.Error())
			s.deps.Log.Error("backup.probe", "restorability probe could not delete its temporary index",
				map[string]any{"index": temp, "error": err.Error()})
			return
		}
		res.TempDeleted = true
	}()

	// 3. Restore it renamed.
	progress("restoring " + idx + " from " + doc.Snapshot + " as " + temp)
	body, err := json.Marshal(map[string]any{
		"indices":              idx,
		"rename_pattern":       "(.+)",
		"rename_replacement":   probeIndexPrefix + "$1",
		"include_global_state": false,
		"include_aliases":      false,
		"index_settings":       map[string]any{"index.number_of_replicas": 0},
	})
	if err != nil {
		return res, err
	}
	if err := s.osDo(ctx, http.MethodPost,
		"/_snapshot/"+s.repo()+"/"+doc.Snapshot+"/_restore?wait_for_completion=true",
		body, nil, 20*time.Minute); err != nil {
		res.Detail = strings.TrimSpace(res.Detail + " restore failed: " + err.Error())
		return res, err
	}

	// 4. Wait for the temp index to be usable, then count it.
	progress("waiting for " + temp + " to become available")
	if err := s.osDo(ctx, http.MethodGet,
		"/_cluster/health/"+temp+"?wait_for_status=yellow&timeout=60s", nil, nil, 90*time.Second); err != nil {
		res.Detail = strings.TrimSpace(res.Detail + " temp index never became available: " + err.Error())
		return res, err
	}
	progress("comparing doc counts")
	var cnt struct {
		Count int64 `json:"count"`
	}
	if err := s.osDo(ctx, http.MethodGet, "/"+temp+"/_count", nil, &cnt, 60*time.Second); err != nil {
		res.Detail = strings.TrimSpace(res.Detail + " restored index could not be counted: " + err.Error())
		return res, err
	}
	res.RestoredDocs = cnt.Count

	// 6. The verdict. An uncomparable source (SourceDocs < 0) is NEVER a match.
	res.Match = res.SourceDocs >= 0 && res.SourceDocs == res.RestoredDocs
	res.DurationSeconds = int(s.now().Sub(started).Seconds())
	if res.Detail == "" {
		if res.Match {
			res.Detail = "restored " + idx + " as " + temp + " and the doc counts matched (" +
				strconv.FormatInt(res.SourceDocs, 10) + ")"
		} else {
			res.Detail = "restored " + strconv.FormatInt(res.RestoredDocs, 10) +
				" docs but the live source holds " + strconv.FormatInt(res.SourceDocs, 10)
		}
	}
	return res, nil
}

// liveDocCounts reads every live index's doc count in one _cat call.
func (s *Service) liveDocCounts(ctx context.Context) (map[string]int64, error) {
	var rows []struct {
		Index string `json:"index"`
		Docs  string `json:"docs.count"`
	}
	if err := s.osDo(ctx, http.MethodGet, "/_cat/indices?h=index,docs.count&format=json",
		nil, &rows, 30*time.Second); err != nil {
		return map[string]int64{}, err
	}
	out := make(map[string]int64, len(rows))
	for _, r := range rows {
		n, err := strconv.ParseInt(strings.TrimSpace(r.Docs), 10, 64)
		if err != nil {
			continue // a closed/red index reports no count; it is simply not a candidate
		}
		out[r.Index] = n
	}
	return out, nil
}

// smallestIndexBySnapshotSize is the fallback when nothing in the snapshot
// still exists live: pick the cheapest index to restore, by its size INSIDE the
// snapshot.
func (s *Service) smallestIndexBySnapshotSize(ctx context.Context, doc osSnapshotDoc) (string, error) {
	var body struct {
		Snapshots []struct {
			Indices map[string]struct {
				Stats struct {
					Total struct {
						SizeBytes int64 `json:"size_in_bytes"`
					} `json:"total"`
				} `json:"stats"`
			} `json:"indices"`
		} `json:"snapshots"`
	}
	if err := s.osDo(ctx, http.MethodGet,
		"/_snapshot/"+s.repo()+"/"+doc.Snapshot+"/_status", nil, &body, 60*time.Second); err == nil &&
		len(body.Snapshots) > 0 {
		best, bestSize := "", int64(-1)
		for name, st := range body.Snapshots[0].Indices {
			if best == "" || st.Stats.Total.SizeBytes < bestSize {
				best, bestSize = name, st.Stats.Total.SizeBytes
			}
		}
		if best != "" {
			return best, nil
		}
	}
	// _status unavailable: fall back to the first index by name, which is
	// deterministic and still a real restore. Never guess a name.
	names := append([]string(nil), doc.Indices...)
	sort.Strings(names)
	if len(names) == 0 {
		return "", jsonError("snapshot " + doc.Snapshot + " lists no indices")
	}
	return names[0], nil
}

// recordProbeVerdict persists the verdict and refreshes the metric cache. Both
// halves matter: the file is what the LIST view reads, the cache is what
// /metrics (and therefore the vmalert rule) reads.
func (s *Service) recordProbeVerdict(res VerifyResult, runErr error) {
	detail := res.Detail
	if runErr != nil {
		detail = strings.TrimSpace("probe failed: " + runErr.Error() + " " + detail)
	}
	verdict := snapshotVerdict{Verified: runErr == nil && res.Match, At: s.now().UTC(), Detail: detail}
	name := res.Snapshot
	if name == "" {
		return // nothing to key on; the operation's own Error already carries the failure
	}
	if err := s.verdicts.record(name, verdict); err != nil {
		s.deps.Log.Error("backup.probe", "could not persist the restorability verdict — the next read will report never-probed",
			map[string]any{"snapshot": name, "error": err.Error()})
	}
	s.metrics.setVerdict(verdict.Verified, verdict.At)
}

// ── the nightly worker ──────────────────────────────────────────────────────

// StartRestorabilityProbe runs the probe on a bounded, cancellable cadence. It
// wakes every 10 minutes, refreshes the metric cache from the repository, and
// probes AT MOST once per Deps.ProbeInterval and only when the newest SUCCESS
// snapshot has not been probed yet.
//
// The start is jittered (crypto/rand) so the probe never lands exactly on the
// 01:30 snapshot window — two writers against the same repository at the same
// minute is how a repository gets a partially-written blob tree.
func (s *Service) StartRestorabilityProbe(ctx context.Context) {
	interval := s.deps.ProbeInterval
	if delay := snapshotProbeJitter(); delay > 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
	tick := time.NewTicker(10 * time.Minute)
	defer tick.Stop()
	var lastProbe time.Time
	for {
		s.ProbeTick(ctx, interval, &lastProbe)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// ProbeTick is one wake-up: refresh the cache, then probe if it is due. Split
// out so the worker's decision logic is unit-testable without a ticker.
func (s *Service) ProbeTick(ctx context.Context, interval time.Duration, lastProbe *time.Time) {
	// FIRST, and deliberately before the early return below: the bundle
	// restore-drill gauges are read off a local file and owe nothing to the
	// search cluster. Refreshing them after the inventory fetch meant an
	// unreachable OpenSearch froze the drill metrics too, and "the drill has
	// not run in 9 days" would then have been invisible for exactly as long as
	// the cluster was down — two independent failures reported as one.
	s.refreshDrillMetrics()

	docs, err := s.fetchSnapshots(ctx)
	if err != nil {
		s.deps.Log.Warn("backup.probe", "snapshot inventory unreadable — restorability metrics keep their last known value",
			map[string]any{"error": err.Error()})
		return
	}
	newest, ok := newestSuccessSnapshot(docs)
	if ok {
		s.metrics.setLastSuccess(time.UnixMilli(newest.EndTimeMs).UTC())
	} else {
		s.metrics.setLastSuccess(time.Time{})
	}
	// Re-publish the stored verdict for the newest SUCCESS. A verdict for an
	// OLDER snapshot is not evidence about this one: the metric must fall back
	// to 0 (not proven) the moment a new, unprobed snapshot becomes the newest.
	verdicts := s.verdicts.all()
	if ok {
		if v, seen := verdicts[newest.Snapshot]; seen {
			s.metrics.setVerdict(v.Verified, v.At)
		} else {
			s.metrics.setVerdict(false, time.Time{})
		}
	} else {
		s.metrics.setVerdict(false, time.Time{})
	}
	if !s.deps.ProbeEnabled || !ok {
		return
	}
	if _, seen := verdicts[newest.Snapshot]; seen {
		return // already proven (or disproven) — probing it again nightly buys nothing
	}
	if !lastProbe.IsZero() && s.now().Sub(*lastProbe) < interval {
		return
	}
	*lastProbe = s.now()
	pctx, cancel := context.WithTimeout(ctx, snapshotVerifyTimeout)
	defer cancel()
	res, probeErr := s.RunRestorabilityProbe(pctx, newest.Snapshot, func(string) {})
	s.recordProbeVerdict(res, probeErr)
	if probeErr != nil {
		s.deps.Log.Error("backup.probe", "scheduled restorability probe FAILED — the newest snapshot is not proven restorable",
			map[string]any{"snapshot": newest.Snapshot, "error": probeErr.Error()})
		return
	}
	s.deps.Log.Info("backup.probe", "restorability probe completed", map[string]any{
		"snapshot": res.Snapshot, "index": res.Index, "match": res.Match,
		"source_docs": res.SourceDocs, "restored_docs": res.RestoredDocs,
	})
}

// snapshotProbeJitter is a few minutes of crypto/rand start delay. math/rand is
// deliberately not used: gosec G404 flags it, and a seeded generator is shared
// mutable state (§5).
func snapshotProbeJitter() time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(5*time.Minute)))
	if err != nil {
		return 0 // fail safe to no delay rather than to a fixed, colliding one
	}
	return time.Duration(n.Int64())
}

// ── the inventory view ──────────────────────────────────────────────────────

// ListSnapshots renders the repository inventory, honestly. limit bounds the
// rendered rows; withSizes measures each one (one _status call per snapshot).
func (s *Service) ListSnapshots(ctx context.Context, limit int, withSizes bool) SnapshotListView {
	view := SnapshotListView{
		Repository: s.RepositoryView(ctx),
		Snapshots:  []SnapshotView{},
	}
	docs, err := s.fetchSnapshots(ctx)
	if err != nil {
		view.Detail = "snapshot inventory unreadable: " + err.Error()
		return view
	}
	view.Total = len(docs)
	verdicts := s.verdicts.all()
	if len(docs) > limit {
		docs = docs[:limit]
	}
	for _, d := range docs {
		view.Snapshots = append(view.Snapshots, s.snapshotViewOf(ctx, d, verdicts, withSizes))
	}
	if !withSizes {
		view.Detail = strings.TrimSpace(view.Detail + " sizes omitted — pass ?sizes=1 to measure (one _status call per snapshot against the repository)")
	}
	return view
}

// snapshotViewOf renders one restore point, honestly.
func (s *Service) snapshotViewOf(ctx context.Context, d osSnapshotDoc, verdicts map[string]snapshotVerdict, withSizes bool) SnapshotView {
	v := SnapshotView{
		Name:            d.Snapshot,
		State:           d.State,
		Indices:         d.Indices,
		IndexCount:      len(d.Indices),
		DurationSeconds: int(d.DurationMs / 1000),
		Failures:        []SnapshotShardFailure{},
		SizeDetail:      "not measured on this read — pass ?sizes=1",
	}
	if v.Indices == nil {
		v.Indices = []string{}
	}
	if d.StartTimeMs > 0 {
		v.StartedAt = time.UnixMilli(d.StartTimeMs).UTC().Format(time.RFC3339)
	}
	if d.EndTimeMs > 0 {
		v.EndedAt = time.UnixMilli(d.EndTimeMs).UTC().Format(time.RFC3339)
	}
	v.Shards = SnapshotShardTotals{Total: d.Shards.Total, Successful: d.Shards.Successful, Failed: d.Shards.Failed}
	for i, f := range d.Failures {
		if i >= snapshotFailureCap {
			v.FailuresTrimmed = len(d.Failures) - snapshotFailureCap
			break
		}
		v.Failures = append(v.Failures, SnapshotShardFailure{Index: f.Index, Shard: f.ShardID, Reason: f.Reason})
	}
	if withSizes {
		if n, err := s.snapshotSizeBytes(ctx, d.Snapshot); err == nil {
			v.SizeBytes = &n
			v.SizeDetail = "measured from the repository _status"
		} else {
			v.SizeDetail = "size unreadable: " + err.Error()
		}
	}
	if rec, ok := verdicts[d.Snapshot]; ok {
		verified := rec.Verified
		v.RestorableVerified = &verified
		v.RestorableVerifiedAt = rec.At.UTC().Format(time.RFC3339)
		v.RestorableDetail = rec.Detail
		if v.RestorableDetail == "" {
			v.RestorableDetail = "probe recorded no detail"
		}
	} else {
		v.RestorableDetail = SnapshotNeverProbedDetail
	}
	return v
}

// snapshotSizeBytes measures one snapshot from the repository _status.
func (s *Service) snapshotSizeBytes(ctx context.Context, name string) (int64, error) {
	var body struct {
		Snapshots []struct {
			Stats struct {
				Total struct {
					SizeBytes int64 `json:"size_in_bytes"`
				} `json:"total"`
			} `json:"stats"`
		} `json:"snapshots"`
	}
	if err := s.osDo(ctx, http.MethodGet,
		"/_snapshot/"+s.repo()+"/"+name+"/_status", nil, &body, 30*time.Second); err != nil {
		return 0, err
	}
	if len(body.Snapshots) == 0 {
		return 0, jsonError("repository returned no _status for " + name)
	}
	return body.Snapshots[0].Stats.Total.SizeBytes, nil
}

// RepositoryView reads the repository registration itself. It does NOT verify:
// verification WRITES to the repository, and a list view must not.
func (s *Service) RepositoryView(ctx context.Context) SnapshotRepositoryView {
	v := SnapshotRepositoryView{
		Name:           s.repo(),
		Verified:       nil,
		VerifiedDetail: "not verified on this read — verification writes to the repository",
	}
	var body map[string]struct {
		Type     string            `json:"type"`
		Settings map[string]string `json:"settings"`
	}
	if err := s.osDo(ctx, http.MethodGet, "/_snapshot/"+s.repo(), nil, &body, 10*time.Second); err != nil {
		v.Detail = "repository not readable: " + err.Error()
		return v
	}
	entry, ok := body[s.repo()]
	if !ok {
		v.Detail = "repository " + s.repo() + " is NOT registered — the search tier has no backup"
		v.DiskDetail = "no registered repository, so there is no filesystem to measure"
		return v
	}
	v.Registered = true
	v.Type = entry.Type
	v.Location = entry.Settings["location"]
	s.fillRepositoryHeadroom(ctx, &v)
	return v
}

// clampToInt64 saturates rather than wrapping. A wrapped byte count would be a
// negative free-space figure — a number an operator would read as catastrophe.
func clampToInt64(v uint64) int64 {
	const maxInt64 = uint64(1)<<63 - 1
	if v > maxInt64 {
		return int64(maxInt64)
	}
	return int64(v)
}

// fillRepositoryHeadroom measures how much room the repository still has.
//
// "How many restore points fit" is the retention arithmetic behind the
// 2026-08-27 incident, and it is unanswerable without free/total bytes. Two
// sources are tried, in the order of how directly they answer the question:
//
//  1. statfs on the repository path AS THE API CONTAINER SEES IT. Exact when
//     the path is mounted — and it need not be: nothing requires the api
//     container to mount data/opensearch-snapshots.
//  2. OpenSearch's own GET /_nodes/stats/fs, which reports the DATA path's
//     filesystem. In the shipped compose deployment path.repo sits on the same
//     filesystem, so it is the right order of magnitude — and the response says
//     so rather than implying an exact repository measurement. This call needs
//     cluster:monitor/nodes/stats; where the api's role does not carry it the
//     call 403s, and that is reported, not hidden.
//
// When neither works both pointers stay nil and DiskDetail says exactly where
// the number can be got instead. A guessed headroom would be worse than none.
func (s *Service) fillRepositoryHeadroom(ctx context.Context, v *SnapshotRepositoryView) {
	if v.Location != "" {
		// syscall.Statfs is POSIX-only; this platform ships on Linux
		// containers exclusively (deployment/docker), so there is no non-POSIX
		// build to keep compiling.
		var st syscall.Statfs_t
		// Bsize is a SIGNED field in Statfs_t on Linux while the block counts
		// are unsigned, so the multiplication needs a widening conversion that
		// a negative Bsize would wrap (gosec G115). A negative block size is
		// nonsense from any real filesystem, but "nonsense from the kernel"
		// must not become "the disk is full" on an operator's screen — so the
		// sign is CHECKED rather than assumed, and an impossible value falls
		// through to the honest not-measured path below.
		if err := syscall.Statfs(v.Location, &st); err == nil && st.Bsize > 0 {
			// Bavail is blocks available to an UNPRIVILEGED writer, which is
			// the number that decides whether the next snapshot fits — not
			// Bfree, which includes the root reserve. Both block counts are
			// already uint64 on the linux/amd64 target this platform ships on
			// (deployment/docker is Linux-only), so only Bsize — which the
			// kernel declares SIGNED — needs a conversion, and the guard above
			// proves it is positive before the widening. The product is clamped
			// on the way back to int64 so an absurd value can never publish a
			// NEGATIVE headroom, which an operator would read as a full disk.
			bsize := uint64(st.Bsize) // #nosec G115 -- guarded > 0 on the line above
			free := clampToInt64(st.Bavail * bsize)
			total := clampToInt64(st.Blocks * bsize)
			v.DiskFreeBytes, v.DiskTotalBytes = &free, &total
			v.DiskDetail = "measured with statfs on " + v.Location + " as the api container sees it"
			return
		}
	}
	var stats struct {
		Nodes map[string]struct {
			FS struct {
				Total struct {
					TotalBytes     int64 `json:"total_in_bytes"`
					AvailableBytes int64 `json:"available_in_bytes"`
				} `json:"total"`
			} `json:"fs"`
		} `json:"nodes"`
	}
	if err := s.osDo(ctx, http.MethodGet, "/_nodes/stats/fs", nil, &stats, 10*time.Second); err == nil {
		for _, n := range stats.Nodes {
			if n.FS.Total.TotalBytes <= 0 {
				continue
			}
			free, total := n.FS.Total.AvailableBytes, n.FS.Total.TotalBytes
			v.DiskFreeBytes, v.DiskTotalBytes = &free, &total
			v.DiskDetail = "not measured on the repository path directly (the api container does not mount " +
				strconv.Quote(v.Location) + "): these are OpenSearch's own data-path filesystem totals from " +
				"_nodes/stats/fs, which in the shipped deployment is the same filesystem path.repo sits on"
			return
		}
		v.DiskDetail = "_nodes/stats/fs returned no filesystem totals, and the api container does not mount " +
			strconv.Quote(v.Location) + " — headroom is measurable only on the host"
		return
	}
	v.DiskDetail = "the api container does not mount the repository path (" + v.Location + "), and OpenSearch's " +
		"_nodes/stats/fs is not readable with the api's role (cluster:monitor/nodes/stats is granted to the " +
		"monitor identity, not the api) — headroom is measurable only on the host, e.g. `df -h` on the " +
		"data/opensearch-snapshots bind mount"
}

// ── snapshot naming ─────────────────────────────────────────────────────────

// newManualSnapshotName generates the ONLY name a manual snapshot can have. The
// client supplies nothing: a browser-chosen string would be a repository path
// segment chosen by a browser.
func newManualSnapshotName(now time.Time) (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	suffix := make([]byte, 6)
	for i := range suffix {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		suffix[i] = alphabet[n.Int64()]
	}
	name := "netops-manual-" + now.UTC().Format("2006-01-02t15-04-05") + "-" + string(suffix)
	if !snapshotNameRe.MatchString(name) {
		// Belt and braces: the generator and the grammar must never diverge.
		return "", jsonError("generated snapshot name failed its own grammar")
	}
	return name, nil
}

// ── restore planning ────────────────────────────────────────────────────────

// restorePlan is a VALIDATED restore. Nothing reaches OpenSearch that did not
// come out of this struct.
type restorePlan struct {
	snapshot string
	indices  []string // already verified to exist in the snapshot; empty = all
	mode     string
	prefix   string
}

// planRestore validates a restore request against the closed grammars AND
// against the snapshot's real contents. It returns the HTTP status the refusal
// deserves so the handler never has to guess.
func (s *Service) planRestore(ctx context.Context, req snapshotRestoreRequest) (restorePlan, int, error) {
	plan := restorePlan{
		snapshot: strings.TrimSpace(req.Snapshot),
		mode:     strings.TrimSpace(req.Mode),
		prefix:   strings.TrimSpace(req.RenamePrefix),
	}
	if !snapshotNameRe.MatchString(plan.snapshot) {
		return plan, http.StatusBadRequest, errBadSnapshotName
	}
	switch plan.mode {
	case "":
		plan.mode = RestoreModeRenamed
	case RestoreModeRenamed, RestoreModeInPlace:
	default:
		return plan, http.StatusBadRequest, errBadRestoreMode
	}
	if plan.mode == RestoreModeInPlace {
		if req.Confirm != plan.snapshot {
			return plan, http.StatusBadRequest, jsonError(
				"an in_place restore OVERWRITES live indices: confirm must equal the snapshot name exactly (type-to-confirm)")
		}
		plan.prefix = "" // meaningless in place; never echoed as if it applied
	} else {
		if plan.prefix == "" {
			plan.prefix = DefaultRestorePrefix
		}
		if !restorePrefixRe.MatchString(plan.prefix) {
			return plan, http.StatusBadRequest, errBadRestorePrefix
		}
	}
	if len(req.Indices) > snapshotRestoreMaxIndices {
		return plan, http.StatusBadRequest, jsonError("at most 200 indices may be named in one restore")
	}
	doc, err := s.findSnapshot(ctx, plan.snapshot)
	if err != nil {
		if isSnapshotNotFound(err) {
			return plan, http.StatusNotFound, err
		}
		return plan, http.StatusBadGateway, err
	}
	inSnapshot := make(map[string]bool, len(doc.Indices))
	for _, i := range doc.Indices {
		inSnapshot[i] = true
	}
	for _, raw := range req.Indices {
		idx := strings.TrimSpace(raw)
		if !restoreIndexRe.MatchString(idx) {
			return plan, http.StatusBadRequest, jsonError(
				"index name " + strconv.Quote(idx) + " must match ^[a-z0-9][a-z0-9._-]{0,254}$")
		}
		if !inSnapshot[idx] {
			return plan, http.StatusBadRequest, jsonError(
				"index " + strconv.Quote(idx) + " is not present in snapshot " + plan.snapshot)
		}
		plan.indices = append(plan.indices, idx)
	}
	if plan.mode == RestoreModeInPlace && len(plan.indices) == 0 {
		// in_place with no explicit list means "every index in the snapshot" —
		// materialise it so the close/open steps have concrete names.
		plan.indices = append(plan.indices, doc.Indices...)
		sort.Strings(plan.indices)
	}
	return plan, http.StatusOK, nil
}

// run builds the operation body for a validated plan.
func (p restorePlan) run(s *Service, opID string) func(ctx context.Context, progress func(string)) error {
	return func(ctx context.Context, progress func(string)) error {
		payload := map[string]any{
			"include_global_state": false,
			"include_aliases":      false,
		}
		if len(p.indices) > 0 {
			payload["indices"] = strings.Join(p.indices, ",")
		}
		restored := p.indices
		if p.mode == RestoreModeRenamed {
			payload["rename_pattern"] = "(.+)"
			payload["rename_replacement"] = p.prefix + "$1"
			restored = make([]string, 0, len(p.indices))
			for _, i := range p.indices {
				restored = append(restored, p.prefix+i)
			}
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if p.mode == RestoreModeInPlace {
			// OpenSearch REFUSES to restore over an open index. Close → restore
			// → reopen is the documented sequence; each step is named so a
			// failure says WHICH step failed, and a failure never leaves an
			// index closed silently.
			progress("closing " + strconv.Itoa(len(p.indices)) + " live indices")
			if err := s.closeIndices(ctx, p.indices); err != nil {
				return fmt.Errorf("close step failed: %w%s", err, s.reopenNote(ctx, p.indices))
			}
			progress("restoring in place from " + p.snapshot)
			if err := s.osDo(ctx, http.MethodPost,
				"/_snapshot/"+s.repo()+"/"+p.snapshot+"/_restore?wait_for_completion=true",
				body, nil, snapshotRestoreTimeout); err != nil {
				return fmt.Errorf("restore step failed: %w%s", err, s.reopenNote(ctx, p.indices))
			}
			progress("reopening the restored indices")
			if err := s.openIndices(ctx, p.indices); err != nil {
				return fmt.Errorf("reopen step failed — THE INDICES ARE STILL CLOSED and must be opened by hand: %w", err)
			}
		} else {
			progress("restoring from " + p.snapshot + " under " + p.prefix)
			if err := s.osDo(ctx, http.MethodPost,
				"/_snapshot/"+s.repo()+"/"+p.snapshot+"/_restore?wait_for_completion=true",
				body, nil, snapshotRestoreTimeout); err != nil {
				return fmt.Errorf("restore step failed: %w", err)
			}
		}
		if len(restored) > 0 {
			s.ops.update(opID, func(o *Operation) { o.RestoredIndices = restored })
		}
		return nil
	}
}

// closeIndices closes every named index.
func (s *Service) closeIndices(ctx context.Context, idx []string) error {
	if len(idx) == 0 {
		return nil
	}
	return s.osDo(ctx, http.MethodPost, "/"+strings.Join(idx, ",")+"/_close", nil, nil, 5*time.Minute)
}

// openIndices reopens every named index.
func (s *Service) openIndices(ctx context.Context, idx []string) error {
	if len(idx) == 0 {
		return nil
	}
	return s.osDo(ctx, http.MethodPost, "/"+strings.Join(idx, ",")+"/_open", nil, nil, 5*time.Minute)
}

// reopenNote attempts the reopen after a failed in_place step and reports
// WHETHER IT WORKED. Leaving an index closed without saying so is the silent
// failure §10 forbids — an operator reading "restore failed" would have no idea
// their search tier was down.
func (s *Service) reopenNote(ctx context.Context, idx []string) string {
	if err := s.openIndices(context.WithoutCancel(ctx), idx); err != nil {
		return " — the indices were left CLOSED and the automatic reopen also failed: " + err.Error()
	}
	return " — the affected indices were reopened successfully"
}
