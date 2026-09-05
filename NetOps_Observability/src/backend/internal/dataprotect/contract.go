package dataprotect

import "time"

// contract.go — the wire contract for the Data Protection surface.
//
// Types only. The behaviour lives in ops.go (snapshot management + async
// operations), coverage.go (the per-engine coverage table), policy.go (the SM
// policy control plane) and config.go (the backup intent); http.go owns the
// routes. Keeping the schema in one file is deliberate: the frontend is built
// against these shapes and against internal/openapi/openapi.go, and a contract
// that is scattered across handlers drifts.
//
// THE HONESTY RULE, which every type below obeys:
//   a value we do not measure is a nil pointer, and it always ships with a
//   sibling `*_detail` string saying WHY it is nil.
// Never a fabricated zero, never a blank that an operator reads as "fine".
// This surface exists because of the 2026-08-27 incident, where a repository
// whose blob tree had been deleted still reported a policy, a schedule and a
// list of restore points — all of them unrestorable, for seven days, silently.
//
// Every route that carries these types is platform-GLOBAL plumbing and is gated
// by the injected platform-admin Gate (CLAUDE.md §3a rule 3), audited on both
// outcomes, and classified "platform" in route_isolation_test.go. The browser
// never speaks to OpenSearch: the api proxies with the service identity and the
// admin certificate never leaves the host.

// ── snapshot inventory ──────────────────────────────────────────────────────

// SnapshotRepositoryView is the repository itself, not its contents. A
// registered repository that fails verification is the exact state the
// 2026-08-27 incident produced from the other direction, so both facts are
// carried separately and neither is inferred from the other.
type SnapshotRepositoryView struct {
	Name       string `json:"name"`
	Registered bool   `json:"registered"`
	Type       string `json:"type,omitempty"`     // "fs"
	Location   string `json:"location,omitempty"` // in-container path, not a secret
	// Verified is nil when no verification was attempted on this read (the list
	// view does not verify — verification writes to the repository).
	Verified       *bool  `json:"verified"`
	VerifiedDetail string `json:"verified_detail"`
	Detail         string `json:"detail,omitempty"`

	// Disk headroom on the filesystem the repository lives on. The retention
	// arithmetic that produced the 2026-08-27 incident is a headroom question —
	// "how many restore points fit" is unanswerable without it. Both pointers
	// are nil whenever the api cannot measure (it runs in a container that need
	// not mount the repository path), and DiskDetail then says exactly WHY and
	// where the number can be got instead.
	DiskFreeBytes  *int64 `json:"disk_free_bytes"`
	DiskTotalBytes *int64 `json:"disk_total_bytes"`
	DiskDetail     string `json:"disk_detail"`
}

// SnapshotShardTotals mirrors the OpenSearch shard accounting verbatim. A
// PARTIAL snapshot is a FAILED restore point for the shards it lost, and the
// GUI must be able to say which.
type SnapshotShardTotals struct {
	Total      int `json:"total"`
	Successful int `json:"successful"`
	Failed     int `json:"failed"`
}

// SnapshotShardFailure is one shard OpenSearch could not snapshot, with the
// reason it gave. Carrying the reason is tracker 225(b): the 2026-08-27 window
// was diagnosable only from the NoSuchFileException text, and nothing surfaced
// it for a week.
type SnapshotShardFailure struct {
	Index  string `json:"index"`
	Shard  int    `json:"shard"`
	Reason string `json:"reason"`
}

// SnapshotView is one restore point as the GUI renders it.
type SnapshotView struct {
	Name            string                 `json:"name"`
	State           string                 `json:"state"` // SUCCESS | PARTIAL | IN_PROGRESS | FAILED | INCOMPATIBLE
	Indices         []string               `json:"indices"`
	IndexCount      int                    `json:"index_count"`
	StartedAt       string                 `json:"started_at,omitempty"` // RFC3339 UTC
	EndedAt         string                 `json:"ended_at,omitempty"`   // RFC3339 UTC; empty while IN_PROGRESS
	DurationSeconds int                    `json:"duration_seconds"`
	Shards          SnapshotShardTotals    `json:"shards"`
	Failures        []SnapshotShardFailure `json:"failures"` // capped at snapshotFailureCap, never nil
	FailuresTrimmed int                    `json:"failures_trimmed"`
	// SizeBytes is nil unless the caller asked for sizes (?sizes=1) — measuring
	// costs one _status call per snapshot against the repository.
	SizeBytes  *int64 `json:"size_bytes"`
	SizeDetail string `json:"size_detail"`
	// RestorableVerified is the probe verdict: true = a restore of this snapshot
	// was actually performed and doc counts matched; false = a probe ran and did
	// not match; nil = never probed. "Never probed" is NOT "fine".
	RestorableVerified   *bool  `json:"restorable_verified"`
	RestorableVerifiedAt string `json:"restorable_verified_at,omitempty"` // RFC3339 UTC
	RestorableDetail     string `json:"restorable_detail"`
}

// SnapshotListView is GET /api/system/backup/snapshots/list.
type SnapshotListView struct {
	Repository SnapshotRepositoryView `json:"repository"`
	Snapshots  []SnapshotView         `json:"snapshots"` // newest first, never nil
	Total      int                    `json:"total"`
	Detail     string                 `json:"detail,omitempty"`
}

// ── async operations ────────────────────────────────────────────────────────

// Operation kinds. Closed vocabulary — a client switch over these is total.
const (
	OpKindSnapshotCreate  = "snapshot_create"
	OpKindSnapshotDelete  = "snapshot_delete"
	OpKindSnapshotRestore = "snapshot_restore"
	OpKindSnapshotVerify  = "snapshot_verify"
)

// Operation states.
const (
	OpStateRunning   = "running"
	OpStateSucceeded = "succeeded"
	OpStateFailed    = "failed"
)

// OperationTarget is what an operation acts on, echoed back so a poller that
// never saw the request can still render the row.
type OperationTarget struct {
	Snapshot     string   `json:"snapshot,omitempty"`
	Indices      []string `json:"indices,omitempty"`
	Mode         string   `json:"mode,omitempty"`          // restore only: "renamed" | "in_place"
	RenamePrefix string   `json:"rename_prefix,omitempty"` // restore only
}

// VerifyResult is the restorability probe's evidence. It is deliberately the
// counts, not a boolean: "the restore returned 200" is not proof, matching doc
// counts against the live source is.
type VerifyResult struct {
	Snapshot        string `json:"snapshot"`
	Index           string `json:"index"`      // the index that was probed (smallest by doc count)
	TempIndex       string `json:"temp_index"` // the disposable target it was restored into
	SourceDocs      int64  `json:"source_docs"`
	RestoredDocs    int64  `json:"restored_docs"`
	Match           bool   `json:"match"`
	TempDeleted     bool   `json:"temp_deleted"`
	DurationSeconds int    `json:"duration_seconds"`
	Detail          string `json:"detail,omitempty"`
}

// Operation is one long-running action. Every POST in this group returns 202
// with an Operation; the caller polls GET /api/system/backup/operations/{id}.
type Operation struct {
	ID        string          `json:"id"` // opaque, matches operationIDRe
	Kind      string          `json:"kind"`
	State     string          `json:"state"`
	Actor     string          `json:"actor"`
	StartedAt time.Time       `json:"started_at"`
	EndedAt   *time.Time      `json:"ended_at"`
	Target    OperationTarget `json:"target"`
	// Progress is the current step in plain words, updated as the operation
	// advances ("restoring netops-flows-… as probe-…", "comparing doc counts").
	Progress string `json:"progress,omitempty"`
	// Verify is populated only for OpKindSnapshotVerify, and only once it ends.
	Verify *VerifyResult `json:"verify,omitempty"`
	// RestoredIndices is populated only for OpKindSnapshotRestore.
	RestoredIndices []string `json:"restored_indices,omitempty"`
	Error           string   `json:"error,omitempty"`
}

// OperationListView is GET /api/system/backup/operations.
type OperationListView struct {
	Operations []Operation `json:"operations"` // newest first, never nil
	Capacity   int         `json:"capacity"`   // ring size, so a caller knows what it cannot see
	Detail     string      `json:"detail,omitempty"`
}

// ── request bodies ──────────────────────────────────────────────────────────

// snapshotCreateRequest — POST /api/system/backup/snapshots/create.
// There is deliberately NO client-supplied name: the name is generated
// server-side against a closed grammar so nothing a browser sends can shape a
// repository path.
type snapshotCreateRequest struct {
	// Note is recorded in the audit trail only. Bounded, control chars refused.
	Note string `json:"note,omitempty"`
}

// snapshotDeleteRequest — POST /api/system/backup/snapshots/delete.
// Confirm must equal Snapshot exactly (type-to-confirm, the same guard the
// tenant delete uses). Deleting a restore point is not undoable.
type snapshotDeleteRequest struct {
	Snapshot string `json:"snapshot"`
	Confirm  string `json:"confirm"`
}

// Restore modes.
const (
	RestoreModeRenamed = "renamed"
	RestoreModeInPlace = "in_place"
)

// snapshotRestoreRequest — POST /api/system/backup/snapshots/restore.
//
// The DEFAULT is renamed: the snapshot's indices land under RenamePrefix and
// nothing live is touched, so a restore can never be the thing that destroys
// production. in_place closes and overwrites the live indices and therefore
// requires the type-to-confirm token, exactly like the delete.
type snapshotRestoreRequest struct {
	Snapshot string `json:"snapshot"`
	// Indices is optional; empty restores every index in the snapshot.
	Indices []string `json:"indices,omitempty"`
	// Mode defaults to RestoreModeRenamed when empty.
	Mode string `json:"mode,omitempty"`
	// RenamePrefix defaults to defaultRestorePrefix; ignored for in_place.
	RenamePrefix string `json:"rename_prefix,omitempty"`
	// Confirm is REQUIRED when Mode == RestoreModeInPlace and must equal Snapshot.
	Confirm string `json:"confirm,omitempty"`
}

// snapshotVerifyRequest — POST /api/system/backup/snapshots/verify.
// Snapshot empty = probe the newest SUCCESS.
type snapshotVerifyRequest struct {
	Snapshot string `json:"snapshot,omitempty"`
}

// ── per-engine coverage ─────────────────────────────────────────────────────

// Coverage verdicts. "unknown" is a first-class answer: a store we cannot
// measure right now is not a store we can call covered.
const (
	CoverageYes           = "yes"
	CoverageNo            = "no"
	CoverageNotApplicable = "not_applicable"
	CoverageUnknown       = "unknown"
)

// Backup target kinds.
const (
	TargetNone    = "none"
	TargetLocal   = "local"
	TargetRemote  = "remote"
	TargetOffsite = "offsite"
)

// CoverageSchedule is when a mechanism is supposed to run, and whether the GUI
// governs it. GovernedByGUI=false is how a host cron the owner installed by
// hand is shown as "external, not governed here" rather than silently ignored.
type CoverageSchedule struct {
	Enabled       bool   `json:"enabled"`
	Cron          string `json:"cron,omitempty"`
	Timezone      string `json:"timezone,omitempty"`
	GovernedByGUI bool   `json:"governed_by_gui"`
	Detail        string `json:"detail"`
}

// CoverageRun is one attempt: when, and what came of it.
type CoverageRun struct {
	At     string `json:"at"`     // RFC3339 UTC
	Result string `json:"result"` // success | partial | failed | pass | fail
	Detail string `json:"detail,omitempty"`
}

// CoverageRetention describes how many copies survive and for how long.
type CoverageRetention struct {
	MaxCount   *int   `json:"max_count"`
	MaxAgeDays *int   `json:"max_age_days"`
	Detail     string `json:"detail"`
}

// CoverageTarget is where the copy lives and what protects it. Immutable and
// Encrypted are pointers because "we do not know" is a different answer from
// "no" — and on a filesystem repository the honest answer to Immutable is no.
type CoverageTarget struct {
	Kind string `json:"kind"` // none | local | remote | offsite
	// Location is a description, never a credentialed URL. Anything that could
	// carry a secret (userinfo, query string) is stripped before it lands here.
	Location        string `json:"location,omitempty"`
	Immutable       *bool  `json:"immutable"`
	ImmutableDetail string `json:"immutable_detail"`
	Encrypted       *bool  `json:"encrypted"`
	EncryptedDetail string `json:"encrypted_detail"`
	Detail          string `json:"detail,omitempty"`
}

// EngineCoverage is one row of the enterprise backup dashboard.
type EngineCoverage struct {
	ID   string `json:"id"`   // opensearch | system_bundle | clickhouse | postgres | victoriametrics | secrets_tls | device_configs
	Name string `json:"name"` // human label
	// Covered is the headline verdict; CoveredReason is ALWAYS populated, for
	// every verdict including "yes" — an operator must be able to read why.
	Covered       string `json:"covered"`
	CoveredReason string `json:"covered_reason"`

	Schedule    *CoverageSchedule `json:"schedule"`
	LastAttempt *CoverageRun      `json:"last_attempt"`
	// ScheduleDetail / LastAttemptDetail / RetentionDetail are the sibling
	// explanations for the three nullable STRUCTS above and below. A bare null
	// makes a row fall back to the engine-level Detail, which is not the same
	// sentence — the honesty rule applies per field, not per row. Populated
	// whenever the matching pointer is nil; empty when it is set.
	ScheduleDetail    string `json:"schedule_detail"`
	LastAttemptDetail string `json:"last_attempt_detail"`
	RetentionDetail   string `json:"retention_detail"`
	// LastSuccessAt is the newest copy we believe is good. Empty = never.
	LastSuccessAt string `json:"last_success_at,omitempty"`
	// LastVerified is the newest RESTORABILITY proof, not the newest copy.
	// A backup that has never been restored is not a proven backup.
	LastVerified *CoverageRun `json:"last_verified"`

	SizeBytes  *int64 `json:"size_bytes"`
	SizeDetail string `json:"size_detail"`

	Retention *CoverageRetention `json:"retention"`
	Target    CoverageTarget     `json:"target"`

	// RPOHours is the achieved recovery point: the age of the last GOOD copy.
	// nil with a reason whenever there is no good copy or we cannot date one.
	RPOHours  *float64 `json:"rpo_hours"`
	RPODetail string   `json:"rpo_detail"`

	// RPOTargetHours is the recovery point the configured SCHEDULE implies —
	// the number RPOHours is judged against. It is DERIVED from a real
	// schedule (the SM creation cron, the bundle cron, the config-backup
	// interval) and is nil with a reason wherever no schedule exists or its
	// cadence is not derivable. It is never a policy someone typed in, and it
	// is never invented: an engine with no mechanism has no target, and saying
	// "24h" there would be the exact fiction this surface exists to prevent.
	RPOTargetHours  *float64 `json:"rpo_target_hours"`
	RPOTargetDetail string   `json:"rpo_target_detail"`

	Detail string `json:"detail,omitempty"`
}

// ExternalMechanism is a scheduled job that touches this host's data but is NOT
// owned by the product — a host cron the operator installed. The page shows it
// as "external, not governed here" instead of pretending the GUI toggle
// controls it. Silently ignoring it is how a disabled GUI toggle can coexist
// with a job that still runs, which is precisely the defect this closes.
type ExternalMechanism struct {
	Name     string `json:"name"`
	Source   string `json:"source"` // e.g. "host crontab", "systemd timer"
	Schedule string `json:"schedule,omitempty"`
	Detail   string `json:"detail"`
}

// BackupCoverageView is GET /api/system/backup/coverage.
type BackupCoverageView struct {
	GeneratedAt time.Time           `json:"generated_at"`
	Engines     []EngineCoverage    `json:"engines"`  // never nil
	External    []ExternalMechanism `json:"external"` // never nil
	Detail      string              `json:"detail,omitempty"`
}
