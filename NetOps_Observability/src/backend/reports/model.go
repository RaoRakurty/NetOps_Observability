// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package reports

import (
	"context"
	"encoding/json"
	"time"
)

// model.go — the shared contract for the async reporting pipeline. These types
// and interfaces are deliberately free of any database/transport import so the
// pipeline's moving parts (queue, execution history, renderer, artifact store)
// can be tested against fakes, and so the Postgres-backed implementations live
// via the injected DB seam (implemented by package main's rlsPG adapter).

// ---- lifecycle enums -------------------------------------------------------

// JobStatus is the queue-row lifecycle (the mechanics), distinct from ExecStatus
// (the user-facing outcome of a report run).
type JobStatus string

const (
	JobQueued  JobStatus = "queued"
	JobRunning JobStatus = "running"
	JobFailed  JobStatus = "failed" // dead-lettered: attempts exhausted
	JobDone    JobStatus = "done"
)

// ExecStatus is the outcome recorded in the immutable execution history.
type ExecStatus string

const (
	StatusQueued    ExecStatus = "queued"
	StatusRunning   ExecStatus = "running"
	StatusCompleted ExecStatus = "completed"
	StatusFailed    ExecStatus = "failed"
	StatusCancelled ExecStatus = "cancelled"
)

// Phase is a point in an execution's lifecycle, stamped with a timestamp in the
// events timeline so per-phase latency (queue wait vs render vs deliver) is
// reconstructable after the fact — "where did the 14 minutes go?".
type Phase string

const (
	PhaseQueued     Phase = "queued"
	PhaseRunning    Phase = "running"
	PhaseRendering  Phase = "rendering"
	PhaseDelivering Phase = "delivering"
	PhaseExporting  Phase = "exporting" // log-export: streaming OpenSearch → artifact
	PhaseCompleted  Phase = "completed"
	PhaseFailed     Phase = "failed"
)

// ---- queue -----------------------------------------------------------------

// Job is one claimable unit of work on the shared substrate. JobType selects the
// worker handler ("report" renders+delivers ScheduleID for the instant FireTime;
// "export" streams a log query to an artifact; future: "archive"). Payload is a
// frozen, self-contained snapshot of the job's parameters so it survives the
// source being edited/deleted after enqueue. The empty JobType means "report".
type Job struct {
	ID          string
	JobType     string
	TenantID    string
	ScheduleID  string
	ExecutionID string
	FireTime    time.Time
	Attempts    int
	Payload     json.RawMessage
	// LockedBy is the worker holding the lease, stamped by Claim (transient —
	// never part of the enqueue payload). Terminal writes (Complete/Fail) must
	// present it so a worker that lost its lease cannot finalize a job another
	// worker now owns (M11).
	LockedBy string
}

// JobQueue is the durable, Postgres-backed work queue (FOR UPDATE SKIP LOCKED).
// All methods are context-aware; implementations run queue mechanics under the
// platform scope (infrastructure), never tenant scope.
type JobQueue interface {
	// Enqueue is idempotent on (ScheduleID, FireTime): a duplicate is a no-op and
	// reports created=false. runAfter gates first visibility (now for "send now").
	Enqueue(ctx context.Context, j Job, runAfter time.Time) (job Job, created bool, err error)
	// Claim atomically leases up to n runnable jobs to workerID (status→running,
	// lease stamped), skipping rows locked by other workers and re-claiming jobs
	// whose lease has lapsed (crash recovery).
	Claim(ctx context.Context, workerID string, n int, lease time.Duration) ([]Job, error)
	// RenewLease extends the lease while a long job is still in flight; returns an
	// error if the job is no longer leased by workerID (lease lost).
	RenewLease(ctx context.Context, jobID, workerID string, lease time.Duration) error
	// Complete finalizes a successfully processed job (terminal, not
	// re-claimable) — only while workerID still holds the lease; a lost lease
	// returns ErrLeaseLost instead of clobbering the new owner's run (M11).
	Complete(ctx context.Context, jobID, workerID string) error
	// Fail reschedules with backoff (dead=false → back to runnable at retryAfter)
	// or dead-letters (dead=true → terminal failed). Lease-guarded like Complete.
	Fail(ctx context.Context, jobID, workerID string, attempt int, cause string, retryAfter time.Time, dead bool) error
	// Release returns a leased job to runnable (e.g. graceful shutdown mid-flight).
	Release(ctx context.Context, jobID string) error
	// RecoverExpiredLeases resets jobs whose lease lapsed back to runnable and
	// returns how many — for metrics/logging (Claim also self-heals them).
	RecoverExpiredLeases(ctx context.Context, now time.Time) (int, error)
	// Pending returns the count of runnable jobs (queue depth) for metrics.
	Pending(ctx context.Context) (int, error)
}

// ---- execution history -----------------------------------------------------

// DeliveryStatus is the per-recipient/per-channel outcome of one delivery
// attempt. Its shape maps 1:1 to a future execution_deliveries table, so
// per-recipient retry (a later phase) is a mechanical promotion, not a reshape.
type DeliveryStatus struct {
	Channel   string    `json:"channel"`   // notify channel name, or "email"
	Recipient string    `json:"recipient"` // address / channel target
	OK        bool      `json:"ok"`
	Attempt   int       `json:"attempt"`
	Error     string    `json:"error,omitempty"`
	At        time.Time `json:"at"`
}

// ArtifactRef points at a stored artifact without carrying its bytes.
type ArtifactRef struct {
	Format      string `json:"format"`
	ContentType string `json:"content_type"`
	SizeBytes   int    `json:"size_bytes"`
	SHA256      string `json:"sha256"`
	Summary     string `json:"summary"`
	Key         string `json:"key"` // ArtifactStore lookup key (execution id)
}

// ExecutionRecord is the immutable history row for one report fire (the
// denormalized summary; ExecEvent rows carry the phase detail).
type ExecutionRecord struct {
	ID          string           `json:"id"`
	Kind        string           `json:"kind,omitempty"` // "report" | "export" | "archive"
	TenantID    string           `json:"tenant_id"`
	ScheduleID  string           `json:"schedule_id"`
	JobID       string           `json:"job_id,omitempty"`
	FireTime    time.Time        `json:"fire_time"`
	StartedAt   time.Time        `json:"started_at,omitempty"`
	CompletedAt time.Time        `json:"completed_at,omitempty"`
	Status      ExecStatus       `json:"status"`
	Artifacts   []ArtifactRef    `json:"artifacts,omitempty"` // one per rendered format
	Deliveries  []DeliveryStatus `json:"delivery_status,omitempty"`
	Error       string           `json:"error,omitempty"`
}

// PrimaryArtifact returns the HTML artifact (the email body / default view), or
// the first artifact if no HTML one exists, or nil.
func (e ExecutionRecord) PrimaryArtifact() *ArtifactRef {
	for i := range e.Artifacts {
		if e.Artifacts[i].Format == "html" {
			return &e.Artifacts[i]
		}
	}
	if len(e.Artifacts) > 0 {
		return &e.Artifacts[0]
	}
	return nil
}

// ArtifactByFormat returns the artifact for a given format, or nil.
func (e ExecutionRecord) ArtifactByFormat(format string) *ArtifactRef {
	for i := range e.Artifacts {
		if e.Artifacts[i].Format == format {
			return &e.Artifacts[i]
		}
	}
	return nil
}

// ExecEvent is a single phase transition with its timestamp.
type ExecEvent struct {
	Phase Phase     `json:"phase"`
	At    time.Time `json:"at"`
	Note  string    `json:"note,omitempty"`
}

// ExecQuery parameterizes a history listing (newest-first, keyset via Before).
// Kind, when set, scopes the listing to one execution type ("report"/"export") so
// the reports drawer and the exports drawer don't bleed into each other.
type ExecQuery struct {
	Kind       string
	ScheduleID string
	Before     time.Time
	Limit      int
}

// ExecScope is WHO is reading the execution history, resolved by the caller and
// handed to the store as data. Both reads below take one; neither takes a bare
// (tenant, cross) pair any more.
//
// The pair was not enough. An execution row is the ledger entry for one report
// fire, and it carries the rendered SUMMARY of that report ("3 active alert(s) ·
// 2 critical/error") plus the key of the stored artifact — the complete
// HTML/XLSX/PDF document, rendered under the owning tenant's own scope. The
// platform operator's Global view is cross=true, and cross meant "everything",
// so a tenant that platform staff may administer but must not READ
// (Tenant.OperatorRestricted) had its report runs listed and its rendered
// documents streamed on request.
//
// Expressed as a pair there was nowhere for "cross-tenant EXCEPT these" to ride,
// which is the same wall alerts.EpisodeScope and reports.DeviceScope hit. And a
// filter at the handler could not make up the difference either: List applies
// its LIMIT inside the store, over the unfiltered set, so a post-filter would
// hand back a short page whose missing slots are themselves the disclosure — and
// runsFromExecutions reads a fixed 200-row window, which a restricted tenant's
// runs would silently consume, taking a VISIBLE tenant's runs off the operator's
// screen. The filter and the bound have to be the same pass, and that pass is in
// the store.
//
// Hidden is the operator-visibility restriction in its tenant_id form, which is
// the exact form for an execution: the row names its owning tenant. Deny is the
// operator scoped INTO a restricted tenant — it reads nothing at all.
//
// The zero value is a CLOSED scope (tenant "", not cross): the platform's own
// executions only, the right default for a caller that forgot to say who it is.
type ExecScope struct {
	Tenant string
	Cross  bool
	Deny   bool
	Hidden []string
}

// ExecScopeFor builds the ordinary scope, for callers with no restriction to
// apply (the engine's own bookkeeping, tests).
func ExecScopeFor(tenant string, cross bool) ExecScope {
	return ExecScope{Tenant: tenant, Cross: cross}
}

// PlatformExecScope is the UNRESTRICTED platform scope, for the readers that act
// on behalf of the PLATFORM rather than on behalf of a principal:
//
//   - the pipeline's own de-duplication probe, which must see every tenant's last
//     fire or it would re-fire a restricted tenant's schedule forever, and
//   - the signed-link download paths (/api/reports/view, /api/exports/view),
//     where the short-lived token IS the authorization and the recipient is the
//     tenant itself. The restriction hides a tenant from the platform, never from
//     itself, so resolving it there would take a tenant's own report away from
//     the address it asked for it at.
//
// It is deliberately not derivable from claims: an operator request must go
// through the principal's own scope, never this.
func PlatformExecScope() ExecScope { return ExecScope{Cross: true} }

// Sees reports whether this scope may read one execution row: the restriction
// first, then the ordinary tenancy rule — in that order, because the tenancy
// rule answers TRUE FOR EVERYTHING on the cross-tenant path and would otherwise
// hand a hidden row straight back.
func (sc ExecScope) Sees(rec ExecutionRecord) bool {
	if sc.Deny {
		return false
	}
	for _, id := range sc.Hidden {
		// A blank entry is skipped rather than matched: a blank owner is
		// PLATFORM-owned, which the restriction never hides, and the SQL half
		// (hiddenLower) drops blanks for the same reason — the two halves of
		// one rule must not disagree.
		if h := normTenant(id); h != "" && h == normTenant(rec.TenantID) {
			return false
		}
	}
	return sc.Cross || normTenant(rec.TenantID) == normTenant(sc.Tenant)
}

// hiddenLower renders the restriction as the lower-cased list a SQL exclusion
// binds, or nil when there is nothing to exclude.
func (sc ExecScope) hiddenLower() []string {
	if len(sc.Hidden) == 0 {
		return nil
	}
	out := make([]string, 0, len(sc.Hidden))
	for _, id := range sc.Hidden {
		if h := normTenant(id); h != "" {
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ExecutionStore is the immutable execution history + phase-event timeline.
type ExecutionStore interface {
	// Append inserts the initial queued record (tenant from e.TenantID). Writes
	// run as platform owner (infrastructure); reads are RLS tenant-scoped.
	Append(ctx context.Context, e ExecutionRecord) error
	// Status transitions update the row by id (the worker owns the lifecycle).
	// They are lease-guarded like the queue's Complete/Fail (NV-B): lockedBy is
	// the caller's worker id, and the write applies only while that worker still
	// holds the job lease for this execution — a zombie worker whose lease was
	// re-claimed elsewhere gets ErrLeaseLost instead of overwriting the new
	// owner's ledger state. The execution id is SHARED across re-claims (Claim
	// returns the queue row's execution_id), so without the guard a zombie's
	// late terminal write could flip a completed run to failed (or vice versa)
	// on the /api/reports/runs observability surface.
	MarkRunning(ctx context.Context, id string, at time.Time, lockedBy string) error
	Complete(ctx context.Context, id string, at time.Time, refs []ArtifactRef, deliveries []DeliveryStatus, lockedBy string) error
	FailExec(ctx context.Context, id string, at time.Time, cause string, deliveries []DeliveryStatus, lockedBy string) error
	// Cancel is operator-initiated (no lease to present) and stays unguarded.
	Cancel(ctx context.Context, id string, at time.Time, reason string) error
	// RecordEvent appends a phase transition (tenant sets the events row scope).
	RecordEvent(ctx context.Context, tenant, execID string, phase Phase, at time.Time, note string) error
	// Get and List take the RESOLVED ExecScope, not a (tenant, cross) pair, so
	// the operator-visibility restriction reaches the store rather than stopping
	// at a handler that would have to remember it. A row the scope may not see
	// is reported as ABSENT (found=false), which the HTTP callers answer 404 —
	// never 403, which would confirm the id exists.
	Get(ctx context.Context, sc ExecScope, id string) (ExecutionRecord, []ExecEvent, bool, error)
	List(ctx context.Context, sc ExecScope, q ExecQuery) ([]ExecutionRecord, error)
}

// ---- rendering & artifacts -------------------------------------------------

// Section is a formatting-free block of gathered data (the renderers do layout).
// Header is the optional column-header row (bolded in HTML/Excel); Rows are the
// data rows; Note is free text shown when a section isn't tabular.
type Section struct {
	Title  string     `json:"title"`
	Header []string   `json:"header,omitempty"`
	Rows   [][]string `json:"rows,omitempty"`
	Note   string     `json:"note,omitempty"`
}

// ViewModel is the gathered, transport-neutral data for one report fire.
type ViewModel struct {
	ReportID    string
	ReportName  string
	Kind        string
	TenantID    string
	GeneratedAt time.Time
	Severity    string
	Description string
	Summary     string
	Sections    []Section
}

// Artifact is a rendered, deliverable document.
type Artifact struct {
	Format      string // "html" (later "pdf")
	ContentType string
	Bytes       []byte
	Summary     string // one-line subject/summary
}

// Renderer turns a ViewModel into a deliverable Artifact. HTML now; a PDF sidecar
// implements the same interface later with no change to scheduler/worker/delivery.
type Renderer interface {
	Format() string
	Render(ctx context.Context, vm ViewModel) (Artifact, error)
}

// ArtifactStore decouples artifact bytes from where they live. Phase-1 writes to
// app_kv; filesystem/S3/PDF-blob backends drop in later with no caller change.
// Retention/cleanup hangs off Delete.
type ArtifactStore interface {
	Save(ctx context.Context, execID string, a Artifact) (ArtifactRef, error)
	Load(ctx context.Context, ref ArtifactRef) (Artifact, error)
	Delete(ctx context.Context, ref ArtifactRef) error
}
