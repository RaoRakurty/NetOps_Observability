package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netops/backend/reports"
)

// report_pipeline.go — the asynchronous reporting spine (PG backend only).
//
// It replaces the synchronous render+deliver path with: a calendar/timezone
// scheduler that ONLY enqueues jobs, a durable Postgres queue, and a pool of
// stateless workers that claim → render → deliver → record an immutable
// execution. The legacy in-process reportScheduler still runs on the file
// backend (see main.go); this type runs when STORE_BACKEND=postgres.
type reportPipeline struct {
	srv        *server
	queue      reports.JobQueue
	execs      reports.ExecutionStore
	artifacts  reports.ArtifactStore
	renderers  map[string]reports.Renderer // format -> renderer (html always; xlsx; pdf if sidecar)
	delivery   *reportDelivery
	deliveries deliveryRecorder // per-recipient ledger (skip-on-retry)

	workers     int
	maxAttempts int
	lease       time.Duration
	jobTimeout  time.Duration
	pollEvery   time.Duration
	tickEvery   time.Duration
	tickJitter  time.Duration

	maxCatchupRuns int
	maxCatchupAge  time.Duration

	// observability counters (atomic; exported via /metrics).
	metCompleted     atomic.Int64
	metFailed        atomic.Int64
	metRetries       atomic.Int64
	metExportDone    atomic.Int64
	metExportFailed  atomic.Int64
	metExportRows    atomic.Int64
	metExportBytes   atomic.Int64
	metExportSeconds atomic.Int64
}

func newReportPipeline(s *server, q reports.JobQueue, es reports.ExecutionStore, art reports.ArtifactStore, html reports.Renderer, deliveries deliveryRecorder) *reportPipeline {
	// Build the renderer set: HTML always; Excel in-process; PDF only when a
	// sidecar URL is configured (nil renderer => format unavailable, skipped).
	renderers := map[string]reports.Renderer{"html": html, "xlsx": reports.NewXLSXRenderer()}
	if pdf := reports.NewPDFRenderer(html, os.Getenv("REPORT_PDF_SIDECAR_URL")); pdf != nil {
		renderers["pdf"] = pdf
	}
	return &reportPipeline{
		srv:        s,
		queue:      q,
		execs:      es,
		artifacts:  art,
		renderers:  renderers,
		delivery:   newReportDelivery(s),
		deliveries: deliveries,

		workers:     envInt("REPORT_WORKERS", 4),
		maxAttempts: 5,
		lease:       2 * time.Minute,
		jobTimeout:  2 * time.Minute,
		pollEvery:   3 * time.Second,
		tickEvery:   time.Minute,
		tickJitter:  5 * time.Second,

		maxCatchupRuns: envInt("REPORT_MAX_CATCHUP_RUNS", 50),
		maxCatchupAge:  envDuration("REPORT_MAX_CATCHUP_AGE", 7*24*time.Hour),
	}
}

// Start launches the scheduler goroutine and the worker pool. It returns
// immediately; all loops exit when ctx is cancelled.
func (p *reportPipeline) Start(ctx context.Context) {
	safeGo("report-scheduler", func() { p.runScheduler(ctx) })
	for i := 0; i < p.workers; i++ {
		safeGo("report-worker-"+strconv.Itoa(i), func() { p.runWorker(ctx, i) })
	}
	logInfo("reports.pipeline", "async reporting pipeline started",
		map[string]any{"workers": p.workers, "lease_s": p.lease.Seconds()})
}

// ---- scheduler (enqueue-only) ----------------------------------------------

func (p *reportPipeline) runScheduler(ctx context.Context) {
	t := time.NewTicker(p.tickEvery)
	defer t.Stop()
	p.enqueueDue(ctx, time.Now().UTC()) // evaluate once on boot
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// Small jitter so multiple replicas don't wake in lockstep and burst.
			sleepJitter(ctx, p.tickJitter)
			p.enqueueDue(ctx, time.Now().UTC())
		}
	}
}

// enqueueDue walks every enabled report and enqueues any fires due since the last
// one recorded, bounded by the catch-up limits. Enqueue is idempotent on
// (schedule, fire), so this is safe across restarts and replicas.
func (p *reportPipeline) enqueueDue(ctx context.Context, now time.Time) {
	for _, o := range p.srv.saved.List("report", "", true) {
		spec, err := parseReportSpec(o.Body)
		if err != nil || !spec.Enabled {
			continue
		}
		anchor := p.anchorFor(ctx, o, now)
		for _, fire := range p.firesDue(spec, anchor, now) {
			p.enqueueFire(ctx, o, fire, now)
		}
	}
}

// anchorFor is the lower bound for catch-up: the latest of the newest recorded
// execution, the report's creation time (so a brand-new report doesn't backfill
// history), and now-maxCatchupAge (so a long outage backfills at most that far).
func (p *reportPipeline) anchorFor(ctx context.Context, o SavedObject, now time.Time) time.Time {
	anchor := now.Add(-p.maxCatchupAge)
	if !o.CreatedAt.IsZero() && o.CreatedAt.After(anchor) {
		anchor = o.CreatedAt
	}
	recent, err := p.execs.List(ctx, "", true, reports.ExecQuery{ScheduleID: o.ID, Limit: 1})
	if err == nil && len(recent) > 0 && recent[0].FireTime.After(anchor) {
		anchor = recent[0].FireTime
	}
	return anchor
}

// firesDue lists the fire instants in (anchor, now], capped by maxCatchupRuns,
// using the calendar recurrence when present and valid, else the legacy interval.
func (p *reportPipeline) firesDue(spec reportSpec, anchor, now time.Time) []time.Time {
	if spec.Schedule != nil && spec.Schedule.Valid() {
		return spec.Schedule.Between(anchor, now, p.maxCatchupRuns)
	}
	if spec.IntervalMinutes > 0 {
		return intervalFires(anchor, now, time.Duration(spec.IntervalMinutes)*time.Minute, p.maxCatchupRuns)
	}
	return nil
}

func (p *reportPipeline) enqueueFire(ctx context.Context, o SavedObject, fire, now time.Time) {
	tenant := normTenant(o.TenantID)
	execID := randHex(8)
	job := reports.Job{TenantID: tenant, ScheduleID: o.ID, ExecutionID: execID, FireTime: fire}
	enq, created, err := p.queue.Enqueue(ctx, job, fire)
	if err != nil {
		logError("reports.scheduler", "enqueue", merge(corr(execID, tenant, o.ID, "", ""), errf(err)))
		return
	}
	if !created {
		return // a job for this (schedule, fire) already exists
	}
	rec := reports.ExecutionRecord{ID: execID, TenantID: tenant, ScheduleID: o.ID, JobID: enq.ID, FireTime: fire, Status: reports.StatusQueued}
	if err := p.execs.Append(ctx, rec); err != nil {
		logError("reports.scheduler", "append execution", merge(corr(execID, tenant, o.ID, enq.ID, ""), errf(err)))
		return
	}
	_ = p.execs.RecordEvent(ctx, tenant, execID, reports.PhaseQueued, now, "")
	logInfo("reports.scheduler", "enqueued report fire", corr(execID, tenant, o.ID, enq.ID, ""))
}

// EnqueueNow enqueues an immediate, out-of-band run of a report ("Send now"),
// returning the new execution id. The synthetic fire_time keeps it from
// colliding with a scheduled fire's idempotency key.
func (p *reportPipeline) EnqueueNow(ctx context.Context, o SavedObject) (string, error) {
	now := time.Now().UTC()
	tenant := normTenant(o.TenantID)
	execID := randHex(8)
	// A nanosecond-unique fire_time avoids the UNIQUE(schedule_id, fire_time)
	// clashing with a real scheduled instant.
	job := reports.Job{TenantID: tenant, ScheduleID: o.ID, ExecutionID: execID, FireTime: now}
	enq, _, err := p.queue.Enqueue(ctx, job, now)
	if err != nil {
		return "", err
	}
	rec := reports.ExecutionRecord{ID: execID, TenantID: tenant, ScheduleID: o.ID, JobID: enq.ID, FireTime: now, Status: reports.StatusQueued}
	if err := p.execs.Append(ctx, rec); err != nil {
		return "", err
	}
	_ = p.execs.RecordEvent(ctx, tenant, execID, reports.PhaseQueued, now, "send now")
	return execID, nil
}

// ---- worker pool -----------------------------------------------------------

func (p *reportPipeline) runWorker(ctx context.Context, idx int) {
	host, _ := os.Hostname()
	workerID := host + "-" + strconv.Itoa(idx)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		jobs, err := p.queue.Claim(ctx, workerID, 1, p.lease)
		if err != nil {
			logError("reports.worker", "claim", map[string]any{"worker_id": workerID, "error": err.Error()})
			sleepCtx(ctx, p.pollEvery)
			continue
		}
		if len(jobs) == 0 {
			sleepCtx(ctx, p.pollEvery)
			continue
		}
		for _, j := range jobs {
			p.process(ctx, workerID, j)
		}
	}
}

// process is the worker's per-job entry point on the shared substrate: it sets up
// the per-type timeout + lease heartbeat, marks the execution running, then
// dispatches to the handler selected by job.JobType. New job types (export today,
// archive later) plug in here — one pool, explicit types, no second queue.
func (p *reportPipeline) process(ctx context.Context, workerID string, job reports.Job) {
	timeout := p.jobTimeout
	if job.JobType == jobTypeExport {
		timeout = envDuration("MAX_EXPORT_RUNTIME", 5*time.Minute) // live policy; exports run minutes
	}
	jctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Heartbeat renews the lease while the job runs so a slow render/export can't
	// have its lease lapse and be double-claimed by another worker.
	stopHB := make(chan struct{})
	go p.heartbeat(jctx, workerID, job.ID, stopHB)
	defer close(stopHB)

	tenant := normTenant(job.TenantID)
	fields := corr(job.ExecutionID, tenant, job.ScheduleID, job.ID, workerID)
	now := time.Now().UTC()

	_ = p.execs.MarkRunning(jctx, job.ExecutionID, now)
	_ = p.execs.RecordEvent(jctx, tenant, job.ExecutionID, reports.PhaseRunning, now, workerID)

	switch job.JobType {
	case jobTypeExport:
		p.processExport(ctx, jctx, workerID, job, tenant, fields)
	case jobTypeIncidentSync:
		p.processIncidentSync(ctx, jctx, workerID, job, tenant, fields)
	case jobTypeIntegrationInbound:
		p.processIntegrationInbound(ctx, jctx, workerID, job, tenant, fields)
	default:
		p.processReport(ctx, jctx, workerID, job, tenant, fields)
	}
}

// processReport renders + delivers a scheduled/now report (the original worker
// body). ctx is the parent (durable terminal writes); jctx carries the job
// timeout. The execution is already marked running by process().
func (p *reportPipeline) processReport(ctx, jctx context.Context, workerID string, job reports.Job, tenant string, fields map[string]any) {
	o, ok := p.srv.saved.Get(job.ScheduleID)
	if !ok {
		// The report was deleted after enqueue — finalize honestly, don't retry.
		p.fail(ctx, jctx, job, tenant, "report no longer exists", nil, true, fields)
		return
	}
	spec, err := parseReportSpec(o.Body)
	if err != nil {
		p.fail(ctx, jctx, job, tenant, "invalid report spec: "+err.Error(), nil, true, fields)
		return
	}

	// Build the dataset once, then render every requested format in parallel.
	_ = p.execs.RecordEvent(jctx, tenant, job.ExecutionID, reports.PhaseRendering, time.Now().UTC(), "")
	vm := p.srv.reports.buildViewModel(o, spec, job.FireTime)
	alert := alertFromViewModel(vm, job.FireTime)
	refs, arts, err := p.renderAll(jctx, job.ExecutionID, vm, normalizeFormats(spec.Formats))
	if err != nil {
		p.fail(ctx, jctx, job, tenant, "render: "+err.Error(), nil, p.dead(job), fields)
		return
	}

	// Deliver: HTML artifact is the email body; xlsx/pdf ride as attachments.
	_ = p.execs.RecordEvent(jctx, tenant, job.ExecutionID, reports.PhaseDelivering, time.Now().UTC(), "")
	cross := tenant == "" || tenant == normTenant(TenantGlobal)
	htmlArt := arts["html"]
	var attachments []reports.Artifact
	for _, f := range []string{"xlsx", "pdf"} {
		if a, ok := arts[f]; ok {
			attachments = append(attachments, a)
		}
	}
	// On a retry, skip recipients already delivered on a prior attempt.
	var skip map[string]bool
	if p.deliveries != nil {
		skip, _ = p.deliveries.Delivered(jctx, job.ExecutionID)
	}
	statuses := p.delivery.Deliver(jctx, deliverReq{
		Tenant: tenant, Cross: cross,
		ContactPoints: spec.ContactPoints, Channels: spec.Channels,
		Subject: htmlArt.Summary, ContentType: htmlArt.ContentType, Body: htmlArt.Bytes,
		Attachments:    attachments,
		Alert:          alert,
		Mode:           spec.DeliveryMode,
		ReportName:     o.Name,
		ExecutionID:    job.ExecutionID,
		Attempt:        job.Attempts,
		SkipRecipients: skip,
	})
	if p.deliveries != nil {
		if err := p.deliveries.Record(ctx, tenant, job.ExecutionID, statuses); err != nil {
			logError("reports.worker", "record deliveries", merge(fields, errf(err)))
		}
	}

	done := time.Now().UTC()
	// Use the parent ctx for the terminal writes so a job that finished right at
	// the timeout still records its completion.
	if err := p.execs.Complete(ctx, job.ExecutionID, done, refs, statuses); err != nil {
		logError("reports.worker", "record completion", merge(fields, errf(err)))
	}
	_ = p.execs.RecordEvent(ctx, tenant, job.ExecutionID, reports.PhaseCompleted, done, "")
	if err := p.queue.Complete(ctx, job.ID); err != nil {
		logError("reports.worker", "finalize job", merge(fields, errf(err)))
	}
	p.metCompleted.Add(1)
	logInfo("reports.worker", "report delivered", merge(fields, map[string]any{"recipients": len(statuses)}))
}

func (p *reportPipeline) heartbeat(ctx context.Context, workerID, jobID string, stop <-chan struct{}) {
	t := time.NewTicker(p.lease / 3)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-stop:
			return
		case <-t.C:
			if err := p.queue.RenewLease(ctx, jobID, workerID, p.lease); err != nil {
				return // lease lost or ctx done; the worker will observe failure/timeout
			}
		}
	}
}

func (p *reportPipeline) dead(job reports.Job) bool { return job.Attempts >= p.maxAttempts }

// runsFromExecutions derives the legacy reportRun map (last/next/status per
// report) from the immutable execution history, so GET /api/reports/runs keeps
// working under the async backend. List is newest-first, so the first row seen
// per schedule is its latest run; the next fire comes from the recurrence.
func (p *reportPipeline) runsFromExecutions(ctx context.Context, tenant string, cross bool) map[string]reportRun {
	out := map[string]reportRun{}
	list, err := p.execs.List(ctx, tenant, cross, reports.ExecQuery{Kind: "report", Limit: 200})
	if err != nil {
		return out
	}
	now := time.Now().UTC()
	for _, e := range list {
		if _, seen := out[e.ScheduleID]; seen {
			continue
		}
		run := reportRun{Status: string(e.Status), LastRun: e.FireTime}
		if !e.CompletedAt.IsZero() {
			run.LastRun = e.CompletedAt
		}
		if a := e.PrimaryArtifact(); a != nil {
			run.Detail = a.Summary
		} else if e.Error != "" {
			run.Detail = e.Error
		}
		if o, ok := p.srv.saved.Get(e.ScheduleID); ok {
			if spec, err := parseReportSpec(o.Body); err == nil && spec.Schedule != nil {
				if nf, ok := spec.Schedule.NextFire(now); ok {
					run.NextRun = nf
				}
			}
		}
		out[e.ScheduleID] = run
	}
	return out
}

// writeMetrics emits the pipeline's Prometheus gauges/counters. Called from
// /metrics; the queue depth is a cheap bounded COUNT.
func (p *reportPipeline) writeMetrics(w io.Writer) {
	pending := -1
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	if n, err := p.queue.Pending(ctx); err == nil {
		pending = n
	}
	cancel()
	fmt.Fprintf(w, "# HELP netops_report_jobs_pending Runnable report jobs in the queue.\n")
	fmt.Fprintf(w, "# TYPE netops_report_jobs_pending gauge\n")
	fmt.Fprintf(w, "netops_report_jobs_pending %d\n", pending)
	fmt.Fprintf(w, "# HELP netops_report_executions_completed_total Report executions delivered.\n")
	fmt.Fprintf(w, "# TYPE netops_report_executions_completed_total counter\n")
	fmt.Fprintf(w, "netops_report_executions_completed_total %d\n", p.metCompleted.Load())
	fmt.Fprintf(w, "# HELP netops_report_jobs_dead_total Report jobs that exhausted retries.\n")
	fmt.Fprintf(w, "# TYPE netops_report_jobs_dead_total counter\n")
	fmt.Fprintf(w, "netops_report_jobs_dead_total %d\n", p.metFailed.Load())
	fmt.Fprintf(w, "# HELP netops_report_job_retries_total Report job retry attempts scheduled.\n")
	fmt.Fprintf(w, "# TYPE netops_report_job_retries_total counter\n")
	fmt.Fprintf(w, "netops_report_job_retries_total %d\n", p.metRetries.Load())
	// Log-export executions (shared substrate, job_type=export).
	fmt.Fprintf(w, "# HELP netops_log_export_executions_total Log export executions completed.\n")
	fmt.Fprintf(w, "# TYPE netops_log_export_executions_total counter\n")
	fmt.Fprintf(w, "netops_log_export_executions_total %d\n", p.metExportDone.Load())
	fmt.Fprintf(w, "# HELP netops_log_export_failures_total Log export executions that failed.\n")
	fmt.Fprintf(w, "# TYPE netops_log_export_failures_total counter\n")
	fmt.Fprintf(w, "netops_log_export_failures_total %d\n", p.metExportFailed.Load())
	fmt.Fprintf(w, "# HELP netops_log_export_rows_total Rows written across log exports.\n")
	fmt.Fprintf(w, "# TYPE netops_log_export_rows_total counter\n")
	fmt.Fprintf(w, "netops_log_export_rows_total %d\n", p.metExportRows.Load())
	fmt.Fprintf(w, "# HELP netops_log_export_bytes_total Bytes written across log exports.\n")
	fmt.Fprintf(w, "# TYPE netops_log_export_bytes_total counter\n")
	fmt.Fprintf(w, "netops_log_export_bytes_total %d\n", p.metExportBytes.Load())
	fmt.Fprintf(w, "# HELP netops_log_export_seconds_total Cumulative log export run time (seconds).\n")
	fmt.Fprintf(w, "# TYPE netops_log_export_seconds_total counter\n")
	fmt.Fprintf(w, "netops_log_export_seconds_total %d\n", p.metExportSeconds.Load())
}

// fail records a failure: an immutable failed execution when terminal, and a
// queue retry-with-backoff (or dead-letter). ctx is the parent (for durable
// writes); jctx is the job context (already possibly cancelled).
func (p *reportPipeline) fail(ctx, _ context.Context, job reports.Job, tenant, cause string, statuses []reports.DeliveryStatus, dead bool, fields map[string]any) {
	now := time.Now().UTC()
	_ = p.execs.RecordEvent(ctx, tenant, job.ExecutionID, reports.PhaseFailed, now, cause)
	if dead {
		if err := p.execs.FailExec(ctx, job.ExecutionID, now, cause, statuses); err != nil {
			logError("reports.worker", "record failure", merge(fields, errf(err)))
		}
	}
	retryAfter := now.Add(backoff(job.Attempts))
	if err := p.queue.Fail(ctx, job.ID, job.Attempts, cause, retryAfter, dead); err != nil {
		logError("reports.worker", "requeue", merge(fields, errf(err)))
	}
	if dead {
		p.metFailed.Add(1)
	} else {
		p.metRetries.Add(1)
	}
	logWarn("reports.worker", "report job failed", merge(fields, map[string]any{"cause": cause, "dead": dead, "attempt": job.Attempts}))
}

// ---- helpers ---------------------------------------------------------------

// errFormatUnavailable marks a requested format with no configured renderer
// (e.g. pdf without a sidecar) — skipped silently, never fatal.
var errFormatUnavailable = errors.New("format renderer unavailable")

// errRenderIncomplete marks a render slot whose goroutine never reported back —
// today only possible when a renderer panics and safeGo recovers it.
var errRenderIncomplete = errors.New("renderer did not complete")

// renderAll renders the dataset to every requested format in parallel, storing
// each artifact under a per-format key (execID_format). HTML is the primary (the
// email body) — its failure sinks the job; a non-HTML format failing is logged
// and skipped so a PDF-sidecar outage can't block the whole report. Returns the
// stored refs and the rendered artifacts (by format) for delivery.
func (p *reportPipeline) renderAll(ctx context.Context, execID string, vm reports.ViewModel, formats []string) ([]reports.ArtifactRef, map[string]reports.Artifact, error) {
	type out struct {
		format string
		art    reports.Artifact
		ref    reports.ArtifactRef
		err    error
	}
	results := make([]out, len(formats))
	var wg sync.WaitGroup
	for i, f := range formats {
		r, ok := p.renderers[f]
		if !ok || r == nil {
			results[i] = out{format: f, err: errFormatUnavailable}
			continue
		}
		wg.Add(1)
		// Pre-seed the slot: if the goroutine dies (a panic recovered by safeGo)
		// it never overwrites this, so the format reports a failure instead of a
		// silently empty artifact.
		results[i] = out{format: f, err: errRenderIncomplete}
		// Panic-guarded: a renderer fault must fail its format, not the process
		// (and the deferred Done still releases the caller either way).
		safeGo("report-render:"+f, func() {
			defer wg.Done()
			art, err := r.Render(ctx, vm)
			if err != nil {
				results[i] = out{format: f, err: err}
				return
			}
			ref, err := p.artifacts.Save(ctx, execID+"_"+f, art)
			results[i] = out{format: f, art: art, ref: ref, err: err}
		})
	}
	wg.Wait()

	arts := map[string]reports.Artifact{}
	var refs []reports.ArtifactRef
	htmlOK := false
	for _, o := range results {
		if o.err != nil {
			if o.format == "html" {
				return nil, nil, o.err
			}
			if !errors.Is(o.err, errFormatUnavailable) {
				logWarn("reports.worker", "format render skipped", map[string]any{"format": o.format, "error": o.err.Error(), "execution_id": execID})
			}
			continue
		}
		arts[o.format] = o.art
		refs = append(refs, o.ref)
		if o.format == "html" {
			htmlOK = true
		}
	}
	if !htmlOK {
		return nil, nil, errors.New("primary HTML render produced no artifact")
	}
	return refs, arts, nil
}

// normalizeFormats dedupes the requested formats and guarantees html is present
// (it's the email body), html first.
func normalizeFormats(in []string) []string {
	out := []string{"html"}
	seen := map[string]bool{"html": true}
	for _, f := range in {
		f = strings.ToLower(strings.TrimSpace(f))
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return out
}

func intervalFires(anchor, now time.Time, interval time.Duration, max int) []time.Time {
	if interval <= 0 {
		return nil
	}
	var out []time.Time
	for t := anchor.Add(interval); !t.After(now) && len(out) < max; t = t.Add(interval) {
		out = append(out, t)
	}
	return out
}

// backoff returns an exponential delay with ±25% jitter, capped at 30 minutes.
func backoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	base := 30 * time.Second
	d := base << (attempt - 1)
	if d > 30*time.Minute || d <= 0 {
		d = 30 * time.Minute
	}
	jitter := time.Duration(rand.Int63n(int64(d) / 4)) //nolint:gosec // non-crypto jitter is fine
	return d - (d / 8) + jitter
}

func sleepJitter(ctx context.Context, max time.Duration) {
	if max <= 0 {
		return
	}
	sleepCtx(ctx, time.Duration(rand.Int63n(int64(max)))) //nolint:gosec
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// corr builds the correlation fields stamped on every pipeline log line so a
// single `grep execution_id` reconstructs a report's whole lifecycle.
func corr(execID, tenant, scheduleID, jobID, workerID string) map[string]any {
	m := map[string]any{"execution_id": execID, "tenant_id": tenant, "schedule_id": scheduleID}
	if jobID != "" {
		m["job_id"] = jobID
	}
	if workerID != "" {
		m["worker_id"] = workerID
	}
	return m
}

func merge(a, b map[string]any) map[string]any {
	out := make(map[string]any, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func errf(err error) map[string]any { return map[string]any{"error": err.Error()} }

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func envDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}
