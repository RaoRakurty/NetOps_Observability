package backend

import (
	"context"
	"encoding/json"
	"time"

	"netops/backend/reports"
)

// integration_inbound_job.go — ASYNC inbound apply (#43 P3 hardening). The webhook
// handler verifies + records an inbound event, then enqueues this job instead of
// applying inline. The shared PG worker pool then orders/reconciles/applies it to
// the incident lifecycle. Why async:
//   - the webhook returns 200 immediately (never blocks the external caller);
//   - a worker crash mid-apply is crash-safe — the lease lapses, another worker
//     re-claims the job, and the re-run is IDEMPOTENT (the ordering watermark
//     drops an already-applied event as stale; an interrupted apply re-applies a
//     same-state transition, a no-op). This closes failure scenario #10.

const jobTypeIntegrationInbound = "integration_inbound"

type integrationInboundPayload struct {
	EventID       string `json:"event_id"`       // integration_events ledger row id
	CorrelationID string `json:"correlation_id"` // §9 end-to-end trace id (carried into worker logs)
}

// EnqueueIntegrationInbound queues the apply of a recorded inbound event. The
// correlationID is persisted in the job payload so it survives a crash/re-claim
// and threads into the worker's apply logs.
//
// IDEMPOTENT PER EVENT (M14): recordedAt is the ledger row's created_at —
// stable across redeliveries — and becomes the job's FireTime, so the queue's
// UNIQUE(schedule_id, fire_time) collapses a re-enqueue of the same event into
// the existing job (created=false, no duplicate execution record). The
// previous FireTime=now() made every redelivery's enqueue a NEW job, which is
// exactly why the recorded-but-never-enqueued recovery path couldn't exist.
func (p *reportPipeline) EnqueueIntegrationInbound(ctx context.Context, tenant, eventID, correlationID string, recordedAt time.Time) (string, bool, error) {
	tenant = normTenant(tenant)
	fire := recordedAt.UTC()
	if fire.IsZero() {
		fire = time.Now().UTC() // defensive: a zero fire_time would collide across events
	}
	execID := randHex(8)
	payload, _ := json.Marshal(integrationInboundPayload{EventID: eventID, CorrelationID: correlationID}) // discard: marshalling an in-memory value cannot fail
	job := reports.Job{
		JobType: jobTypeIntegrationInbound, TenantID: tenant,
		ScheduleID: "itsm-inbound:" + eventID, ExecutionID: execID, FireTime: fire, Payload: payload,
	}
	_, created, err := p.queue.Enqueue(ctx, job, time.Now().UTC())
	if err != nil {
		return "", false, err
	}
	if !created {
		return "", false, nil // the apply job already exists — nothing new to record
	}
	rec := reports.ExecutionRecord{
		ID: execID, Kind: jobTypeIntegrationInbound, TenantID: tenant,
		ScheduleID: job.ScheduleID, JobID: execID, FireTime: fire, Status: reports.StatusQueued,
	}
	if err := p.execs.Append(ctx, rec); err != nil {
		return "", true, err
	}
	return execID, true, nil
}

// processIntegrationInbound loads the recorded event + its tenant config and
// drives the apply (order → reconcile → incident transition). Idempotent: safe to
// re-run after a crash. The execution is already marked running by process().
func (p *reportPipeline) processIntegrationInbound(ctx, jctx context.Context, _ string, job reports.Job, tenant string, fields map[string]any) {
	var pl integrationInboundPayload
	if err := json.Unmarshal(job.Payload, &pl); err != nil {
		p.fail(ctx, jctx, job, tenant, "invalid inbound payload: "+err.Error(), nil, true, fields)
		return
	}
	if p.srv.integrations == nil {
		p.fail(ctx, jctx, job, tenant, "integration store unavailable", nil, true, fields)
		return
	}
	ev, found, err := p.srv.integrations.GetInboundEvent(jctx, pl.EventID)
	if err != nil {
		p.fail(ctx, jctx, job, tenant, "load inbound event: "+err.Error(), nil, p.dead(job), fields)
		return
	}
	if !found {
		p.fail(ctx, jctx, job, tenant, "inbound event no longer exists", nil, true, fields)
		return
	}
	cfg, ok, cfgErr := p.srv.integrations.GetConfig(jctx, ev.Tenant, false, ev.Provider)
	if cfgErr != nil {
		// M14: a store ERROR is not "config removed" — dropping here turned a
		// transient database blip into a permanently un-applied transition.
		// Retry (dead-letter only after max attempts) so the verdict reflects
		// what happened, not what the outage looked like.
		p.fail(ctx, jctx, job, tenant, "load integration config: "+cfgErr.Error(), nil, p.dead(job), fields)
		return
	}
	if !ok {
		// Config removed after the webhook landed — nothing to apply against.
		p.srv.markInboundEvent(ctx, pl.EventID, "dropped", "config-removed")
		p.finishInbound(ctx, job, tenant, fields)
		return
	}
	// applyInboundEvent records its own ledger verdict + advances the watermark;
	// a returned error is a TRANSIENT store failure → retry, never a "dropped"
	// verdict (M14).
	mutated, applyErr := p.srv.applyInboundEvent(jctx, cfg, ev, pl.EventID, pl.CorrelationID)
	if applyErr != nil {
		p.fail(ctx, jctx, job, tenant, "apply inbound event: "+applyErr.Error(), nil, p.dead(job), fields)
		return
	}
	p.srv.intgInbound(mutated)
	p.finishInbound(ctx, job, tenant, fields)
	logInfo("integration.inbound", "applied", merge(fields, map[string]any{
		"provider": ev.Provider, "external_id": ev.ExternalID, "event_id": pl.EventID,
		"correlation_id": pl.CorrelationID}))
}

func (p *reportPipeline) finishInbound(ctx context.Context, job reports.Job, tenant string, fields map[string]any) {
	now := time.Now().UTC()
	if err := p.execs.Complete(ctx, job.ExecutionID, now, nil, nil); err != nil {
		logError("integration.inbound", "record completion", merge(fields, errf(err)))
	}
	p.recordPhase(ctx, tenant, job.ExecutionID, reports.PhaseCompleted, now, "")
	if err := p.queue.Complete(ctx, job.ID, job.LockedBy); err != nil {
		logError("integration.inbound", "finalize job", merge(fields, errf(err)))
	}
}
