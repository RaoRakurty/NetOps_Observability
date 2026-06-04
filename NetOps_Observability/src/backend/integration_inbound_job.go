package main

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
	EventID string `json:"event_id"` // integration_events ledger row id
}

// EnqueueIntegrationInbound queues the apply of a recorded inbound event.
func (p *reportPipeline) EnqueueIntegrationInbound(ctx context.Context, tenant, eventID string) (string, error) {
	now := time.Now().UTC()
	tenant = normTenant(tenant)
	execID := randHex(8)
	payload, _ := json.Marshal(integrationInboundPayload{EventID: eventID})
	job := reports.Job{
		JobType: jobTypeIntegrationInbound, TenantID: tenant,
		ScheduleID: "itsm-inbound:" + eventID, ExecutionID: execID, FireTime: now, Payload: payload,
	}
	if _, _, err := p.queue.Enqueue(ctx, job, now); err != nil {
		return "", err
	}
	rec := reports.ExecutionRecord{
		ID: execID, Kind: jobTypeIntegrationInbound, TenantID: tenant,
		ScheduleID: job.ScheduleID, JobID: execID, FireTime: now, Status: reports.StatusQueued,
	}
	if err := p.execs.Append(ctx, rec); err != nil {
		return "", err
	}
	return execID, nil
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
	cfg, ok, _ := p.srv.integrations.GetConfig(jctx, ev.Tenant, false, ev.Provider)
	if !ok {
		// Config removed after the webhook landed — nothing to apply against.
		_ = p.srv.integrations.MarkEvent(ctx, pl.EventID, "dropped", "config-removed")
		p.finishInbound(ctx, job, tenant, fields)
		return
	}
	// applyInboundEvent records its own ledger verdict + advances the watermark.
	p.srv.intgInbound(p.srv.applyInboundEvent(jctx, cfg, ev, pl.EventID))
	p.finishInbound(ctx, job, tenant, fields)
	logInfo("integration.inbound", "applied", merge(fields, map[string]any{
		"provider": ev.Provider, "external_id": ev.ExternalID, "event_id": pl.EventID}))
}

func (p *reportPipeline) finishInbound(ctx context.Context, job reports.Job, tenant string, fields map[string]any) {
	now := time.Now().UTC()
	_ = p.execs.Complete(ctx, job.ExecutionID, now, nil, nil)
	_ = p.execs.RecordEvent(ctx, tenant, job.ExecutionID, reports.PhaseCompleted, now, "")
	if err := p.queue.Complete(ctx, job.ID); err != nil {
		logError("integration.inbound", "finalize job", merge(fields, errf(err)))
	}
}
