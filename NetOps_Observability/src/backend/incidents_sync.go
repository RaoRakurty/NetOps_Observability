package backend

import (
	"context"
	"encoding/json"
	"errors"
	"netops/backend/integration"
	"time"

	"netops/backend/reports"
)

// incidents_sync.go — the optional, async ITSM PROJECTION of an incident, run on
// the shared execution substrate (job_type=incident_sync). The incident is the
// system of record; an ITSM outage NEVER affects incident creation/lifecycle — it
// only records sync_status=failed and the job retries with backoff (dead-letters
// after max attempts). Idempotent: a re-run on an already-ticketed incident is a
// no-op, so retries can't create duplicate tickets.

const jobTypeIncidentSync = "incident_sync"

type incidentSyncPayload struct {
	IncidentID string `json:"incident_id"`
}

// EnqueueIncidentSync queues an ITSM projection for an incident and marks it
// sync_status=pending. Returns the execution id.
func (p *reportPipeline) EnqueueIncidentSync(ctx context.Context, tenant, incidentID string) (string, error) {
	now := time.Now().UTC()
	tenant = normTenant(tenant)
	execID := randHex(8)
	payload, _ := json.Marshal(incidentSyncPayload{IncidentID: incidentID}) // discard: marshalling an in-memory value cannot fail
	job := reports.Job{
		JobType: jobTypeIncidentSync, TenantID: tenant,
		ScheduleID: "syncinc:" + incidentID + ":" + execID, ExecutionID: execID, FireTime: now, Payload: payload,
	}
	if _, _, err := p.queue.Enqueue(ctx, job, now); err != nil {
		return "", err
	}
	rec := reports.ExecutionRecord{
		ID: execID, Kind: jobTypeIncidentSync, TenantID: tenant,
		ScheduleID: job.ScheduleID, JobID: execID, FireTime: now, Status: reports.StatusQueued,
	}
	if err := p.execs.Append(ctx, rec); err != nil {
		return "", err
	}
	if p.srv.incidents != nil {
		if err := p.srv.incidents.MarkSync(ctx, incidentID, "", "", "", "pending", now); err != nil {
			logWarn("incidents.sync", "mark pending", map[string]any{"incident_id": incidentID, "error": err.Error()})
		}
	}
	return execID, nil
}

// processIncidentSync creates/updates the external ticket. ctx is the parent
// (durable writes); jctx carries the job timeout. The execution is already marked
// running by process().
func (p *reportPipeline) processIncidentSync(ctx, jctx context.Context, _ string, job reports.Job, tenant string, fields map[string]any) {
	var pl incidentSyncPayload
	if err := json.Unmarshal(job.Payload, &pl); err != nil {
		p.fail(ctx, jctx, job, tenant, "invalid incident-sync payload: "+err.Error(), nil, true, fields)
		return
	}
	if p.srv.incidents == nil {
		p.fail(ctx, jctx, job, tenant, "incident store unavailable", nil, true, fields)
		return
	}
	inc, _, found, err := p.srv.incidents.Get(jctx, "", true, pl.IncidentID)
	if err != nil {
		p.fail(ctx, jctx, job, tenant, "load incident: "+err.Error(), nil, p.dead(job), fields)
		return
	}
	if !found {
		p.fail(ctx, jctx, job, tenant, "incident no longer exists", nil, true, fields)
		return
	}
	// Idempotency: a ticket already exists for this incident — never create a
	// second one (retries and re-promotes become no-ops). A failed sync leaves
	// external_ticket_id empty, so it still retries.
	if inc.ExternalTicket != "" {
		p.finishIncidentSync(ctx, job, tenant, fields)
		return
	}

	system, ticketID, url, perr := p.projectIncident(inc)
	now := time.Now().UTC()
	if perr != nil {
		if err := p.srv.incidents.MarkSync(ctx, inc.ID, system, "", "", "failed", now); err != nil {
			logError("incidents.sync", "mark sync failed", merge(fields, errf(err)))
		}
		p.srv.incidentSync(false)
		// Transient ITSM/config error → retry with backoff; the incident is untouched.
		p.fail(ctx, jctx, job, tenant, "itsm projection: "+perr.Error(), nil, p.dead(job), fields)
		return
	}
	if err := p.srv.incidents.MarkSync(ctx, inc.ID, system, ticketID, url, "synced", now); err != nil {
		logError("incidents.sync", "mark synced", merge(fields, errf(err)))
	}
	// Record the external↔internal mapping so the drift reconciler can poll this
	// ticket and so a future inbound webhook correlates by it. applied_seq starts
	// at 0 — the first poll/webhook that observes a newer version drives state.
	if p.srv.integrations != nil && ticketID != "" {
		if err := p.srv.integrations.UpsertMapping(ctx, integration.Mapping{
			Tenant: inc.TenantID, Provider: system, ExternalID: ticketID,
			IncidentID: inc.ID, State: inc.Status,
		}); err != nil {
			// The ticket exists but the reconciler can't poll it and inbound
			// webhooks won't correlate — that drift must not be silent.
			logError("incidents.sync", "record ticket mapping", merge(fields, errf(err)))
		}
	}
	p.srv.incidentSync(true)
	p.finishIncidentSync(ctx, job, tenant, fields)
	logInfo("incidents.sync", "incident projected to ITSM",
		merge(fields, map[string]any{"system": system, "ticket": ticketID, "incident_id": inc.ID}))
}

func (p *reportPipeline) finishIncidentSync(ctx context.Context, job reports.Job, tenant string, fields map[string]any) {
	now := time.Now().UTC()
	if err := p.execs.Complete(ctx, job.ExecutionID, now, nil, nil, job.LockedBy); err != nil {
		logError("incidents.sync", "record completion", merge(fields, errf(err)))
	}
	p.recordPhase(ctx, tenant, job.ExecutionID, reports.PhaseCompleted, now, "")
	if err := p.queue.Complete(ctx, job.ID, job.LockedBy); err != nil {
		logError("incidents.sync", "finalize job", merge(fields, errf(err)))
	}
}

// projectIncident creates a ticket in the incident's OWN tenant ITSM — ServiceNow
// preferred, then Jira. A tenant's incidents can only ever reach that tenant's
// connector (resolved by inc.TenantID); global/"" incidents reach the platform
// connector. Returns (system, ticketID, url).
func (p *reportPipeline) projectIncident(inc Incident) (string, string, string, error) {
	if sn := p.srv.serviceNowFor(inc.TenantID); sn != nil && sn.Configured() {
		id, url, err := sn.CreateForIncident(inc.Title, inc.Description, inc.Severity, "")
		return "servicenow", id, url, err
	}
	if j := p.srv.jiraFor(inc.TenantID); j != nil && j.Configured() {
		id, url, err := j.CreateForIncident(inc.Title, inc.Description, inc.Severity)
		return "jira", id, url, err
	}
	return "", "", "", errors.New("no ITSM integration configured for this tenant")
}

// itsmConfiguredFor reports whether the given tenant has an external ticketing
// target available — so the auto-policy doesn't enqueue syncs that only
// dead-letter for a tenant with no connector.
func (s *server) itsmConfiguredFor(tenant string) bool {
	sn := s.serviceNowFor(tenant)
	j := s.jiraFor(tenant)
	return (sn != nil && sn.Configured()) || (j != nil && j.Configured())
}
