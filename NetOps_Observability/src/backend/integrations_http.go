package backend

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"

	"netops/backend/integration"
)

// readBounded reads the request body with a hard size cap (webhook bodies are
// untrusted; cap before signature work).
func readBounded(w http.ResponseWriter, r *http.Request, max int64) ([]byte, error) {
	return io.ReadAll(http.MaxBytesReader(w, r.Body, max))
}

// integrations_http.go — the Integration Platform's HTTP surface (P2b):
//   - admin config (GET/PUT /api/integrations[/{provider}]) — tenant-scoped.
//   - inbound webhook (POST /api/integrations/webhook/{provider}/{token}) —
//     UNAUTHENTICATED by JWT; authenticated by the opaque per-tenant token + the
//     provider's signature. Verified → normalized → recorded (3-level dedup) →
//     (when FEATURE_ITSM_INBOUND is on AND the config is bidirectional) ENQUEUED
//     to the worker pool, which orders/reconciles/applies it to the incident
//     lifecycle (integration_inbound_job.go). The webhook returns 200 immediately.
//
// The actual incident MUTATION is gated behind FEATURE_ITSM_INBOUND (default OFF)
// so the ingest path can be enabled and observed before it drives state. The
// apply is async + crash-safe (worker lease re-claim + idempotent re-run).

func itsmInboundEnabled() bool { return os.Getenv("FEATURE_ITSM_INBOUND") == "true" }

// ---- admin config ----------------------------------------------------------

type integrationConfigInput struct {
	Enabled        bool              `json:"enabled"`
	SyncMode       string            `json:"sync_mode"`
	WebhookEnabled bool              `json:"webhook_enabled"`
	WebhookSecret  string            `json:"webhook_secret,omitempty"` // write-only
	StateMap       map[string]string `json:"state_map"`
}

func integrationConfigPublic(c integration.Config) map[string]any {
	out := map[string]any{
		"provider":           c.Provider,
		"enabled":            c.Enabled,
		"sync_mode":          c.SyncMode,
		"webhook_enabled":    c.WebhookEnabled,
		"webhook_secret_set": c.WebhookSecret != "",
		"state_map":          c.StateMap,
	}
	if c.WebhookToken != "" {
		out["webhook_url"] = "/api/integrations/webhook/" + c.Provider + "/" + c.WebhookToken
	}
	return out
}

func (s *server) handleIntegrations(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if s.integrations == nil {
		writeError(w, http.StatusConflict, errors.New("integration platform requires the Postgres backend"))
		return
	}
	tenant, _ := principalTenant(claims)
	key := itsmKey(tenant)

	// PUT /api/integrations/{provider}
	if provider := strings.TrimPrefix(r.URL.Path, "/api/integrations/"); provider != "" && provider != r.URL.Path {
		s.putIntegrationConfig(w, r, key, strings.Trim(provider, "/"))
		return
	}
	// GET /api/integrations
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfgs, err := s.integrations.ListConfigs(r.Context(), key, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]map[string]any, 0, len(cfgs))
	for _, c := range cfgs {
		out = append(out, integrationConfigPublic(c))
	}
	writeJSON(w, http.StatusOK, map[string]any{"integrations": out, "inbound_enabled": itsmInboundEnabled()})
}

func (s *server) putIntegrationConfig(w http.ResponseWriter, r *http.Request, tenant, provider string) {
	if r.Method != http.MethodPut {
		w.Header().Set("Allow", "PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.providers.Get(provider); !ok {
		writeError(w, http.StatusBadRequest, errors.New("unknown provider: "+provider))
		return
	}
	var in integrationConfigInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if in.SyncMode != "outbound" && in.SyncMode != "bidirectional" {
		in.SyncMode = "outbound"
	}
	// Merge against the stored row (preserve write-only secret + token).
	prev, _, _ := s.integrations.GetConfig(r.Context(), tenant, false, provider)
	cfg := integration.Config{
		Tenant: tenant, Provider: provider,
		Enabled: in.Enabled, SyncMode: in.SyncMode,
		WebhookEnabled: in.WebhookEnabled,
		WebhookToken:   prev.WebhookToken,
		WebhookSecret:  firstNonEmptyStr(in.WebhookSecret, prev.WebhookSecret),
		StateMap:       in.StateMap,
	}
	// Mint an opaque token the first time webhooks are enabled.
	if cfg.WebhookEnabled && cfg.WebhookToken == "" {
		cfg.WebhookToken = randHex(24)
	}
	if err := s.integrations.UpsertConfig(r.Context(), cfg); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	logInfo("integration", "config updated", map[string]any{"tenant": tenant, "provider": provider, "webhook": cfg.WebhookEnabled})
	writeJSON(w, http.StatusOK, integrationConfigPublic(cfg))
}

func firstNonEmptyStr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// handleIntegrationReconcile runs an on-demand drift sweep for the caller's tenant
// (a "sync now" for NOC operators — reconcile without waiting for the periodic
// loop). Admin + tenant-scoped.
func (s *server) handleIntegrationReconcile(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.integrations == nil || s.reportPipeline == nil {
		writeError(w, http.StatusConflict, errors.New("integration platform requires the Postgres backend"))
		return
	}
	tenant, _ := principalTenant(claims)
	key := itsmKey(tenant)
	cfgs, err := s.integrations.ListConfigs(r.Context(), key, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	n := 0
	for _, cfg := range cfgs {
		if cfg.Bidirectional() {
			s.reconcileProvider(r.Context(), cfg)
			n++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"reconciled_providers": n})
}

// ---- inbound webhook -------------------------------------------------------

func (s *server) handleIntegrationWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.integrations == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	// Path: /api/integrations/webhook/{provider}/{token}
	rest := strings.TrimPrefix(r.URL.Path, "/api/integrations/webhook/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	providerType, token := parts[0], parts[1]

	prov, ok := s.providers.Get(providerType)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	cfg, found, err := s.integrations.ConfigByToken(r.Context(), token)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// Unknown token / wrong provider / webhook disabled → 404 (don't leak which).
	if !found || cfg.Provider != providerType || !cfg.WebhookEnabled {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	body, err := readBounded(w, r, 512<<10)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := prov.VerifyWebhook(r, body, cfg.WebhookSecret); err != nil {
		s.intgWebhookRejected()
		writeError(w, http.StatusUnauthorized, errors.New("signature verification failed"))
		return
	}
	events, err := prov.Normalize(cfg.Tenant, body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	ctx := r.Context()
	queued := 0
	// F-75: these three counters replace `len(events)`. The old response said
	// `received: <number PARSED>`, so all N could fail to record and the body
	// still reported N. Worse, the 200 told ServiceNow/Jira the delivery
	// succeeded — and a webhook sender's retry is the ONLY recovery mechanism
	// for an inbound ticket-state transition. A 200 over a failed write turned a
	// transient database error into permanent, unrecoverable loss.
	recorded, duplicates, failed := 0, 0, 0
	for _, ev := range events {
		id, correlationID, inserted, err := s.integrations.RecordInbound(ctx, ev)
		if err != nil {
			failed++
			logError("integration", "record inbound", map[string]any{"provider": providerType, "error": err.Error()})
			continue
		}
		if !inserted {
			duplicates++
			continue // level-1 raw duplicate (redelivery) — already handled
		}
		recorded++
		s.intgWebhookReceived()
		logInfo("integration", "inbound recorded", map[string]any{
			"provider": providerType, "external_id": ev.ExternalID, "event_id": id,
			"correlation_id": correlationID, "alert_id": ev.AlertID})
		// Mutation is gated: only a bidirectional config with the flag on drives
		// state. The apply is ENQUEUED (async, crash-safe via the worker lease),
		// so the webhook returns immediately and never blocks the caller.
		if itsmInboundEnabled() && cfg.Bidirectional() && s.reportPipeline != nil {
			if _, err := s.reportPipeline.EnqueueIntegrationInbound(ctx, ev.Tenant, id, correlationID); err != nil {
				// Recorded in the ledger but never queued: the transition would
				// sit forever unapplied. Count it as failed so the sender
				// redelivers — RecordInbound dedupes the replay.
				failed++
				logError("integration", "enqueue inbound", map[string]any{"provider": providerType, "error": err.Error()})
				continue
			}
			queued++
		} else if err := s.integrations.MarkEvent(ctx, id, "received", "ingest-only"); err != nil {
			// Not fatal — the event IS in the ledger — but it must not vanish.
			logError("integration", "mark event", map[string]any{"provider": providerType, "event_id": id, "error": err.Error()})
		}
	}

	out := inboundOutcome{
		Parsed: len(events), Recorded: recorded,
		Duplicates: duplicates, Queued: queued, Failed: failed,
	}
	if failed > 0 {
		logError("integration", "inbound webhook partially failed — asking the sender to redeliver",
			map[string]any{"provider": providerType, "parsed": len(events), "failed": failed})
	}
	writeJSON(w, out.status(), out.body())
}

// inboundOutcome is one webhook delivery's tally, and the decision it implies.
//
// F-75: the handler used to answer `{"received": len(events)}` with a hard-coded
// 200 — the count of events PARSED, not recorded. All N could fail to write and
// the response still said N, with a 200 that told ServiceNow/Jira the delivery
// had succeeded. A webhook sender's retry is the only recovery path for an
// inbound ticket-state transition, so that 200 converted a transient database
// error into permanent, unrecoverable loss.
//
// Split out as a value with no IO so the decision is testable: the concrete
// *integration.Store is nil on the file backend, which is precisely why nothing
// exercised this path before.
type inboundOutcome struct {
	Parsed     int // events the provider's Normalize produced
	Recorded   int // newly written to the ledger
	Duplicates int // level-1 raw duplicates — already durable from an earlier delivery
	Queued     int // enqueued for the apply worker
	Failed     int // could not be recorded, or recorded but not queued
}

// status returns 500 when anything failed, so the sender redelivers. Partial
// success is still a failure: replay is safe because RecordInbound dedupes raw
// duplicates, so events that DID land are not applied twice.
func (o inboundOutcome) status() int {
	if o.Failed > 0 {
		return http.StatusInternalServerError
	}
	return http.StatusOK
}

// body reports what actually happened. `received` counts what is DURABLE
// (new + already-stored duplicates), never what was merely parsed.
func (o inboundOutcome) body() map[string]any {
	return map[string]any{
		"received":   o.Recorded + o.Duplicates,
		"parsed":     o.Parsed,
		"new":        o.Recorded,
		"duplicates": o.Duplicates,
		"queued":     o.Queued,
		"failed":     o.Failed,
	}
}

// applyInboundEvent orders/reconciles one recorded event and applies the verdict
// to the incident lifecycle. Returns true when it mutated an incident.
func (s *server) applyInboundEvent(ctx context.Context, cfg integration.Config, ev integration.IntegrationEvent, ledgerID, correlationID string) bool {
	if s.incidents == nil {
		_ = s.integrations.MarkEvent(ctx, ledgerID, "dropped", "no-incident-store")
		return false
	}
	// Correlate to the originating incident.
	inc, found := s.correlateIncident(ctx, cfg.Tenant, ev)
	if !found {
		_ = s.integrations.MarkEvent(ctx, ledgerID, "dropped", "no-incident")
		return false
	}
	// Watermark for this external incident (§4a).
	m, _, _ := s.integrations.GetMapping(ctx, cfg.Tenant, false, ev.Provider, ev.ExternalID)

	decision := cfg.MappingEngineFor().Reconcile(ev, integration.InternalState(inc.Status), m.Applied)
	if !decision.Apply {
		_ = s.integrations.MarkEvent(ctx, ledgerID, "dropped", decision.Reason)
		return false
	}

	actor := "itsm:" + ev.Provider
	if ev.Actor != "" {
		actor = ev.Provider + ":" + ev.Actor
	}
	mutated := true
	switch {
	case decision.Target != "":
		if _, err := s.incidents.Transition(ctx, cfg.Tenant, false, inc.ID, string(decision.Target), actor, "via "+ev.Provider); err != nil {
			_ = s.integrations.MarkEvent(ctx, ledgerID, "dropped", "transition: "+err.Error())
			return false
		}
	case decision.Assignee != "":
		if _, err := s.incidents.Assign(ctx, cfg.Tenant, false, inc.ID, decision.Assignee, actor); err != nil {
			_ = s.integrations.MarkEvent(ctx, ledgerID, "dropped", "assign: "+err.Error())
			return false
		}
	case decision.Comment != "":
		if _, err := s.incidents.AddNote(ctx, cfg.Tenant, false, inc.ID, actor, decision.Comment); err != nil {
			_ = s.integrations.MarkEvent(ctx, ledgerID, "dropped", "note: "+err.Error())
			return false
		}
	default:
		mutated = false
	}

	// Advance the watermark + record the verdict.
	state := string(decision.Target)
	if state == "" {
		state = inc.Status
	}
	_ = s.integrations.UpsertMapping(ctx, integration.Mapping{
		Tenant: cfg.Tenant, Provider: ev.Provider, ExternalID: ev.ExternalID,
		IncidentID: inc.ID, State: state, Applied: decision.Watermark,
	})
	_ = s.integrations.MarkEvent(ctx, ledgerID, "applied", decision.Reason)
	logInfo("integration", "inbound applied", map[string]any{
		"provider": ev.Provider, "external_id": ev.ExternalID, "incident_id": inc.ID,
		"target": string(decision.Target), "reason": decision.Reason,
		"correlation_id": correlationID, "alert_id": ev.AlertID,
	})
	return mutated
}

// correlateIncident resolves the internal incident an inbound event refers to.
// Slack actions carry our internal incident id directly (the button value);
// ticketing providers correlate via the external_ticket_id forward link.
func (s *server) correlateIncident(ctx context.Context, tenant string, ev integration.IntegrationEvent) (Incident, bool) {
	if ev.Provider == "slack" && ev.AlertID != "" {
		inc, _, found, err := s.incidents.Get(ctx, tenant, false, ev.AlertID)
		if err != nil {
			return Incident{}, false
		}
		return inc, found
	}
	inc, found, err := s.incidents.FindByExternalTicket(ctx, tenant, ev.Provider, ev.ExternalID)
	if err != nil {
		return Incident{}, false
	}
	return inc, found
}
