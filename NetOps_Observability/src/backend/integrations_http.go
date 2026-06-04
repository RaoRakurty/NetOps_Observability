package main

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

func integrationConfigPublic(c integrationConfig) map[string]any {
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
	cfg := integrationConfig{
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
	for _, ev := range events {
		id, inserted, err := s.integrations.RecordInbound(ctx, ev)
		if err != nil {
			logError("integration", "record inbound", map[string]any{"provider": providerType, "error": err.Error()})
			continue
		}
		if !inserted {
			continue // level-1 raw duplicate (redelivery) — already handled
		}
		s.intgWebhookReceived()
		// Mutation is gated: only a bidirectional config with the flag on drives
		// state. The apply is ENQUEUED (async, crash-safe via the worker lease),
		// so the webhook returns immediately and never blocks the caller.
		if itsmInboundEnabled() && cfg.Bidirectional() && s.reportPipeline != nil {
			if _, err := s.reportPipeline.EnqueueIntegrationInbound(ctx, ev.Tenant, id); err != nil {
				logError("integration", "enqueue inbound", map[string]any{"provider": providerType, "error": err.Error()})
				continue
			}
			queued++
		} else {
			_ = s.integrations.MarkEvent(ctx, id, "received", "ingest-only")
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"received": len(events), "queued": queued})
}

// applyInboundEvent orders/reconciles one recorded event and applies the verdict
// to the incident lifecycle. Returns true when it mutated an incident.
func (s *server) applyInboundEvent(ctx context.Context, cfg integrationConfig, ev integration.IntegrationEvent, ledgerID string) bool {
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

	decision := cfg.mappingEngine().Reconcile(ev, integration.InternalState(inc.Status), m.Applied)
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
	_ = s.integrations.UpsertMapping(ctx, integrationMapping{
		Tenant: cfg.Tenant, Provider: ev.Provider, ExternalID: ev.ExternalID,
		IncidentID: inc.ID, State: state, Applied: decision.Watermark,
	})
	_ = s.integrations.MarkEvent(ctx, ledgerID, "applied", decision.Reason)
	logInfo("integration", "inbound applied", map[string]any{
		"provider": ev.Provider, "external_id": ev.ExternalID, "incident_id": inc.ID,
		"target": string(decision.Target), "reason": decision.Reason,
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
