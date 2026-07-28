package main

import (
	"context"
	"errors"
	"netops/backend/internal/incident"
	"os"
	"strconv"
	"time"

	"netops/backend/integration"
)

// integration_reconciler.go — the DRIFT RECONCILER (design §7), the safety net for
// dropped / duplicated / out-of-order webhooks. Periodically, per bidirectional
// (tenant, provider), it polls each open ticket's current state and — when the
// external version is ahead of what we've applied — SYNTHESIZES a canonical
// inbound event and re-drives it through the SAME async apply path
// (RecordInbound → EnqueueIntegrationInbound). So all dedup / ordering /
// conflict / idempotency logic is reused; the reconciler adds no new state rules.
//
// Gated behind FEATURE_ITSM_RECONCILE (default off); it makes outbound calls to
// the ITSM systems, so an operator enables it deliberately.

const (
	reconcileBatchPerProvider = 50
)

// startDriftReconciler launches the periodic loop (no-op unless enabled + PG).
func (s *server) startDriftReconciler(ctx context.Context) {
	if s.integrations == nil || s.reportPipeline == nil {
		return
	}
	if os.Getenv("FEATURE_ITSM_RECONCILE") != "true" {
		return
	}
	interval := 5 * time.Minute
	if v := os.Getenv("ITSM_RECONCILE_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= time.Minute {
			interval = d
		}
	}
	safeGo("itsm-drift-reconciler", func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.reconcileDriftOnce(ctx)
			}
		}
	})
	logInfo("integration.reconcile", "drift reconciler started", map[string]any{"interval": interval.String()})
}

// reconcileDriftOnce sweeps every bidirectional (tenant, provider).
func (s *server) reconcileDriftOnce(ctx context.Context) {
	cfgs, err := s.integrations.ListBidirectionalConfigs(ctx)
	if err != nil {
		logError("integration.reconcile", "list configs", errf(err))
		return
	}
	for _, cfg := range cfgs {
		s.reconcileProvider(ctx, cfg)
	}
}

// reconcileProvider polls one tenant's open tickets for a provider and re-drives
// any drift through the inbound pipeline.
func (s *server) reconcileProvider(ctx context.Context, cfg integrationConfig) {
	maps, err := s.integrations.ListOpenMappings(ctx, cfg.Tenant, cfg.Provider, reconcileBatchPerProvider)
	if err != nil {
		logError("integration.reconcile", "list mappings", merge(map[string]any{"tenant": cfg.Tenant, "provider": cfg.Provider}, errf(err)))
		return
	}
	engine := cfg.mappingEngine()
	for _, m := range maps {
		state, version, found, perr := s.pollExternalState(cfg.Provider, cfg.Tenant, m.ExternalID)
		// Rotate this mapping to the back of the stalest-first queue regardless.
		_ = s.integrations.TouchMapping(ctx, cfg.Tenant, cfg.Provider, m.ExternalID)
		if perr != nil || !found {
			continue // transient poll error or ticket gone — leave for next sweep
		}

		// CASE A (ITSM → NMS): the external ticket changed since we last applied →
		// synthesize a canonical event and re-drive it through the inbound pipeline
		// (idempotent via the synthetic provider_evt_id + the ordering watermark).
		if version > m.Applied.Seq {
			ev := integration.IntegrationEvent{
				Provider:      cfg.Provider,
				Tenant:        cfg.Tenant,
				ProviderEvtID: "poll:" + m.ExternalID + ":" + strconv.FormatInt(version, 10),
				ExternalID:    m.ExternalID,
				ExternalSeq:   version,
				Type:          integration.EventUpdated,
				ExternalState: integration.CanonicalState(cfg.Provider, state),
			}
			id, correlationID, inserted, rerr := s.integrations.RecordInbound(ctx, ev)
			if rerr != nil || !inserted {
				continue // dedup: this exact poll result was already handled
			}
			if _, eerr := s.reportPipeline.EnqueueIntegrationInbound(ctx, cfg.Tenant, id, correlationID); eerr != nil {
				logError("integration.reconcile", "enqueue drift", errf(eerr))
				continue
			}
			s.intgDrift(false)
			logInfo("integration.reconcile", "inbound drift → re-drove", map[string]any{
				"tenant": cfg.Tenant, "provider": cfg.Provider, "external_id": m.ExternalID,
				"external_version": version, "applied_seq": m.Applied.Seq, "state": ev.ExternalState,
				"correlation_id": correlationID,
			})
			continue
		}

		// CASE B (NMS → ITSM): the external ticket is unchanged, but NMS has gone
		// terminal (alert cleared) while the ticket is still open → push a Resolve
		// (NMS owns terminal). Idempotent: the PATCH/transition no-ops if already
		// resolved, and we mark the mapping terminal so it stops being polled.
		extInternal, mapped := engine.MapState(integration.CanonicalState(cfg.Provider, state))
		if !mapped || extInternal.IsTerminal() {
			continue
		}
		inc, _, incFound, _ := s.incidents.Get(ctx, cfg.Tenant, false, m.IncidentID)
		if !incFound || !incident.IsTerminalStatus(inc.Status) {
			continue
		}
		if rerr := s.resolveExternalTicket(cfg.Provider, cfg.Tenant, m.ExternalID); rerr != nil {
			logError("integration.reconcile", "outbound resolve", merge(map[string]any{"external_id": m.ExternalID}, errf(rerr)))
			continue
		}
		_ = s.integrations.UpsertMapping(ctx, integrationMapping{
			Tenant: cfg.Tenant, Provider: cfg.Provider, ExternalID: m.ExternalID,
			IncidentID: m.IncidentID, State: inc.Status, Applied: m.Applied,
		})
		s.intgDrift(true)
		logInfo("integration.reconcile", "outbound drift → pushed resolve to ITSM", map[string]any{
			"tenant": cfg.Tenant, "provider": cfg.Provider, "external_id": m.ExternalID, "nms_status": inc.Status,
		})
	}
}

// resolveExternalTicket pushes a Resolve to the external system via the per-tenant
// outbound connector (drift case B).
func (s *server) resolveExternalTicket(provider, tenant, externalID string) error {
	switch provider {
	case "servicenow":
		if c := s.serviceNowFor(tenant); c != nil {
			return c.ResolveExternal(externalID)
		}
	case "jira":
		if c := s.jiraFor(tenant); c != nil {
			return c.ResolveExternal(externalID)
		}
	}
	return errors.New("no outbound connector for provider " + provider)
}

// pollExternalState fetches an external ticket's current (state, version) via the
// per-tenant outbound connector.
func (s *server) pollExternalState(provider, tenant, externalID string) (string, int64, bool, error) {
	switch provider {
	case "servicenow":
		if c := s.serviceNowFor(tenant); c != nil {
			return c.PollState(externalID)
		}
	case "jira":
		if c := s.jiraFor(tenant); c != nil {
			return c.PollState(externalID)
		}
	}
	return "", 0, false, nil // provider has no poll connector (e.g. slack/pagerduty)
}
