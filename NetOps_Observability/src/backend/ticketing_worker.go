package main

import (
	"errors"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"time"
)

// ticketing_worker.go — the outbox worker (#78 P2). It drains ticket_outbox so
// external ticketing NEVER blocks correlation: the policy layer (P3) only
// ENQUEUES; this worker claims due rows (SKIP LOCKED), dispatches through the
// ticketAdapter, and on failure retries with exponential backoff + jitter,
// dead-lettering after max_retries. Every action writes a ticket_audit_log
// entry; a successful create/update advances the correlix_ticket_link.
//
// At-most-once is enforced two ways: the outbox idempotency_key (one row per
// logical action) and ServiceNow's native correlation_id (a create looks up an
// existing incident first, so a lost link store never doubles a ticket).

// ticketConnResolver yields the connection for a (tenant, system). Returns
// ok=false when no connection is configured (a transient hold, not a failure).
type ticketConnResolver func(ctx context.Context, tenant, system string) (ticketSystemConfig, bool, error)

type ticketWorker struct {
	store       ticketingStore
	adapters    map[string]ticketAdapter
	resolveConn ticketConnResolver
	workerID    string
	batch       int
	lease       time.Duration
	maxRetries  int
}

func newTicketWorker(store ticketingStore, resolve ticketConnResolver) *ticketWorker {
	return &ticketWorker{
		store:       store,
		adapters: map[string]ticketAdapter{"servicenow": newServiceNowAdapter(), "pagerduty": newPagerDutyTicketAdapter()},
		resolveConn: resolve,
		workerID:    "ticket-" + randID()[:8],
		batch:       16,
		lease:       2 * time.Minute,
		maxRetries:  8,
	}
}

// Run drives tick() on an interval until ctx is cancelled. Dormant unless wired
// in (FEATURE_RCA_TICKETING) — ticketing is opt-in.
func (w *ticketWorker) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := w.tick(ctx, time.Now().UTC()); err != nil {
				logWarn("ticketing", "outbox tick failed", map[string]any{"error": err.Error()})
			}
		}
	}
}

// tick claims one due batch and processes each item. Returns the count handled.
func (w *ticketWorker) tick(ctx context.Context, now time.Time) (int, error) {
	items, err := w.store.ClaimDueOutbox(ctx, w.workerID, w.batch, w.lease)
	if err != nil {
		return 0, err
	}
	for _, it := range items {
		w.process(ctx, it, now)
	}
	return len(items), nil
}

// process dispatches one claimed item and writes back its next state.
func (w *ticketWorker) process(ctx context.Context, it ticketOutboxItem, now time.Time) {
	adapter := w.adapters[orDefault(it.ExternalSystem, "servicenow")]
	if adapter == nil {
		w.deadLetter(ctx, it, "no adapter for "+it.ExternalSystem)
		return
	}
	cfg, ok, err := w.resolveConn(ctx, it.TenantID, it.ExternalSystem)
	if err != nil {
		w.retryLater(ctx, it, now, "resolve connection: "+err.Error())
		return
	}
	if !ok || cfg.InstanceURL == "" {
		// Not configured yet — a transient hold, not a permanent failure.
		w.retryLater(ctx, it, now, "no ticketing connection configured")
		return
	}

	// #103 defensive tenant assertion: the resolved connection must belong to
	// the outbox item's tenant — on ANY mismatch, never call the provider.
	if canonicalCorrTenant(cfg.TenantID) != canonicalCorrTenant(it.TenantID) {
		w.deadLetter(ctx, it, "SECURITY: connection tenant mismatch (delivery quarantined)")
		logWarn("ticketing", "SECURITY: outbox/connection tenant mismatch — delivery refused",
			map[string]any{"outbox_id": it.ID, "system": it.ExternalSystem})
		return
	}
	if err := w.dispatch(ctx, adapter, cfg, it, now); err != nil {
		var perm permanentDeliveryError
		var rl rateLimitedError
		switch {
		case errors.As(err, &perm):
			w.deadLetter(ctx, it, err.Error())
		case errors.As(err, &rl):
			w.retryAfter(ctx, it, now, rl.After, err.Error())
		default:
			w.retryLater(ctx, it, now, err.Error())
		}
		return
	}
	w.succeed(ctx, it)
}

// dispatch performs the external action and updates the link/audit on success.
func (w *ticketWorker) dispatch(ctx context.Context, adapter ticketAdapter, cfg ticketSystemConfig, it ticketOutboxItem, now time.Time) error {
	switch it.Action {
	case "create":
		return w.doCreate(ctx, adapter, cfg, it, now)
	case "update":
		return w.doUpdate(ctx, adapter, cfg, it, now)
	case "add_work_note":
		ref, err := w.linkRef(ctx, it)
		if err != nil {
			return err
		}
		if err := adapter.AddWorkNote(ctx, cfg, ref, outboxNote(it)); err != nil {
			return err
		}
		w.audit(ctx, it, "add_work_note", "ok", "", "")
		return nil
	case "resolve":
		ref, err := w.linkRef(ctx, it)
		if err != nil {
			return err
		}
		if err := adapter.ResolveIncident(ctx, cfg, ref, outboxNote(it)); err != nil {
			return err
		}
		w.markLinkStatus(ctx, it, "resolved")
		w.audit(ctx, it, "resolve", "ok", "open", "resolved")
		return nil
	default:
		return fmt.Errorf("unknown action %q", it.Action)
	}
}

func (w *ticketWorker) doCreate(ctx context.Context, adapter ticketAdapter, cfg ticketSystemConfig, it ticketOutboxItem, now time.Time) error {
	p, err := outboxPayload(it)
	if err != nil {
		return err
	}
	// Idempotency: if an incident already carries this correlation_id (a prior
	// create whose link store failed), adopt it instead of creating a second.
	ref, found, err := adapter.LookupByCorrelationID(ctx, cfg, it.CorrObjectID)
	if err != nil {
		return err
	}
	if !found {
		ref, err = adapter.CreateIncident(ctx, cfg, p)
		if err != nil {
			return err
		}
	}
	w.upsertLink(ctx, it, cfg, ref, p, "open", now)
	w.audit(ctx, it, "create", "ok", "", "open")
	return nil
}

func (w *ticketWorker) doUpdate(ctx context.Context, adapter ticketAdapter, cfg ticketSystemConfig, it ticketOutboxItem, now time.Time) error {
	p, err := outboxPayload(it)
	if err != nil {
		return err
	}
	ref, err := w.linkRef(ctx, it)
	if err != nil {
		return err
	}
	if err := adapter.UpdateIncident(ctx, cfg, ref, p); err != nil {
		return err
	}
	w.upsertLink(ctx, it, cfg, ref, p, "updated", now)
	w.audit(ctx, it, "update", "ok", "open", "updated")
	return nil
}

// ── link + audit writers ─────────────────────────────────────────────────────

// linkRef loads the existing ticket ref for an update/note/resolve action.
func (w *ticketWorker) linkRef(ctx context.Context, it ticketOutboxItem) (ticketRef, error) {
	l, found, err := w.store.GetLink(ctx, it.TenantID, false, it.CorrObjectID, it.ExternalSystem)
	if err != nil {
		return ticketRef{}, err
	}
	if !found || l.SysID == "" {
		return ticketRef{}, fmt.Errorf("no ticket link for %s/%s", it.CorrObjectID, it.ExternalSystem)
	}
	return ticketRef{Number: l.TicketNumber, SysID: l.SysID, URL: l.InstanceURL}, nil
}

func (w *ticketWorker) upsertLink(ctx context.Context, it ticketOutboxItem, cfg ticketSystemConfig, ref ticketRef, p ticketPayload, status string, now time.Time) {
	t := now
	_ = w.store.PutLink(ctx, ticketLink{
		TenantID:        it.TenantID,
		CorrObjectID:    it.CorrObjectID,
		ExternalSystem:  it.ExternalSystem,
		// The BARE instance URL (not ref.URL, the full incident deep-link) —
		// ticketStatusView appends the nav_to.do path itself.
		InstanceURL:     cfg.InstanceURL,
		TicketNumber:    ref.Number,
		SysID:           ref.SysID,
		DedupeKey:       dedupeKey(it.TenantID, it.CorrObjectID, it.ExternalSystem),
		Status:          status,
		LastVerdict:     p.Verdict,
		LastConfidence:  p.Confidence,
		LastPayloadHash: payloadHash(p),
		LastSyncedAt:    &t,
	})
}

func (w *ticketWorker) markLinkStatus(ctx context.Context, it ticketOutboxItem, status string) {
	l, found, err := w.store.GetLink(ctx, it.TenantID, false, it.CorrObjectID, it.ExternalSystem)
	if err != nil || !found {
		return
	}
	now := time.Now().UTC()
	l.Status = status
	l.LastSyncedAt = &now
	_ = w.store.PutLink(ctx, l)
}

func (w *ticketWorker) audit(ctx context.Context, it ticketOutboxItem, action, result, oldStatus, newStatus string) {
	_ = w.store.AppendAudit(ctx, ticketAuditEntry{
		TenantID:       it.TenantID,
		ID:             randID(),
		CorrObjectID:   it.CorrObjectID,
		ExternalSystem: it.ExternalSystem,
		Action:         action,
		Actor:          "system",
		OldStatus:      oldStatus,
		NewStatus:      newStatus,
		PayloadHash:    payloadHashRaw(it.Payload),
		Result:         result,
	})
}

// ── retry / dead-letter ──────────────────────────────────────────────────────

func (w *ticketWorker) succeed(ctx context.Context, it ticketOutboxItem) {
	it.Status = "sent"
	it.LastError = ""
	_ = w.store.FinishOutbox(ctx, it)
}

// retryLater bumps the retry count and schedules the next attempt with capped
// exponential backoff + deterministic jitter, dead-lettering past max_retries.
func (w *ticketWorker) retryLater(ctx context.Context, it ticketOutboxItem, now time.Time, reason string) {
	it.RetryCount++
	it.LastError = truncate(reason, 480)
	max := it.MaxRetries
	if max == 0 {
		max = w.maxRetries
	}
	if it.RetryCount >= max {
		it.Status = "dead_letter"
		_ = w.store.FinishOutbox(ctx, it)
		w.audit(ctx, it, it.Action, "dead_letter", "", "")
		logWarn("ticketing", "outbox item dead-lettered", map[string]any{
			"corr_object_id": it.CorrObjectID, "action": it.Action, "retries": it.RetryCount})
		return
	}
	it.Status = "retrying"
	it.NextRetryAt = now.Add(backoffDelay(it.RetryCount))
	_ = w.store.FinishOutbox(ctx, it)
}

func (w *ticketWorker) deadLetter(ctx context.Context, it ticketOutboxItem, reason string) {
	it.Status = "dead_letter"
	it.LastError = truncate(reason, 480)
	_ = w.store.FinishOutbox(ctx, it)
	w.audit(ctx, it, it.Action, "dead_letter", "", "")
}

// backoffDelay is capped exponential backoff with a deterministic jitter derived
// from the attempt (no Math.random — the harness forbids it and it would break
// resume): base 30s * 2^(n-1), capped at 30m, ± up to ~12% from the attempt.
func backoffDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	base := 30 * time.Second * time.Duration(math.Pow(2, float64(attempt-1)))
	if base > 30*time.Minute {
		base = 30 * time.Minute
	}
	jitter := time.Duration(attempt*271%1000) * base / 8000 // 0..12.5% deterministic
	return base + jitter
}

// ── outbox payload helpers ───────────────────────────────────────────────────

// enqueueTicketCreate enqueues a create action for an RCA object. Used by P3's
// policy layer and the P2/E2E tests. Idempotency-keyed so re-enqueue is a no-op.
func enqueueTicketCreate(ctx context.Context, store ticketingStore, tenant, system string, p ticketPayload) error {
	return store.EnqueueOutbox(ctx, ticketOutboxItem{
		TenantID:       tenant,
		ID:             randID(),
		CorrObjectID:   p.CorrObjectID,
		ExternalSystem: system,
		Action:         "create",
		IdempotencyKey: fmt.Sprintf("%s:create:%s:%s", system, normTenant(tenant), p.CorrObjectID),
		Payload:        payloadToMap(p),
		Status:         "pending",
	})
}

// enqueueTicketUpdate enqueues an update keyed by the payload hash (one row per
// distinct RCA state) so identical re-syncs collapse.
func enqueueTicketUpdate(ctx context.Context, store ticketingStore, tenant, system string, p ticketPayload) error {
	return store.EnqueueOutbox(ctx, ticketOutboxItem{
		TenantID:       tenant,
		ID:             randID(),
		CorrObjectID:   p.CorrObjectID,
		ExternalSystem: system,
		Action:         "update",
		IdempotencyKey: fmt.Sprintf("%s:update:%s:%s:%s", system, normTenant(tenant), p.CorrObjectID, payloadHash(p)),
		Payload:        payloadToMap(p),
		Status:         "pending",
	})
}

func payloadToMap(p ticketPayload) map[string]any {
	b, _ := json.Marshal(p)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func outboxPayload(it ticketOutboxItem) (ticketPayload, error) {
	b, err := json.Marshal(it.Payload)
	if err != nil {
		return ticketPayload{}, err
	}
	var p ticketPayload
	if err := json.Unmarshal(b, &p); err != nil {
		return ticketPayload{}, fmt.Errorf("decode outbox payload: %w", err)
	}
	if p.CorrObjectID == "" {
		p.CorrObjectID = it.CorrObjectID
	}
	return p, nil
}

func outboxNote(it ticketOutboxItem) string {
	if n, ok := it.Payload["note"].(string); ok && n != "" {
		return n
	}
	if p, err := outboxPayload(it); err == nil && p.Summary != "" {
		return p.Summary
	}
	return "Correlix RCA update"
}

func dedupeKey(tenant, corrID, system string) string {
	return fmt.Sprintf("%s:%s:%s", normTenant(tenant), corrID, system)
}

func payloadHash(p ticketPayload) string {
	b, _ := json.Marshal(p)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:16]
}

func payloadHashRaw(m map[string]any) string {
	b, _ := json.Marshal(m)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:16]
}

// ── #103 delivery-error classification ──────────────────────────────────────

// permanentDeliveryError marks a provider rejection that retries cannot fix
// (payload 400, revoked credential 401/403) — dead-letter, don't burn retries.
type permanentDeliveryError struct{ Err error }

func (e permanentDeliveryError) Error() string { return e.Err.Error() }
func (e permanentDeliveryError) Unwrap() error { return e.Err }

// rateLimitedError carries the provider's Retry-After so the outbox honors it
// instead of the default backoff curve.
type rateLimitedError struct{ After time.Duration }

func (e rateLimitedError) Error() string {
	return fmt.Sprintf("rate limited; retry after %s", e.After)
}

// retryAfter schedules the item's next attempt at an explicit provider-given
// delay (429 Retry-After), still counting toward max_retries.
func (w *ticketWorker) retryAfter(ctx context.Context, it ticketOutboxItem, now time.Time, after time.Duration, msg string) {
	it.RetryCount++
	it.LastError = truncate(msg, 480)
	max := it.MaxRetries
	if max == 0 {
		max = w.maxRetries
	}
	if it.RetryCount >= max {
		it.Status = "dead_letter"
		_ = w.store.FinishOutbox(ctx, it)
		w.audit(ctx, it, it.Action, "dead_letter", "", "")
		return
	}
	it.Status = "retrying"
	it.NextRetryAt = now.Add(after)
	_ = w.store.FinishOutbox(ctx, it)
}
