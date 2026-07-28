package ticketing

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"time"
)

// ticketing_worker.go — the outbox worker (#78 P2). It drains ticket_outbox so
// external ticketing NEVER blocks correlation: the policy layer (P3) only
// ENQUEUES; this worker claims due rows (SKIP LOCKED), dispatches through the
// Adapter, and on failure retries with exponential backoff + jitter,
// dead-lettering after max_retries. Every action writes a ticket_audit_log
// entry; a successful create/update advances the correlix_ticket_link.
//
// At-most-once is enforced two ways: the outbox idempotency_key (one row per
// logical action) and ServiceNow's native correlation_id (a create looks up an
// existing incident first, so a lost link store never doubles a ticket).

// ConnResolver yields the connection for a (tenant, system). Returns
// ok=false when no connection is configured (a transient hold, not a failure).
type ConnResolver func(ctx context.Context, tenant, system string) (SystemConfig, bool, error)

type Worker struct {
	warnf       func(msg string, fields map[string]any)
	errf        func(msg string, fields map[string]any)
	store       Store
	adapters    map[string]Adapter
	resolveConn ConnResolver
	workerID    string
	batch       int
	lease       time.Duration
	maxRetries  int
}

// SetMaxRetries overrides the dead-letter threshold (tests dead-letter fast;
// ops could tune it the same way).
func (w *Worker) SetMaxRetries(n int) {
	if n > 0 {
		w.maxRetries = n
	}
}

// RegisterAdapter swaps/installs a provider adapter (tests inject
// httptest-backed adapters; a future plugin path would land here too).
func (w *Worker) RegisterAdapter(name string, a Adapter) { w.adapters[name] = a }

// canonicalCorrTenant mirrors the sweeper's tenant canonicalization: blank and
// "global" are the same platform realm (duplicated; the sweeper stays in main).
func canonicalCorrTenant(t string) string {
	t = normTenant(t)
	if t == "" {
		return "global"
	}
	return t
}

// randHexID mirrors the integrator's 32-hex object id (duplicated).
func randHexID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// NewWorker builds the outbox worker. warnf/errf are the structured log sinks
// (nil → silent; the store-error refusal behavior is unchanged).
func NewWorker(store Store, resolve ConnResolver, warnf, errf func(msg string, fields map[string]any)) *Worker {
	if warnf == nil {
		warnf = func(string, map[string]any) {}
	}
	if errf == nil {
		errf = func(string, map[string]any) {}
	}
	return &Worker{
		warnf:       warnf,
		errf:        errf,
		store:       store,
		adapters:    map[string]Adapter{"servicenow": NewServiceNowAdapter(), "pagerduty": NewPagerDutyAdapter(), "slack": NewSlackAdapter(), "jira": NewJiraAdapter()},
		resolveConn: resolve,
		workerID:    "ticket-" + randHexID()[:8],
		batch:       16,
		lease:       2 * time.Minute,
		maxRetries:  8,
	}
}

// Run drives tick() on an interval until ctx is cancelled. Dormant unless wired
// in (FEATURE_RCA_TICKETING) — ticketing is opt-in.
func (w *Worker) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := w.Tick(ctx, time.Now().UTC()); err != nil {
				w.warnf("outbox tick failed", map[string]any{"error": err.Error()})
			}
		}
	}
}

// tick claims one due batch and processes each item. Returns the count handled.
// Tick claims due outbox work once and processes it (the Run loop cadence;
// tests drive it directly).
func (w *Worker) Tick(ctx context.Context, now time.Time) (int, error) {
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
func (w *Worker) process(ctx context.Context, it OutboxItem, now time.Time) {
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
		w.warnf("SECURITY: outbox/connection tenant mismatch — delivery refused",
			map[string]any{"outbox_id": it.ID, "system": it.ExternalSystem})
		return
	}
	if err := w.dispatch(ctx, adapter, cfg, it, now); err != nil {
		var perm PermanentDeliveryError
		var rl RateLimitedError
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
// #103-H E6: the ticket link's lifecycle_state is the ordering authority —
// stale or duplicate operations become AUDITED no-op successes, never
// external calls and never infinite retries. The state machine:
//
//	(none) -> open -> updated* -> resolved   (reopen only via a NEW create
//	decision from the sweeper after the flap-suppression window, never by a
//	stale queued row from the previous life.)
func (w *Worker) dispatch(ctx context.Context, adapter Adapter, cfg SystemConfig, it OutboxItem, now time.Time) error {
	link, linkFound, lerr := w.store.GetLink(ctx, it.TenantID, false, it.CorrObjectID, it.ExternalSystem)
	if lerr != nil {
		return lerr // transient store trouble: retry
	}
	switch it.Action {
	case "create":
		if linkFound {
			switch link.Status {
			case "open", "updated":
				// Duplicate OPEN (sweeper replay / crash-after-success):
				// the incident already exists — one identity, no second call.
				w.audit(ctx, it, "create", "noop_duplicate", link.Status, link.Status)
				return nil
			case "resolved":
				// Stale OPEN arriving after a RESOLVE: automatic reopening is
				// policy territory (flap suppression), not a queue accident.
				w.audit(ctx, it, "create", "noop_stale_after_resolve", "resolved", "resolved")
				return nil
			}
		}
		return w.doCreate(ctx, adapter, cfg, it, now)
	case "update":
		if linkFound && link.Status == "resolved" {
			// An old UPDATE must never reopen/repage a resolved incident.
			w.audit(ctx, it, "update", "noop_stale_after_resolve", "resolved", "resolved")
			return nil
		}
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
		if linkFound && link.Status == "resolved" {
			// Repeated RESOLVE: downstream is already closed — no-op.
			w.audit(ctx, it, "resolve", "noop_duplicate", "resolved", "resolved")
			return nil
		}
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

func (w *Worker) doCreate(ctx context.Context, adapter Adapter, cfg SystemConfig, it OutboxItem, now time.Time) error {
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

func (w *Worker) doUpdate(ctx context.Context, adapter Adapter, cfg SystemConfig, it OutboxItem, now time.Time) error {
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
func (w *Worker) linkRef(ctx context.Context, it OutboxItem) (Ref, error) {
	l, found, err := w.store.GetLink(ctx, it.TenantID, false, it.CorrObjectID, it.ExternalSystem)
	if err != nil {
		return Ref{}, err
	}
	if !found || l.SysID == "" {
		return Ref{}, fmt.Errorf("no ticket link for %s/%s", it.CorrObjectID, it.ExternalSystem)
	}
	return Ref{Number: l.TicketNumber, SysID: l.SysID, URL: l.InstanceURL}, nil
}

// storeErr surfaces a ticketing-store write failure.
//
// F-30: these writes were all `_ = w.store.…`. The worker is a proper outbox
// with idempotent create-adoption, so a failed FinishOutbox is RE-RUN rather
// than lost — but it is re-run silently, and a lost AppendAudit is a compliance
// record that simply never existed. §10 forbids a silent failure regardless of
// whether the system recovers from it: an operator debugging a duplicate
// notification needs to see that the outbox could not be marked done.
func (w *Worker) storeErr(op string, it OutboxItem, err error) {
	if err == nil {
		return
	}
	w.errf("store write failed", map[string]any{
		"op": op, "corr_object_id": it.CorrObjectID, "external_system": it.ExternalSystem,
		"action": it.Action, "status": it.Status, "err": err.Error(),
	})
}

func (w *Worker) upsertLink(ctx context.Context, it OutboxItem, cfg SystemConfig, ref Ref, p Payload, status string, now time.Time) {
	t := now
	w.storeErr("PutLink", it, w.store.PutLink(ctx, Link{
		TenantID:       it.TenantID,
		CorrObjectID:   it.CorrObjectID,
		ExternalSystem: it.ExternalSystem,
		// The BARE instance URL (not ref.URL, the full incident deep-link) —
		// ticketStatusView appends the nav_to.do path itself.
		InstanceURL:     cfg.InstanceURL,
		TicketNumber:    ref.Number,
		SysID:           ref.SysID,
		DedupeKey:       DedupeKey(it.TenantID, it.CorrObjectID, it.ExternalSystem),
		Status:          status,
		LastVerdict:     p.Verdict,
		LastConfidence:  p.Confidence,
		LastPayloadHash: PayloadHash(p),
		LastSyncedAt:    &t,
	}))
}

func (w *Worker) markLinkStatus(ctx context.Context, it OutboxItem, status string) {
	l, found, err := w.store.GetLink(ctx, it.TenantID, false, it.CorrObjectID, it.ExternalSystem)
	if err != nil {
		// The link store did not answer. Skipping is the only safe action (we
		// must not invent a link), but it leaves the ticket showing its OLD
		// status forever while the outbox item is marked done — so the read
		// failure is reported through the same channel as a write failure (§10).
		w.storeErr("GetLink", it, err)
		return
	}
	if !found {
		return // answered: no link for this object/system — nothing to mark
	}
	now := time.Now().UTC()
	l.Status = status
	l.LastSyncedAt = &now
	w.storeErr("PutLink", it, w.store.PutLink(ctx, l))
}

func (w *Worker) audit(ctx context.Context, it OutboxItem, action, result, oldStatus, newStatus string) {
	w.storeErr("AppendAudit", it, w.store.AppendAudit(ctx, AuditEntry{
		TenantID:       it.TenantID,
		ID:             randHexID(),
		CorrObjectID:   it.CorrObjectID,
		ExternalSystem: it.ExternalSystem,
		Action:         action,
		Actor:          "system",
		OldStatus:      oldStatus,
		NewStatus:      newStatus,
		PayloadHash:    PayloadHashRaw(it.Payload),
		Result:         result,
	}))
}

// ── retry / dead-letter ──────────────────────────────────────────────────────

func (w *Worker) succeed(ctx context.Context, it OutboxItem) {
	it.Status = "sent"
	it.LastError = ""
	w.storeErr("FinishOutbox", it, w.store.FinishOutbox(ctx, it))
}

// retryLater bumps the retry count and schedules the next attempt with capped
// exponential backoff + deterministic jitter, dead-lettering past max_retries.
func (w *Worker) retryLater(ctx context.Context, it OutboxItem, now time.Time, reason string) {
	it.RetryCount++
	it.LastError = Truncate(reason, 480)
	max := it.MaxRetries
	if max == 0 {
		max = w.maxRetries
	}
	if it.RetryCount >= max {
		it.Status = "dead_letter"
		w.storeErr("FinishOutbox", it, w.store.FinishOutbox(ctx, it))
		w.audit(ctx, it, it.Action, "dead_letter", "", "")
		w.warnf("outbox item dead-lettered", map[string]any{
			"corr_object_id": it.CorrObjectID, "action": it.Action, "retries": it.RetryCount})
		return
	}
	it.Status = "retrying"
	it.NextRetryAt = now.Add(backoffDelay(it.RetryCount, it.ID))
	w.storeErr("FinishOutbox", it, w.store.FinishOutbox(ctx, it))
}

func (w *Worker) deadLetter(ctx context.Context, it OutboxItem, reason string) {
	it.Status = "dead_letter"
	it.LastError = Truncate(reason, 480)
	w.storeErr("FinishOutbox", it, w.store.FinishOutbox(ctx, it))
	w.audit(ctx, it, it.Action, "dead_letter", "", "")
}

// backoffDelay is capped exponential backoff with jitter derived from the ITEM,
// not the attempt: base 30s * 2^(n-1), capped at 30m, plus 0-50% spread.
//
// Deriving jitter from the attempt number gave every item at attempt N an
// IDENTICAL delay, so a full outbox (10k items) retried in lockstep and
// re-flooded the recovering ServiceNow/Jira it had just failed against. Hashing
// (id, attempt) spreads items across the window while staying deterministic —
// still no Math.random, so a restart resumes the same schedule and tests can
// assert exact values.
func backoffDelay(attempt int, id string) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 16 { // 2^16 * 30s is far past the cap; guard the Pow from overflowing
		attempt = 16
	}
	base := 30 * time.Second * time.Duration(math.Pow(2, float64(attempt-1)))
	if base > 30*time.Minute {
		base = 30 * time.Minute
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	_, _ = h.Write([]byte{byte(attempt)})
	frac := float64(h.Sum32()) / float64(math.MaxUint32) // [0,1]
	return base + time.Duration(frac*0.5*float64(base))
}

// ── outbox payload helpers ───────────────────────────────────────────────────

// EnqueueCreate enqueues a create action for an RCA object. Used by P3's
// policy layer and the P2/E2E tests. Idempotency-keyed so re-enqueue is a no-op.
func EnqueueCreate(ctx context.Context, store Store, tenant, system string, p Payload) error {
	return store.EnqueueOutbox(ctx, OutboxItem{
		TenantID:       tenant,
		ID:             randHexID(),
		CorrObjectID:   p.CorrObjectID,
		ExternalSystem: system,
		Action:         "create",
		IdempotencyKey: fmt.Sprintf("%s:create:%s:%s", system, normTenant(tenant), p.CorrObjectID),
		Payload:        payloadToMap(p),
		Status:         "pending",
	})
}

// EnqueueUpdate enqueues an update keyed by the payload hash (one row per
// distinct RCA state) so identical re-syncs collapse.
func EnqueueUpdate(ctx context.Context, store Store, tenant, system string, p Payload) error {
	return store.EnqueueOutbox(ctx, OutboxItem{
		TenantID:       tenant,
		ID:             randHexID(),
		CorrObjectID:   p.CorrObjectID,
		ExternalSystem: system,
		Action:         "update",
		IdempotencyKey: fmt.Sprintf("%s:update:%s:%s:%s", system, normTenant(tenant), p.CorrObjectID, PayloadHash(p)),
		Payload:        payloadToMap(p),
		Status:         "pending",
	})
}

func payloadToMap(p Payload) map[string]any {
	b, _ := json.Marshal(p)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func outboxPayload(it OutboxItem) (Payload, error) {
	b, err := json.Marshal(it.Payload)
	if err != nil {
		return Payload{}, err
	}
	var p Payload
	if err := json.Unmarshal(b, &p); err != nil {
		return Payload{}, fmt.Errorf("decode outbox payload: %w", err)
	}
	if p.CorrObjectID == "" {
		p.CorrObjectID = it.CorrObjectID
	}
	return p, nil
}

func outboxNote(it OutboxItem) string {
	if n, ok := it.Payload["note"].(string); ok && n != "" {
		return n
	}
	if p, err := outboxPayload(it); err == nil && p.Summary != "" {
		return p.Summary
	}
	return "Correlix RCA update"
}

func PayloadHash(p Payload) string {
	b, _ := json.Marshal(p)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:16]
}

func PayloadHashRaw(m map[string]any) string {
	b, _ := json.Marshal(m)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:16]
}

// retryAfter schedules the item's next attempt at an explicit provider-given
// delay (429 Retry-After), still counting toward max_retries.
func (w *Worker) retryAfter(ctx context.Context, it OutboxItem, now time.Time, after time.Duration, msg string) {
	it.RetryCount++
	it.LastError = Truncate(msg, 480)
	max := it.MaxRetries
	if max == 0 {
		max = w.maxRetries
	}
	if it.RetryCount >= max {
		it.Status = "dead_letter"
		w.storeErr("FinishOutbox", it, w.store.FinishOutbox(ctx, it))
		w.audit(ctx, it, it.Action, "dead_letter", "", "")
		return
	}
	it.Status = "retrying"
	it.NextRetryAt = now.Add(after)
	w.storeErr("FinishOutbox", it, w.store.FinishOutbox(ctx, it))
}
