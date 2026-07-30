package backend

// cloud_notify.go — notification routing from cloud signals (Wave 4 #12,
// detection→resolution, slice 1).
//
// When a CLOUD correlation object OPENS (the engine grounded cloud_health /
// cloud_change signals into a corr object — the same objects the investigation
// drawer renders), the owning tenant gets a notification through the SAME
// per-tenant notifier configuration the RCA lanes already use: the tenant's OWN
// Slack RCA webhook and/or PagerDuty RCA routing key from itsmConfigStore
// (#103). No new notifier code (notify.Slack / notify.PagerDuty are the
// existing lanes) and no new config surface (the ITSM/RCA notification settings
// are the routing table).
//
// Deliberately NOT the platform-global dispatcher (notify_config.go lane): that
// lane is operator/self-health only, guarded by PlatformScopeFilter — customer
// cloud incidents must never fan out to platform-global destinations, and a
// tenant's incident must only ever reach that tenant's own channels.
//
// Tenant isolation (CLAUDE.md §3a): like the ticket sweeper, the candidate scan
// is a cross-tenant background read ("__all__"), but each object carries its own
// tenant_id from the corr row and routing resolves ONLY that tenant's config
// (itsmKey) — tenant A's signal can never reach tenant B's webhook/key.
//
// Delivery contract: at-most-once per correlation object per process (in-memory
// seen set + process-start watermark; a restart never re-pages history). Send
// errors are logged, never retried into a page storm — durable retryable
// delivery is the ticketing outbox's job, not this lane's.
//
// Dormant unless FEATURE_CLOUD_SIGNAL_NOTIFICATIONS=true (env-driven, like
// FEATURE_SLACK_NOTIFICATIONS et al).

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"netops/backend/internal/chschema"
	"netops/backend/models"
	"netops/backend/notify"
)

const (
	// Objects created earlier than this before a tick are out of scope even on
	// the first sweep — bounded read, and "opened" means recent by definition.
	cloudNotifyDefaultLookback = 30 * time.Minute
	// Cloud-object detection window for the archive prefilter (same bounded
	// pattern as cloudEvidenceObjectsSQL).
	cloudNotifyArchiveHours = 24
	cloudNotifyMaxPerTick   = 200
	cloudNotifySeenCap      = 4096
)

// cloudNotifyTarget is one per-tenant destination resolved from the EXISTING
// RCA notification config: system is a notify lane name ("slack"/"pagerduty"),
// secret is that tenant's own webhook URL / routing key (write-only, never logged).
type cloudNotifyTarget struct {
	System string
	Secret string
}

// cloudNotifyResolver resolves the owning tenant's notification targets.
// Injected (CLAUDE.md §5: interfaces for external deps) so routing decisions
// are unit-testable without a live config store.
type cloudNotifyResolver func(tenant string) []cloudNotifyTarget

// cloudNotifyLanes is the PURE routing decision: which existing notifier lanes
// a tenant's RCA config enables. Disabled or secret-less lanes never route.
func cloudNotifyLanes(cfg itsmConfig) []cloudNotifyTarget {
	out := make([]cloudNotifyTarget, 0, 2)
	if cfg.Slack.Enabled && cfg.Slack.WebhookURL != "" {
		out = append(out, cloudNotifyTarget{System: "slack", Secret: cfg.Slack.WebhookURL})
	}
	if cfg.PagerDuty.Enabled && cfg.PagerDuty.RoutingKey != "" {
		out = append(out, cloudNotifyTarget{System: "pagerduty", Secret: cfg.PagerDuty.RoutingKey})
	}
	return out
}

// rcaNotifyTargets resolves ONE tenant's own notification lanes. The lookup is
// keyed by itsmKey(tenant) exactly like every other per-tenant ITSM resolve —
// an unknown tenant gets nothing, never another tenant's config.
func rcaNotifyTargets(s *itsmConfigStore, tenant string) []cloudNotifyTarget {
	cfg, ok := s.ConfigFor(tenant)
	if !ok {
		return nil
	}
	return cloudNotifyLanes(cfg)
}

// cloudNotifyCandidate is one newly-opened cloud correlation object.
type cloudNotifyCandidate struct {
	id         string
	tenant     string // owning tenant from the corr row (routing authority)
	tier       string
	hypothesis string
	apps       []string
	createdAt  time.Time
}

// cloudNotifySeverity maps the engine's own verdict tier onto the platform
// severity vocabulary the notify lanes already understand (pdSeverity enum).
// We never invent a severity the engine didn't imply.
func cloudNotifySeverity(tier string) string {
	switch strings.ToLower(strings.TrimSpace(tier)) {
	case "confirmed":
		return "critical"
	case "suspected":
		return "error"
	default:
		return "warning"
	}
}

// cloudNotifyAlert builds the models.Alert the existing lanes dispatch. Pure.
func cloudNotifyAlert(c cloudNotifyCandidate) models.Alert {
	summary := "Cloud incident opened"
	if c.hypothesis != "" {
		summary = "Cloud incident opened: " + c.hypothesis
	}
	if len(c.apps) > 0 {
		summary += " (affects " + strings.Join(c.apps, ", ") + ")"
	}
	return models.Alert{
		ID:       "cloud-rca-" + c.id, // stable → PagerDuty dedup key
		Rule:     "cloud_rca_open",
		Severity: cloudNotifySeverity(c.tier),
		Summary:  summary,
		Labels: map[string]string{
			"layer":          "cloud",
			"tenant":         c.tenant,
			"correlation_id": c.id,
			"verdict_tier":   c.tier,
		},
		FiredAt: c.createdAt,
	}
}

// cloudNotifyCandidatesSQL scans newly-opened cloud correlation objects across
// tenants. Bounded on every axis (#100 read contract): archive prefilter window,
// created_at lookback, LIMIT, named columns. Cloud detection = the object
// grounded at least one source='cloud' signal — the same fact the evidence
// ledger uses, never a guess. chaos_fixture objects are excluded here like the
// ticket sweeper: a lab storm must never page a customer.
func cloudNotifyCandidatesSQL(lookbackSec, limit int) string {
	return fmt.Sprintf(`
WITH cloud_objs AS (
     SELECT DISTINCT archived_for
       FROM netops.corr_signals_archive
      WHERE source = 'cloud' AND ts > now() - INTERVAL %d HOUR
)
SELECT toString(correlation_id)  AS correlation_id,
       tenant_id                 AS tenant_id,
       toString(verdict_tier)    AS verdict_tier,
       top_hypothesis            AS top_hypothesis,
       affected                  AS affected,
       `+chschema.ISO("created_at")+`   AS created_at_s
  FROM netops.corr_current FINAL
 WHERE correlation_id IN (SELECT archived_for FROM cloud_objs)
   AND state = 'open'
   AND created_at >= now() - INTERVAL %d SECOND
   AND merged_into IS NULL
   AND chaos_fixture = ''
 ORDER BY created_at ASC
 LIMIT %d
 FORMAT JSON`, cloudNotifyArchiveHours, lookbackSec, limit)
}

// cloudNotifySweeper polls for newly-opened cloud correlation objects and
// routes each to its owning tenant's lanes. Mirrors ticketSweeper's shape.
type cloudNotifySweeper struct {
	srv       *server
	resolve   cloudNotifyResolver
	send      func(target cloudNotifyTarget, a models.Alert) error
	lookback  time.Duration
	limit     int
	startedAt time.Time
	seen      map[string]bool
	seenOrder []string
}

func newCloudNotifySweeper(srv *server, resolve cloudNotifyResolver) *cloudNotifySweeper {
	lookback := cloudNotifyDefaultLookback
	if v := os.Getenv("CLOUD_NOTIFY_LOOKBACK"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			lookback = d
		}
	}
	return &cloudNotifySweeper{
		srv:       srv,
		resolve:   resolve,
		send:      sendViaNotifyLane,
		lookback:  lookback,
		limit:     cloudNotifyMaxPerTick,
		startedAt: time.Now().UTC(),
		seen:      make(map[string]bool),
	}
}

// sendViaNotifyLane dispatches through the EXISTING notify package lanes —
// the "reuse platform notifier lanes" contract. No new notifier code.
func sendViaNotifyLane(t cloudNotifyTarget, a models.Alert) error {
	switch t.System {
	case "slack":
		return notify.NewSlack(t.Secret).Send(a)
	case "pagerduty":
		return notify.NewPagerDuty(t.Secret).Send(a)
	}
	return fmt.Errorf("unknown notify lane %q", t.System)
}

// Run drives tick() on an interval until ctx is cancelled. Started only under
// FEATURE_CLOUD_SIGNAL_NOTIFICATIONS.
func (sw *cloudNotifySweeper) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := sw.tick(ctx); err != nil {
				logWarn("cloud", "cloud notify sweep failed", map[string]any{"error": err.Error()})
			} else if n > 0 {
				logInfo("cloud", "cloud signal notifications dispatched", map[string]any{"count": n})
			}
		}
	}
}

// tick scans one bounded batch and notifies each unseen object once.
func (sw *cloudNotifySweeper) tick(ctx context.Context) (int, error) {
	cands, err := sw.candidates(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, c := range cands {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		if !sw.shouldNotify(c.id, c.createdAt) {
			continue
		}
		sw.markSeen(c.id)
		if sw.dispatch(c) {
			n++
		}
	}
	return n, nil
}

// shouldNotify is the PURE at-most-once gate: never an already-seen object,
// never one that opened before this process started (restart ≠ re-page).
func (sw *cloudNotifySweeper) shouldNotify(id string, createdAt time.Time) bool {
	if id == "" || sw.seen[id] {
		return false
	}
	return !createdAt.Before(sw.startedAt)
}

func (sw *cloudNotifySweeper) markSeen(id string) {
	if sw.seen[id] {
		return
	}
	sw.seen[id] = true
	sw.seenOrder = append(sw.seenOrder, id)
	if len(sw.seenOrder) > cloudNotifySeenCap {
		delete(sw.seen, sw.seenOrder[0])
		sw.seenOrder = sw.seenOrder[1:]
	}
}

// dispatch routes one object to its OWNING tenant's lanes. Returns true when at
// least one lane accepted the notification. A tenant with no configured lane is
// an honest no-op (nothing to notify through), not an error.
func (sw *cloudNotifySweeper) dispatch(c cloudNotifyCandidate) bool {
	targets := sw.resolve(c.tenant)
	if len(targets) == 0 {
		return false
	}
	a := cloudNotifyAlert(c)
	sent := 0
	for _, t := range targets {
		if err := sw.send(t, a); err != nil {
			// Secret never logged; §10: the failure is observable.
			logWarn("cloud", "cloud signal notification failed", map[string]any{
				"lane": t.System, "tenant": c.tenant, "correlation_id": c.id, "error": err.Error()})
			continue
		}
		sent++
	}
	return sent > 0
}

// candidates lists newly-opened cloud objects across tenants (cross-tenant
// background read like the ticket sweeper; every downstream route is keyed to
// the object's own tenant).
func (sw *cloudNotifySweeper) candidates(ctx context.Context) ([]cloudNotifyCandidate, error) {
	sql := cloudNotifyCandidatesSQL(int(sw.lookback.Seconds()), sw.limit)
	rows, err := sw.srv.chRowsScope(ctx, "__all__", sql, "worker:cloud-notify")
	if err != nil {
		return nil, err
	}
	out := make([]cloudNotifyCandidate, 0, len(rows))
	for _, row := range rows {
		id := asString(row["correlation_id"])
		if !isUUIDToken(id) {
			continue
		}
		created, err := time.Parse(time.RFC3339, asString(row["created_at_s"]))
		if err != nil {
			continue // a row without a parseable open time can't pass the watermark honestly
		}
		out = append(out, cloudNotifyCandidate{
			id:         id,
			tenant:     canonicalCorrTenant(asString(row["tenant_id"])),
			tier:       asString(row["verdict_tier"]),
			hypothesis: asString(row["top_hypothesis"]),
			apps:       affectedApps(asString(row["affected"])),
			createdAt:  created.UTC(),
		})
	}
	return out, nil
}
