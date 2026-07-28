package ai

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"strings"
)

// ai_feedback_store.go — persistence for the Iris AI feedback loop (spec §14).
// Thumbs up/down on AI answers, PRIVACY-SAFE (rating + intent/mode/conversation id
// only, never question/answer text). Two backends like every other store: in-memory
// (default, tenant-filtered in the store) and Postgres (tenant_iso FORCE-RLS via
// withTenant). Tenant isolation is enforced in the store itself (CLAUDE.md §3a).

type FeedbackRow struct {
	TenantID       string    `json:"-"`
	ID             string    `json:"id"`
	ConversationID string    `json:"conversation_id,omitempty"`
	Sub            string    `json:"-"`
	Intent         string    `json:"intent,omitempty"`
	Mode           string    `json:"mode,omitempty"`
	Rating         string    `json:"rating"` // up | down
	At             time.Time `json:"at"`
}

// FeedbackStats is the aggregate the quality loop reads (tenant-scoped).
type FeedbackStats struct {
	Up       int                      `json:"up"`
	Down     int                      `json:"down"`
	ByIntent map[string]*UpDownCounts `json:"by_intent"`
}

type UpDownCounts struct {
	Up   int `json:"up"`
	Down int `json:"down"`
}

type FeedbackStore interface {
	Put(ctx context.Context, row FeedbackRow) error
	// Stats aggregates the caller's OWN feedback over the window (default-closed
	// unless cross). up/down totals + a per-intent breakdown.
	Stats(ctx context.Context, tenant string, cross bool, sinceSeconds int) (FeedbackStats, error)
}

func AggregateFeedback(rows []FeedbackRow) FeedbackStats {
	st := FeedbackStats{ByIntent: map[string]*UpDownCounts{}}
	for _, r := range rows {
		c := st.ByIntent[r.Intent]
		if c == nil {
			c = &UpDownCounts{}
			st.ByIntent[r.Intent] = c
		}
		if r.Rating == "down" {
			st.Down++
			c.Down++
		} else {
			st.Up++
			c.Up++
		}
	}
	return st
}

// ── in-memory backend ─────────────────────────────────────────────────────────

// normTenant mirrors the integrator's normalization (duplicated).
func normTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// FeedbackDB is the injected relational seam (the portintel.DB idiom).
type FeedbackDB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

// NewMemFeedbackStore / NewPGFeedbackStore build the two backends.
func NewMemFeedbackStore() *memFeedbackStore { return &memFeedbackStore{} }

func NewPGFeedbackStore(db FeedbackDB) *pgFeedbackStore { return &pgFeedbackStore{db: db} }

type memFeedbackStore struct {
	mu sync.RWMutex
	by map[string]FeedbackRow // key: tenant\x1fid
}

func (m *memFeedbackStore) Put(_ context.Context, row FeedbackRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	row.TenantID = normTenant(row.TenantID)
	m.by[row.TenantID+"\x1f"+row.ID] = row
	return nil
}

func (m *memFeedbackStore) Stats(_ context.Context, tenant string, cross bool, sinceSeconds int) (FeedbackStats, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t := normTenant(tenant)
	cutoff := time.Now().Add(-time.Duration(sinceSeconds) * time.Second)
	var rows []FeedbackRow
	for _, r := range m.by {
		if !cross && r.TenantID != t { // default-closed tenant filter
			continue
		}
		if sinceSeconds > 0 && r.At.Before(cutoff) {
			continue
		}
		rows = append(rows, r)
	}
	return AggregateFeedback(rows), nil
}

// ── Postgres backend (tenant_iso FORCE-RLS via withTenant) ────────────────────

type pgFeedbackStore struct{ db FeedbackDB }

func (s *pgFeedbackStore) Put(ctx context.Context, row FeedbackRow) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	at := row.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	return s.db.WithTenant(ctx, row.TenantID, false, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO ai_feedback (tenant_id, id, conversation_id, sub, intent, mode, rating, at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (tenant_id, id) DO UPDATE SET rating = EXCLUDED.rating, at = EXCLUDED.at`,
			normTenant(row.TenantID), row.ID, row.ConversationID, row.Sub, row.Intent, row.Mode, row.Rating, at)
		return err
	})
}

func (s *pgFeedbackStore) Stats(ctx context.Context, tenant string, cross bool, sinceSeconds int) (FeedbackStats, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if sinceSeconds <= 0 {
		sinceSeconds = 30 * 24 * 3600
	}
	var rows []FeedbackRow
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rs, err := tx.Query(ctx, `
SELECT tenant_id, id, intent, mode, rating, at
  FROM ai_feedback
 WHERE at >= now() - INTERVAL '1 second' * $1`, sinceSeconds)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var r FeedbackRow
			if err := rs.Scan(&r.TenantID, &r.ID, &r.Intent, &r.Mode, &r.Rating, &r.At); err != nil {
				return err
			}
			rows = append(rows, r)
		}
		return rs.Err()
	})
	if err != nil {
		return FeedbackStats{ByIntent: map[string]*UpDownCounts{}}, err
	}
	return AggregateFeedback(rows), nil
}
