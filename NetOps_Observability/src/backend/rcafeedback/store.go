package rcafeedback

// store.go — persistence for RCA operator verdicts. Two backends behind ONE
// interface (the maintenance/wireless convention): FileStore for the default
// (non-Postgres) build + tests, pgStore for the Postgres build (migration 0036,
// tenant_iso FORCE-RLS through the injected WithTenant seam).
//
// Isolation is enforced IN the store (CLAUDE.md §3a rule 4): every read is
// scoped by the caller's tenant — Postgres by the RLS policy, file by a
// tenant-keyed map. There is no unscoped "list all", and the aggregate the
// summary endpoint serves is produced under the same scope as the list.

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/internal/platformdb"
)

// Store is the append-only verdict register. `cross` is the platform-owner
// cross-tenant flag from principalTenant(claims); a non-cross caller can never
// observe another tenant's rows through any method here.
type Store interface {
	// List returns one case's verdicts, NEWEST FIRST.
	List(ctx context.Context, tenant string, cross bool, correlationID string) ([]Feedback, error)
	// Add appends one verdict. TenantID must already carry the server-derived
	// owner (never the request body); id and CreatedAt are stamped here.
	Add(ctx context.Context, tenant string, cross bool, f Feedback) (Feedback, error)
	// Buckets aggregates the caller-visible rows created at/after `since` into
	// (verdict, template) counts. Aggregating in the store keeps the response
	// bounded regardless of how many verdicts exist.
	Buckets(ctx context.Context, tenant string, cross bool, since time.Time) ([]Bucket, error)
}

// newUUIDv4 mints an RFC-4122 v4 id. Duplicated per the no-shared-utils rule
// (CLAUDE.md §2: no "utils" dumping ground), same as maintenance/store.go.
func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// visible reports whether a caller scoped to `tenant` (or cross-tenant) may see
// rows owned by `owner`. The ONE place the file backend answers that question.
func visible(tenant string, cross bool, owner string) bool {
	return cross || owner == NormTenant(tenant)
}

// newestFirst orders a case listing: created_at desc, id asc as the tiebreak so
// two verdicts written in the same instant still have a deterministic order.
func newestFirst(rows []Feedback) {
	sort.Slice(rows, func(i, j int) bool {
		if !rows[i].CreatedAt.Equal(rows[j].CreatedAt) {
			return rows[i].CreatedAt.After(rows[j].CreatedAt)
		}
		return rows[i].ID < rows[j].ID
	})
}

// ── file backend (default build; tenant-filtered IN the store) ───────────────

// FileStore is the non-Postgres backend. Path "" keeps it purely in memory
// (tests); a real path is loaded at construction and rewritten on every append.
type FileStore struct {
	mu   sync.RWMutex
	path string
	rows map[string]map[string][]Feedback // tenant → correlation id → verdicts
}

// NewFileStore loads persisted verdicts; a missing or corrupt file starts empty
// (the maintenance/episode convention — these state files are operator input,
// rebuildable, and a parse failure must not block boot).
func NewFileStore(path string) *FileStore {
	s := &FileStore{path: path, rows: map[string]map[string][]Feedback{}}
	if path == "" {
		return s
	}
	if b, err := platformdb.Load(path); err == nil && len(b) > 0 {
		var list []Feedback
		if json.Unmarshal(b, &list) == nil {
			for _, f := range list {
				s.insertLocked(f)
			}
		}
	}
	return s
}

// insertLocked appends one row into the tenant→case index (call with mu held,
// or during construction before the store is shared).
func (s *FileStore) insertLocked(f Feedback) {
	t := NormTenant(f.TenantID)
	if s.rows[t] == nil {
		s.rows[t] = map[string][]Feedback{}
	}
	s.rows[t][f.CorrelationID] = append(s.rows[t][f.CorrelationID], f)
}

// flushLocked persists the full set (call with mu held). A marshal or write
// failure is RETURNED, never swallowed — the caller answers 500 rather than
// reporting a verdict that was not stored (§10).
func (s *FileStore) flushLocked() error {
	if s.path == "" {
		return nil
	}
	list := []Feedback{}
	for _, byCase := range s.rows {
		for _, rows := range byCase {
			list = append(list, rows...)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	b, err := json.Marshal(list)
	if err != nil {
		return fmt.Errorf("encode rca feedback: %w", err)
	}
	return platformdb.Save(s.path, b)
}

func (s *FileStore) List(_ context.Context, tenant string, cross bool, correlationID string) ([]Feedback, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Feedback{}
	for owner, byCase := range s.rows {
		if !visible(tenant, cross, owner) {
			continue
		}
		out = append(out, byCase[correlationID]...)
	}
	newestFirst(out)
	return out, nil
}

func (s *FileStore) Add(_ context.Context, _ string, _ bool, f Feedback) (Feedback, error) {
	id, err := newUUIDv4()
	if err != nil {
		return Feedback{}, err
	}
	f.ID = id
	f.TenantID = NormTenant(f.TenantID)
	if f.CreatedAt.IsZero() {
		f.CreatedAt = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.rows[f.TenantID][f.CorrelationID]) >= MaxPerCase {
		return Feedback{}, ErrLimit
	}
	s.insertLocked(f)
	if err := s.flushLocked(); err != nil {
		// Roll the in-memory append back so the store never reports a row the
		// file does not hold (the action-item register's rule).
		rows := s.rows[f.TenantID][f.CorrelationID]
		s.rows[f.TenantID][f.CorrelationID] = rows[:len(rows)-1]
		return Feedback{}, err
	}
	return f, nil
}

func (s *FileStore) Buckets(_ context.Context, tenant string, cross bool, since time.Time) ([]Bucket, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	type key struct{ verdict, template string }
	agg := map[key]int{}
	for owner, byCase := range s.rows {
		if !visible(tenant, cross, owner) {
			continue
		}
		for _, rows := range byCase {
			for _, f := range rows {
				if f.CreatedAt.Before(since) {
					continue
				}
				agg[key{f.Verdict, f.TopHypothesis}]++
			}
		}
	}
	out := make([]Bucket, 0, len(agg))
	for k, n := range agg {
		out = append(out, Bucket{Verdict: k.verdict, Template: k.template, N: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Template != out[j].Template {
			return out[i].Template < out[j].Template
		}
		return out[i].Verdict < out[j].Verdict
	})
	return out, nil
}

// ── Postgres backend (tenant_iso FORCE-RLS via WithTenant, migration 0036) ───

// DB is the injected relational seam (the maintenance/wireless idiom): run fn
// inside a transaction whose row-level security is scoped to tenant.
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

type pgStore struct{ db DB }

// NewPGStore builds the Postgres-backed register.
func NewPGStore(db DB) Store { return &pgStore{db: db} }

const pgFeedbackCols = `tenant_id, id, correlation_id, verdict, wrong_part, reason,
	correlation_version, top_hypothesis, verdict_tier, created_by, created_at`

func scanPGFeedback(rows pgx.Rows) (Feedback, error) {
	var (
		f   Feedback
		ver *int32
	)
	if err := rows.Scan(&f.TenantID, &f.ID, &f.CorrelationID, &f.Verdict, &f.WrongPart,
		&f.Reason, &ver, &f.TopHypothesis, &f.VerdictTier, &f.CreatedBy, &f.CreatedAt); err != nil {
		return Feedback{}, err
	}
	if ver != nil {
		v := int(*ver)
		f.CorrelationVersion = &v
	}
	f.CreatedAt = f.CreatedAt.UTC()
	return f, nil
}

func (p *pgStore) List(ctx context.Context, tenant string, cross bool, correlationID string) ([]Feedback, error) {
	out := []Feedback{}
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+pgFeedbackCols+`
		    FROM rca_feedback WHERE correlation_id = $1
		    ORDER BY created_at DESC, id ASC`, correlationID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			f, err := scanPGFeedback(rows)
			if err != nil {
				return err
			}
			out = append(out, f)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (p *pgStore) Add(ctx context.Context, tenant string, cross bool, f Feedback) (Feedback, error) {
	id, err := newUUIDv4()
	if err != nil {
		return Feedback{}, err
	}
	f.ID = id
	f.TenantID = NormTenant(f.TenantID)
	if f.CreatedAt.IsZero() {
		f.CreatedAt = time.Now().UTC()
	}
	var version *int32
	if f.CorrelationVersion != nil {
		// Bounded by Validate (1..1<<30), so the narrowing is safe.
		v := int32(*f.CorrelationVersion) // #nosec G115 -- Validate caps correlation_version at 1<<30
		version = &v
	}
	err = p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM rca_feedback
		    WHERE tenant_id = $1 AND correlation_id = $2`, f.TenantID, f.CorrelationID).Scan(&n); err != nil {
			return err
		}
		if n >= MaxPerCase {
			return ErrLimit
		}
		_, err := tx.Exec(ctx, `INSERT INTO rca_feedback
		        (tenant_id, id, correlation_id, verdict, wrong_part, reason,
		         correlation_version, top_hypothesis, verdict_tier, created_by, created_at)
		    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
			f.TenantID, f.ID, f.CorrelationID, f.Verdict, f.WrongPart, f.Reason,
			version, f.TopHypothesis, f.VerdictTier, f.CreatedBy, f.CreatedAt)
		return err
	})
	if err != nil {
		return Feedback{}, err
	}
	return f, nil
}

func (p *pgStore) Buckets(ctx context.Context, tenant string, cross bool, since time.Time) ([]Bucket, error) {
	out := []Bucket{}
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT verdict, top_hypothesis, count(*)
		    FROM rca_feedback WHERE created_at >= $1
		    GROUP BY verdict, top_hypothesis
		    ORDER BY top_hypothesis ASC, verdict ASC`, since)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				b Bucket
				n int64
			)
			if err := rows.Scan(&b.Verdict, &b.Template, &n); err != nil {
				return err
			}
			b.N = int(n)
			out = append(out, b)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

var _ Store = (*FileStore)(nil)
var _ Store = (*pgStore)(nil)
