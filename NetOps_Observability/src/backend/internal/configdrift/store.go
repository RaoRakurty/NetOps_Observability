package configdrift

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/internal/platformdb"
)

// store.go — the per-device drift-state register. Two backends behind ONE
// interface (the rcafeedback/configstore convention): FileStore for the default
// build and tests, pgStore for STORE_BACKEND=postgres (migration 0038,
// config_drift_state, tenant_iso FORCE-RLS through the injected WithTenant
// seam).
//
// §3a rule 4: the store itself is the filter. There is no unscoped list — List
// takes (tenant, cross) and a scoped caller can never page into another
// tenant's devices, whatever cursor it supplies.

// ErrNotFound is the 404 condition (including every cross-tenant id).
var ErrNotFound = errors.New("not found")

// listLimits bound the bulk list (§9).
const (
	DefaultListLimit = 100
	MaxListLimit     = 500
)

// StateStore is the drift-state register.
type StateStore interface {
	// Get returns one device's state. ok=false means no row (never captured).
	Get(ctx context.Context, tenant string, cross bool, deviceID string) (State, bool, error)
	// Put upserts a device's state. s.TenantID must already carry the owner
	// derived from the DEVICE record.
	Put(ctx context.Context, tenant string, cross bool, s State) error
	// List pages the caller's OWN devices' states, ordered by device id, and
	// returns the next cursor ("" = last page) and the total matching count.
	List(ctx context.Context, tenant string, cross bool, state, cursor string, limit int) ([]State, string, int, error)
	// Counts aggregates the caller-visible rows by state (the gauge + the badge
	// rollup).
	Counts(ctx context.Context, tenant string, cross bool) (map[string]int, error)
}

// clampLimit bounds a caller-supplied page size.
func clampLimit(n int) int {
	switch {
	case n <= 0:
		return DefaultListLimit
	case n > MaxListLimit:
		return MaxListLimit
	default:
		return n
	}
}

// ── file backend ────────────────────────────────────────────────────────────

type stateKey struct{ tenant, device string }

// FileStore is the non-Postgres backend. Path "" keeps it purely in memory.
type FileStore struct {
	mu   sync.RWMutex
	path string
	rows map[stateKey]State
}

// NewFileStore loads the persisted register; a missing or corrupt file starts
// empty (this state is derived and fully rebuildable from the next capture).
func NewFileStore(path string) *FileStore {
	s := &FileStore{path: path, rows: map[stateKey]State{}}
	if path == "" {
		return s
	}
	if b, err := platformdb.Load(path); err == nil && len(b) > 0 {
		var list []State
		if json.Unmarshal(b, &list) == nil {
			for _, st := range list {
				st.TenantID = NormTenant(st.TenantID)
				s.rows[stateKey{st.TenantID, st.DeviceID}] = st
			}
		}
	}
	return s
}

func (s *FileStore) flushLocked() error {
	if s.path == "" {
		return nil
	}
	list := make([]State, 0, len(s.rows))
	for _, st := range s.rows {
		list = append(list, st)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].TenantID != list[j].TenantID {
			return list[i].TenantID < list[j].TenantID
		}
		return list[i].DeviceID < list[j].DeviceID
	})
	b, err := json.Marshal(list)
	if err != nil {
		return fmt.Errorf("encode config drift state: %w", err)
	}
	return platformdb.Save(s.path, b)
}

// Get implements StateStore.
func (s *FileStore) Get(_ context.Context, tenant string, cross bool, deviceID string) (State, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for k, st := range s.rows {
		if k.device == deviceID && visible(tenant, cross, k.tenant) {
			return st, true, nil
		}
	}
	return State{}, false, nil
}

// Put implements StateStore.
func (s *FileStore) Put(_ context.Context, _ string, _ bool, st State) error {
	if st.DeviceID == "" {
		return errors.New("configdrift: state needs a device id")
	}
	st.TenantID = NormTenant(st.TenantID)
	if st.UpdatedAt.IsZero() {
		st.UpdatedAt = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows[stateKey{st.TenantID, st.DeviceID}] = st
	return s.flushLocked()
}

// visibleSorted collects the caller's rows, optionally filtered by state.
func (s *FileStore) visibleSorted(tenant string, cross bool, state string) []State {
	out := make([]State, 0, len(s.rows))
	for k, st := range s.rows {
		if !visible(tenant, cross, k.tenant) {
			continue
		}
		if state != "" && st.State != state {
			continue
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DeviceID != out[j].DeviceID {
			return out[i].DeviceID < out[j].DeviceID
		}
		return out[i].TenantID < out[j].TenantID
	})
	return out
}

// List implements StateStore.
func (s *FileStore) List(_ context.Context, tenant string, cross bool, state, cursor string, limit int) ([]State, string, int, error) {
	limit = clampLimit(limit)
	s.mu.RLock()
	defer s.mu.RUnlock()
	all := s.visibleSorted(tenant, cross, state)
	total := len(all)
	start := 0
	if cursor != "" {
		start = sort.Search(len(all), func(i int) bool { return all[i].DeviceID > cursor })
	}
	end := start + limit
	if end > len(all) {
		end = len(all)
	}
	page := append([]State(nil), all[start:end]...)
	next := ""
	if end < len(all) && len(page) > 0 {
		next = page[len(page)-1].DeviceID
	}
	return page, next, total, nil
}

// Counts implements StateStore.
func (s *FileStore) Counts(_ context.Context, tenant string, cross bool) (map[string]int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]int{}
	for k, st := range s.rows {
		if !visible(tenant, cross, k.tenant) {
			continue
		}
		out[st.State]++
	}
	return out, nil
}

// ── Postgres backend (tenant_iso FORCE-RLS via WithTenant, migration 0038) ───

// DB is the injected relational seam.
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

type pgStore struct{ db DB }

// NewPGStore builds the Postgres-backed drift-state register.
func NewPGStore(db DB) StateStore { return &pgStore{db: db} }

const pgStateCols = `tenant_id, device_id, state, last_sha, golden_sha,
	lines_added, lines_removed, last_error, last_capture_at, changed_at, updated_at`

func scanState(rows pgx.Rows) (State, error) {
	var (
		st       State
		lastCap  *time.Time
		changed  *time.Time
		updated  time.Time
		errText  string
		lastSHA  string
		goldSHA  string
		added    int32
		removedN int32
	)
	if err := rows.Scan(&st.TenantID, &st.DeviceID, &st.State, &lastSHA, &goldSHA,
		&added, &removedN, &errText, &lastCap, &changed, &updated); err != nil {
		return State{}, err
	}
	st.LastSHA, st.GoldenSHA, st.LastError = lastSHA, goldSHA, errText
	st.Added, st.Removed = int(added), int(removedN)
	if lastCap != nil {
		st.LastCapture = lastCap.UTC()
	}
	if changed != nil {
		st.ChangedAt = changed.UTC()
	}
	st.UpdatedAt = updated.UTC()
	return st, nil
}

func (p *pgStore) Get(ctx context.Context, tenant string, cross bool, deviceID string) (State, bool, error) {
	var (
		out   State
		found bool
	)
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+pgStateCols+`
		    FROM config_drift_state WHERE device_id = $1 LIMIT 1`, deviceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		if rows.Next() {
			st, err := scanState(rows)
			if err != nil {
				return err
			}
			out, found = st, true
		}
		return rows.Err()
	})
	return out, found, err
}

func (p *pgStore) Put(ctx context.Context, tenant string, cross bool, st State) error {
	if st.DeviceID == "" {
		return errors.New("configdrift: state needs a device id")
	}
	st.TenantID = NormTenant(st.TenantID)
	if st.UpdatedAt.IsZero() {
		st.UpdatedAt = time.Now().UTC()
	}
	var lastCap, changed *time.Time
	if !st.LastCapture.IsZero() {
		t := st.LastCapture.UTC()
		lastCap = &t
	}
	if !st.ChangedAt.IsZero() {
		t := st.ChangedAt.UTC()
		changed = &t
	}
	return p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO config_drift_state
		        (tenant_id, device_id, state, last_sha, golden_sha, lines_added,
		         lines_removed, last_error, last_capture_at, changed_at, updated_at)
		    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		    ON CONFLICT (tenant_id, device_id) DO UPDATE SET
		        state = EXCLUDED.state, last_sha = EXCLUDED.last_sha,
		        golden_sha = EXCLUDED.golden_sha, lines_added = EXCLUDED.lines_added,
		        lines_removed = EXCLUDED.lines_removed, last_error = EXCLUDED.last_error,
		        last_capture_at = EXCLUDED.last_capture_at,
		        changed_at = EXCLUDED.changed_at, updated_at = EXCLUDED.updated_at`,
			st.TenantID, st.DeviceID, st.State, st.LastSHA, st.GoldenSHA,
			int32(st.Added), int32(st.Removed), st.LastError, lastCap, changed, st.UpdatedAt) // #nosec G115 -- diff line counts are bounded by MaxDiffLines
		return err
	})
}

func (p *pgStore) List(ctx context.Context, tenant string, cross bool, state, cursor string, limit int) ([]State, string, int, error) {
	limit = clampLimit(limit)
	out := []State{}
	total := 0
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM config_drift_state
		    WHERE ($1 = '' OR state = $1)`, state).Scan(&total); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT `+pgStateCols+`
		    FROM config_drift_state
		    WHERE ($1 = '' OR state = $1) AND ($2 = '' OR device_id > $2)
		    ORDER BY device_id ASC LIMIT $3`, state, cursor, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			st, err := scanState(rows)
			if err != nil {
				return err
			}
			out = append(out, st)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, "", 0, err
	}
	next := ""
	if len(out) == limit && len(out) < total {
		next = out[len(out)-1].DeviceID
	}
	return out, next, total, nil
}

func (p *pgStore) Counts(ctx context.Context, tenant string, cross bool) (map[string]int, error) {
	out := map[string]int{}
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT state, count(*) FROM config_drift_state
		    GROUP BY state ORDER BY state ASC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				st string
				n  int64
			)
			if err := rows.Scan(&st, &n); err != nil {
				return err
			}
			out[st] = int(n)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

var (
	_ StateStore = (*FileStore)(nil)
	_ StateStore = (*pgStore)(nil)
)
