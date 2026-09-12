// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bgpwatch

// baseline.go — the PERSISTED first-seen origin per (tenant, prefix), and the
// reason a fully propagated origin change is detectable at all (tracker 281).
//
// THE PROBLEM THIS CLOSES. With expected_origins undeclared, which is the
// shipped default, classify.go had nowhere honest to get a baseline from, so it
// re-derived one from the CURRENT pass's dominant origin. An origin change that
// won every vantage point therefore BECAME the baseline in the same pass and
// classified clean. Only a minority unexpected origin was ever detectable. The
// honesty fix (1bf933fa) made the product say that; this file removes it.
//
// THE SHAPE. One row per (tenant, prefix): the origin set that was corroborated
// the first time we measured the prefix, when that was, and whether an operator
// has since accepted a different one. A later pass is compared against THAT
// row, which does not move, so a change is a change.
//
// WHAT A BASELINE IS NOT. It is a REMEMBERED OBSERVATION, not declared intent.
// If the prefix was already hijacked the first time we looked, the wrong origin
// is what gets recorded, and no amount of persistence can tell us otherwise.
// Declaring expected_origins is still the stronger statement, and every surface
// here says so rather than implying the baseline was verified by anyone.
//
// THE THREE CASES THAT ARE NOT INCIDENTS, and how they are told apart:
//
//   - FIRST EVER SEEN — no row exists. There is nothing to have changed FROM,
//     so the pass cannot be a change and never is one. The row is written after
//     that pass, never before it, so the first observation is never judged
//     against a baseline derived from itself.
//   - A NEW PREFIX — a prefix added to the watchlist later has no row either,
//     so it takes the first-ever-seen path. Adding a prefix cannot page anyone.
//   - A LEGITIMATE RE-HOMING — the operator ACCEPTS the new origin set
//     (Accept), which replaces the row and stamps who did it. The next pass
//     matches and the incident resolves. That is what stops a real origin
//     change alerting forever.
//
// Isolation lives IN the store (§3a rule 4), as it does for the policy and
// watchlist registers: Postgres by the tenant_iso FORCE-RLS policy of migration
// 0048 reached through the injected WithTenant seam, the file backend by a
// tenant-keyed map. Neither has an unscoped "list all", and every method
// refuses "" and "*" outright.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/internal/platformdb"
)

// Baseline SOURCES — the closed vocabulary of how a row came to exist. A reader
// must always be able to tell an observation we remembered from a decision a
// person made.
const (
	// BaselineFirstSeen: recorded from the first corroborated measurement of
	// the prefix. Nobody confirmed it.
	BaselineFirstSeen = "first_observation"
	// BaselineAccepted: an operator stated this origin set, by name and at a
	// time that is stored with it.
	BaselineAccepted = "operator_accepted"
)

// Store bounds (§9).
const (
	// MaxBaselinePrefixes caps one tenant's baseline rows. It matches the
	// watchlist cap, because one watched prefix is what creates one row.
	MaxBaselinePrefixes = MaxWatchEntriesPerTenant
	// MaxBaselineOrigins caps one row's origin set, matching the declared-set
	// cap so an accepted set can never be wider than a declared one.
	MaxBaselineOrigins = MaxDeclaredASNs
	// MaxBaselineBytes caps the whole serialized file register.
	MaxBaselineBytes = 4 << 20
)

// ErrBaselineFull is returned when a tenant is at MaxBaselinePrefixes and a NEW
// prefix would be recorded. Accepting a change on an EXISTING row always works.
var ErrBaselineFull = fmt.Errorf("bgpwatch: origin-baseline register is full (max %d prefixes per tenant)", MaxBaselinePrefixes)

// ErrNoBaseline is returned when a row a caller named does not exist for this
// tenant. It is the SAME answer another tenant's prefix gets, which is what
// keeps a cross-tenant probe from distinguishing "not yours" from "not there".
var ErrNoBaseline = errors.New("bgpwatch: no origin baseline is recorded for that prefix")

// OriginBaseline is ONE prefix's remembered origin, for ONE tenant.
type OriginBaseline struct {
	Prefix string `json:"prefix"`
	// Origins is the baseline origin set, sorted and deduped. More than one is
	// normal and legitimate: an anycast or multi-homed prefix really is
	// originated by several ASNs, and recording only the loudest would alert on
	// the others forever.
	Origins []uint32 `json:"origins"`
	// Source is BaselineFirstSeen or BaselineAccepted.
	Source string `json:"source"`
	// Vantages is how many DISTINCT collector peers corroborated the set at the
	// moment it was recorded. Zero on an accepted row: an operator's decision
	// is not a measurement and must not borrow a measurement's authority.
	Vantages int `json:"vantages"`
	// FirstSeen is when this prefix was first measured, and it SURVIVES an
	// accept: the row moves, the history of when we started watching does not.
	FirstSeen time.Time `json:"first_seen"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by,omitempty"`
}

// Has reports whether asn is in the baseline set.
func (b OriginBaseline) Has(asn uint32) bool {
	for _, a := range b.Origins {
		if a == asn {
			return true
		}
	}
	return false
}

// describe renders the row for an operator message.
func (b OriginBaseline) describe() string {
	who := "recorded from the first measurement of this prefix"
	if b.Source == BaselineAccepted {
		who = "accepted by an operator"
		if strings.TrimSpace(b.UpdatedBy) != "" {
			who += " (" + clip(b.UpdatedBy, 64) + ")"
		}
	}
	return fmt.Sprintf("AS%s, %s on %s", joinASNs(b.Origins), who, b.UpdatedAt.UTC().Format(time.RFC3339))
}

// cloneBaseline DEEP-copies a row. A shallow copy would hand a caller a live
// slice into the store, and a caller that sorted or appended to it would
// silently move what the evaluator alerts on.
func cloneBaseline(b OriginBaseline) OriginBaseline {
	b.Origins = append([]uint32(nil), b.Origins...)
	return b
}

// normalizeOrigins bounds, dedupes and sorts an origin set. AS0 is reserved
// (RFC 7607) and is dropped, exactly as the declared-set normalizer drops it.
// An EMPTY result is an error: a baseline naming no origin matches nothing and
// would alert on every pass forever.
func normalizeOrigins(in []uint32) ([]uint32, error) {
	if len(in) > MaxBaselineOrigins {
		return nil, fmt.Errorf("at most %d origin ASNs per baseline", MaxBaselineOrigins)
	}
	seen := map[uint32]bool{}
	out := make([]uint32, 0, len(in))
	for _, a := range in {
		if a == 0 || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil, errors.New("a baseline must name at least one origin AS")
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// sanitizeBaseline validates and bounds one row, whether it came off disk, off
// the wire or off the evaluator (§3 — a stored row is still untrusted input).
// A row that cannot be made safe is REFUSED, never repaired into something
// nobody recorded.
func sanitizeBaseline(b OriginBaseline) (OriginBaseline, error) {
	p, err := parsePrefix(b.Prefix)
	if err != nil {
		return OriginBaseline{}, fmt.Errorf("%q is not a prefix", clip(b.Prefix, 64))
	}
	origins, err := normalizeOrigins(b.Origins)
	if err != nil {
		return OriginBaseline{}, err
	}
	if b.Source != BaselineFirstSeen && b.Source != BaselineAccepted {
		return OriginBaseline{}, fmt.Errorf("unknown baseline source %q", clip(b.Source, 32))
	}
	out := OriginBaseline{
		Prefix: p.String(), Origins: origins, Source: b.Source,
		Vantages: b.Vantages, FirstSeen: b.FirstSeen.UTC(), UpdatedAt: b.UpdatedAt.UTC(),
		UpdatedBy: clip(strings.TrimSpace(b.UpdatedBy), 128),
	}
	if out.Vantages < 0 || out.Vantages > 4096 {
		out.Vantages = 0
	}
	if out.FirstSeen.IsZero() {
		out.FirstSeen = out.UpdatedAt
	}
	return out, nil
}

// BaselineStore is the per-tenant origin-baseline register. Every method takes
// a CONCRETE tenant: a baseline is a fact about one customer's address space,
// so there is no cross-tenant read of it, not even for the platform owner.
type BaselineStore interface {
	// Baselines returns ONE tenant's rows, keyed by canonical prefix.
	Baselines(ctx context.Context, tenant string) (map[string]OriginBaseline, error)
	// Record writes a FIRST baseline. It NEVER overwrites: when a row already
	// exists it returns that row with recorded=false. That is what makes two
	// passes, or two processes, unable to move a baseline by accident — moving
	// one is a decision, and a decision goes through Accept.
	Record(ctx context.Context, tenant string, b OriginBaseline) (OriginBaseline, bool, error)
	// Accept REPLACES the baseline with an origin set an operator stated, and
	// stamps who stated it. It is the path a legitimate re-homing takes, and
	// the reason a real origin change stops alerting.
	Accept(ctx context.Context, tenant, prefix, owner string, origins []uint32, now time.Time) (OriginBaseline, error)
	// Forget deletes ONE row so the next measurement records a fresh baseline.
	// ErrNoBaseline when there is nothing to delete for this tenant.
	Forget(ctx context.Context, tenant, prefix string) error
}

// ── file backend ────────────────────────────────────────────────────────────

// BaselineFileStore is the non-Postgres backend. Path "" keeps it purely in
// memory (tests, and a dev build with no persistence configured).
type BaselineFileStore struct {
	mu   sync.RWMutex
	path string
	// rows is tenant → prefix → row. The tenant key IS the isolation boundary.
	rows    map[string]map[string]OriginBaseline
	loadErr error
	// unreadable is the stricter half of loadErr: the file EXISTS but its
	// contents could not be established. While it is set every write is
	// refused, because a flush would REPLACE a file we never read.
	unreadable error
}

// NewBaselineFileStore loads the persisted register. A MISSING file starts
// empty; a file that exists but could not be read or parsed starts empty AND
// records the error, which the integrator logs, AND refuses every write from
// then on. Folding those two cases together is the data-loss class closed in
// 4efbc78d, and here it would be worse than losing rows: an empty register
// makes every watched prefix look like a first observation, so the next pass
// would re-record a baseline from whatever is being announced right now.
func NewBaselineFileStore(path string) *BaselineFileStore {
	s := &BaselineFileStore{path: path, rows: map[string]map[string]OriginBaseline{}}
	if path == "" {
		return s
	}
	b, err := platformdb.Load(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Genuinely absent: nothing has been recorded yet. That is the normal
		// first-boot state and an empty register is the right answer.
		return s
	case err != nil:
		// UNREADABLE IS NOT ABSENT.
		s.loadErr = fmt.Errorf("bgpwatch: the origin-baseline file could not be read: %w", err)
		s.unreadable = s.loadErr
		return s
	case len(b) == 0:
		// Present but empty: nothing stored yet, nothing broken.
		return s
	}
	var raw map[string][]OriginBaseline
	if err := json.Unmarshal(b, &raw); err != nil {
		s.loadErr = fmt.Errorf("bgpwatch: the origin-baseline file could not be parsed: %w", err)
		s.unreadable = s.loadErr
		return s
	}
	for rawTenant, list := range raw {
		t, terr := concreteTenant(rawTenant)
		if terr != nil {
			// A persisted "" or "*" bucket is not a tenant's data and must
			// never become one.
			s.loadErr = errors.New("bgpwatch: the origin-baseline file holds a non-concrete tenant bucket; it was dropped")
			continue
		}
		for _, row := range list {
			clean, cerr := sanitizeBaseline(row)
			if cerr != nil {
				// A row we cannot trust must not silently become "no baseline",
				// which is the state that re-learns from the current table.
				s.loadErr = fmt.Errorf("bgpwatch: the origin-baseline file holds an unusable row for tenant %s: %w", t, cerr)
				continue
			}
			if s.rows[t] == nil {
				s.rows[t] = map[string]OriginBaseline{}
			}
			if len(s.rows[t]) >= MaxBaselinePrefixes {
				s.loadErr = fmt.Errorf("bgpwatch: tenant %s holds more than %d origin baselines; the rest were not loaded", t, MaxBaselinePrefixes)
				break
			}
			s.rows[t][clean.Prefix] = clean
		}
	}
	return s
}

// LoadErr reports a corrupt-file condition for the integrator to log.
func (s *BaselineFileStore) LoadErr() error { return s.loadErr }

// Baselines returns ONE tenant's rows.
func (s *BaselineFileStore) Baselines(_ context.Context, tenant string) (map[string]OriginBaseline, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]OriginBaseline, len(s.rows[t]))
	for k, v := range s.rows[t] {
		out[k] = cloneBaseline(v)
	}
	return out, nil
}

// Record writes a first baseline, and never a second one.
func (s *BaselineFileStore) Record(_ context.Context, tenant string, b OriginBaseline) (OriginBaseline, bool, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return OriginBaseline{}, false, err
	}
	clean, err := sanitizeBaseline(b)
	if err != nil {
		return OriginBaseline{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, had := s.rows[t][clean.Prefix]; had {
		return cloneBaseline(existing), false, nil
	}
	if len(s.rows[t]) >= MaxBaselinePrefixes {
		return OriginBaseline{}, false, ErrBaselineFull
	}
	// PERSIST-THEN-ADOPT (33303ace). The row is serialized as an OVERRIDE over
	// the map we already hold and written to disk first; s.rows only learns
	// about it once the write has succeeded. Nothing is mutated and put back,
	// so a failed flush leaves memory and disk agreeing.
	if err := s.flushViewLocked(t, clean.Prefix, &clean); err != nil {
		return OriginBaseline{}, false, err
	}
	if s.rows[t] == nil {
		s.rows[t] = map[string]OriginBaseline{}
	}
	s.rows[t][clean.Prefix] = clean
	return cloneBaseline(clean), true, nil
}

// Accept replaces one row with an operator-stated origin set.
func (s *BaselineFileStore) Accept(_ context.Context, tenant, prefix, owner string, origins []uint32, now time.Time) (OriginBaseline, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return OriginBaseline{}, err
	}
	p, err := parsePrefix(prefix)
	if err != nil {
		return OriginBaseline{}, fmt.Errorf("%q is not a prefix", clip(prefix, 64))
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	firstSeen := now.UTC()
	if prev, had := s.rows[t][p.String()]; had {
		firstSeen = prev.FirstSeen // when we started watching does not move
	}
	row, err := sanitizeBaseline(OriginBaseline{
		Prefix: p.String(), Origins: origins, Source: BaselineAccepted,
		FirstSeen: firstSeen, UpdatedAt: now.UTC(), UpdatedBy: owner,
	})
	if err != nil {
		return OriginBaseline{}, err
	}
	if _, had := s.rows[t][row.Prefix]; !had && len(s.rows[t]) >= MaxBaselinePrefixes {
		return OriginBaseline{}, ErrBaselineFull
	}
	if err := s.flushViewLocked(t, row.Prefix, &row); err != nil {
		return OriginBaseline{}, err
	}
	if s.rows[t] == nil {
		s.rows[t] = map[string]OriginBaseline{}
	}
	s.rows[t][row.Prefix] = row
	return cloneBaseline(row), nil
}

// Forget deletes ONE row.
func (s *BaselineFileStore) Forget(_ context.Context, tenant, prefix string) error {
	t, err := concreteTenant(tenant)
	if err != nil {
		return err
	}
	p, err := parsePrefix(prefix)
	if err != nil {
		return fmt.Errorf("%q is not a prefix", clip(prefix, 64))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, had := s.rows[t][p.String()]; !had {
		return ErrNoBaseline
	}
	if err := s.flushViewLocked(t, p.String(), nil); err != nil {
		return err
	}
	delete(s.rows[t], p.String())
	return nil
}

// flushViewLocked serializes the register with ONE override applied, WITHOUT
// touching s.rows: row non-nil writes or replaces it, row nil removes it. The
// caller adopts the change into s.rows only after this returns nil.
func (s *BaselineFileStore) flushViewLocked(tenant, prefix string, row *OriginBaseline) error {
	if s.unreadable != nil {
		// The file's real contents are unknown, so a flush would not update it,
		// it would REPLACE it with what this process holds. Refuse, and say
		// why: the caller reports an error instead of losing every baseline.
		return fmt.Errorf("%w: %w", ErrStoreUnreadable, s.unreadable)
	}
	if s.path == "" {
		return nil
	}
	view := make(map[string][]OriginBaseline, len(s.rows)+1)
	for t, bucket := range s.rows {
		list := make([]OriginBaseline, 0, len(bucket)+1)
		for p, b := range bucket {
			if t == tenant && p == prefix {
				continue // the override decides this key
			}
			list = append(list, b)
		}
		if t == tenant && row != nil {
			list = append(list, *row)
		}
		if len(list) == 0 {
			continue
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Prefix < list[j].Prefix })
		view[t] = list
	}
	if _, seen := s.rows[tenant]; !seen && row != nil {
		view[tenant] = []OriginBaseline{*row}
	}
	b, err := json.Marshal(view)
	if err != nil {
		return err
	}
	if len(b) > MaxBaselineBytes {
		return errors.New("bgpwatch: origin-baseline register exceeds its size bound")
	}
	return platformdb.Save(s.path, b)
}

// ── Postgres backend (tenant_iso FORCE-RLS via WithTenant, migration 0048) ──

type pgBaselineStore struct{ db DB }

// NewPGBaselineStore builds the Postgres backend.
func NewPGBaselineStore(db DB) BaselineStore { return &pgBaselineStore{db: db} }

// Baselines reads ONE tenant's rows. cross is ALWAYS false: the GUC is the
// concrete tenant, never the '*' wildcard.
func (s *pgBaselineStore) Baselines(ctx context.Context, tenant string) (map[string]OriginBaseline, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return nil, err
	}
	out := map[string]OriginBaseline{}
	err = s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		rows, qerr := tx.Query(ctx,
			`SELECT prefix, origins, source, vantages, first_seen, updated_at, updated_by
			   FROM bgp_origin_baseline WHERE tenant_id = $1 ORDER BY prefix LIMIT $2`, t, MaxBaselinePrefixes)
		if qerr != nil {
			return qerr
		}
		defer rows.Close()
		for rows.Next() {
			var b OriginBaseline
			var raw []byte
			if serr := rows.Scan(&b.Prefix, &raw, &b.Source, &b.Vantages, &b.FirstSeen, &b.UpdatedAt, &b.UpdatedBy); serr != nil {
				return serr
			}
			if len(raw) > 0 {
				if jerr := json.Unmarshal(raw, &b.Origins); jerr != nil {
					return fmt.Errorf("stored origin baseline for %s is unreadable: %w", clip(b.Prefix, 64), jerr)
				}
			}
			clean, cerr := sanitizeBaseline(b)
			if cerr != nil {
				// Never downgrade an unusable row to "no baseline": that is the
				// state that re-learns from whatever is announced right now.
				return fmt.Errorf("stored origin baseline for %s is unusable: %w", clip(b.Prefix, 64), cerr)
			}
			out[clean.Prefix] = clean
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Record inserts a first baseline. ON CONFLICT DO NOTHING is what makes it
// insert-if-absent in ONE statement: two api replicas measuring the same prefix
// in the same minute cannot move each other's baseline.
func (s *pgBaselineStore) Record(ctx context.Context, tenant string, b OriginBaseline) (OriginBaseline, bool, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return OriginBaseline{}, false, err
	}
	clean, err := sanitizeBaseline(b)
	if err != nil {
		return OriginBaseline{}, false, err
	}
	body, err := json.Marshal(clean.Origins)
	if err != nil {
		return OriginBaseline{}, false, err
	}
	var recorded bool
	var stored OriginBaseline
	err = s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		var n int
		if cerr := tx.QueryRow(ctx, `SELECT count(*) FROM bgp_origin_baseline WHERE tenant_id = $1`, t).Scan(&n); cerr != nil {
			return cerr
		}
		if n >= MaxBaselinePrefixes {
			var exists bool
			if eerr := tx.QueryRow(ctx,
				`SELECT EXISTS (SELECT 1 FROM bgp_origin_baseline WHERE tenant_id = $1 AND prefix = $2)`,
				t, clean.Prefix).Scan(&exists); eerr != nil {
				return eerr
			}
			if !exists {
				return ErrBaselineFull
			}
		}
		tag, xerr := tx.Exec(ctx,
			`INSERT INTO bgp_origin_baseline (tenant_id, prefix, origins, source, vantages, first_seen, updated_at, updated_by)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			 ON CONFLICT (tenant_id, prefix) DO NOTHING`,
			t, clean.Prefix, body, clean.Source, clean.Vantages, clean.FirstSeen, clean.UpdatedAt, clean.UpdatedBy)
		if xerr != nil {
			return xerr
		}
		recorded = tag.RowsAffected() == 1
		row, rerr := s.readOneTx(ctx, tx, t, clean.Prefix)
		if rerr != nil {
			return rerr
		}
		stored = row
		return nil
	})
	if err != nil {
		return OriginBaseline{}, false, err
	}
	return stored, recorded, nil
}

// Accept replaces one row, preserving first_seen through the upsert.
func (s *pgBaselineStore) Accept(ctx context.Context, tenant, prefix, owner string, origins []uint32, now time.Time) (OriginBaseline, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return OriginBaseline{}, err
	}
	p, err := parsePrefix(prefix)
	if err != nil {
		return OriginBaseline{}, fmt.Errorf("%q is not a prefix", clip(prefix, 64))
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	clean, err := sanitizeBaseline(OriginBaseline{
		Prefix: p.String(), Origins: origins, Source: BaselineAccepted,
		FirstSeen: now.UTC(), UpdatedAt: now.UTC(), UpdatedBy: owner,
	})
	if err != nil {
		return OriginBaseline{}, err
	}
	body, err := json.Marshal(clean.Origins)
	if err != nil {
		return OriginBaseline{}, err
	}
	var stored OriginBaseline
	err = s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		if _, xerr := tx.Exec(ctx,
			`INSERT INTO bgp_origin_baseline (tenant_id, prefix, origins, source, vantages, first_seen, updated_at, updated_by)
			 VALUES ($1,$2,$3,$4,0,$5,$6,$7)
			 ON CONFLICT (tenant_id, prefix) DO UPDATE SET
			   origins = EXCLUDED.origins, source = EXCLUDED.source, vantages = 0,
			   updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by`,
			t, clean.Prefix, body, clean.Source, clean.FirstSeen, clean.UpdatedAt, clean.UpdatedBy); xerr != nil {
			return xerr
		}
		row, rerr := s.readOneTx(ctx, tx, t, clean.Prefix)
		if rerr != nil {
			return rerr
		}
		stored = row
		return nil
	})
	if err != nil {
		return OriginBaseline{}, err
	}
	return stored, nil
}

// Forget deletes ONE row. A prefix this tenant does not hold is ErrNoBaseline,
// which is exactly what another tenant's prefix returns.
func (s *pgBaselineStore) Forget(ctx context.Context, tenant, prefix string) error {
	t, err := concreteTenant(tenant)
	if err != nil {
		return err
	}
	p, err := parsePrefix(prefix)
	if err != nil {
		return fmt.Errorf("%q is not a prefix", clip(prefix, 64))
	}
	return s.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		tag, xerr := tx.Exec(ctx, `DELETE FROM bgp_origin_baseline WHERE tenant_id = $1 AND prefix = $2`, t, p.String())
		if xerr != nil {
			return xerr
		}
		if tag.RowsAffected() == 0 {
			return ErrNoBaseline
		}
		return nil
	})
}

// readOneTx reads one row back inside the caller's transaction, so what the
// caller is handed is what the database actually holds.
func (s *pgBaselineStore) readOneTx(ctx context.Context, tx pgx.Tx, tenant, prefix string) (OriginBaseline, error) {
	var b OriginBaseline
	var raw []byte
	err := tx.QueryRow(ctx,
		`SELECT prefix, origins, source, vantages, first_seen, updated_at, updated_by
		   FROM bgp_origin_baseline WHERE tenant_id = $1 AND prefix = $2`, tenant, prefix).
		Scan(&b.Prefix, &raw, &b.Source, &b.Vantages, &b.FirstSeen, &b.UpdatedAt, &b.UpdatedBy)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return OriginBaseline{}, ErrNoBaseline
		}
		return OriginBaseline{}, err
	}
	if len(raw) > 0 {
		if jerr := json.Unmarshal(raw, &b.Origins); jerr != nil {
			return OriginBaseline{}, fmt.Errorf("stored origin baseline for %s is unreadable: %w", clip(prefix, 64), jerr)
		}
	}
	return sanitizeBaseline(b)
}
