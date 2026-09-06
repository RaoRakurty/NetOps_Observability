// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// investigation_memory.go — IRIS Phase B: tenant-scoped INVESTIGATION MEMORY
// (design doc IRIS_TROUBLESHOOTING_MODEL_2026-09-02.md §3.5).
//
// WHAT IT IS. One row per CONCLUDED investigation: the entity it was about
// (device, peer, prefix, correlation case), the skill chain that ran, the final
// verdict text, the citations that verdict rested on, and the operator's
// judgement of it. It answers "have we seen this before, and were we right?"
//
// WHAT IT IS NOT (the load-bearing rule, NetClaw's own): memory is PRIOR
// CONTEXT, never current state and never a rule. It is surfaced to the model as
// ordinary cited EVIDENCE with its outcome stated, exactly like a log line or a
// finding — it declares NO chain signal, so a remembered conclusion can never
// steer which skill runs next (see recall.go for the full argument). Current
// state is verified first, every time.
//
// STORAGE (CLAUDE.md §3a rule 4). Two backends behind one interface, the
// rcafeedback/maintenance convention: FileStore for the default build + tests
// (tenant-keyed map, no unscoped "list all") and pgStore for the Postgres build
// (migration 0040, tenant_iso FORCE-RLS through the injected WithTenant seam).
// Isolation is enforced IN the store: a non-cross caller can never observe
// another tenant's row through any method here, and a recall with NO entity key
// returns nothing rather than a tenant-wide dump.
//
// BOUNDS (§9). Every field is clipped at write; every tenant's history is capped
// at MaxInvestigationsPerTenant with oldest-first eviction, so memory cannot
// grow without limit; every read is capped and windowed.

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/internal/platformdb"
)

// Write-side caps. Each is applied in NormalizeInvestigation, so a row that
// reaches either backend is already bounded regardless of who built it.
const (
	// MaxInvestigationsPerTenant is the RETENTION CAP: how many concluded
	// investigations one tenant keeps. Oldest-first eviction, so the memory of a
	// busy tenant stays bounded and recent — an unbounded history is both a
	// storage leak and a relevance problem.
	MaxInvestigationsPerTenant = 200
	// maxInvestigationVerdictChars bounds the stored verdict text. The verdict is
	// a few sentences by construction; the cap is what stops a pathological
	// narrative from being replayed into a future prompt.
	maxInvestigationVerdictChars = 600
	// maxInvestigationCitations bounds how many citation ids one row records.
	maxInvestigationCitations = 12
	// maxInvestigationSkills bounds the recorded chain (it can never exceed the
	// per-turn round budget, but the store does not trust its caller).
	maxInvestigationSkills = MaxInvestigationRounds
	// maxInvestigationKeyChars bounds every entity key (device id/name, peer,
	// prefix, correlation id).
	maxInvestigationKeyChars = 128
	// maxInvestigationSkillChars bounds one recorded skill name.
	maxInvestigationSkillChars = 64
	// maxInvestigationCitationChars bounds one recorded citation id.
	maxInvestigationCitationChars = 128
)

// InvestigationOutcome is the CLOSED outcome vocabulary — the operator's
// judgement of a concluded investigation. Anything else normalizes to
// OutcomeUnknown (fail closed: an unrecognized judgement is not a confirmation).
type InvestigationOutcome string

const (
	// OutcomeConfirmed — an operator marked the answer right.
	OutcomeConfirmed InvestigationOutcome = "confirmed"
	// OutcomeWrong — an operator marked the answer wrong. A wrong memory is kept
	// ON PURPOSE: knowing a past conclusion was rejected is more useful than
	// forgetting it, provided the outcome is always stated with it.
	OutcomeWrong InvestigationOutcome = "wrong"
	// OutcomeUnknown — recorded without an operator judgement (nobody rated it).
	OutcomeUnknown InvestigationOutcome = "unknown"
)

// validOutcome normalizes an outcome to the closed vocabulary.
func validOutcome(o InvestigationOutcome) InvestigationOutcome {
	switch o {
	case OutcomeConfirmed, OutcomeWrong:
		return o
	default:
		return OutcomeUnknown
	}
}

// OutcomePhrase is the ONE place the outcome is put into operator words. Both
// the recall tool and any future UI read it, so "operator confirmed" never
// drifts into "verified" (which would claim more than we know).
func OutcomePhrase(o InvestigationOutcome) string {
	switch validOutcome(o) {
	case OutcomeConfirmed:
		return "operator confirmed"
	case OutcomeWrong:
		return "operator marked wrong"
	default:
		return "unverified"
	}
}

// InvestigationRow is one concluded investigation. TenantID is the owner,
// stamped by the server from the authenticated principal — never from a
// request body (§3a rule 2).
type InvestigationRow struct {
	TenantID string `json:"-"`
	ID       string `json:"id"`
	// Entity keys. Any subset may be set; a recall matches on the ones supplied.
	DeviceID      string `json:"device_id,omitempty"`
	DeviceName    string `json:"device_name,omitempty"`
	Peer          string `json:"peer,omitempty"`
	Prefix        string `json:"prefix,omitempty"`
	CorrelationID string `json:"correlation_id,omitempty"`
	// Skills is the skill CHAIN that produced the conclusion, in order.
	Skills []string `json:"skills,omitempty"`
	// Verdict is the final answer text, clipped. Citations are the citation ids
	// the answer rested on — kept so a remembered conclusion can be traced back
	// to the evidence that produced it rather than believed on its own word.
	Verdict   string               `json:"verdict"`
	Citations []string             `json:"citations,omitempty"`
	Outcome   InvestigationOutcome `json:"outcome"`
	CreatedAt time.Time            `json:"created_at"`
	// ResolvedAt is when the investigation CONCLUDED (when the operator judged
	// it). It is the recall ordering key: recency of the conclusion is what
	// matters, not when the question was first asked.
	ResolvedAt time.Time `json:"resolved_at"`
}

// HasKey reports whether the row carries at least one entity key. A row without
// one could never be recalled, so it is refused at write.
func (r InvestigationRow) HasKey() bool {
	return r.DeviceID != "" || r.DeviceName != "" || r.Peer != "" || r.Prefix != "" || r.CorrelationID != ""
}

// InvestigationQuery is a recall. At least one entity key is REQUIRED — the
// store has no unscoped list, by design (§3a rule 4). Keys are OR-ed: a row
// matching any supplied key is returned, newest conclusion first.
type InvestigationQuery struct {
	Device        string // device id OR name (matched against both)
	Peer          string
	Prefix        string
	CorrelationID string
	Since         time.Time // conclusions older than this are not recalled
	Limit         int       // capped at MaxRecallRows by the caller
}

// HasKey reports whether the query names anything to recall by.
func (q InvestigationQuery) HasKey() bool {
	return q.Device != "" || q.Peer != "" || q.Prefix != "" || q.CorrelationID != ""
}

// matches reports whether one row answers this query. Comparison is
// case-insensitive on the operator-facing keys (device names and prefixes are
// typed by humans); the tenant filter is applied by the CALLER, never here.
func (q InvestigationQuery) matches(r InvestigationRow) bool {
	if q.Device != "" && (strings.EqualFold(r.DeviceID, q.Device) || strings.EqualFold(r.DeviceName, q.Device)) {
		return true
	}
	if q.Peer != "" && strings.EqualFold(r.Peer, q.Peer) {
		return true
	}
	if q.Prefix != "" && strings.EqualFold(r.Prefix, q.Prefix) {
		return true
	}
	if q.CorrelationID != "" && strings.EqualFold(r.CorrelationID, q.CorrelationID) {
		return true
	}
	return false
}

// InvestigationStore is the memory register. `cross` is the platform-owner
// cross-tenant flag from principalTenant(claims); a non-cross caller can never
// observe another tenant's rows through any method here.
type InvestigationStore interface {
	// Record appends one concluded investigation, evicting the tenant's oldest
	// rows past MaxInvestigationsPerTenant.
	Record(ctx context.Context, row InvestigationRow) error
	// Recall returns the caller-visible rows matching q, newest conclusion
	// first. A query with no entity key returns NOTHING (no unscoped list).
	Recall(ctx context.Context, tenant string, cross bool, q InvestigationQuery) ([]InvestigationRow, error)
}

// NormalizeInvestigation clips and validates one row before it is stored. It is
// exported so the write path (the server's feedback handler) and both backends
// share exactly one definition of a well-formed row.
func NormalizeInvestigation(row InvestigationRow) (InvestigationRow, error) {
	row.TenantID = normTenant(row.TenantID)
	row.DeviceID = clipKey(row.DeviceID)
	row.DeviceName = clipKey(row.DeviceName)
	row.Peer = clipKey(row.Peer)
	row.Prefix = clipKey(row.Prefix)
	row.CorrelationID = clipKey(row.CorrelationID)
	row.Verdict = clampText(row.Verdict, maxInvestigationVerdictChars)
	row.Outcome = validOutcome(row.Outcome)
	row.Skills = clipList(row.Skills, maxInvestigationSkills, maxInvestigationSkillChars)
	row.Citations = clipList(row.Citations, maxInvestigationCitations, maxInvestigationCitationChars)
	if !row.HasKey() {
		return InvestigationRow{}, fmt.Errorf("investigation memory: a row needs at least one entity key")
	}
	if row.Verdict == "" {
		return InvestigationRow{}, fmt.Errorf("investigation memory: a row needs a verdict")
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = time.Now().UTC()
	}
	if row.ResolvedAt.IsZero() {
		row.ResolvedAt = time.Now().UTC()
	}
	// Both stamps are normalized to UTC and TRUNCATED TO MICROSECONDS, the
	// resolution of the Postgres backend's TIMESTAMPTZ column (pgx encodes a
	// time.Time as microseconds since the epoch and drops the remaining
	// nanoseconds). Without this the two backends would not store the same
	// instant: the file store would keep the caller's nanoseconds while the
	// same row read back from Postgres came back truncated, so a recorded row
	// would not compare equal to itself after a round trip. Truncating once, at
	// the single point that defines a well-formed row, keeps `Record` →
	// `Recall` exact on BOTH backends and keeps the ordering/eviction key
	// identical in each.
	row.CreatedAt = row.CreatedAt.UTC().Truncate(time.Microsecond)
	row.ResolvedAt = row.ResolvedAt.UTC().Truncate(time.Microsecond)
	if row.ID == "" {
		id, err := newInvestigationID()
		if err != nil {
			return InvestigationRow{}, err
		}
		row.ID = id
	}
	return row, nil
}

// newInvestigationID mints an RFC-4122 v4 id. Duplicated per the no-shared-utils
// rule (CLAUDE.md §2: no "utils" dumping ground), same as rcafeedback/store.go.
func newInvestigationID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// clipKey trims and bounds one entity key.
func clipKey(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > maxInvestigationKeyChars {
		return v[:maxInvestigationKeyChars]
	}
	return v
}

// clipList bounds a string list by count and per-item length, dropping blanks.
func clipList(in []string, maxItems, maxChars int) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if len(out) >= maxItems {
			break
		}
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if len(v) > maxChars {
			v = v[:maxChars]
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// newestConcluded orders a recall: resolved_at desc, id asc as the tiebreak so
// two conclusions written in the same instant still order deterministically.
func newestConcluded(rows []InvestigationRow) {
	sort.Slice(rows, func(i, j int) bool {
		if !rows[i].ResolvedAt.Equal(rows[j].ResolvedAt) {
			return rows[i].ResolvedAt.After(rows[j].ResolvedAt)
		}
		return rows[i].ID < rows[j].ID
	})
}

// ── file backend (default build; tenant-filtered IN the store) ───────────────

// InvestigationFileStore is the non-Postgres backend. Path "" keeps it purely
// in memory (tests); a real path is loaded at construction and rewritten on
// every append.
type InvestigationFileStore struct {
	mu   sync.RWMutex
	path string
	rows map[string][]InvestigationRow // tenant → rows, oldest first
}

// NewInvestigationFileStore loads persisted memory; a missing or corrupt file
// starts EMPTY (the maintenance/rcafeedback convention — this state file is
// rebuildable operational history, and a parse failure must not block boot).
func NewInvestigationFileStore(path string) *InvestigationFileStore {
	s := &InvestigationFileStore{path: path, rows: map[string][]InvestigationRow{}}
	if path == "" {
		return s
	}
	if b, err := platformdb.Load(path); err == nil && len(b) > 0 {
		var list []persistedInvestigation
		if json.Unmarshal(b, &list) == nil {
			for _, p := range list {
				row := p.InvestigationRow
				row.TenantID = normTenant(p.TenantID)
				if row.TenantID == "" {
					// A row with no owner is unattributable: loading it under the
					// empty tenant would make it visible to a caller it may not
					// belong to. Drop it rather than guess.
					continue
				}
				s.rows[row.TenantID] = append(s.rows[row.TenantID], row)
			}
			for t := range s.rows {
				s.evictLocked(t)
			}
		}
	}
	return s
}

// persistedInvestigation carries the owner on the wire. InvestigationRow keeps
// TenantID json:"-" so an API projection can never leak it; the FILE, which is
// per-deployment and holds every tenant, must record it.
type persistedInvestigation struct {
	InvestigationRow
	TenantID string `json:"tenant_id"`
}

// evictLocked enforces the per-tenant retention cap, oldest first (call with mu
// held, or during construction before the store is shared).
//
// The sort is the EXACT REVERSE of newestConcluded (resolved_at asc, then id
// DESC), so keeping the tail keeps precisely the rows a recall would call the
// newest — including when two conclusions share an instant, where the smaller
// id sorts newer. That is also what the Postgres sweep keeps (`ORDER BY
// resolved_at DESC, id ASC OFFSET cap`), so a tie at the cap boundary evicts
// the same row on both backends. Tie-breaking the other way here would evict
// the very row recall returns first.
func (s *InvestigationFileStore) evictLocked(tenant string) {
	rows := s.rows[tenant]
	sort.Slice(rows, func(i, j int) bool {
		if !rows[i].ResolvedAt.Equal(rows[j].ResolvedAt) {
			return rows[i].ResolvedAt.Before(rows[j].ResolvedAt)
		}
		return rows[i].ID > rows[j].ID
	})
	if len(rows) > MaxInvestigationsPerTenant {
		rows = rows[len(rows)-MaxInvestigationsPerTenant:]
	}
	s.rows[tenant] = rows
}

// flushLocked persists the full set (call with mu held). A marshal or write
// failure is RETURNED, never swallowed — the caller logs it rather than
// reporting a memory that was not stored (§10).
func (s *InvestigationFileStore) flushLocked() error {
	if s.path == "" {
		return nil
	}
	list := []persistedInvestigation{}
	for tenant, rows := range s.rows {
		for _, r := range rows {
			list = append(list, persistedInvestigation{InvestigationRow: r, TenantID: tenant})
		}
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].TenantID != list[j].TenantID {
			return list[i].TenantID < list[j].TenantID
		}
		return list[i].ID < list[j].ID
	})
	b, err := json.Marshal(list)
	if err != nil {
		return fmt.Errorf("encode investigation memory: %w", err)
	}
	return platformdb.Save(s.path, b)
}

func (s *InvestigationFileStore) Record(_ context.Context, row InvestigationRow) error {
	row, err := NormalizeInvestigation(row)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	before := s.rows[row.TenantID]
	s.rows[row.TenantID] = append(append([]InvestigationRow{}, before...), row)
	s.evictLocked(row.TenantID)
	if err := s.flushLocked(); err != nil {
		s.rows[row.TenantID] = before // never report a row the file does not hold
		return err
	}
	return nil
}

func (s *InvestigationFileStore) Recall(_ context.Context, tenant string, cross bool, q InvestigationQuery) ([]InvestigationRow, error) {
	if !q.HasKey() {
		return nil, nil // no unscoped list, ever
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	t := normTenant(tenant)
	out := []InvestigationRow{}
	for owner, rows := range s.rows {
		if !cross && owner != t { // default-closed tenant filter
			continue
		}
		for _, r := range rows {
			if !q.Since.IsZero() && r.ResolvedAt.Before(q.Since) {
				continue
			}
			if q.matches(r) {
				out = append(out, r)
			}
		}
	}
	newestConcluded(out)
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

// ── Postgres backend (tenant_iso FORCE-RLS via WithTenant, migration 0040) ───

// InvestigationDB is the injected relational seam (the rcafeedback/portintel
// idiom): run fn inside a transaction whose row-level security is scoped to
// tenant.
type InvestigationDB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

type pgInvestigationStore struct{ db InvestigationDB }

// NewPGInvestigationStore builds the Postgres-backed memory register.
func NewPGInvestigationStore(db InvestigationDB) InvestigationStore {
	return &pgInvestigationStore{db: db}
}

const pgInvestigationCols = `tenant_id, id, device_id, device_name, peer, prefix,
	correlation_id, skills, verdict, citations, outcome, created_at, resolved_at`

func (p *pgInvestigationStore) Record(ctx context.Context, row InvestigationRow) error {
	row, err := NormalizeInvestigation(row)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// The array columns are NOT NULL: a nil slice would encode as NULL and be
	// refused, so an absent chain or citation list is written as an EMPTY array
	// (which is what it means — "none", not "unknown").
	skills, citations := row.Skills, row.Citations
	if skills == nil {
		skills = []string{}
	}
	if citations == nil {
		citations = []string{}
	}
	return p.db.WithTenant(ctx, row.TenantID, false, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO iris_investigations (`+pgInvestigationCols+`)
		    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
			row.TenantID, row.ID, row.DeviceID, row.DeviceName, row.Peer, row.Prefix,
			row.CorrelationID, skills, row.Verdict, citations, string(row.Outcome),
			row.CreatedAt, row.ResolvedAt); err != nil {
			return err
		}
		// Retention cap, applied in the SAME transaction so the tenant's history
		// is never observed over its bound. RLS scopes the delete as well.
		_, err := tx.Exec(ctx, `DELETE FROM iris_investigations
		    WHERE tenant_id = $1::text AND id IN (
		        SELECT id FROM iris_investigations WHERE tenant_id = $1::text
		         ORDER BY resolved_at DESC, id ASC OFFSET $2::int)`,
			row.TenantID, MaxInvestigationsPerTenant)
		return err
	})
}

func (p *pgInvestigationStore) Recall(ctx context.Context, tenant string, cross bool, q InvestigationQuery) ([]InvestigationRow, error) {
	if !q.HasKey() {
		return nil, nil // no unscoped list, ever
	}
	limit := q.Limit
	if limit <= 0 || limit > MaxRecallRows {
		limit = MaxRecallRows
	}
	since := q.Since
	if since.IsZero() {
		since = time.Unix(0, 0).UTC()
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out := []InvestigationRow{}
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+pgInvestigationCols+`
		    FROM iris_investigations
		   WHERE resolved_at >= $1::timestamptz
		     AND ( ($2::text <> '' AND (lower(device_id) = lower($2::text) OR lower(device_name) = lower($2::text)))
		        OR ($3::text <> '' AND lower(peer) = lower($3::text))
		        OR ($4::text <> '' AND lower(prefix) = lower($4::text))
		        OR ($5::text <> '' AND lower(correlation_id) = lower($5::text)) )
		   ORDER BY resolved_at DESC, id ASC
		   LIMIT $6::int`,
			since, q.Device, q.Peer, q.Prefix, q.CorrelationID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				r       InvestigationRow
				outcome string
			)
			if err := rows.Scan(&r.TenantID, &r.ID, &r.DeviceID, &r.DeviceName, &r.Peer,
				&r.Prefix, &r.CorrelationID, &r.Skills, &r.Verdict, &r.Citations,
				&outcome, &r.CreatedAt, &r.ResolvedAt); err != nil {
				return err
			}
			r.Outcome = validOutcome(InvestigationOutcome(outcome))
			r.CreatedAt, r.ResolvedAt = r.CreatedAt.UTC(), r.ResolvedAt.UTC()
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

var _ InvestigationStore = (*InvestigationFileStore)(nil)
var _ InvestigationStore = (*pgInvestigationStore)(nil)
