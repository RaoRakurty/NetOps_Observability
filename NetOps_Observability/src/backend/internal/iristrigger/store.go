// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package iristrigger

import (
	"context"
	"crypto/rand"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Store holds triggers, the workspace settings and the run history. Every
// method takes the tenant from the caller's token (or, for the scheduler, from
// the row it is acting on) — never from a request body.
type Store interface {
	Settings(ctx context.Context, tenant string) (Settings, error)
	PutSettings(ctx context.Context, tenant string, s Settings) error

	List(ctx context.Context, tenant string) ([]Trigger, error)
	Get(ctx context.Context, tenant, id string) (Trigger, error)
	// Create stores a validated trigger under tenant, stamping its id, author
	// and times. ErrTooMany past MaxTriggersPerTenant.
	Create(ctx context.Context, tenant, author string, t Trigger, now time.Time) (Trigger, error)
	// SetEnabled turns one trigger on or off.
	SetEnabled(ctx context.Context, tenant, id string, on bool, now time.Time) (Trigger, error)
	Delete(ctx context.Context, tenant, id string) error

	// Admit records the start of a run. ErrDuplicate when this trigger already
	// has a run under run.DedupeKey (one run per incident, one per schedule
	// slot). When the workspace's admitted runs today already reached
	// maxRunsPerDay the run is stored as skipped (daily_run_cap) and returned
	// that way — counted under the same lock as the check, so two concurrent
	// admissions cannot both pass the cap. An admitted run moves the trigger's
	// last-run time.
	Admit(ctx context.Context, tenant string, run Run, maxRunsPerDay int, now time.Time) (Run, error)
	// Skip stores a run that never started, with its reason. ErrDuplicate as
	// for Admit.
	Skip(ctx context.Context, tenant string, run Run, now time.Time) (Run, error)
	// Finish closes an admitted run.
	Finish(ctx context.Context, tenant, id, status, reason, investigationID string, tokens int, summary string, now time.Time) error
	// TokensToday is the tokens the workspace's triggered runs used on day.
	TokensToday(ctx context.Context, tenant string, day time.Time) (int, error)
	// Runs lists the workspace's most recent runs, newest first.
	Runs(ctx context.Context, tenant string, limit int) ([]Run, error)

	// DueSchedules returns every ENABLED schedule trigger in a workspace whose
	// switch is on, across tenants — the scheduler's only cross-tenant read.
	// Each trigger carries its TenantID; the run itself is always scoped to it.
	DueSchedules(ctx context.Context, now time.Time) ([]Trigger, error)
}

// NewID returns a random lowercase UUID v4.
func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("iristrigger: id: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func normTenant(t string) (string, error) {
	t = strings.ToLower(strings.TrimSpace(t))
	if t == "" || t == "*" || strings.ContainsAny(t, "\x00*") {
		return "", fmt.Errorf("%w: tenant", ErrInvalid)
	}
	return t, nil
}

func clampLimit(n int) int {
	if n < 1 {
		return 1
	}
	if n > MaxRunsListed {
		return MaxRunsListed
	}
	return n
}

func clampSummary(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > MaxRunSummary {
		s = string(r[:MaxRunSummary-1]) + "…"
	}
	return s
}

// admittedStatus reports whether a run counts against the daily run cap:
// started runs do, skipped ones do not.
func admittedStatus(s string) bool { return s == RunRunning || s == RunDone || s == RunFailed }

// ---- in-memory store (file backend / tests) ---------------------------------

// MemStore is the in-process Store. It is what a deployment without the
// Postgres platform store uses — triggers there do not survive a restart, and
// the settings page says so.
type MemStore struct {
	mu       sync.Mutex
	settings map[string]Settings
	triggers map[string]map[string]Trigger // tenant → id → trigger
	runs     map[string][]Run              // tenant → runs, oldest first
}

// NewMemStore returns an empty store.
func NewMemStore() *MemStore {
	return &MemStore{settings: map[string]Settings{}, triggers: map[string]map[string]Trigger{}, runs: map[string][]Run{}}
}

func (m *MemStore) Settings(_ context.Context, tenant string) (Settings, error) {
	t, err := normTenant(tenant)
	if err != nil {
		return Settings{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.settings[t]; ok {
		return s, nil
	}
	return DefaultSettings(), nil
}

func (m *MemStore) PutSettings(_ context.Context, tenant string, s Settings) error {
	t, err := normTenant(tenant)
	if err != nil {
		return err
	}
	if err := ValidateSettings(&s); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.settings[t] = s
	return nil
}

func (m *MemStore) List(_ context.Context, tenant string) ([]Trigger, error) {
	t, err := normTenant(tenant)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Trigger, 0, len(m.triggers[t]))
	for _, tr := range m.triggers[t] {
		out = append(out, tr)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

func (m *MemStore) Get(_ context.Context, tenant, id string) (Trigger, error) {
	t, err := normTenant(tenant)
	if err != nil {
		return Trigger{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	tr, ok := m.triggers[t][id]
	if !ok {
		return Trigger{}, ErrNotFound
	}
	return tr, nil
}

func (m *MemStore) Create(_ context.Context, tenant, author string, tr Trigger, now time.Time) (Trigger, error) {
	t, err := normTenant(tenant)
	if err != nil {
		return Trigger{}, err
	}
	if err := Validate(&tr); err != nil {
		return Trigger{}, err
	}
	id, err := NewID()
	if err != nil {
		return Trigger{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.triggers[t]) >= MaxTriggersPerTenant {
		return Trigger{}, ErrTooMany
	}
	if m.triggers[t] == nil {
		m.triggers[t] = map[string]Trigger{}
	}
	now = now.UTC()
	tr.ID, tr.TenantID, tr.CreatedBy, tr.CreatedAt, tr.UpdatedAt, tr.LastRunAt = id, t, author, now, now, nil
	m.triggers[t][id] = tr
	return tr, nil
}

func (m *MemStore) SetEnabled(_ context.Context, tenant, id string, on bool, now time.Time) (Trigger, error) {
	t, err := normTenant(tenant)
	if err != nil {
		return Trigger{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	tr, ok := m.triggers[t][id]
	if !ok {
		return Trigger{}, ErrNotFound
	}
	tr.Enabled, tr.UpdatedAt = on, now.UTC()
	m.triggers[t][id] = tr
	return tr, nil
}

func (m *MemStore) Delete(_ context.Context, tenant, id string) error {
	t, err := normTenant(tenant)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.triggers[t][id]; !ok {
		return ErrNotFound
	}
	delete(m.triggers[t], id)
	return nil
}

func (m *MemStore) dupLocked(t string, run Run) bool {
	for _, r := range m.runs[t] {
		if r.TriggerID == run.TriggerID && r.DedupeKey == run.DedupeKey {
			return true
		}
	}
	return false
}

func (m *MemStore) insertLocked(t string, run Run, now time.Time) (Run, error) {
	id, err := NewID()
	if err != nil {
		return Run{}, err
	}
	run.ID, run.TenantID, run.StartedAt = id, t, now.UTC()
	run.Summary = clampSummary(run.Summary)
	if run.Status == RunSkipped {
		f := now.UTC()
		run.FinishedAt = &f
	}
	m.runs[t] = append(m.runs[t], run)
	if len(m.runs[t]) > 2000 { // bounded history (§9)
		m.runs[t] = m.runs[t][len(m.runs[t])-2000:]
	}
	return run, nil
}

func (m *MemStore) Admit(_ context.Context, tenant string, run Run, maxRunsPerDay int, now time.Time) (Run, error) {
	t, err := normTenant(tenant)
	if err != nil {
		return Run{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dupLocked(t, run) {
		return Run{}, ErrDuplicate
	}
	day, admitted := Day(now), 0
	for _, r := range m.runs[t] {
		if admittedStatus(r.Status) && !r.StartedAt.Before(day) {
			admitted++
		}
	}
	if admitted >= maxRunsPerDay {
		run.Status, run.Reason = RunSkipped, SkipRunCap
		return m.insertLocked(t, run, now)
	}
	run.Status, run.Reason = RunRunning, ""
	out, err := m.insertLocked(t, run, now)
	if err != nil {
		return Run{}, err
	}
	if tr, ok := m.triggers[t][run.TriggerID]; ok {
		at := now.UTC()
		tr.LastRunAt = &at
		m.triggers[t][run.TriggerID] = tr
	}
	return out, nil
}

func (m *MemStore) Skip(_ context.Context, tenant string, run Run, now time.Time) (Run, error) {
	t, err := normTenant(tenant)
	if err != nil {
		return Run{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dupLocked(t, run) {
		return Run{}, ErrDuplicate
	}
	run.Status = RunSkipped
	return m.insertLocked(t, run, now)
}

func (m *MemStore) Finish(_ context.Context, tenant, id, status, reason, invID string, tokens int, summary string, now time.Time) error {
	t, err := normTenant(tenant)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.runs[t] {
		if m.runs[t][i].ID == id {
			r := &m.runs[t][i]
			f := now.UTC()
			r.Status, r.Reason, r.InvestigationID, r.Tokens, r.Summary, r.FinishedAt = status, reason, invID, max(tokens, 0), clampSummary(summary), &f
			return nil
		}
	}
	return ErrNotFound
}

func (m *MemStore) TokensToday(_ context.Context, tenant string, day time.Time) (int, error) {
	t, err := normTenant(tenant)
	if err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	from, to, n := Day(day), Day(day).Add(24*time.Hour), 0
	for _, r := range m.runs[t] {
		if !r.StartedAt.Before(from) && r.StartedAt.Before(to) {
			n += r.Tokens
		}
	}
	return n, nil
}

func (m *MemStore) Runs(_ context.Context, tenant string, limit int) ([]Run, error) {
	t, err := normTenant(tenant)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	all := m.runs[t]
	limit = clampLimit(limit)
	out := make([]Run, 0, limit)
	for i := len(all) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, all[i])
	}
	return out, nil
}

func (m *MemStore) DueSchedules(_ context.Context, now time.Time) ([]Trigger, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Trigger
	for t, byID := range m.triggers {
		if s, ok := m.settings[t]; !ok || !s.Enabled {
			continue
		}
		for _, tr := range byID {
			if tr.Due(now) {
				out = append(out, tr)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
