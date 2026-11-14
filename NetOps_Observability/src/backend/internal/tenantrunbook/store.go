// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tenantrunbook

// store.go — the Store contract, the gate both stores share, and the memory store
// (tests and file-backend previews; production uses PGStore). A transition is two
// steps: prepare runs unlocked against a snapshot and may take seconds; decide runs
// under the lock, is pure, and is where orgcontext.Apply is called. Both stores run
// the same two functions, so they cannot drift.

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"netops/backend/internal/orgcontext"
)

// Store is the runbook store. tenant is ALWAYS the principal's own.
type Store interface {
	// List returns the tenant's runbooks with their history.
	List(ctx context.Context, tenant string) ([]Runbook, error)
	// Get returns one runbook (orgcontext.ErrNotFound for another tenant's).
	Get(ctx context.Context, tenant, id string) (Runbook, error)
	// Create makes a runbook whose version 1 is a draft by actor.
	Create(ctx context.Context, tenant, actor string, in NewRunbook) (Runbook, error)
	// Do applies one transition. A draft's op.Body is CanonicalBody's output.
	Do(ctx context.Context, tenant, id string, op orgcontext.Op) (Runbook, error)
	// Check runs the harness over the open version (or, with none, the active
	// one) and changes nothing.
	Check(ctx context.Context, tenant, id string) (HarnessResult, error)
	// Reprove re-runs the ACTIVE version's cases under the current fingerprint
	// and records the result on that version (active.go). The text and its
	// approval are untouched; ErrNothingActive when nothing is approved. actor
	// is who asked (a person, or the server's lazy re-check), for the record.
	Reprove(ctx context.Context, tenant, id, actor string) (ReproveResult, error)
	// Links lists a runbook's links.
	Links(ctx context.Context, tenant, id string) ([]Link, error)
	// PutLink adds a link; adding one that exists changes nothing.
	PutLink(ctx context.Context, tenant, id, actor string, t LinkType, key string) ([]Link, error)
	// DeleteLink removes a link; orgcontext.ErrNotFound when it is not there.
	DeleteLink(ctx context.Context, tenant, id string, t LinkType, key string) ([]Link, error)
	// ListByLink returns the tenant's runbooks linked to (t, key).
	ListByLink(ctx context.Context, tenant string, t LinkType, key string) ([]RetrievalDoc, error)
	// Search returns the tenant's runbooks matching q over name + when-to-use,
	// best match first, then active first, then most recent.
	Search(ctx context.Context, tenant, q string, limit int) ([]RetrievalDoc, error)
}

// Config is what both stores need.
type Config struct {
	Harness Harness
	// ToolNames are the registered Iris tool names (prose may not name one).
	ToolNames func() []string
	Metrics   *Metrics
}

func (c Config) tools() []string {
	if c.ToolNames == nil {
		return nil
	}
	return c.ToolNames()
}

// ---- the gate -------------------------------------------------------------

// checkNew validates a create. The result carries the searchable text.
func (c Config) checkNew(tenant, actor string, in NewRunbook) (string, string, error) {
	if strings.TrimSpace(tenant) == "" || strings.TrimSpace(actor) == "" {
		return "", "", orgcontext.ErrInvalid
	}
	sk, err := Parse(tenant, in.Name, in.Kind, in.Source, c.tools())
	if err != nil {
		return "", "", err
	}
	body, err := CanonicalBody(in.Source)
	if err != nil {
		return "", "", err
	}
	return body, whenToUseOf(sk), nil
}

func newRunbook(tenant, actor, id, body, whenToUse string, in NewRunbook, now time.Time) Runbook {
	return Runbook{
		Doc: orgcontext.Doc{
			ID: id, TenantID: tenant, Scope: orgcontext.ScopeTenant, Key: in.Name, CreatedBy: actor, CreatedAt: now, UpdatedAt: now,
			Versions: []orgcontext.Version{{Version: 1, Body: body, BodySHA256: orgcontext.BodySHA256(body), State: orgcontext.StateDraft, Author: actor, CreatedAt: now}},
		},
		RunbookKind: in.Kind, WhenToUse: whenToUse, Harness: map[int]Stamp{}, Recheck: map[int]map[string]Stamp{},
	}
}

// proof is what prepare hands decide: the text that was proven and how it went.
type proof struct {
	sha256 string
	stamp  Stamp
}

// prepare does everything that may take time, before any lock. list returns the
// tenant's runbooks; it is only called when a harness run needs the siblings.
func (c Config) prepare(ctx context.Context, before Runbook, op orgcontext.Op, list func() ([]Runbook, error)) (*proof, error) {
	switch op.Kind {
	case orgcontext.OpDraft, orgcontext.OpSubmit, orgcontext.OpRollback:
	default:
		return nil, nil
	}
	// A move Apply would refuse is refused before anyone waits for a harness run.
	if _, err := orgcontext.Apply(before.Doc, op); err != nil {
		return nil, err
	}
	if op.Kind == orgcontext.OpDraft {
		// The text is the author's to fix, so this is a refusal with a reason.
		src, err := SplitBody(op.Body)
		if err != nil {
			return nil, orgcontext.ErrInvalid
		}
		if _, err := Parse(before.TenantID, before.Name(), before.RunbookKind, src, c.tools()); err != nil {
			return nil, err
		}
		return nil, nil
	}
	var target orgcontext.Version
	if op.Kind == orgcontext.OpSubmit {
		target, _ = before.draft()
	} else {
		target, _ = before.version(op.ToVersion)
	}
	res, err := c.prove(ctx, before, target, list)
	if err != nil {
		return nil, err
	}
	if !res.Passed {
		return nil, &HarnessError{Problems: res.Problems}
	}
	at := op.Now.UTC()
	return &proof{sha256: target.BodySHA256, stamp: Stamp{Passed: true, Fingerprint: res.Fingerprint, At: &at}}, nil
}

// prove runs the harness over one version of before.
func (c Config) prove(ctx context.Context, before Runbook, v orgcontext.Version, list func() ([]Runbook, error)) (HarnessResult, error) {
	if c.Harness == nil {
		return HarnessResult{}, errors.New("tenantrunbook: no harness is configured")
	}
	src, err := SplitBody(v.Body)
	if err != nil {
		return HarnessResult{}, err
	}
	req := HarnessRequest{Tenant: before.TenantID, Name: before.Name(), Kind: before.RunbookKind, Source: src}
	if before.RunbookKind == KindInvestigative {
		all, err := list()
		if err != nil {
			return HarnessResult{}, err
		}
		req.Siblings = activeSources(all, before.ID)
	}
	res, err := c.Harness.Run(ctx, req)
	c.Metrics.harness(res, err)
	return res, err
}

// activeSources is the tenant's other investigative runbooks' approved texts.
func activeSources(all []Runbook, except string) map[string]Source {
	out := map[string]Source{}
	for _, r := range all {
		if r.ID == except || r.RunbookKind != KindInvestigative {
			continue
		}
		a, ok := r.Active()
		if !ok {
			continue
		}
		if src, err := SplitBody(a.Body); err == nil {
			out[r.Name()] = src
		}
	}
	return out
}

// decide is the locked step. before is what the row holds NOW.
func (c Config) decide(before Runbook, op orgcontext.Op, p *proof) (Runbook, error) {
	// Bounds are read under the lock, so concurrent writers cannot both pass.
	_, hasDraft := before.draft()
	if (op.Kind == orgcontext.OpDraft && !hasDraft) || op.Kind == orgcontext.OpRollback {
		if len(before.Versions) >= MaxVersionsPerRunbook {
			return Runbook{}, orgcontext.ErrFull
		}
	}
	doc, err := orgcontext.Apply(before.Doc, op)
	if err != nil {
		return Runbook{}, err
	}
	after := before.clone()
	after.Doc = doc
	switch op.Kind {
	case orgcontext.OpSubmit:
		// The text proven is the text being submitted: an edit since then fails.
		d, ok := before.draft()
		if !ok || p == nil || d.BodySHA256 != p.sha256 {
			return Runbook{}, orgcontext.ErrStale
		}
		after.Harness[d.Version] = p.stamp
	case orgcontext.OpApprove:
		if !c.proven(before, op.Version) {
			c.Metrics.staleApproval()
			return Runbook{}, ErrHarnessStale
		}
	case orgcontext.OpRollback:
		t, ok := before.version(op.ToVersion)
		if !ok || p == nil || t.BodySHA256 != p.sha256 {
			return Runbook{}, orgcontext.ErrStale
		}
		after.Harness[after.latest()] = p.stamp
	case orgcontext.OpWithdraw:
		if v, ok := after.draft(); ok {
			delete(after.Harness, v.Version) // the next submit proves it again
		}
	case orgcontext.OpDiscard:
		for n := range after.Harness {
			if _, still := after.version(n); !still {
				delete(after.Harness, n)
			}
		}
	}
	after.WhenToUse = c.searchText(after, before.WhenToUse)
	return after, nil
}

// proven is the approval rule: a pass, under the fingerprint that is current now.
func (c Config) proven(r Runbook, version int) bool {
	st, ok := r.Harness[version]
	if !ok || !st.Passed {
		return false
	}
	if r.RunbookKind == KindMOP {
		return st.Fingerprint == FingerprintNotApplicable
	}
	return c.Harness != nil && st.Fingerprint != "" && st.Fingerprint == c.Harness.Fingerprint()
}

// searchText is what the runbook is found by: the active version's when-to-use
// while there is one, so an unapproved edit cannot change it; otherwise the newest
// text. A text that does not parse leaves it as it was.
func (c Config) searchText(r Runbook, was string) string {
	v, ok := r.Active()
	if !ok {
		if v, ok = r.Open(); !ok {
			return was
		}
	}
	src, err := SplitBody(v.Body)
	if err != nil {
		return was
	}
	sk, err := Parse(r.TenantID, r.Name(), r.RunbookKind, src, nil)
	if err != nil {
		return was
	}
	return whenToUseOf(sk)
}

// checkTarget is the version a dry run proves.
func checkTarget(r Runbook) (orgcontext.Version, error) {
	if v, ok := r.Open(); ok {
		return v, nil
	}
	if v, ok := r.Active(); ok {
		return v, nil
	}
	return orgcontext.Version{}, orgcontext.ErrWrongState
}

func checkLink(t LinkType, key string) error {
	if !ValidLinkType(t) {
		return orgcontext.Problem{Field: "link_type", Rule: "unknown", Say: "a link is to an alert, a signature, an entity or an incident"}
	}
	return CheckLinkKey(key)
}

func retrievalOf(r Runbook) RetrievalDoc {
	d := RetrievalDoc{
		ID: r.ID, Tenant: r.TenantID, Type: retrievalType, Source: retrievalSource, Name: r.Name(),
		Authority: AuthorityUnapproved, Scope: orgcontext.ScopeTenant, CreatedAt: r.CreatedAt, Snippet: r.WhenToUse,
	}
	if a, ok := r.Active(); ok {
		d.Authority, d.ApprovedAt = AuthorityApproved, a.DecidedAt
	}
	return d
}

// sortRecency is active first, then most recently changed.
func sortRecency(rs []Runbook) {
	sort.SliceStable(rs, func(i, j int) bool {
		_, ai := rs[i].Active()
		_, aj := rs[j].Active()
		if ai != aj {
			return ai
		}
		if !rs[i].UpdatedAt.Equal(rs[j].UpdatedAt) {
			return rs[i].UpdatedAt.After(rs[j].UpdatedAt)
		}
		return rs[i].ID < rs[j].ID
	})
}

func clampLimit(n int) int {
	if n <= 0 {
		return DefaultSearchLimit
	}
	if n > MaxSearchLimit {
		return MaxSearchLimit
	}
	return n
}

// ---- memory ---------------------------------------------------------------

// MemStore keeps runbooks in memory, keyed by tenant.
type MemStore struct {
	cfg   Config
	mu    sync.Mutex
	rows  map[string]map[string]Runbook // tenant → id → runbook
	links map[string]map[string][]Link  // tenant → id → links
	now   func() time.Time
}

// NewMemStore builds an empty memory store.
func NewMemStore(cfg Config) *MemStore {
	return &MemStore{cfg: cfg, rows: map[string]map[string]Runbook{}, links: map[string]map[string][]Link{},
		now: func() time.Time { return time.Now().UTC() }}
}

func (m *MemStore) sorted(tenant string) []Runbook {
	out := make([]Runbook, 0, len(m.rows[tenant]))
	for _, r := range m.rows[tenant] {
		out = append(out, r.clone())
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt) || (out[i].CreatedAt.Equal(out[j].CreatedAt) && out[i].ID < out[j].ID)
	})
	return out
}

// List implements Store.
func (m *MemStore) List(_ context.Context, tenant string) ([]Runbook, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sorted(tenant), nil
}

// Get implements Store.
func (m *MemStore) Get(_ context.Context, tenant, id string) (Runbook, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[tenant][id]
	if !ok {
		return Runbook{}, orgcontext.ErrNotFound
	}
	return r.clone(), nil
}

// Create implements Store.
func (m *MemStore) Create(_ context.Context, tenant, actor string, in NewRunbook) (out Runbook, err error) {
	defer func() { m.cfg.Metrics.op("create", err) }()
	body, when, err := m.cfg.checkNew(tenant, actor, in)
	if err != nil {
		return Runbook{}, err
	}
	id, err := orgcontext.NewID()
	if err != nil {
		return Runbook{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.rows[tenant]) >= MaxRunbooksPerTenant {
		return Runbook{}, orgcontext.ErrFull
	}
	for _, r := range m.rows[tenant] {
		if r.Name() == in.Name {
			return Runbook{}, orgcontext.ErrExists
		}
	}
	r := newRunbook(tenant, actor, id, body, when, in, m.now())
	if m.rows[tenant] == nil {
		m.rows[tenant] = map[string]Runbook{}
	}
	m.rows[tenant][id] = r
	return r.clone(), nil
}

// Do implements Store.
func (m *MemStore) Do(ctx context.Context, tenant, id string, op orgcontext.Op) (out Runbook, err error) {
	defer func() { m.cfg.Metrics.op(string(op.Kind), err) }()
	if op.Now.IsZero() {
		op.Now = m.now()
	}
	before, err := m.Get(ctx, tenant, id)
	if err != nil {
		return Runbook{}, err
	}
	p, err := m.cfg.prepare(ctx, before, op, func() ([]Runbook, error) { return m.List(ctx, tenant) })
	if err != nil {
		return Runbook{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.rows[tenant][id]
	if !ok {
		return Runbook{}, orgcontext.ErrNotFound
	}
	after, err := m.cfg.decide(cur, op, p)
	if err != nil {
		return Runbook{}, err
	}
	if len(after.Versions) == 0 {
		delete(m.rows[tenant], id)
		delete(m.links[tenant], id)
		return after, nil
	}
	m.rows[tenant][id] = after
	return after.clone(), nil
}

// Reprove implements Store.
// The memory store keeps no re-check author; PGStore records it.
func (m *MemStore) Reprove(ctx context.Context, tenant, id, _ string) (out ReproveResult, err error) {
	defer func() { m.cfg.Metrics.op("reprove", err) }()
	before, err := m.Get(ctx, tenant, id)
	if err != nil {
		return ReproveResult{}, err
	}
	v, res, out, err := m.cfg.reprovePrepare(ctx, before, func() ([]Runbook, error) { return m.List(ctx, tenant) })
	if err != nil || out.AlreadyOK {
		return out, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.rows[tenant][id]
	if !ok {
		return ReproveResult{}, orgcontext.ErrNotFound
	}
	if st, record := m.cfg.reproveDecide(cur, v.Version, v.BodySHA256, res, m.now()); record {
		m.rows[tenant][id] = withRecheck(cur, v.Version, st)
	}
	return out, nil
}

// Check implements Store.
func (m *MemStore) Check(ctx context.Context, tenant, id string) (HarnessResult, error) {
	r, err := m.Get(ctx, tenant, id)
	if err != nil {
		return HarnessResult{}, err
	}
	v, err := checkTarget(r)
	if err != nil {
		return HarnessResult{}, err
	}
	return m.cfg.prove(ctx, r, v, func() ([]Runbook, error) { return m.List(ctx, tenant) })
}

// Links implements Store.
func (m *MemStore) Links(_ context.Context, tenant, id string) ([]Link, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rows[tenant][id]; !ok {
		return nil, orgcontext.ErrNotFound
	}
	return append([]Link{}, m.links[tenant][id]...), nil
}

// PutLink implements Store.
func (m *MemStore) PutLink(_ context.Context, tenant, id, actor string, t LinkType, key string) (out []Link, err error) {
	defer func() { m.cfg.Metrics.op("link", err) }()
	if err := checkLink(t, key); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rows[tenant][id]; !ok {
		return nil, orgcontext.ErrNotFound
	}
	cur := m.links[tenant][id]
	for _, l := range cur {
		if l.Type == t && l.Key == key {
			return append([]Link{}, cur...), nil
		}
	}
	if len(cur) >= MaxLinksPerRunbook {
		return nil, orgcontext.ErrFull
	}
	if m.links[tenant] == nil {
		m.links[tenant] = map[string][]Link{}
	}
	m.links[tenant][id] = append(cur, Link{Type: t, Key: key, CreatedBy: actor, CreatedAt: m.now()})
	return append([]Link{}, m.links[tenant][id]...), nil
}

// DeleteLink implements Store.
func (m *MemStore) DeleteLink(_ context.Context, tenant, id string, t LinkType, key string) (out []Link, err error) {
	defer func() { m.cfg.Metrics.op("unlink", err) }()
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.rows[tenant][id]; !ok {
		return nil, orgcontext.ErrNotFound
	}
	cur := m.links[tenant][id]
	for i, l := range cur {
		if l.Type == t && l.Key == key {
			m.links[tenant][id] = append(append([]Link{}, cur[:i]...), cur[i+1:]...)
			return append([]Link{}, m.links[tenant][id]...), nil
		}
	}
	return nil, orgcontext.ErrNotFound
}

// ListByLink implements Store.
func (m *MemStore) ListByLink(_ context.Context, tenant string, t LinkType, key string) ([]RetrievalDoc, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var rs []Runbook
	for id, ls := range m.links[tenant] {
		for _, l := range ls {
			if l.Type == t && l.Key == key {
				rs = append(rs, m.rows[tenant][id])
				break
			}
		}
	}
	sortRecency(rs)
	out := make([]RetrievalDoc, 0, len(rs))
	for _, r := range rs {
		out = append(out, retrievalOf(r))
	}
	return out, nil
}

// Search implements Store. It approximates plainto_tsquery('simple', q): every
// word of q must be a word of the name or the when-to-use. The rank is the number
// of matches, so a memory store's ordering is only as fine as that.
func (m *MemStore) Search(_ context.Context, tenant, q string, limit int) ([]RetrievalDoc, error) {
	words := searchWords(q)
	if len(words) == 0 {
		return []RetrievalDoc{}, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rank := map[string]int{}
	var rs []Runbook
	for _, r := range m.rows[tenant] {
		have := map[string]int{}
		for _, w := range searchWords(r.Name() + " " + r.WhenToUse) {
			have[w]++
		}
		score := 0
		for _, w := range words {
			if have[w] == 0 {
				score = -1
				break
			}
			score += have[w]
		}
		if score > 0 {
			rank[r.ID] = score
			rs = append(rs, r)
		}
	}
	sortRecency(rs)
	sort.SliceStable(rs, func(i, j int) bool { return rank[rs[i].ID] > rank[rs[j].ID] })
	if n := clampLimit(limit); len(rs) > n {
		rs = rs[:n]
	}
	out := make([]RetrievalDoc, 0, len(rs))
	for _, r := range rs {
		out = append(out, retrievalOf(r))
	}
	return out, nil
}

func searchWords(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
}
