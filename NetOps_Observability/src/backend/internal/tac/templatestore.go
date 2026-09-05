package tac

// templatestore.go — where a tenant's TAC command templates live.
//
// ISOLATION LIVES IN THE STORE (§3a rule 4). Rows are held in a tenant-keyed
// map, so a lookup for tenant A can only ever walk A's bucket; there is no
// "list everything" on this seam at all, deliberately, because a surface that
// could enumerate every tenant's templates is exactly the thing that leaks and
// nothing in this feature needs one. Writes take a CONCRETE tenant or fail: ""
// and "*" are refused here, so no future caller can reintroduce a wildcard.
//
// OWNERSHIP IS STAMPED, NEVER ACCEPTED (§3a rule 2). Create takes the tenant and
// the author from the resolved principal; a tenant on the wire cannot even be
// expressed (the wire type has no such field) and the Source is set by the store
// — a tenant cannot write `correlix-default` onto a row of its own.
//
// DEFAULTS ARE NOT ROWS. Correlix's own templates are GENERATED from the
// catalog (templatedefaults.go) and merged into a listing at read time. They are
// readable by every tenant, identical for every tenant, and immutable: a write
// to a `correlix:` id is ErrTemplateImmutable, and a DELETE of one is
// ErrTemplateNotFound-shaped in the handler because a tenant deleting a default
// makes no sense as a request at all.
//
// Persistence goes through platformdb (the same seam the dem/saved/watchlist
// stores use), so the file backend and its Postgres twin are a wiring choice and
// not a rewrite.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/platformdb"
)

// TemplateStore is the template seam. Both backends satisfy it; the HTTP layer
// knows nothing else about storage.
//
// Every method takes the caller's CONCRETE tenant. Get/Update/Delete return
// ErrTemplateNotFound for an id owned by another tenant — a cross-tenant id must
// never be confirmed to exist (§3a rule 1).
type TemplateStore interface {
	List(ctx context.Context, tenant string) ([]Template, error)
	Get(ctx context.Context, tenant, id string) (Template, error)
	Create(ctx context.Context, t Template) (Template, error)
	Update(ctx context.Context, tenant, id string, t Template) (Template, error)
	Delete(ctx context.Context, tenant, id string) error
}

// EnvTemplatesFile is the file backend's path knob.
const EnvTemplatesFile = "TAC_TEMPLATES_FILE"

// concreteTenantID returns the tenant when it is a real one. "" and "*" are not
// tenants: they are "no scope" and "every scope", and neither may own a row.
func concreteTenantID(tenant string) (string, error) {
	t := strings.TrimSpace(tenant)
	if t == "" || t == "*" {
		return "", ErrNoTenant
	}
	return t, nil
}

// newTemplateID mints an id for a tenant row. It is random rather than derived
// so two tenants' identically-named templates never share an id, and it can
// never begin with the `correlix:` namespace.
func newTemplateID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is not a condition this store can paper over with
		// a predictable id; a time-derived fallback would make ids guessable.
		// The caller sees the write fail, which is the honest outcome.
		return ""
	}
	return "tpl-" + hex.EncodeToString(b[:])
}

// FileTemplateStore is the non-Postgres backend. Path "" keeps it purely in
// memory (tests, and a dev build with no persistence configured).
type FileTemplateStore struct {
	mu   sync.RWMutex
	path string
	// rows is tenant → id → template. The tenant key IS the isolation boundary.
	rows    map[string]map[string]Template
	loadErr error
	now     func() time.Time
}

var _ TemplateStore = (*FileTemplateStore)(nil)

// NewFileTemplateStore loads the persisted templates. A missing file starts
// empty; a CORRUPT file starts empty AND records the error, which the integrator
// logs — a template set that failed to load must never look like one a tenant
// never wrote (§10).
func NewFileTemplateStore(path string) *FileTemplateStore {
	s := &FileTemplateStore{
		path: path,
		rows: map[string]map[string]Template{},
		now:  func() time.Time { return time.Now().UTC() },
	}
	if path == "" {
		return s
	}
	b, err := platformdb.Load(path)
	if err != nil {
		return s // absent store → empty, not an error
	}
	var rows map[string][]Template
	if uerr := json.Unmarshal(b, &rows); uerr != nil {
		s.loadErr = uerr
		return s
	}
	for rawTenant, list := range rows {
		t, terr := concreteTenantID(rawTenant)
		if terr != nil {
			// A persisted "" or "*" bucket is not a tenant's data and must never
			// become one; drop it and say so rather than serving it.
			s.loadErr = errors.New("tac: the template file holds a non-concrete tenant bucket; it was dropped")
			continue
		}
		for _, tpl := range list {
			tpl.TenantID = t // the bucket is authoritative, never the row's own field
			tpl.Source = SourceTenant
			if tpl.ID == "" || !tplIDRE.MatchString(tpl.ID) || IsDefaultTemplateID(tpl.ID) || len(tpl.Steps) == 0 {
				s.loadErr = errors.New("tac: the template file holds an invalid row; it was dropped")
				continue
			}
			if s.rows[t] == nil {
				s.rows[t] = map[string]Template{}
			}
			if len(s.rows[t]) >= MaxTemplatesPerTenant {
				break
			}
			s.rows[t][tpl.ID] = tpl
		}
	}
	return s
}

// LoadErr reports a corrupt-file condition for the integrator to log.
func (s *FileTemplateStore) LoadErr() error { return s.loadErr }

// flushLocked persists the whole set. Callers hold the write lock and roll their
// change back when this fails, so a failed write never leaves the in-memory view
// ahead of the file.
func (s *FileTemplateStore) flushLocked() error {
	if s.path == "" {
		return nil
	}
	out := make(map[string][]Template, len(s.rows))
	for tenant, bucket := range s.rows {
		list := make([]Template, 0, len(bucket))
		for _, t := range bucket {
			list = append(list, t)
		}
		SortTemplates(list)
		out[tenant] = list
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return platformdb.Save(s.path, b)
}

func (s *FileTemplateStore) List(_ context.Context, tenant string) ([]Template, error) {
	out := []Template{}
	t, err := concreteTenantID(tenant)
	if err != nil {
		return out, nil // default-closed: no scope, no rows (never a 500)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, tpl := range s.rows[t] {
		out = append(out, tpl)
	}
	SortTemplates(out)
	return out, nil
}

func (s *FileTemplateStore) Get(_ context.Context, tenant, id string) (Template, error) {
	t, err := concreteTenantID(tenant)
	if err != nil {
		return Template{}, ErrTemplateNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	tpl, ok := s.rows[t][id]
	if !ok {
		return Template{}, ErrTemplateNotFound
	}
	return tpl, nil
}

func (s *FileTemplateStore) Create(_ context.Context, in Template) (Template, error) {
	t, err := concreteTenantID(in.TenantID)
	if err != nil {
		return Template{}, err
	}
	in.TenantID = t
	in.Source = SourceTenant // stamped, never accepted
	in.ID = newTemplateID()
	if in.ID == "" {
		return Template{}, errors.New("tac: could not mint a template id")
	}
	now := s.now()
	in.CreatedAt, in.UpdatedAt, in.Version = now, now, 1
	in.CreatedBy = clip(in.CreatedBy, 128)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rows[t] == nil {
		s.rows[t] = map[string]Template{}
	}
	if len(s.rows[t]) >= MaxTemplatesPerTenant {
		return Template{}, ErrTemplatesFull
	}
	s.rows[t][in.ID] = in
	if ferr := s.flushLocked(); ferr != nil {
		delete(s.rows[t], in.ID)
		return Template{}, ferr
	}
	return in, nil
}

func (s *FileTemplateStore) Update(_ context.Context, tenant, id string, next Template) (Template, error) {
	t, err := concreteTenantID(tenant)
	if err != nil {
		return Template{}, ErrTemplateNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.rows[t][id]
	if !ok {
		return Template{}, ErrTemplateNotFound
	}
	merged := mergeTemplate(prev, next, s.now())
	s.rows[t][id] = merged
	if ferr := s.flushLocked(); ferr != nil {
		s.rows[t][id] = prev
		return Template{}, ferr
	}
	return merged, nil
}

func (s *FileTemplateStore) Delete(_ context.Context, tenant, id string) error {
	t, err := concreteTenantID(tenant)
	if err != nil {
		return ErrTemplateNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.rows[t][id]
	if !ok {
		return ErrTemplateNotFound
	}
	delete(s.rows[t], id)
	if ferr := s.flushLocked(); ferr != nil {
		s.rows[t][id] = prev
		return ferr
	}
	return nil
}

// mergeTemplate folds an update onto the stored row. IDENTITY IS IMMUTABLE: the
// id, the owner, the author, the creation time and the source are the previous
// row's, always — an update may change what the template says, never whose it is
// or where it came from. The version increments, so a bundle can name the exact
// revision that ran.
func mergeTemplate(prev, next Template, at time.Time) Template {
	out := next
	out.ID = prev.ID
	out.TenantID = prev.TenantID
	out.Source = prev.Source
	out.CreatedAt = prev.CreatedAt
	out.CreatedBy = prev.CreatedBy
	out.UpdatedAt = at
	out.Version = prev.Version + 1
	return out
}

// ResolveTemplateRef turns a template id into the provenance a bundle records.
//
// It exists so the collect path never takes a template's NAME, SOURCE or VERSION
// from the client: the client says which template it loaded, and the server
// looks up what that id actually is — in the caller's own tenant, or among the
// Correlix defaults. An id neither of those holds is an error, not an
// unattributed collection: a MANIFEST that named a template nobody can find
// would be worse provenance than none.
//
// An empty id is the honest "no template" case and yields a zero ref with no
// error — an operator may edit the plan without saving or loading anything.
func ResolveTemplateRef(ctx context.Context, store TemplateStore, cat *Catalog, tenant, id string) (TemplateRef, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return TemplateRef{}, nil
	}
	if !tplIDRE.MatchString(id) {
		return TemplateRef{}, ErrTemplateNotFound
	}
	if IsDefaultTemplateID(id) {
		t, ok := cat.DefaultTemplate(id)
		if !ok {
			return TemplateRef{}, ErrTemplateNotFound
		}
		return TemplateRef{ID: t.ID, Name: t.Name, Source: t.Source, Version: t.Version}, nil
	}
	if store == nil {
		return TemplateRef{}, ErrTemplateNotFound
	}
	t, err := store.Get(ctx, tenant, id)
	if err != nil {
		return TemplateRef{}, ErrTemplateNotFound
	}
	return TemplateRef{ID: t.ID, Name: t.Name, Source: t.Source, Version: t.Version}, nil
}
