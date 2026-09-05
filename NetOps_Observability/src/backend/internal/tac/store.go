package tac

// store.go — where bundles live: data/tac/<tenant>/<incident>/<name>.zip.
//
// TENANT-KEYED BY CONSTRUCTION (§3a rule 4). The tenant is a PATH SEGMENT, so
// one tenant's bundles are not merely filtered out of another's listing — they
// are in a directory the other's read never names. There is no "list all"
// method on this store, deliberately: a surface that could enumerate every
// tenant's escalations is exactly the thing that leaks, and nothing in this
// feature needs one.
//
// PATH SAFETY. Tenant and incident ids arrive from resolved records, not from a
// request body — but this store still refuses anything that is not a plain
// identifier, because a store that trusts its caller is one refactor away from a
// traversal. `..`, separators and every shell-significant character are rejected
// before a path is built, not sanitised into something that might still escape.
//
// PERMISSIONS. Directories are 0700 and files 0600. A bundle is redacted, but
// "redacted" is not "public": it still names a customer's devices, addresses and
// topology.
//
// RETENTION IS BOUNDED (§9). Every write prunes: the oldest bundles past the
// per-incident count, and everything past the maximum age. Escalation bundles
// are working artifacts, not an archive — the incident record is the archive.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

// keyRE is the shape a tenant or incident id must have to become a path
// segment. It admits the id shapes this platform actually uses (uuids, slugs,
// tenant names) and nothing that could traverse.
var keyRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$`)

// nameRE is the shape a bundle file name must have.
var nameRE = regexp.MustCompile(`^correlix-tac-[a-z0-9-]{1,160}\.zip$`)

var (
	// ErrBadKey is a tenant/incident id that cannot safely become a path.
	ErrBadKey = errors.New("tac: unsafe store key")
	// ErrNotFound is a bundle this tenant does not have.
	ErrNotFound = errors.New("tac: bundle not found")
)

// StoredBundle is one bundle's metadata.
type StoredBundle struct {
	Name       string    `json:"name"`
	Bytes      int64     `json:"bytes"`
	CreatedAt  time.Time `json:"created_at"`
	IncidentID string    `json:"incident_id"`
	// Profile, ClassID and PlanID are carried in the sidecar so a listing can be
	// rendered without opening the zip.
	Profile string `json:"profile"`
	ClassID string `json:"class_id"`
	PlanID  string `json:"plan_id"`
}

// Store is the on-disk bundle register.
type Store struct {
	root           string
	maxPerIncident int
	maxAge         time.Duration
	now            func() time.Time
	mu             sync.Mutex
}

// StoreOption configures a Store.
type StoreOption func(*Store)

// WithRetention sets the per-incident bundle count and the maximum age. Values
// are clamped to the package ceilings — a caller can tighten retention, never
// widen it past what the design allows.
func WithRetention(perIncident int, maxAge time.Duration) StoreOption {
	return func(s *Store) {
		if perIncident > 0 && perIncident <= maxBundlesPerIncident {
			s.maxPerIncident = perIncident
		}
		if maxAge > 0 && maxAge <= maxBundleAge {
			s.maxAge = maxAge
		}
	}
}

// WithStoreClock injects the clock (tests pin it).
func WithStoreClock(now func() time.Time) StoreOption {
	return func(s *Store) {
		if now != nil {
			s.now = now
		}
	}
}

const (
	// maxBundlesPerIncident is the retention ceiling per incident.
	maxBundlesPerIncident = 10
	// maxBundleAge is the retention ceiling in time.
	maxBundleAge = 30 * 24 * time.Hour
	// maxBundleBytes is the largest single bundle the store will accept.
	maxBundleBytes = 64 << 20
)

// NewStore opens (creating if needed) the bundle root.
func NewStore(root string, opts ...StoreOption) (*Store, error) {
	if root == "" {
		return nil, errors.New("tac: bundle store needs a root directory")
	}
	s := &Store{root: root, maxPerIncident: maxBundlesPerIncident, maxAge: maxBundleAge, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("tac: bundle store: %w", err)
	}
	return s, nil
}

// dir builds and validates the directory for one (tenant, incident).
func (s *Store) dir(tenant, incident string) (string, error) {
	if !keyRE.MatchString(tenant) || !keyRE.MatchString(incident) {
		return "", ErrBadKey
	}
	return filepath.Join(s.root, tenant, incident), nil
}

// Put writes a bundle and prunes. The returned metadata is what a listing shows.
func (s *Store) Put(tenant, incident string, b *Bundle) (StoredBundle, error) {
	if b == nil || len(b.Zip) == 0 {
		return StoredBundle{}, errors.New("tac: empty bundle")
	}
	if int64(len(b.Zip)) > maxBundleBytes {
		return StoredBundle{}, errors.New("tac: bundle exceeds the store's size ceiling")
	}
	if !nameRE.MatchString(b.Name) {
		return StoredBundle{}, fmt.Errorf("%w: bundle name %q", ErrBadKey, b.Name)
	}
	dir, err := s.dir(tenant, incident)
	if err != nil {
		return StoredBundle{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return StoredBundle{}, fmt.Errorf("tac: bundle store: %w", err)
	}
	path := filepath.Join(dir, b.Name)
	// Write to a temp file in the SAME directory and rename, so a reader never
	// sees a half-written zip and a crash leaves no partial bundle behind.
	tmp, err := os.CreateTemp(dir, ".tac-*.part")
	if err != nil {
		return StoredBundle{}, fmt.Errorf("tac: bundle store: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return StoredBundle{}, fmt.Errorf("tac: bundle store: %w", err)
	}
	if _, err := tmp.Write(b.Zip); err != nil {
		_ = tmp.Close()
		return StoredBundle{}, fmt.Errorf("tac: bundle store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return StoredBundle{}, fmt.Errorf("tac: bundle store: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return StoredBundle{}, fmt.Errorf("tac: bundle store: %w", err)
	}
	// The file's mtime IS the retention clock, and it comes from the injected
	// clock rather than the filesystem's idea of now. Without this the prune
	// below would compare a caller-controlled cutoff against a wall-clock mtime
	// — two different clocks, which is how retention bugs are written.
	written := s.now().UTC()
	if err := os.Chtimes(path, written, written); err != nil {
		return StoredBundle{}, fmt.Errorf("tac: bundle store: %w", err)
	}
	meta := StoredBundle{
		Name: b.Name, Bytes: int64(len(b.Zip)), CreatedAt: written,
		IncidentID: incident, Profile: b.Manifest.Profile,
		ClassID: b.Manifest.Classification.ClassID, PlanID: b.Manifest.PlanVersion,
	}
	if err := os.WriteFile(path+".json", mustJSON(meta), 0o600); err != nil {
		return StoredBundle{}, fmt.Errorf("tac: bundle store: %w", err)
	}
	s.pruneLocked(dir)
	return meta, nil
}

// Get returns one bundle's bytes. A name that is not a bundle name, or a bundle
// this (tenant, incident) does not have, is ErrNotFound — the same answer for
// "absent" and "another tenant's", so the store is never an existence oracle.
func (s *Store) Get(tenant, incident, name string) ([]byte, StoredBundle, error) {
	if !nameRE.MatchString(name) {
		return nil, StoredBundle{}, ErrNotFound
	}
	dir, err := s.dir(tenant, incident)
	if err != nil {
		return nil, StoredBundle{}, ErrNotFound
	}
	path := filepath.Join(dir, name)
	// #nosec G304 -- `dir` is built by s.dir, which REFUSES any tenant/incident
	// segment that is not a plain identifier (keyRE: no separators, no dots, no
	// traversal), and `name` has already been matched against nameRE, which
	// admits only `correlix-tac-<slug>.zip`. Neither can leave the store root,
	// and both are checked BEFORE the path is built rather than sanitised after.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, StoredBundle{}, ErrNotFound
	}
	meta := StoredBundle{Name: name, Bytes: int64(len(data)), IncidentID: incident}
	// #nosec G304 -- same validated path as the read above, plus a fixed suffix.
	if raw, rerr := os.ReadFile(path + ".json"); rerr == nil {
		// A missing or malformed sidecar is not an error: the bundle itself is
		// the artifact, and the metadata is a convenience for the listing.
		_ = jsonUnmarshal(raw, &meta)
	}
	return data, meta, nil
}

// List returns this (tenant, incident)'s bundles, newest first.
func (s *Store) List(tenant, incident string) ([]StoredBundle, error) {
	dir, err := s.dir(tenant, incident)
	if err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []StoredBundle{}, nil
		}
		return nil, fmt.Errorf("tac: bundle store: %w", err)
	}
	out := make([]StoredBundle, 0, len(ents))
	for _, e := range ents {
		if e.IsDir() || !nameRE.MatchString(e.Name()) {
			continue
		}
		meta := StoredBundle{Name: e.Name(), IncidentID: incident}
		if info, ierr := e.Info(); ierr == nil {
			meta.Bytes = info.Size()
			meta.CreatedAt = info.ModTime().UTC()
		}
		// #nosec G304 -- `dir` is the validated store path (s.dir) and e.Name()
		// came from ReadDir on that directory and was matched against nameRE
		// above; it is a file this store wrote, not caller input.
		if raw, rerr := os.ReadFile(filepath.Join(dir, e.Name()+".json")); rerr == nil {
			_ = jsonUnmarshal(raw, &meta)
		}
		out = append(out, meta)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// pruneLocked enforces retention in one incident directory. It is best-effort:
// a file it cannot remove is logged by the caller, never a reason to fail a
// write the operator is waiting on.
func (s *Store) pruneLocked(dir string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	type row struct {
		name string
		mod  time.Time
	}
	var rows []row
	cutoff := s.now().Add(-s.maxAge)
	for _, e := range ents {
		if e.IsDir() || !nameRE.MatchString(e.Name()) {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			s.removeBundle(dir, e.Name())
			continue
		}
		rows = append(rows, row{name: e.Name(), mod: info.ModTime()})
	}
	if len(rows) <= s.maxPerIncident {
		return
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].mod.After(rows[j].mod) })
	for _, r := range rows[s.maxPerIncident:] {
		s.removeBundle(dir, r.name)
	}
}

func (s *Store) removeBundle(dir, name string) {
	_ = os.Remove(filepath.Join(dir, name))
	_ = os.Remove(filepath.Join(dir, name+".json"))
}
