// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package fieldeval is the per-install home of customer-derived Iris eval
// cases (tracker 337 N-H3).
//
// WHERE FIELD CASES LIVE (decision, owner-delegated 2026-11-15). A question an
// operator really asked is customer data even after review: device names,
// sites, the way a team talks about its network. So field cases never enter
// the repository. They live in a per-install store on the host — default
// data/iris-eval/, under the data/ directory git already ignores — one
// directory per tenant, written 0600. The store has no HTTP surface: only
// someone with shell access to the install (the platform owner) can file or
// read it, and the `iriseval field-list` view prints counts only.
//
// HOW CASES ARRIVE. A workspace admin exports review-gated candidates
// (GET /api/ai/triage/candidates — their own questions, plus colleagues who
// opted in to sharing) and the platform owner files the reviewed export with
// `iriseval field-import` (cmd/iriseval). Every field case is HELD OUT (evalsplit: source
// "field" is always held out), so it can measure generalisation and never feed
// a tuning source. A case becomes scorable only once a person writes its
// expected_route label in the file; an unlabelled case is kept but not scored.
//
// The store refuses a root inside a git work tree unless the path passes
// through a "data" directory, so a mistyped --root cannot drop customer text
// into a commit.
package fieldeval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"netops/backend/internal/evalsplit"
	"netops/backend/internal/iristriage"
)

// DefaultRoot is the store's default location, relative to the install root.
const DefaultRoot = "data/iris-eval"

// Corpus is the evalsplit corpus name of field cases.
const Corpus = "field"

// SchemaVersion of a stored file.
const SchemaVersion = 1

// maxCasesPerImport bounds one import (an export is already capped server-side).
const maxCasesPerImport = 5000

// Case is one customer-derived eval case.
type Case struct {
	ID             string `json:"id"`
	Question       string `json:"question"`
	Source         string `json:"source"`                    // "miss" | "correction"
	CorrectionKind string `json:"correction_kind,omitempty"` // the operator's correction kind
	ObservedRoute  string `json:"observed_route,omitempty"`  // what Iris did at the time
	Class          string `json:"class,omitempty"`           // the miss class at the time
	Pooled         bool   `json:"pooled,omitempty"`          // a consenting colleague's question
	// ExpectedRoute is the reviewer's label. Empty: kept, not scored.
	ExpectedRoute string `json:"expected_route"`
	Split         string `json:"split"`
}

// File is one import, as stored.
type File struct {
	SchemaVersion int    `json:"schema_version"`
	Tenant        string `json:"tenant"`
	ImportedAt    string `json:"imported_at"`
	Notice        string `json:"notice"`
	Cases         []Case `json:"cases"`
}

// Notice heads every stored file.
const Notice = "Customer-derived Iris eval cases. Never commit this file. Held out: never use these cases to tune a prompt, a few-shot library or a phrase list. Write expected_route on a case to make it scorable."

// Store is a field-eval store rooted at one directory.
type Store struct{ root string }

var tenantRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// ErrInsideRepository is returned for a root inside a git work tree that does
// not pass through a data/ directory.
var ErrInsideRepository = errors.New("field-eval cases are customer data and must not be written inside the repository; use a gitignored data/ directory (default " + DefaultRoot + ")")

// Open validates root and returns its store. It creates nothing.
func Open(root string) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		root = DefaultRoot
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("fieldeval: root: %w", err)
	}
	if err := refuseRepoTree(abs); err != nil {
		return nil, err
	}
	return &Store{root: abs}, nil
}

// Root is the store's absolute directory.
func (s *Store) Root() string { return s.root }

// refuseRepoTree refuses abs when an ancestor holds a .git entry and the path
// below that work tree has no "data" component.
func refuseRepoTree(abs string) error {
	for dir := abs; ; dir = filepath.Dir(dir) {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			rel, err := filepath.Rel(dir, abs)
			if err != nil {
				return ErrInsideRepository
			}
			for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
				if part == "data" {
					return nil
				}
			}
			return ErrInsideRepository
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
	}
}

// caseID is stable per tenant, question and kind, so a re-import of the same
// question is recognised and the id never depends on import order.
func caseID(tenant string, c iristriage.Candidate) string {
	norm := strings.Join(strings.Fields(strings.ToLower(c.Question)), " ")
	sum := sha256.Sum256([]byte("correlix.fieldeval.v1\x00" + tenant + "\x00" + norm + "\x00" + c.Source + "\x00" + c.Kind))
	return "field-" + hex.EncodeToString(sum[:8])
}

// Import files one reviewed candidates export for tenant. A question already in
// the tenant's store is skipped. It returns the written file ("" when every
// candidate was already known) and how many cases it holds.
func (s *Store) Import(tenant string, export iristriage.CandidateFile, now time.Time) (string, int, error) {
	if !tenantRe.MatchString(tenant) {
		return "", 0, fmt.Errorf("fieldeval: %q is not a tenant id", tenant)
	}
	if len(export.Candidates) > maxCasesPerImport {
		return "", 0, fmt.Errorf("fieldeval: %d candidates is more than one import takes (%d)", len(export.Candidates), maxCasesPerImport)
	}
	known, err := s.tenantIDs(tenant)
	if err != nil {
		return "", 0, err
	}
	out := File{SchemaVersion: SchemaVersion, Tenant: tenant, ImportedAt: now.UTC().Format(time.RFC3339), Notice: Notice}
	for _, c := range export.Candidates {
		q := strings.TrimSpace(c.Question)
		if q == "" {
			continue
		}
		id := caseID(tenant, c)
		if known[id] {
			continue
		}
		known[id] = true
		out.Cases = append(out.Cases, Case{ID: id, Question: q, Source: c.Source, CorrectionKind: c.Kind,
			ObservedRoute: c.Route, Class: c.Class, Pooled: c.Pooled,
			Split: string(evalsplit.Assign(Corpus, id, evalsplit.SourceField))})
	}
	if len(out.Cases) == 0 {
		return "", 0, nil
	}
	dir := filepath.Join(s.root, tenant)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", 0, fmt.Errorf("fieldeval: %w", err)
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", 0, fmt.Errorf("fieldeval: %w", err)
	}
	path := filepath.Join(dir, "field-"+now.UTC().Format("20060102-150405")+".json")
	if _, err := os.Stat(path); err == nil {
		return "", 0, fmt.Errorf("fieldeval: %s already exists; import again in a second", path)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return "", 0, fmt.Errorf("fieldeval: %w", err)
	}
	return path, len(out.Cases), nil
}

// tenantIDs returns the ids already stored for tenant.
func (s *Store) tenantIDs(tenant string) (map[string]bool, error) {
	ids := map[string]bool{}
	files, err := s.tenantFiles(tenant)
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		for _, c := range f.Cases {
			ids[c.ID] = true
		}
	}
	return ids, nil
}

func (s *Store) tenantFiles(tenant string) ([]File, error) {
	paths, err := filepath.Glob(filepath.Join(s.root, tenant, "field-*.json"))
	if err != nil {
		return nil, fmt.Errorf("fieldeval: %w", err)
	}
	sort.Strings(paths)
	var out []File
	for _, p := range paths {
		raw, err := os.ReadFile(p) // #nosec G304 -- a file under the operator-chosen store root
		if err != nil {
			return nil, fmt.Errorf("fieldeval: %w", err)
		}
		var f File
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("fieldeval: %s: %w", p, err)
		}
		if f.Tenant != tenant {
			return nil, fmt.Errorf("fieldeval: %s says tenant %q but sits under %q", p, f.Tenant, tenant)
		}
		out = append(out, f)
	}
	return out, nil
}

// Tenant is one tenant's cases.
type Tenant struct {
	ID    string
	Cases []Case
}

// Load returns every tenant's cases, tenants in id order. A missing root is an
// empty store.
func (s *Store) Load() ([]Tenant, error) {
	entries, err := os.ReadDir(s.root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("fieldeval: %w", err)
	}
	var out []Tenant
	for _, e := range entries {
		if !e.IsDir() || !tenantRe.MatchString(e.Name()) {
			continue
		}
		files, err := s.tenantFiles(e.Name())
		if err != nil {
			return nil, err
		}
		t := Tenant{ID: e.Name()}
		for _, f := range files {
			t.Cases = append(t.Cases, f.Cases...)
		}
		out = append(out, t)
	}
	return out, nil
}

// Labelled returns the cases a reviewer has labelled, the ones an eval scores.
func Labelled(cases []Case) []Case {
	var out []Case
	for _, c := range cases {
		if strings.TrimSpace(c.ExpectedRoute) != "" {
			out = append(out, c)
		}
	}
	return out
}

// Count is one tenant's totals, as field-list prints them (no question text).
type Count struct {
	Tenant   string `json:"tenant"`
	Cases    int    `json:"cases"`
	Labelled int    `json:"labelled"`
	Pooled   int    `json:"pooled"`
}

// Counts summarises the store without any question text.
func (s *Store) Counts() ([]Count, error) {
	ts, err := s.Load()
	if err != nil {
		return nil, err
	}
	out := make([]Count, 0, len(ts))
	for _, t := range ts {
		c := Count{Tenant: t.ID, Cases: len(t.Cases), Labelled: len(Labelled(t.Cases))}
		for _, x := range t.Cases {
			if x.Pooled {
				c.Pooled++
			}
		}
		out = append(out, c)
	}
	return out, nil
}
