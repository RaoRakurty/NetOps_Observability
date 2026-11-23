// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package corsallow

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultKey is where the saved list lives in the platform key-value store.
const DefaultKey = "/data/cors_allowed_origins.json"

// Store is the persistence seam: one blob. A missing blob is fs.ErrNotExist
// (the platformdb Backend contract).
type Store interface {
	Load() ([]byte, error)
	Save([]byte) error
}

// KVStore adapts a key-value backend (platformdb.Load / platformdb.Save).
type KVStore struct {
	Key    string
	LoadFn func(string) ([]byte, error)
	SaveFn func(string, []byte) error
}

func (k KVStore) Load() ([]byte, error) { return k.LoadFn(k.Key) }
func (k KVStore) Save(b []byte) error   { return k.SaveFn(k.Key, b) }

// Source says where the list in force comes from.
type Source string

const (
	SourceSaved Source = "saved" // the platform administrator's saved list
	SourceEnv   Source = "env"   // the install value (CORS_ALLOWED_ORIGINS)
	SourceNone  Source = "none"  // neither: no cross-origin caller is allowed
)

// record is the saved blob. Inherit = the administrator reset to the install
// value; it is a record (not a deletion) because the KV seam has no delete and
// because "reset by whom, when" belongs in it.
type record struct {
	Version   int       `json:"v"`
	Origins   []string  `json:"origins"`
	Inherit   bool      `json:"inherit,omitempty"`
	UpdatedBy string    `json:"updated_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// View is what the settings page shows.
type View struct {
	Origins    []string  `json:"origins"`     // the list in force
	Source     Source    `json:"source"`      // where it comes from
	EnvOrigins []string  `json:"env_origins"` // the install value, for "reset"
	EnvDropped []string  `json:"env_dropped"` // install entries refused, with why
	UpdatedBy  string    `json:"updated_by,omitempty"`
	UpdatedAt  time.Time `json:"updated_at,omitempty"`
	MaxOrigins int       `json:"max_origins"`
}

// state is one immutable snapshot; the request path reads it lock-free.
type state struct {
	set  map[string]bool
	view View
}

// Allowlist holds the list in force. Allowed is safe for concurrent use and
// never blocks on a writer; Set/Reset serialize among themselves.
type Allowlist struct {
	store      Store
	envOrigins []string
	envDropped []string
	mu         sync.Mutex // serializes writers
	cur        atomic.Pointer[state]
}

// New builds the allowlist from the install value. Until Load succeeds, the
// install value is in force — the same list the stack used before this setting
// existed, so a store outage at boot never widens or narrows access silently.
func New(store Store, envRaw string) *Allowlist {
	a := &Allowlist{store: store}
	a.envOrigins, a.envDropped = ParseEnv(envRaw)
	a.publish(record{Inherit: true})
	return a
}

// EnvDropped lists the install entries that were refused (for a loud boot log).
func (a *Allowlist) EnvDropped() []string { return append([]string(nil), a.envDropped...) }

// Load reads the saved list. No saved list = the install value. An unreadable
// or corrupt record is an error and leaves the install value in force.
func (a *Allowlist) Load() error {
	b, err := a.store.Load()
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read the saved cross-origin allowlist: %w", err)
	}
	var rec record
	if err := json.Unmarshal(b, &rec); err != nil {
		return fmt.Errorf("the saved cross-origin allowlist is not valid JSON: %w", err)
	}
	if !rec.Inherit {
		// Re-validate on read: never trust stored data (CLAUDE.md §3). A record
		// written by an older build or by hand is refused whole, not half-used.
		clean, err := ValidateList(rec.Origins)
		if err != nil {
			return fmt.Errorf("the saved cross-origin allowlist was refused: %w", err)
		}
		rec.Origins = clean
	}
	a.publish(rec)
	return nil
}

// Allowed reports whether a browser Origin header value is on the list in force.
func (a *Allowlist) Allowed(origin string) bool {
	if a == nil || origin == "" {
		return false
	}
	st := a.cur.Load()
	if st == nil || len(st.set) == 0 {
		return false
	}
	o, err := Normalize(origin)
	if err != nil {
		return false
	}
	return st.set[o]
}

// View returns the current settings.
func (a *Allowlist) View() View {
	v := a.cur.Load().view
	v.Origins = append([]string{}, v.Origins...)
	v.EnvOrigins = append([]string{}, v.EnvOrigins...)
	v.EnvDropped = append([]string{}, v.EnvDropped...)
	return v
}

// Set validates and saves a new list (empty = no cross-origin caller), then puts
// it in force. It returns the list before and after. Nothing changes if the
// list is invalid or the save fails.
func (a *Allowlist) Set(origins []string, by string, now time.Time) (before, after []string, err error) {
	clean, err := ValidateList(origins)
	if err != nil {
		return nil, nil, err
	}
	return a.write(record{Version: 1, Origins: clean, UpdatedBy: by, UpdatedAt: now.UTC()})
}

// Reset returns to the install value (CORS_ALLOWED_ORIGINS).
func (a *Allowlist) Reset(by string, now time.Time) (before, after []string, err error) {
	return a.write(record{Version: 1, Inherit: true, UpdatedBy: by, UpdatedAt: now.UTC()})
}

func (a *Allowlist) write(rec record) (before, after []string, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	before = a.View().Origins
	b, err := json.Marshal(rec)
	if err != nil {
		return nil, nil, fmt.Errorf("encode the cross-origin allowlist: %w", err)
	}
	if err := a.store.Save(b); err != nil {
		return nil, nil, fmt.Errorf("save the cross-origin allowlist: %w", err)
	}
	a.publish(rec)
	return before, a.View().Origins, nil
}

// publish builds and swaps in the snapshot for rec.
func (a *Allowlist) publish(rec record) {
	v := View{
		EnvOrigins: append([]string{}, a.envOrigins...),
		EnvDropped: append([]string{}, a.envDropped...),
		UpdatedBy:  rec.UpdatedBy,
		UpdatedAt:  rec.UpdatedAt,
		MaxOrigins: MaxOrigins,
	}
	switch {
	case !rec.Inherit:
		v.Origins, v.Source = append([]string{}, rec.Origins...), SourceSaved
	case len(a.envOrigins) > 0:
		v.Origins, v.Source = append([]string{}, a.envOrigins...), SourceEnv
	default:
		v.Origins, v.Source = []string{}, SourceNone
	}
	set := make(map[string]bool, len(v.Origins))
	for _, o := range v.Origins {
		set[o] = true
	}
	a.cur.Store(&state{set: set, view: v})
}
