// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package featureflags is the registry behind the platform-admin Features page
// (tracker 348, owner 2026-10-05: every feature switchable from the GUI;
// customers never edit .env; env = install defaults only).
//
// PRECEDENCE: a value saved from the console > the install value (the env the
// installer / compose / Helm set) > the code default.
//
// HONESTY: a flag is one of two apply classes.
//
//   - Live — every reader reads it per request or per poll, so a saved value
//     is in force immediately.
//   - Restart — something reads it once at start (a worker, a collector, a
//     bound port). A saved value is DESIRED until the api restarts; the page
//     shows "after restart" and the running value, never a value that is not
//     actually running.
//
// MECHANISM: the readers across the codebase read the process environment.
// At boot, Load applies every saved value to the environment BEFORE any
// reader runs, so the boot snapshot is exactly what runs. At runtime, Set
// applies a Live flag to the environment immediately (its readers read per
// request); a Restart flag is persisted only. Provenance lives HERE, not in
// the environment: which value the console saved, who saved it and when, and
// what was running at boot.
//
// The environment is injected (Env), as is persistence (Store), so the
// package is testable without a process environment or a database.
package featureflags

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Apply is when a changed value takes effect.
type Apply string

const (
	ApplyLive    Apply = "live"
	ApplyRestart Apply = "restart"
)

// Semantics is how the readers interpret the environment string.
type Semantics int

const (
	// TrueOnly: on only when the value is exactly "true".
	TrueOnly Semantics = iota
	// OnUnlessFalse: on unless the value is exactly "false".
	OnUnlessFalse
)

// Spec is one switchable flag.
type Spec struct {
	Env   string // the environment variable every reader reads
	Label string // one plain line for the page
	Group string // page section
	Help  string // one sentence: what turning it on does
	// Semantics also IS the default: an unset TrueOnly flag reads off, an
	// unset OnUnlessFalse flag reads on — exactly what the readers do. There
	// is deliberately no separate Default field that could disagree with them.
	Semantics Semantics
	Apply     Apply //
	// Risky flags reach into the network or out of the platform (device
	// sessions, config pulls, packet capture, write actions). They need an
	// explicit acknowledgement to turn on, and they are forced OFF when the
	// saved values cannot be read at boot.
	Risky bool
}

// Source names where the running value came from.
type Source string

const (
	SourceConsole Source = "console" // saved from the Features page
	SourceInstall Source = "install" // set by the installer / compose / Helm
	SourceDefault Source = "default" // nobody set it
)

// State is one flag as the page shows it.
type State struct {
	Spec
	// Running is the value in force in this process now.
	Running bool
	// Desired is the value that will run after a restart (== Running for Live
	// flags and for Restart flags with no pending change).
	Desired        bool
	RestartPending bool
	Source         Source
	InstallValue   *bool // what the install set, nil when it set nothing
	UpdatedBy      string
	UpdatedAt      time.Time
}

// Env is the process environment, injected.
type Env interface {
	Lookup(key string) (string, bool)
	Set(key, value string) error
}

// OSEnv is the real process environment.
type OSEnv struct{}

func (OSEnv) Lookup(k string) (string, bool) { return os.LookupEnv(k) }
func (OSEnv) Set(k, v string) error          { return os.Setenv(k, v) }

// Store persists the saved values. Load returns os.ErrNotExist (wrapped or
// not) when nothing was ever saved.
type Store interface {
	Load() ([]byte, error)
	Save([]byte) error
}

// record is one saved value.
type record struct {
	Value     bool      `json:"value"`
	UpdatedBy string    `json:"updated_by"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Errors the handler maps to HTTP statuses.
var (
	ErrUnknownFlag  = errors.New("featureflags: no such switchable feature")
	ErrAckRequired  = errors.New("featureflags: turning this feature on needs an explicit acknowledgement")
	ErrStoreFailure = errors.New("featureflags: the saved feature settings could not be written")
)

// Registry is the set of switchable flags and their state.
type Registry struct {
	specs []Spec
	by    map[string]int
	env   Env
	store Store

	mu       sync.RWMutex
	saved    map[string]record
	boot     map[string]bool  // running value at boot (after Load)
	install  map[string]*bool // what the environment said before Load applied anything
	loadErr  error
	loadedAt time.Time
}

// New builds a registry. Specs with a duplicate or empty Env panic: that is a
// programming error in the spec table, caught by the unit test.
func New(specs []Spec, env Env, store Store) *Registry {
	r := &Registry{specs: append([]Spec(nil), specs...), by: map[string]int{}, env: env, store: store,
		saved: map[string]record{}, boot: map[string]bool{}, install: map[string]*bool{}}
	for i, s := range r.specs {
		if s.Env == "" {
			panic("featureflags: empty Env in spec table")
		}
		if _, dup := r.by[s.Env]; dup {
			panic("featureflags: duplicate Env in spec table: " + s.Env)
		}
		r.by[s.Env] = i
	}
	return r
}

func parse(s Spec, v string, set bool) bool {
	if !set {
		return s.Semantics == OnUnlessFalse
	}
	switch s.Semantics {
	case OnUnlessFalse:
		return strings.TrimSpace(v) != "false"
	default:
		return strings.TrimSpace(v) == "true"
	}
}

func render(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// Load reads the saved values and applies them to the environment. It must
// run before any reader of these flags. THREE outcomes: nothing saved (the
// install values stand), saved values applied, or the store failed — then the
// install values stand EXCEPT risky flags, which are forced off, and the error
// is returned so the caller reports it loudly. Load never stops the boot: no
// saved switch may prevent the api from starting, or the page could not undo
// it.
func (r *Registry) Load() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.specs {
		if v, ok := r.env.Lookup(s.Env); ok {
			b := parse(s, v, true)
			r.install[s.Env] = &b
		}
	}
	var saved map[string]record
	b, err := r.store.Load()
	switch {
	case errors.Is(err, os.ErrNotExist):
		err = nil
	case err != nil:
		err = fmt.Errorf("featureflags: read saved settings: %w", err)
	case len(b) == 0:
	default:
		if jerr := json.Unmarshal(b, &saved); jerr != nil {
			err = fmt.Errorf("featureflags: decode saved settings: %w", jerr)
			saved = nil
		}
	}
	r.loadErr = err
	r.loadedAt = time.Now().UTC()
	for _, s := range r.specs {
		if rec, ok := saved[s.Env]; ok {
			r.saved[s.Env] = rec
			if serr := r.env.Set(s.Env, render(rec.Value)); serr != nil && err == nil {
				err = fmt.Errorf("featureflags: apply %s: %w", s.Env, serr)
			}
		} else if r.loadErr != nil && s.Risky {
			// Fail closed for what reaches into the network: an unreadable
			// store must not leave a switch on that the operator turned off.
			_ = r.env.Set(s.Env, "false") // #nosec G104 -- best effort; reported through loadErr
		}
		v, ok := r.env.Lookup(s.Env)
		r.boot[s.Env] = parse(s, v, ok)
	}
	return err
}

// LoadError is the boot-time store failure, nil when the saved values loaded.
func (r *Registry) LoadError() error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.loadErr
}

func (r *Registry) stateLocked(s Spec) State {
	v, ok := r.env.Lookup(s.Env)
	running := parse(s, v, ok)
	if s.Apply == ApplyRestart {
		running = r.boot[s.Env]
	}
	st := State{Spec: s, Running: running, Desired: running, Source: SourceDefault, InstallValue: r.install[s.Env]}
	if st.InstallValue != nil {
		st.Source = SourceInstall
	}
	if rec, ok := r.saved[s.Env]; ok {
		st.Source, st.UpdatedBy, st.UpdatedAt, st.Desired = SourceConsole, rec.UpdatedBy, rec.UpdatedAt, rec.Value
	}
	st.RestartPending = s.Apply == ApplyRestart && st.Desired != st.Running
	return st
}

// List returns every flag, in spec order.
func (r *Registry) List() []State {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]State, 0, len(r.specs))
	for _, s := range r.specs {
		out = append(out, r.stateLocked(s))
	}
	return out
}

// Get returns one flag.
func (r *Registry) Get(env string) (State, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	i, ok := r.by[env]
	if !ok {
		return State{}, false
	}
	return r.stateLocked(r.specs[i]), true
}

// Enabled is the running value — what a reader that goes through the
// registry should use.
func (r *Registry) Enabled(env string) bool {
	st, ok := r.Get(env)
	return ok && st.Running
}

// Set saves a value. ack must equal env to turn a risky flag on. On success a
// Live flag is in force immediately; a Restart flag is desired until restart.
// The previous state is returned for the audit trail.
func (r *Registry) Set(env string, value bool, ack, by string, now time.Time) (before, after State, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	i, ok := r.by[env]
	if !ok {
		return State{}, State{}, ErrUnknownFlag
	}
	s := r.specs[i]
	before = r.stateLocked(s)
	if s.Risky && value && ack != s.Env {
		return before, before, ErrAckRequired
	}
	next := make(map[string]record, len(r.saved)+1)
	for k, v := range r.saved {
		next[k] = v
	}
	next[env] = record{Value: value, UpdatedBy: by, UpdatedAt: now.UTC()}
	b, jerr := json.MarshalIndent(next, "", "  ") // map keys marshal sorted: a stable file
	if jerr != nil {
		return before, before, fmt.Errorf("%w: %w", ErrStoreFailure, jerr)
	}
	if serr := r.store.Save(b); serr != nil {
		return before, before, fmt.Errorf("%w: %w", ErrStoreFailure, serr)
	}
	r.saved = next
	if s.Apply == ApplyLive {
		if serr := r.env.Set(env, render(value)); serr != nil {
			return before, r.stateLocked(s), fmt.Errorf("featureflags: apply %s: %w", env, serr)
		}
	}
	return before, r.stateLocked(s), nil
}
