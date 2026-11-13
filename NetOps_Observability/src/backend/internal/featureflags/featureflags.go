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
	// ConsoleOnly flags take their value from the Features page ALONE (owner
	// 2026-11-12: "it shouldn't be env settings, gui on/off"). The process
	// environment is neither read nor written for them, so no .env line can
	// turn one on: unset reads off, and the only ways to a value are the page
	// and the one-shot upgrade Seed. Must be Live and TrueOnly (New panics
	// otherwise); readers ask Registry.Enabled, never the environment.
	ConsoleOnly bool
	// Requires names a licence capability the flag cannot run without (for
	// example "iris_model"). While the requirement is unmet the flag reads
	// OFF whatever was saved, and turning it on is refused (ErrNotLicensed).
	// The check is injected (SetRequirements) so this package never imports
	// the licence code; until it is injected a Requires flag reads off.
	Requires string
}

// Requirement answers whether a named licence capability is in force, with
// the operator-facing reason when it is not.
type Requirement func(name string) (ok bool, why string)

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
	// Available is false when the flag's licence requirement is unmet; then
	// Running is false and Unavailable says why.
	Available   bool
	Unavailable string
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
	ErrNotLicensed  = errors.New("featureflags: this feature is not included in the installed license")
	// ErrStoreUnread refuses a Seed while the saved settings could not be read:
	// writing then would overwrite whatever the operator saved.
	ErrStoreUnread = errors.New("featureflags: the saved feature settings were not readable at start")
)

// Registry is the set of switchable flags and their state.
type Registry struct {
	specs []Spec
	by    map[string]int
	env   Env
	store Store

	mu       sync.RWMutex
	require  Requirement
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
		if s.ConsoleOnly && (s.Apply != ApplyLive || s.Semantics != TrueOnly) {
			panic("featureflags: a console-only flag must be Live and TrueOnly: " + s.Env)
		}
		if s.Requires != "" && !s.ConsoleOnly {
			// A requirement is enforced by Enabled; an environment-read flag has
			// readers that would never see it.
			panic("featureflags: a licence requirement needs a console-only flag: " + s.Env)
		}
		r.by[s.Env] = i
	}
	return r
}

// SetRequirements injects the licence check for Requires flags. Until it is
// called every Requires flag reads off (fail closed).
func (r *Registry) SetRequirements(fn Requirement) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.require = fn
}

// requirementLocked reports whether s's licence requirement is met.
func (r *Registry) requirementLocked(s Spec) (bool, string) {
	if s.Requires == "" {
		return true, ""
	}
	if r.require == nil {
		return false, "the license check is not available yet"
	}
	return r.require(s.Requires)
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
		if s.ConsoleOnly {
			continue // the environment has no say: no install value exists
		}
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
		if s.ConsoleOnly {
			// Kept in the registry only; the environment is never written, so
			// nothing outside Enabled can read it as on. An unreadable store
			// leaves it off (no record), which is the fail-closed answer.
			if rec, ok := saved[s.Env]; ok {
				r.saved[s.Env] = rec
			}
			continue
		}
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
	var running bool
	switch {
	case s.ConsoleOnly:
		running = r.saved[s.Env].Value // no record reads off
	case s.Apply == ApplyRestart:
		running = r.boot[s.Env]
	default:
		v, ok := r.env.Lookup(s.Env)
		running = parse(s, v, ok)
	}
	st := State{Spec: s, Running: running, Desired: running, Source: SourceDefault, InstallValue: r.install[s.Env], Available: true}
	if st.InstallValue != nil {
		st.Source = SourceInstall
	}
	if rec, ok := r.saved[s.Env]; ok {
		st.Source, st.UpdatedBy, st.UpdatedAt, st.Desired = SourceConsole, rec.UpdatedBy, rec.UpdatedAt, rec.Value
	}
	st.RestartPending = s.Apply == ApplyRestart && st.Desired != st.Running
	if ok, why := r.requirementLocked(s); !ok {
		// The saved choice is kept (Desired) and comes back when the licence
		// does; what runs is off.
		st.Available, st.Unavailable, st.Running = false, why, false
	}
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
	if r == nil {
		return State{}, false // no registry wired: every flag reads off
	}
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
	if value && !before.Available {
		return before, before, ErrNotLicensed
	}
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
	if s.Apply == ApplyLive && !s.ConsoleOnly {
		if serr := r.env.Set(env, render(value)); serr != nil {
			return before, r.stateLocked(s), fmt.Errorf("featureflags: apply %s: %w", env, serr)
		}
	}
	return before, r.stateLocked(s), nil
}

// Seed records a first value for a flag that has NEVER been saved: the
// one-shot upgrade step that keeps an install's existing behaviour when a
// capability moves behind a console-only switch (owner 2026-11-13: an install
// already using an AI model starts with the switch on; every other install
// starts off). It is idempotent by construction — once any value is saved,
// from the page or from an earlier Seed, Seed changes nothing and returns
// false — and it refuses while the saved settings were unreadable at start
// (ErrStoreUnread), because writing then would overwrite them.
//
// It bypasses the acknowledgement on purpose: it only ever preserves what the
// install was already doing. The caller audits a seeded change. A value of
// true is still refused when the licence requirement is unmet.
func (r *Registry) Seed(env string, value bool, by string, now time.Time) (seeded bool, err error) {
	if r == nil {
		return false, ErrUnknownFlag
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	i, ok := r.by[env]
	if !ok {
		return false, ErrUnknownFlag
	}
	if r.loadErr != nil {
		return false, ErrStoreUnread
	}
	if _, saved := r.saved[env]; saved {
		return false, nil
	}
	s := r.specs[i]
	if value {
		if met, _ := r.requirementLocked(s); !met {
			value = false // record the decision as off rather than leave it to re-run
		}
	}
	next := make(map[string]record, len(r.saved)+1)
	for k, v := range r.saved {
		next[k] = v
	}
	next[env] = record{Value: value, UpdatedBy: by, UpdatedAt: now.UTC()}
	b, jerr := json.MarshalIndent(next, "", "  ")
	if jerr != nil {
		return false, fmt.Errorf("%w: %w", ErrStoreFailure, jerr)
	}
	if serr := r.store.Save(b); serr != nil {
		return false, fmt.Errorf("%w: %w", ErrStoreFailure, serr)
	}
	r.saved = next
	if s.Apply == ApplyLive && !s.ConsoleOnly {
		if serr := r.env.Set(env, render(value)); serr != nil {
			return true, fmt.Errorf("featureflags: apply %s: %w", env, serr)
		}
	}
	return true, nil
}
