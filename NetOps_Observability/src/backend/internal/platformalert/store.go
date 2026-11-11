// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package platformalert

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sync"
	"sync/atomic"
	"time"
)

// store.go — the one platform-global record, cached as the LAST GOOD copy.
//
// WHY A CACHE AND NOT A READ PER PUSH. The route exists to report failures of
// the stack it runs in, and the store (Postgres, a data volume) is one of the
// things that fails. A push must therefore never wait on, or be silenced by, a
// store read: the router reads memory. The store is re-read on every save and
// periodically (RefreshLoop), so a change made on another api replica arrives
// within one interval; a read that FAILS keeps the last good copy in force and
// is LOUD — a log line, a gauge, a failure counter and a banner on the admin
// page — because "the destinations could not be re-read" is exactly the kind of
// degradation §10 forbids hiding.

// Vault AAD field ids. Stable strings: changing one makes the stored
// ciphertext for that field undecryptable (the AAD no longer matches).
const (
	FieldNtfyToken    = "platform_alert.ntfy.token"     // #nosec G101 -- vault AAD field id (a config key name), not a credential
	FieldSMSAuthToken = "platform_alert.sms.auth_token" // #nosec G101 -- vault AAD field id (a config key name), not a credential
)

// DefaultKey is the platform-kv key of the record (a file path on the file
// backend, a row key in app_kv on the Postgres backend).
const DefaultKey = "/data/platform_alert_route.json"

// Xform is the vault seal/open transform for a platform-scoped secret field
// (the integrator binds the platform DEK; a dormant vault passes through).
type Xform func(fieldID, value string) (string, error)

// LogFunc is the injected structured logger (§10). level: info|warn|error.
type LogFunc func(level, msg string, fields map[string]any)

// StoreDeps are the store's injected collaborators (§5). Load/Save are
// required; the rest default to safe no-ops.
type StoreDeps struct {
	Key  string
	Load func(key string) ([]byte, error)
	Save func(key string, data []byte) error
	Seal Xform
	Open Xform
	Log  LogFunc
	Now  func() time.Time

	// CachePath is the ON-HOST last-good copy of the record, exactly as it is
	// stored: SEALED (the secrets stay ciphertext under the platform DEK), a
	// 0600 file written atomically under the data volume. It is rewritten on
	// every successful read or save whose bytes differ, and it is consulted
	// ONLY when the store cannot be read and nothing has been read since boot
	// (review 2026-11-11: an api that boots while Postgres flaps or the record
	// will not open would otherwise count every page as not_configured while
	// every layer reads green — the 2026-09-02 shape). When the store reads
	// fine, the cache is never used; it is overwritten.
	//
	// THE ONE REMAINING DEPENDENCY is the vault: opening the cached secrets
	// needs the platform DEK. A vault/swtpm failure at boot therefore still
	// leaves the route unconfigured — loudly (store_ever_read 0, the
	// PlatformAlertsReachNobody page rule) — and the external watchdog
	// (scripts/stack-watchdog.sh, its own ntfy topic) is the layer that covers
	// it. With a dormant vault the file holds the secrets in clear, exactly
	// like the file-backend record itself; hence 0600.
	//
	// Empty CachePath disables the cache (tests, embedders).
	CachePath  string
	ReadCache  func(path string) ([]byte, error)
	WriteCache func(path string, data []byte) error
}

// ErrStoreUnreadable refuses a save that would overwrite a record this process
// has NEVER been able to read, unless the administrator explicitly asks to
// replace it: the record holds sealed, write-only credentials, and a save from
// an empty in-memory copy would destroy them without anyone deciding to.
var ErrStoreUnreadable = errors.New("The saved platform alert settings could not be read, so they cannot be changed safely. Correlix keeps retrying every minute. To replace them with what you enter now, tick 'Replace the saved settings' and save again.")

// Store holds the record.
type Store struct {
	d StoreDeps

	// saveMu serializes writers (Update/Save); mu guards the in-memory copy.
	saveMu sync.Mutex
	mu     sync.RWMutex
	cfg    Config // decrypted, normalized; the LAST GOOD copy
	// everRead is true once the stored record has been read successfully (or
	// was confirmed absent) since boot.
	everRead bool
	// readErr is the most recent refresh failure; nil when the last read
	// succeeded.
	readErr error
	// version increments on every change of cfg, so the Router rebuilds its
	// senders only when something changed.
	version atomic.Uint64

	readFailures atomic.Uint64
	saveFailures atomic.Uint64

	// fromCache is true while the record in force came from the on-host cache
	// (the store has not been read since boot). cacheMu guards cachedBytes
	// (what the cache file holds, so an unchanged record is not rewritten every
	// minute) and cacheErr (the last cache write failure).
	fromCache     bool
	cacheMu       sync.Mutex
	cachedBytes   []byte
	cacheErr      error
	cacheFailures atomic.Uint64
}

// NewStore builds the store and performs the first read. A failed first read
// is not fatal (the route reports itself unconfigured, loudly); it is retried
// by RefreshLoop.
func NewStore(d StoreDeps) *Store {
	if d.Key == "" {
		d.Key = DefaultKey
	}
	if d.Seal == nil {
		d.Seal = passthrough
	}
	if d.Open == nil {
		d.Open = passthrough
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	s := &Store{d: d, cfg: DefaultConfig()}
	s.version.Store(1)
	if s.cacheOn() {
		// What the cache file holds now, so an unchanged record is not
		// rewritten at every boot. An unreadable cache is simply "unknown": the
		// next good read rewrites it.
		if b, err := d.ReadCache(d.CachePath); err == nil {
			s.cachedBytes = b
		}
	}
	if err := s.Refresh(); err != nil {
		s.loadCache()
	}
	return s
}

func (s *Store) cacheOn() bool {
	return s.d.CachePath != "" && s.d.ReadCache != nil && s.d.WriteCache != nil
}

// loadCache installs the on-host last-good copy when NOTHING has been read
// since boot. The store's own read error stays recorded (the store is still
// unreadable and every gauge says so); what changes is that pages reach the
// channels an administrator last configured instead of nobody.
func (s *Store) loadCache() {
	if !s.cacheOn() {
		return
	}
	if _, everRead := s.Health(); everRead {
		return
	}
	b, err := s.d.ReadCache(s.d.CachePath)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		s.log("error", "the on-host copy of the platform alert settings could not be read either; platform alerts reach NOBODY until the store is readable",
			map[string]any{"error": err.Error()})
		return
	}
	var stored Config
	if err := json.Unmarshal(b, &stored); err != nil {
		s.log("error", "the on-host copy of the platform alert settings is corrupt; platform alerts reach NOBODY until the store is readable",
			map[string]any{"error": err.Error()})
		return
	}
	open, err := s.openSecrets(stored)
	if err != nil {
		// The vault is the one dependency the cache cannot remove.
		s.log("error", "the on-host copy of the platform alert settings could not be unsealed (vault); platform alerts reach NOBODY until the vault and the store are readable — the external watchdog still pages",
			map[string]any{"error": err.Error()})
		return
	}
	s.mu.Lock()
	if s.everRead { // a concurrent good read won the race: never overrule it
		s.mu.Unlock()
		return
	}
	s.cfg = open.normalize()
	s.everRead = true
	s.fromCache = true
	routed := s.cfg.PageRouted()
	s.mu.Unlock()
	s.version.Add(1)
	s.log("error", "platform alert settings could not be read from the store; using the LAST GOOD copy kept on this host until the store is readable",
		map[string]any{"page_routed": routed, "cache": s.d.CachePath})
}

// writeCache mirrors a good sealed record to the on-host copy. Failure is loud
// (logged on the transition, counted) but never fails the read or the save:
// the store is the authority, the cache only a boot-time fallback.
func (s *Store) writeCache(sealed []byte) {
	if !s.cacheOn() || sealed == nil {
		return
	}
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if string(s.cachedBytes) == string(sealed) {
		return
	}
	if err := s.d.WriteCache(s.d.CachePath, sealed); err != nil {
		s.cacheFailures.Add(1)
		if s.cacheErr == nil {
			s.log("warn", "could not keep the on-host copy of the platform alert settings; if the store is unreadable at the next start, platform alerts will reach nobody",
				map[string]any{"error": err.Error(), "cache": s.d.CachePath})
		}
		s.cacheErr = err
		return
	}
	s.cacheErr = nil
	s.cachedBytes = append([]byte(nil), sealed...)
}

// defaultSealed is what an absent record mirrors to the cache: the shipped
// default (no secrets, nothing enabled), so a cache can never resurrect a
// record that has since been removed from the store.
func defaultSealed() []byte {
	b, err := json.Marshal(DefaultConfig())
	if err != nil {
		return nil
	}
	return b
}

func passthrough(_, v string) (string, error) { return v, nil }

func (s *Store) log(level, msg string, f map[string]any) {
	if s.d.Log != nil {
		s.d.Log(level, msg, f)
	}
}

// Refresh re-reads the record. On failure the last good copy stays in force.
func (s *Store) Refresh() error {
	if s.d.Load == nil {
		return s.recordReadErr(errors.New("platform alert store has no backend"))
	}
	b, err := s.d.Load(s.d.Key)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Absent is a valid state (nothing configured yet), not a failure.
		s.adopt(DefaultConfig())
		s.writeCache(defaultSealed())
		return nil
	case err != nil:
		return s.recordReadErr(fmt.Errorf("read: %w", err))
	case len(b) == 0:
		s.adopt(DefaultConfig())
		s.writeCache(defaultSealed())
		return nil
	}
	var stored Config
	if uerr := json.Unmarshal(b, &stored); uerr != nil {
		return s.recordReadErr(fmt.Errorf("decode: %w", uerr))
	}
	open, oerr := s.openSecrets(stored)
	if oerr != nil {
		return s.recordReadErr(fmt.Errorf("unseal: %w", oerr))
	}
	s.adopt(open.normalize())
	s.writeCache(b)
	return nil
}

// adopt installs a successfully read record.
func (s *Store) adopt(c Config) {
	s.mu.Lock()
	recovered := s.readErr != nil
	changed := !sameConfig(s.cfg, c)
	s.cfg = c
	s.everRead = true
	s.readErr = nil
	s.fromCache = false
	s.mu.Unlock()
	if changed {
		s.version.Add(1)
	}
	if recovered {
		s.log("info", "platform alert settings are readable again", map[string]any{"key_kind": "platform_alert_route"})
	}
}

func (s *Store) recordReadErr(err error) error {
	s.readFailures.Add(1)
	s.mu.Lock()
	first := s.readErr == nil
	s.readErr = err
	kept := s.everRead
	s.mu.Unlock()
	// LOUD on the transition, quiet on the repeat (the gauge and the counter
	// keep counting): a refresh every minute that logs every minute is its own
	// outage.
	if first {
		msg := "platform alert settings could NOT be read; the last good settings stay in force until a read succeeds"
		if !kept {
			msg = "platform alert settings could NOT be read since start-up; falling back to the on-host copy if one is usable — otherwise platform alerts reach NOBODY until a read succeeds or an administrator replaces them"
		}
		s.log("error", msg, map[string]any{"error": err.Error()})
	}
	return err
}

// sameConfig compares two records for the router's rebuild decision.
func sameConfig(a, b Config) bool {
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(ja) == string(jb)
}

func (s *Store) openSecrets(c Config) (Config, error) {
	var err error
	if c.Ntfy.Token, err = s.d.Open(FieldNtfyToken, c.Ntfy.Token); err != nil {
		return c, err
	}
	if c.SMS.AuthToken, err = s.d.Open(FieldSMSAuthToken, c.SMS.AuthToken); err != nil {
		return c, err
	}
	return c, nil
}

func (s *Store) sealSecrets(c Config) (Config, error) {
	var err error
	if c.Ntfy.Token, err = s.d.Seal(FieldNtfyToken, c.Ntfy.Token); err != nil {
		return c, err
	}
	if c.SMS.AuthToken, err = s.d.Seal(FieldSMSAuthToken, c.SMS.AuthToken); err != nil {
		return c, err
	}
	return c, nil
}

// Current is the record in force (a copy; secrets included — callers that
// render it must go through View).
func (s *Store) Current() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := s.cfg
	c.SMS.To = append([]string(nil), s.cfg.SMS.To...)
	return c
}

// Version identifies the record in force; it changes whenever the record does.
func (s *Store) Version() uint64 { return s.version.Load() }

// FromCache reports whether the record in force came from the on-host cache.
func (s *Store) FromCache() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fromCache
}

// Health reports the store's read state: ok, and whether the record in force
// was ever read (false = nothing was ever read since boot).
func (s *Store) Health() (ok bool, everRead bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.readErr == nil, s.everRead
}

// Update is the read-merge-write path the API uses: mutate receives the record
// in force and returns the record to save, all under one lock, so two
// administrators saving at once cannot interleave a merge with the other's
// write and silently drop a field (or a write-only secret).
func (s *Store) Update(replaceUnreadable bool, mutate func(cur Config) (Config, error)) (Config, error) {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	next, err := mutate(s.Current())
	if err != nil {
		return Config{}, err
	}
	if err := s.save(next, replaceUnreadable); err != nil {
		return Config{}, err
	}
	return s.Current(), nil
}

// Save validates, seals and writes the record, then adopts it. The record is
// NOT adopted unless it was written (F-78: a change that would vanish at the
// next restart must not appear to work now). replaceUnreadable is the
// administrator's explicit consent to overwrite a record that was never read.
func (s *Store) Save(next Config, replaceUnreadable bool) error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	return s.save(next, replaceUnreadable)
}

func (s *Store) save(next Config, replaceUnreadable bool) error {
	next = next.normalize()
	if err := next.Validate(); err != nil {
		return err
	}
	if ok, everRead := s.Health(); !ok && !everRead && !replaceUnreadable {
		return ErrStoreUnreadable
	}
	sealed, err := s.sealSecrets(next)
	if err != nil {
		s.saveFailures.Add(1)
		return fmt.Errorf("seal: %w", err)
	}
	b, err := json.Marshal(sealed)
	if err != nil {
		s.saveFailures.Add(1)
		return fmt.Errorf("encode: %w", err)
	}
	if s.d.Save == nil {
		s.saveFailures.Add(1)
		return errors.New("platform alert store has no backend")
	}
	if err := s.d.Save(s.d.Key, b); err != nil {
		s.saveFailures.Add(1)
		return fmt.Errorf("write: %w", err)
	}
	s.adopt(next)
	s.writeCache(b)
	return nil
}

// RefreshLoop re-reads the record every interval until ctx ends. It is how a
// change saved on another api replica (Postgres backend) reaches this one, and
// how a failed read recovers without a restart.
func (s *Store) RefreshLoop(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// Refresh logs on the transition and counts every failure. While
			// nothing has been read since boot, keep trying the on-host copy
			// too (a vault that was locked at boot may have recovered).
			if err := s.Refresh(); err != nil {
				s.loadCache()
			}
		}
	}
}
