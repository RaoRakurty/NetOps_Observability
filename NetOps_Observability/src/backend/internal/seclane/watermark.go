// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package seclane

// watermark.go — the per-tenant DETECTION HIGH-WATER MARK: the end of the last
// threat window this lane actually assessed.
//
// Why it has to be durable. The detection window used to be
// [now - interval, now], recomputed on every pass, while the real spacing
// between passes is a JITTERED interval PLUS the scan's own duration. Every
// tick therefore left a sliver of time unread, a skipped tick left a whole
// interval unread, and a restart left the entire outage unread — silently, with
// no finding, no UNASSESSED verdict and no log line. The mark is what lets the
// next pass start where the last one stopped, and what lets the lane SAY SO
// (§10) when a gap is too old to catch up on.
//
// It is scan bookkeeping, not evidence: it holds a tenant id and a timestamp,
// never a finding, a device or a log line.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Watermarks persists the per-tenant detection high-water mark.
//
// Load's contract is the important half: an ABSENT store is not a failure and
// returns an empty map with a nil error, but ANY other failure must be
// returned. A store that answered "empty" to an unreadable file would silently
// restart every tenant's window at now and lose the very gap this type exists
// to close.
type Watermarks interface {
	Load() (map[string]time.Time, error)
	Save(tenant string, until time.Time) error
}

// FileWatermarks is the shipped Watermarks: one JSON object on local disk,
// written 0600 through a temp file + rename so a crash mid-write can never
// leave a half-parsed map behind.
type FileWatermarks struct {
	path string

	mu    sync.Mutex
	marks map[string]time.Time
}

// NewFileWatermarks returns the file-backed store at path.
//
// A BLANK path is not quietly tolerated: Load and Save both refuse it. The
// integrator decides whether to persist at all by leaving Deps.Watermarks nil,
// and a store that silently persisted nothing would be indistinguishable from
// one that worked — which is the failure this whole file exists to prevent.
func NewFileWatermarks(path string) *FileWatermarks {
	return &FileWatermarks{path: path, marks: map[string]time.Time{}}
}

// Load reads every stored mark.
func (w *FileWatermarks) Load() (map[string]time.Time, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.path == "" {
		return nil, fmt.Errorf("seclane: no detection watermark path is configured (%s is empty)", EnvWatermarkFile)
	}
	raw, err := os.ReadFile(w.path) // #nosec G304 -- operator-configured state path, never request input
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// The lane has never run on this host. That is an EMPTY store, and
			// the only condition under which starting empty is honest.
			return map[string]time.Time{}, nil
		}
		return nil, fmt.Errorf("seclane: detection watermarks at %s could not be read: %w", w.path, err)
	}
	var stored map[string]string
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, fmt.Errorf("seclane: detection watermarks at %s are not readable JSON: %w", w.path, err)
	}
	out := make(map[string]time.Time, len(stored))
	for tenant, ts := range stored {
		at, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return nil, fmt.Errorf("seclane: detection watermark for one tenant in %s is not a timestamp: %w", w.path, err)
		}
		out[tenant] = at.UTC()
	}
	w.marks = out
	return cloneMarks(out), nil
}

// Save records one tenant's mark durably.
func (w *FileWatermarks) Save(tenant string, until time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.path == "" {
		return fmt.Errorf("seclane: no detection watermark path is configured (%s is empty)", EnvWatermarkFile)
	}
	if w.marks == nil {
		w.marks = map[string]time.Time{}
	}
	w.marks[tenant] = until.UTC()
	stored := make(map[string]string, len(w.marks))
	for id, at := range w.marks {
		stored[id] = at.UTC().Format(time.RFC3339Nano)
	}
	body, err := json.Marshal(stored)
	if err != nil {
		return fmt.Errorf("seclane: detection watermarks could not be encoded: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(w.path), ".watermarks-*")
	if err != nil {
		return fmt.Errorf("seclane: detection watermarks could not be staged: %w", err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }() // no-op once the rename succeeded
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("seclane: detection watermarks could not be secured: %w", err)
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("seclane: detection watermarks could not be written: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("seclane: detection watermarks could not be flushed: %w", err)
	}
	if err := os.Rename(name, w.path); err != nil {
		return fmt.Errorf("seclane: detection watermarks could not be committed: %w", err)
	}
	return nil
}

func cloneMarks(in map[string]time.Time) map[string]time.Time {
	out := make(map[string]time.Time, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
