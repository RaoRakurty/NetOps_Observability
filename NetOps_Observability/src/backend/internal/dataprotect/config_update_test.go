// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package dataprotect

// config_update_test.go — finding 3.8-03: the backup-intent store's durable
// lost update.
//
// The old shape was `Put(Config)`: it took the lock to swap the in-memory copy
// and then wrote the FILE outside it, and every caller did an unsynchronised
// get-then-put. Two concurrent platform-admin writes could therefore leave the
// file holding the LOSING writer's bytes — including the deliberate
// snapshot-schedule STOP that the opensearch-init bootstrap reads back at
// start-up to decide whether to re-enable the nightly snapshot.
//
// These tests assert the OUTCOME (no -race is available on this box): N
// concurrent read-modify-writes must all land, and what is on disk must be what
// is in memory.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestConfigUpdateLosesNoConcurrentWrite — 64 goroutines each increment the
// stored retention through Update. All 64 must land, in memory AND on disk.
func TestConfigUpdateLosesNoConcurrentWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "system_backup.json")
	store, err := NewFileConfigStore(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	zero := 0
	if _, err := store.Update(func(c *Config) error { c.RetainCount = &zero; return nil }); err != nil {
		t.Fatalf("seed: %v", err)
	}

	const writers = 64
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	start := make(chan struct{})
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := store.Update(func(c *Config) error {
				n := 0
				if c.RetainCount != nil {
					n = *c.RetainCount
				}
				n++
				c.RetainCount = &n
				return nil
			})
			if err != nil {
				errs <- err
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent update: %v", err)
	}

	inMemory := store.Get()
	if inMemory.RetainCount == nil || *inMemory.RetainCount != writers {
		t.Fatalf("LOST UPDATE in memory: retain_count=%v, want %d", derefOrNil(inMemory.RetainCount), writers)
	}
	onDisk := readStoredConfig(t, path)
	if onDisk.RetainCount == nil || *onDisk.RetainCount != writers {
		t.Fatalf("LOST UPDATE on disk: retain_count=%v, want %d", derefOrNil(onDisk.RetainCount), writers)
	}
}

// TestConfigUpdateKeepsDiskAndMemoryAgreed — the half that actually costs data:
// whatever the last in-memory state is, THAT is what a restart must read back.
// A concurrent mix of writers touching DIFFERENT fields (the real shape: one
// admin editing the destination, another stopping the snapshot schedule) must
// not leave the file behind memory.
func TestConfigUpdateKeepsDiskAndMemoryAgreed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "system_backup.json")
	store, err := NewFileConfigStore(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	const rounds = 48
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < rounds; i++ {
		wg.Add(2)
		// Writer A edits the off-host destination.
		go func(i int) {
			defer wg.Done()
			<-start
			if _, err := store.Update(func(c *Config) error {
				c.RemoteURL = "/mnt/nas/backups"
				c.UpdatedBy = "alice"
				return nil
			}); err != nil {
				t.Errorf("destination update: %v", err)
			}
		}(i)
		// Writer B records the deliberate snapshot-schedule STOP — the record
		// the bootstrap reads at start-up.
		go func(i int) {
			defer wg.Done()
			<-start
			if _, err := store.Update(func(c *Config) error {
				c.SnapshotScheduleDisabledAt = time.Unix(1788000000, 0).UTC()
				c.SnapshotScheduleDisabledBy = "bob"
				c.SnapshotScheduleDisabledReason = "restoring the repository by hand"
				return nil
			}); err != nil {
				t.Errorf("schedule-stop update: %v", err)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	inMemory := store.Get()
	onDisk := readStoredConfig(t, path)

	// Every field either writer set must be present in BOTH: no update may have
	// been overwritten by another writer's stale copy.
	if inMemory.RemoteURL != "/mnt/nas/backups" || onDisk.RemoteURL != "/mnt/nas/backups" {
		t.Errorf("destination lost: memory=%q disk=%q", inMemory.RemoteURL, onDisk.RemoteURL)
	}
	if inMemory.SnapshotScheduleDisabledBy != "bob" || onDisk.SnapshotScheduleDisabledBy != "bob" {
		t.Errorf("the deliberate snapshot-schedule STOP was lost: memory=%q disk=%q — the bootstrap would re-enable a schedule a human stopped",
			inMemory.SnapshotScheduleDisabledBy, onDisk.SnapshotScheduleDisabledBy)
	}
	if onDisk.SnapshotScheduleDisabledAt.IsZero() {
		t.Error("the stop TIME must be on disk: a restart reads the file, not this process's memory")
	}
	if !onDisk.SnapshotScheduleDisabledAt.Equal(inMemory.SnapshotScheduleDisabledAt) ||
		onDisk.SnapshotScheduleDisabledReason != inMemory.SnapshotScheduleDisabledReason ||
		onDisk.UpdatedBy != inMemory.UpdatedBy {
		t.Fatalf("disk and memory disagree — the file is what survives a restart:\n memory=%+v\n disk=%+v", inMemory, onDisk)
	}
}

// TestConfigUpdateDoesNotAdvanceMemoryWhenTheWriteFails — a write that could
// not be persisted must not leave this process reporting an intent no restart
// would ever see.
func TestConfigUpdateDoesNotAdvanceMemoryWhenTheWriteFails(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileConfigStore(filepath.Join(dir, "system_backup.json"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := store.Update(func(c *Config) error { c.RemoteURL = "/mnt/nas"; return nil }); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Make the directory unwritable so the atomic tmp+rename cannot land.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skipf("cannot make the directory read-only on this filesystem: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if _, err := store.Update(func(c *Config) error { c.RemoteURL = "/mnt/other"; return nil }); err == nil {
		t.Skip("the filesystem allowed the write anyway (running as root?)")
	}
	if got := store.Get().RemoteURL; got != "/mnt/nas" {
		t.Fatalf("memory advanced past a failed write: %q", got)
	}
}

// TestConfigUpdatePropagatesTheCallbackError — a mutation that refuses must
// leave the stored intent untouched, and the error must reach the caller.
func TestConfigUpdatePropagatesTheCallbackError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "system_backup.json")
	store, err := NewFileConfigStore(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := store.Update(func(c *Config) error { c.RemoteURL = "/mnt/nas"; return nil }); err != nil {
		t.Fatalf("seed: %v", err)
	}
	boom := jsonError("refused")
	if _, err := store.Update(func(c *Config) error { c.RemoteURL = "/mnt/other"; return boom }); !errors.Is(err, boom) {
		t.Fatalf("the callback's error must come back unchanged: %v", err)
	}
	if got := store.Get().RemoteURL; got != "/mnt/nas" {
		t.Fatalf("a refused mutation must not be stored: %q", got)
	}
	if got := readStoredConfig(t, path).RemoteURL; got != "/mnt/nas" {
		t.Fatalf("a refused mutation must not reach the file: %q", got)
	}
}

// readStoredConfig reads the intent file the way a restart does.
func readStoredConfig(t *testing.T, path string) Config {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return c
}

func derefOrNil(n *int) any {
	if n == nil {
		return "nil"
	}
	return *n
}
