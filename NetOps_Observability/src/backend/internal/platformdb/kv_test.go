// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package platformdb

// kv_test.go — D-11. FileKV.Save used a FIXED temp path ("<key>.tmp"), so two
// goroutines saving the SAME key interleaved as
//
//	A: write tmp → B: write tmp → A: rename ok → B: rename → ENOENT
//
// The api logged exactly that ("rename /data/audit.json.tmp /data/audit.json:
// no such file or directory") on essentially every request burst, and the
// losing writer's blob was silently dropped — the audit trail did not survive
// a restart on the file backend. These tests pin the unique-temp-name fix.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestFileKVConcurrentSavesOfTheSameKeyNeverFail(t *testing.T) {
	dir := t.TempDir()
	prev := fileRoot
	SetFileRoot(dir)
	t.Cleanup(func() { fileRoot = prev })

	const writers = 64
	f := FileKV{}
	key := "audit.json"

	// Every writer persists a DIFFERENT, self-describing blob, so the survivor
	// can be identified and checked for completeness (a torn write would not
	// unmarshal, or would carry a mismatched length).
	payloads := make(map[string]bool, writers)
	blobs := make([][]byte, writers)
	for i := 0; i < writers; i++ {
		b, err := json.Marshal(map[string]any{
			"writer": i,
			"pad":    strings.Repeat(fmt.Sprintf("%03d", i), 400), // >1 page: a torn write is detectable
		})
		if err != nil {
			t.Fatalf("marshal payload %d: %v", i, err)
		}
		blobs[i] = b
		payloads[string(b)] = true
	}

	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- f.Save(key, blobs[i])
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent Save of one key must never fail, got: %v — this is "+
				"the fixed-temp-path rename race (D-11)", err)
		}
	}

	got, err := f.Load(key)
	if err != nil {
		t.Fatalf("load after concurrent saves: %v", err)
	}
	if !payloads[string(got)] {
		t.Fatalf("final file is not any complete writer's payload (torn or interleaved write): %d bytes", len(got))
	}
	var decoded map[string]any
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("final file is not valid JSON — a partial write survived: %v", err)
	}

	// No litter: every temp file must be renamed away or removed.
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var stray []string
	for _, e := range ents {
		if e.Name() != key {
			stray = append(stray, e.Name())
		}
	}
	if len(stray) != 0 {
		t.Fatalf("stray temp files left behind: %v", stray)
	}
}

func TestFileKVSaveKeepsFileMode0600AndCreatesParents(t *testing.T) {
	dir := t.TempDir()
	prev := fileRoot
	SetFileRoot(dir)
	t.Cleanup(func() { fileRoot = prev })

	f := FileKV{}
	if err := f.Save("nested/deeper/users.json", []byte(`{"v":1}`)); err != nil {
		t.Fatalf("save into a missing subtree: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dir, "nested", "deeper", "users.json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("data file mode = %v, want 0600 (secrets live in these blobs)", got)
	}
	di, err := os.Stat(filepath.Join(dir, "nested", "deeper"))
	if err != nil {
		t.Fatalf("stat parent: %v", err)
	}
	if got := di.Mode().Perm(); got != 0o755 {
		t.Fatalf("parent dir mode = %v, want 0755", got)
	}
}

// The LoadPrefix skip matches on the ".tmp" SUFFIX; Save's unique names must
// keep it, or an in-flight temporary would be served as a committed record.
func TestFileKVTempNamesStayTmpSuffixedForThePrefixSkip(t *testing.T) {
	dir := t.TempDir()
	prev := fileRoot
	SetFileRoot(dir)
	t.Cleanup(func() { fileRoot = prev })

	f := FileKV{}
	sub := filepath.Join(dir, "devices.json.d", "manual")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := f.Save("devices.json.d/manual/aaa", []byte("v")); err != nil {
		t.Fatalf("save: %v", err)
	}
	// Plant a temporary shaped exactly like one of Save's, mid-flight.
	tmp, err := os.CreateTemp(sub, "aaa.*.tmp")
	if err != nil {
		t.Fatalf("createtemp: %v", err)
	}
	if _, err := tmp.WriteString("half"); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatalf("close temp: %v", err)
	}

	got, err := f.LoadPrefix("devices.json.d/")
	if err != nil {
		t.Fatalf("loadprefix: %v", err)
	}
	if len(got) != 1 || string(got["devices.json.d/manual/aaa"]) != "v" {
		t.Fatalf("an in-flight temporary leaked into the record set: %v", got)
	}
}
