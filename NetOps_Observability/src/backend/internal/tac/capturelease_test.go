// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// capturelease_test.go — the evidence a bundle is built from cannot be deleted
// out from under it.
//
// A bundle is assembled WITHOUT the service lock (a multi-megabyte zip must not
// serialise every other escalation on this api), while three service paths close
// the capture it is reading: a new collection starting, a finished collection
// recording its result, and eviction at the register's per-tenant bound. If a
// close lands mid-build the streamed output's spill path is blanked and its
// directory removed, and the bundle writer then falls back to the in-memory
// body — which for a streamed command is empty by construction. The vendor gets
// a header-only stub where the tech-support file should be, and SHA256SUMS
// hashes the stub as if it were the evidence.
//
// The two collisions below are driven through a NARRATOR BARRIER rather than a
// sleep, so they land in the same place on every machine and need no race
// detector to be observable. The stress test behind them drives the same two
// paths unsynchronised, many times over.

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// spillMarker is the content a real streamed output carries. Its presence in
// the bundle is what separates the evidence from a stub.
const spillMarker = "SHOW-TECH-SUPPORT-BODY-THAT-MUST-REACH-THE-VENDOR"

// barrierNarrator stops a bundle build in a known place: inside BuildBundle,
// after Bundle released the service lock and before the output files are read.
// It narrates nothing (the deterministic statement is written instead), which is
// the same fallback a provider outage takes.
type barrierNarrator struct {
	entered chan struct{}
	resume  chan struct{}
}

func newBarrierNarrator() *barrierNarrator {
	return &barrierNarrator{entered: make(chan struct{}), resume: make(chan struct{})}
}

func (b *barrierNarrator) Narrate(context.Context, NarrationRequest) (string, error) {
	close(b.entered)
	<-b.resume
	return "", errors.New("this test narrates nothing")
}

// captureWithSpill builds a capture whose one command was STREAMED to a spill
// file, the way a first-ask collection is.
func captureWithSpill(t *testing.T, root string) *Capture {
	t.Helper()
	dir, err := os.MkdirTemp(root, "spill-")
	if err != nil {
		t.Fatalf("spill dir: %v", err)
	}
	body := strings.Repeat(spillMarker+"\n", 2000)
	path := filepath.Join(dir, "000-first.ask.txt")
	if werr := os.WriteFile(path, []byte(body), 0o600); werr != nil {
		t.Fatalf("spill file: %v", werr)
	}
	return &Capture{
		TenantID: "t1", IncidentID: "inc-1", PlanID: "p1",
		Hostname: "edge1", Platform: "cisco_iosxe", Dialect: "cisco-iosxe",
		StartedAt: time.Unix(1700000000, 0).UTC(), FinishedAt: time.Unix(1700000060, 0).UTC(),
		SpillDir: dir,
		Commands: []CollectedCommand{{
			Intent: "support.firstask", Title: "Support collection", Section: SectionFirstAsk,
			Command: "show tech-support", Bytes: len(body), SpillPath: path,
			StartedAt: time.Unix(1700000000, 0).UTC(),
		}},
		Unbound: []Step{}, Topology: []TopologyNote{},
		TotalBytes: int64(len(body)), Redacted: true,
		CatalogVersion: "test", EngineVersion: Version,
	}
}

// onePlan is the cheapest plan a collection can be started from.
func onePlan() *Plan {
	return &Plan{
		TenantID: "t1", IncidentID: "inc-1", ClassID: "ospf-adjacency",
		DeviceID: "dev-1", Hostname: "edge1", Platform: "cisco_iosxe", Dialect: "cisco-iosxe",
		Steps: []Step{{Intent: "version", Title: "Version", Section: SectionBaseline,
			Command: "show version", TimeoutSeconds: 1, MaxBytes: 4096}},
	}
}

// registerCapture puts one collected escalation into the register, the way a
// finished collection does.
func registerCapture(s *Service, capt *Capture, plan *Plan) map[string]*State {
	byInc := map[string]*State{"inc-1": {
		TenantID: "t1", IncidentID: "inc-1", Plan: plan,
		Capture: capt, Bundles: []StoredBundle{},
	}}
	s.mu.Lock()
	s.states["t1"] = byInc
	s.mu.Unlock()
	return byInc
}

// firstAskOutput is the bundle entry the streamed command writes.
const firstAskOutput = "outputs/01-support-firstask.txt"

// bundleOutput returns the named output file's text from a built bundle.
func bundleOutput(t *testing.T, b *Bundle, name string) string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b.Zip), int64(len(b.Zip)))
	if err != nil {
		t.Fatalf("bundle is not a zip: %v", err)
	}
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, oerr := f.Open()
		if oerr != nil {
			t.Fatalf("open %s: %v", name, oerr)
		}
		defer rc.Close()
		body, rerr := io.ReadAll(rc)
		if rerr != nil {
			t.Fatalf("read %s: %v", name, rerr)
		}
		return string(body)
	}
	t.Fatalf("the bundle carries no %s", name)
	return ""
}

// assertEvidenceOrRefusal is the whole rule: the bundle carries the streamed
// body, or the build failed and said so. A header-only stub is the one outcome
// that is not allowed, because nothing downstream can tell it from evidence.
func assertEvidenceOrRefusal(t *testing.T, b *Bundle, err error, where string) {
	t.Helper()
	if err != nil {
		return
	}
	body := bundleOutput(t, b, firstAskOutput)
	if !strings.Contains(body, spillMarker) {
		t.Fatalf("%s: the bundle shipped a stub where the streamed evidence should be:\n%s", where, body)
	}
}

// TestBundleKeepsItsEvidenceWhileACollectionRestarts — StartCollect closes the
// capture a bundle is already streaming from.
func TestBundleKeepsItsEvidenceWhileACollectionRestarts(t *testing.T) {
	f := newFake()
	f.out["show version"] = "IOS-XE 17.9"
	bar := newBarrierNarrator()
	s := testService(t, WithCollector(testCollector(t, f)), WithNarrator(bar))
	registerCapture(s, captureWithSpill(t, t.TempDir()), onePlan())

	var b *Bundle
	var berr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		b, _, berr = s.Bundle(context.Background(), "t1", "inc-1", BundleInput{Actor: "op"})
	}()

	<-bar.entered
	if _, err := s.StartCollect("t1", "inc-1", nil); err != nil {
		t.Fatalf("start collect: %v", err)
	}
	close(bar.resume)
	<-done

	assertEvidenceOrRefusal(t, b, berr, "a collection restarted mid-bundle")
}

// TestBundleKeepsItsEvidenceWhileTheEscalationIsEvicted — the same collision on
// the eviction path (dropLocked, reached from evictLocked at the register's
// per-tenant bound).
func TestBundleKeepsItsEvidenceWhileTheEscalationIsEvicted(t *testing.T) {
	bar := newBarrierNarrator()
	s := testService(t, WithNarrator(bar))
	byInc := registerCapture(s, captureWithSpill(t, t.TempDir()), nil)

	var b *Bundle
	var berr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		b, _, berr = s.Bundle(context.Background(), "t1", "inc-1", BundleInput{Actor: "op"})
	}()

	<-bar.entered
	s.mu.Lock()
	s.dropLocked(byInc, "inc-1")
	s.mu.Unlock()
	close(bar.resume)
	<-done

	assertEvidenceOrRefusal(t, b, berr, "the escalation was evicted mid-bundle")
}

// TestBundleAndCaptureCloseUnderContention drives the same two paths with no
// barrier at all, many times over, so the unsynchronised write is reachable
// without the race detector as well as with it.
func TestBundleAndCaptureCloseUnderContention(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 60; i++ {
		f := newFake()
		f.out["show version"] = "IOS-XE 17.9"
		s := testService(t, WithCollector(testCollector(t, f)))
		byInc := registerCapture(s, captureWithSpill(t, root), onePlan())

		var wg sync.WaitGroup
		var b *Bundle
		var berr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			b, _, berr = s.Bundle(context.Background(), "t1", "inc-1", BundleInput{Actor: "op"})
		}()
		go func() {
			defer wg.Done()
			s.mu.Lock()
			s.dropLocked(byInc, "inc-1")
			s.mu.Unlock()
		}()
		wg.Wait()

		if berr != nil || b == nil {
			continue
		}
		// The register may already have been emptied when Bundle read it, in
		// which case there is no bundle to judge; when there is one it must
		// carry the evidence.
		if body := bundleOutput(t, b, firstAskOutput); !strings.Contains(body, spillMarker) {
			t.Fatalf("round %d: a concurrent eviction left a stub in the bundle:\n%s", i, body)
		}
	}
}

// TestCaptureCloseWaitsForTheLastReader — the lease's own contract: a Close
// under a lease removes nothing yet, the last Release performs it, and the
// capture can never be leased again afterwards.
func TestCaptureCloseWaitsForTheLastReader(t *testing.T) {
	capt := captureWithSpill(t, t.TempDir())
	dir, path := capt.SpillDir, capt.Commands[0].SpillPath

	if !capt.Retain() {
		t.Fatal("a fresh capture refused a read lease")
	}
	if err := capt.Close(); err != nil {
		t.Fatalf("close under a lease: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the streamed output was removed under a live reader: %v", err)
	}
	if capt.Commands[0].SpillPath == "" {
		t.Fatal("the spill path was blanked under a live reader")
	}
	if capt.Retain() {
		t.Fatal("a capture whose Close has been asked for handed out a new lease")
	}
	if err := capt.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("the spill directory outlived its last reader: %v", err)
	}
	if capt.Commands[0].SpillPath != "" || capt.SpillDir != "" {
		t.Fatal("a released capture still points at files that are gone")
	}
	if capt.Retain() {
		t.Fatal("a released capture handed out a lease")
	}
	if err := capt.Close(); err != nil {
		t.Fatalf("close is not idempotent: %v", err)
	}
}

// TestBundleRefusesACaptureWhoseOutputsAreGone — when the evidence really has
// been released, the answer is a refusal the operator can act on, never a
// bundle of stubs.
func TestBundleRefusesACaptureWhoseOutputsAreGone(t *testing.T) {
	s := testService(t)
	capt := captureWithSpill(t, t.TempDir())
	registerCapture(s, capt, nil)
	if err := capt.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	b, _, err := s.Bundle(context.Background(), "t1", "inc-1", BundleInput{Actor: "op"})
	if err == nil {
		t.Fatalf("a bundle was built from a released capture: %d bytes", len(b.Zip))
	}
	if !strings.Contains(err.Error(), "released") {
		t.Fatalf("the refusal does not say why: %v", err)
	}
}

// TestBuildBundleRefusesAStubbedStreamedOutput is the assertion behind the
// lease: even if a streamed output's path were lost some other way, the builder
// fails loudly instead of hashing a header-only stub into SHA256SUMS.
func TestBuildBundleRefusesAStubbedStreamedOutput(t *testing.T) {
	capt := captureWithSpill(t, t.TempDir())
	capt.Commands[0].SpillPath = "" // the shape a lost spill file leaves behind
	_, err := BuildBundle(context.Background(), BundleInput{
		TenantID: "t1", IncidentID: "inc-1", Capture: capt,
	}, nil, func() time.Time { return time.Unix(1700000100, 0).UTC() })
	if err == nil {
		t.Fatal("a bundle was assembled around a streamed output that is not there")
	}
	if !strings.Contains(err.Error(), "support.firstask") {
		t.Fatalf("the failure does not name the output: %v", err)
	}
}
