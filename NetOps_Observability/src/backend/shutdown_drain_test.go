// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// shutdown_drain_test.go — CONC-MED-3 (2026-07-27 audit): the shutdown drain
// reported success while background work was still mid-write.
//
// Two separate properties are guarded here:
//
//  1. The drain must actually WAIT for every worker registered in the group, and
//     when its bounded wait expires it must name the workers that were still
//     running. "background workers did not drain" with no names told an operator
//     nothing about whether a report render or a ClickHouse backfill was cut off.
//  2. A worker that is NOT registered must be an explicit, listed decision
//     (cancelOnlyWorkers) rather than an omission — the drift guard below fails
//     the build when a new untracked background launch appears in main().

// A registered worker's in-flight write must complete before the drain returns.
func TestDrainWaitsForRegisteredWorker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	g := &workerGroup{}

	var mu sync.Mutex
	wrote := false
	g.start("clickhouse-writer", func() {
		<-ctx.Done()
		time.Sleep(30 * time.Millisecond) // stand-in for flushing an in-flight write
		mu.Lock()
		wrote = true
		mu.Unlock()
	})

	cancel()
	if stuck := g.drain(5 * time.Second); len(stuck) > 0 {
		t.Fatalf("drain reported %v still running, want a clean drain", stuck)
	}
	mu.Lock()
	defer mu.Unlock()
	if !wrote {
		t.Fatal("drain returned before the registered worker finished its write — the shutdown lied")
	}
}

// On timeout the drain must name EVERY worker still running, and only those.
func TestDrainNamesEveryWorkerStillRunningOnTimeout(t *testing.T) {
	g := &workerGroup{}
	release := make(chan struct{})
	for _, name := range []string{"report-render", "ch-backfill"} {
		g.start(name, func() { <-release })
	}
	done := make(chan struct{})
	g.start("already-finished", func() { close(done) })
	<-done

	stuck := g.drain(150 * time.Millisecond)
	sort.Strings(stuck)
	if got, want := strings.Join(stuck, ","), "ch-backfill,report-render"; got != want {
		t.Fatalf("drain reported %q, want %q — the timeout path must name exactly the workers cut short", got, want)
	}
	close(release)
	if again := g.drain(5 * time.Second); len(again) > 0 {
		t.Fatalf("drain still reports %v after the workers returned", again)
	}
}

// The bounded wait is the hang guard: one worker that ignores cancellation costs
// the timeout and no more, so shutdown can never be held open forever.
func TestDrainCannotBeHeldOpenForever(t *testing.T) {
	g := &workerGroup{}
	never := make(chan struct{})
	g.start("ignores-cancellation", func() { <-never })
	defer close(never)

	start := time.Now()
	stuck := g.drain(100 * time.Millisecond)
	elapsed := time.Since(start)
	if len(stuck) != 1 || stuck[0] != "ignores-cancellation" {
		t.Fatalf("drain reported %v, want the uncooperative worker named", stuck)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("drain took %v for a 100ms budget — a stuck worker must not hold shutdown open", elapsed)
	}
}

// A nil group must still run the worker (never silently drop a background loop)
// while being honest that it will not be drained.
func TestNilWorkerGroupStillRunsTheWorker(t *testing.T) {
	var g *workerGroup
	done := make(chan struct{})
	g.start("untracked", func() { close(done) })
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a worker started on a nil group never ran")
	}
	if stuck := g.drain(10 * time.Millisecond); stuck != nil {
		t.Fatalf("nil group drain returned %v, want nil", stuck)
	}
}

// newServer must wire the group onto the server, since that is the one-line
// adoption path for every subsystem that starts goroutines from a *server method.
func TestServerCarriesTheDrainGroup(t *testing.T) {
	s := &server{workers: &workerGroup{}}
	done := make(chan struct{})
	s.workers.start("via-server", func() { close(done) })
	<-done
	if stuck := s.workers.drain(5 * time.Second); len(stuck) > 0 {
		t.Fatalf("drain reported %v", stuck)
	}
	// gofmt realigns struct-literal keys, so match on structure, not spacing.
	if !regexp.MustCompile(`workers:\s+&workerGroup\{\}`).MatchString(mainSource(t)) {
		t.Error("newServer no longer builds srv.workers — subsystems would start on a nil group and never be drained")
	}
}

// cancelOnlyWorkers is a decision record, so it must read like one.
func TestCancelOnlyWorkersListIsWellFormed(t *testing.T) {
	names := cancelOnlyWorkers()
	if len(names) == 0 {
		t.Fatal("the cancel-only list is empty — either every launch is tracked (then delete the list and its guard) or the list rotted")
	}
	seen := map[string]bool{}
	for _, n := range names {
		if strings.TrimSpace(n) == "" {
			t.Error("cancel-only list contains an empty name")
		}
		if seen[n] {
			t.Errorf("cancel-only list names %q twice", n)
		}
		seen[n] = true
	}
	if !sort.StringsAreSorted(names) {
		t.Error("keep the cancel-only list sorted — it is read as a checklist during shutdown review")
	}
}

// ── drift guard ──────────────────────────────────────────────────────────────
//
// The defect this whole fix addresses is that background launches accumulated in
// main() OUTSIDE the drain group and nothing noticed. This guard fails the build
// when that happens again: every start-shaped launch in main() must be either
// registered through the group (workers.start) or accounted for in
// cancelOnlyWorkers().

func mainSource(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	return string(src)
}

// untrackedLaunchSites lists the calls inside func main() that start background
// work but are NOT registered through the drain group. Calls nested inside a
// workers.start(...) argument are tracked by definition and are not descended
// into.
func untrackedLaunchSites(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}
	calleeName := func(e ast.Expr) string {
		switch fn := e.(type) {
		case *ast.Ident:
			return fn.Name
		case *ast.SelectorExpr:
			return fn.Sel.Name
		}
		return ""
	}
	// tracked reports a call on the drain group itself (workers.start / s.workers.start).
	tracked := func(e ast.Expr) bool {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "start" {
			return false
		}
		switch recv := sel.X.(type) {
		case *ast.Ident:
			return recv.Name == "workers"
		case *ast.SelectorExpr:
			return recv.Sel.Name == "workers"
		}
		return false
	}
	var found []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Name.Name != "Run" || fn.Body == nil { // Run() is the entrypoint since the P2 W5 /cmd split
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if tracked(call.Fun) {
				return false // its closure body is inside the group
			}
			name := calleeName(call.Fun)
			if strings.HasPrefix(strings.ToLower(name), "start") || strings.HasPrefix(name, "ensure") {
				found = append(found, fmt.Sprintf("%s (main.go:%d)", name, fset.Position(call.Pos()).Line))
			}
			return true
		})
	}
	return found
}

func TestEveryBackgroundLaunchIsTrackedOrDocumented(t *testing.T) {
	sites := untrackedLaunchSites(t)
	if len(sites) != len(cancelOnlyWorkers()) {
		t.Fatalf("Run() has %d untracked background launch(es) but cancelOnlyWorkers() lists %d.\n"+
			"Untracked launches found:\n  %s\n"+
			"Register the new one with workers.start(...) (preferred — shutdown then WAITS for it), "+
			"or add it to cancelOnlyWorkers() with the reason it is abandoned on SIGTERM. "+
			"Never leave it out of both: that is how the drain came to report success while collectors "+
			"and the report pipeline were still writing.",
			len(sites), len(cancelOnlyWorkers()), strings.Join(sites, "\n  "))
	}
}
