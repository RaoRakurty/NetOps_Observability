// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package safego runs work that must not be able to take the process down.
//
// Go recovers panics only on the goroutine net/http runs a handler on. Every
// OTHER goroutine — background workers, ticker loops, and above all the packet
// decoders fed by unauthenticated UDP (SNMP traps, syslog, flows) — kills the
// entire process when it panics. One malformed trap from anywhere on the
// network is then a total API outage for every tenant, pre-auth. That is the
// failure mode this package exists to remove.
//
// Recovering is NOT swallowing: every recovered panic is reported with its
// name and full stack through an injected Logger, so the bug stays as visible
// as a crash was (§10 — no silent failures) without being as expensive.
//
// The Logger is a parameter rather than a package-level sink so there is no
// mutable global to race on or reconfigure at a distance: the API passes its
// structured JSON logger, collectors and standalone binaries take Stderr,
// which emits the same field names.
package safego

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime/debug"
	"time"
)

// Logger receives a recovered panic. name identifies the goroutine (stable,
// low-cardinality — it ends up as a log field), recovered is the panic value,
// and stack is the stack trace captured at recovery.
type Logger func(name string, recovered any, stack []byte)

// Stderr is the fallback Logger: one JSON line per panic on stderr, using the
// same field names as the API's structured logger so the log pipeline parses
// both identically. Marshalled first and written with a single Write so
// concurrent panics can't interleave into unparseable lines.
func Stderr(name string, recovered any, stack []byte) {
	line, err := json.Marshal(map[string]any{
		"ts":        time.Now().UTC().Format(time.RFC3339Nano),
		"level":     "error",
		"component": "panic",
		"msg":       "goroutine panic recovered",
		"goroutine": name,
		"panic":     fmt.Sprint(recovered),
		"stack":     string(stack),
	})
	if err != nil {
		return
	}
	_, _ = os.Stderr.Write(append(line, '\n')) // stderr is the last resort; nowhere left to report
}

// Go starts fn on its own goroutine with panic recovery, reporting to Stderr.
// Prefer GoWith in the API, which has a structured logger to route panics to.
func Go(name string, fn func()) {
	GoWith(Stderr, name, fn)
}

// GoWith starts fn on its own goroutine with panic recovery, reporting any
// panic through log.
func GoWith(log Logger, name string, fn func()) {
	go func() {
		_ = Run(log, name, fn) // Run's error is the recovered panic, already reported by Run
	}()
}

// Run calls fn on the CURRENT goroutine with panic recovery and reports
// whether it completed. Use it for the per-item body of a loop that must
// survive one poisoned item — a malformed packet should cost that packet, not
// the receiver.
func Run(log Logger, name string, fn func()) (completed bool) {
	defer func() {
		if r := recover(); r != nil {
			completed = false
			report(log, name, r, debug.Stack())
		}
	}()
	fn()
	return true
}

// Recover is the deferred form, for goroutines whose body is not easily
// expressed as a closure: `defer safego.Recover(log, "name")` at the top of
// the function. It must be deferred DIRECTLY (not wrapped) for recover() to
// see the panic.
func Recover(log Logger, name string) {
	if r := recover(); r != nil {
		report(log, name, r, debug.Stack())
	}
}

// report never lets the reporting path itself panic (a Logger with a bug would
// otherwise re-panic inside a deferred recover and kill the process anyway —
// exactly what the caller was defending against).
func report(log Logger, name string, recovered any, stack []byte) {
	defer func() { _ = recover() }() // swallow a panic from the logger itself (see comment above)
	if log == nil {
		log = Stderr
	}
	log(name, recovered, stack)
}
