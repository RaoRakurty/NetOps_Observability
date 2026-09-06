// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package protocoldiag

// sshrunner.go — the POLICY layer between the Collector and the SSH transport.
//
// SSHGateway (sshgw.go) knows how to run one command. This file decides WHICH
// commands may be run at all, HOW MANY may be in flight, HOW MUCH output is
// accepted and HOW LONG one may take. Keeping the two apart is what lets every
// one of those rules be proven in CI against a fake gateway, with no device and
// no socket.
//
// The four guarantees, in the order Run enforces them:
//
//  1. READ-ONLY SHAPE — ValidateReadOnly (collect.go) rejects anything that is
//     not a show/display/get/info with display-only pipe filters.
//  2. CLOSED TABLE — commandtable.go rejects anything the catalog could not have
//     rendered for THIS device's dialect. `show running-config` passes (1) and
//     fails here: this feature runs 15 curated bundles, not arbitrary reads.
//  3. ONE IN FLIGHT PER DEVICE — a second concurrent collection against the same
//     device is refused rather than queued, so an operator (or a retry storm)
//     cannot multiply sessions on a production router (§9 bounded).
//  4. BOUNDED IO — a per-command context deadline and a hard output cap, both
//     passed down to the gateway (§9 all IO has a timeout).
//
// A refusal is an ERROR, never a silent empty capture: the Collector records it
// on that command and the operator sees exactly which probe was refused and why.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/showparse"
)

// SSHCommandRunner is the live CommandRunner: it validates a rendered command
// against the closed per-vendor table and runs it over the injected Gateway.
//
// It is the one component in this package that holds mutable state — the
// per-device in-flight claim set — so that state is a plain mutex-guarded map on
// the struct (no package globals, §5) and is the only thing a concurrent caller
// touches.
type SSHCommandRunner struct {
	gw      Gateway
	gate    commandGate
	max     int64
	timeout time.Duration

	mu   sync.Mutex
	busy map[string]bool // device id → a command is in flight
}

// SSHRunnerOption configures an SSHCommandRunner.
type SSHRunnerOption func(*SSHCommandRunner)

// WithMaxOutputBytes overrides the per-command output cap. A non-positive or
// over-ceiling value is clamped to MaxOutputBytes — a caller cannot widen the
// bound past the package's own ceiling.
func WithMaxOutputBytes(n int64) SSHRunnerOption {
	return func(r *SSHCommandRunner) {
		if n > 0 && n <= MaxOutputBytes {
			r.max = n
		}
	}
}

// WithCommandTimeout overrides the per-command deadline. A non-positive value is
// ignored (the default stands) — there is no "no timeout" setting.
func WithCommandTimeout(d time.Duration) SSHRunnerOption {
	return func(r *SSHCommandRunner) {
		if d > 0 {
			r.timeout = d
		}
	}
}

// NewSSHCommandRunner builds the live runner over a catalog (which becomes the
// closed command table) and a Gateway. Both are REQUIRED: a nil dependency is a
// fail-closed error, never a silent no-op runner that would fabricate empty
// captures.
func NewSSHCommandRunner(catalog *Catalog, gw Gateway, opts ...SSHRunnerOption) (*SSHCommandRunner, error) {
	if catalog == nil {
		return nil, errors.New("protocoldiag: nil catalog")
	}
	if gw == nil {
		return nil, errors.New("protocoldiag: nil gateway")
	}
	return newLiveRunner(gw, catalogGate{table: newCommandTable(catalog)}, opts...), nil
}

// NewSSHBatteryRunner is the live runner for the SHOW-FIRST STATE BATTERY
// (statebattery.go). It is the SAME policy layer — read-only shape, closed
// table, one in flight per device, bounded IO — over the BATTERY's closed table
// instead of the catalog's.
//
// It exists because the two tables must not be merged: a runner that accepted
// both would let a catalog call reach a battery command and the reverse, and the
// whole value of a closed table is that it is exactly as wide as the feature it
// serves. Wiring RunBattery to a catalog runner would refuse every battery
// command (honestly, as ErrCommandNotInTable) — this constructor is the correct
// wiring.
func NewSSHBatteryRunner(battery *StateBattery, gw Gateway, opts ...SSHRunnerOption) (*SSHCommandRunner, error) {
	if battery == nil {
		return nil, errors.New("protocoldiag: nil state battery")
	}
	if gw == nil {
		return nil, errors.New("protocoldiag: nil gateway")
	}
	return newLiveRunner(gw, batteryGate{battery: battery}, opts...), nil
}

// newLiveRunner is the shared constructor behind both live runners.
func newLiveRunner(gw Gateway, gate commandGate, opts ...SSHRunnerOption) *SSHCommandRunner {
	r := &SSHCommandRunner{
		gw:      gw,
		gate:    gate,
		max:     MaxOutputBytes,
		timeout: DefaultCommandTimeout,
		busy:    map[string]bool{},
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// commandGate answers the closed-table question for ONE device: "could the
// feature this runner serves have rendered this exact command for this device?".
// Injecting it is what lets the catalog and the state battery share every other
// policy rule without sharing a table.
type commandGate interface {
	allows(dev Device, command string) bool
	// name identifies the gate in a refusal message.
	name() string
}

// catalogGate is the 15-issue catalog's gate, keyed on the catalog's
// three-value rendering Vendor.
type catalogGate struct{ table *commandTable }

func (g catalogGate) allows(dev Device, command string) bool {
	return g.table.Allows(dev.Vendor(), command)
}
func (g catalogGate) name() string { return "diagnostics catalog" }

// batteryGate is the state battery's gate, keyed on the device's resolved
// vendorprofile DIALECT. A platform that resolves to no dialect is refused —
// there is no fallback dialect, so there is no command to allow.
type batteryGate struct{ battery *StateBattery }

func (g batteryGate) allows(dev Device, command string) bool {
	d, ok := showparse.DialectFromPlatform(dev.Platform)
	if !ok {
		return false
	}
	return g.battery.Allows(d, command)
}
func (g batteryGate) name() string { return "state battery" }

// Run implements CommandRunner.
func (r *SSHCommandRunner) Run(ctx context.Context, device Device, command string) (string, error) {
	// (1) read-only shape — belt to the Collector's braces: this runner is also
	// reachable from any future call site, so it re-validates rather than trust.
	//
	// A BOUNDED REACHABILITY PROBE is the single exception (owner decision,
	// 2026-09-05: ping and traceroute are allowed). It is not a read, so it can
	// never pass ValidateReadOnly; it passes its OWN grammar instead, which caps
	// every count, size, timeout and hop and refuses the flood/sweep/rapid
	// modifiers. Widening this step does not widen what any caller can run: the
	// closed table at step (2) still has to contain the command, and only a
	// feature that authored a probe template has one.
	if err := ValidateReadOnly(command); err != nil {
		if !IsProbeCommand(command) {
			return "", fmt.Errorf("%w: %s", ErrNotReadOnly, err.Error())
		}
		if perr := ValidateBoundedProbe(command); perr != nil {
			return "", fmt.Errorf("%w: %s", ErrNotReadOnly, perr.Error())
		}
	}
	// (2) closed table for THIS device's dialect.
	if !r.gate.allows(device, command) {
		return "", fmt.Errorf("%w: %q is not in the %s table for platform %q",
			ErrCommandNotInTable, command, r.gate.name(), device.Platform)
	}
	if strings.TrimSpace(device.Address) == "" {
		return "", ErrNoAddress
	}
	// (3) one in flight per device.
	key := device.ID
	if key == "" {
		key = device.Address
	}
	if !r.claim(key) {
		return "", ErrDeviceBusy
	}
	defer r.release(key)
	// (4) bounded IO: a per-command deadline on top of whatever the caller set.
	runCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	return r.gw.Run(runCtx, device, command, r.max)
}

// claim marks a device busy, returning false when a command is already running
// on it. Refusing (rather than queueing) is deliberate: a queue would hide the
// contention and still multiply sessions once it drained.
func (r *SSHCommandRunner) claim(deviceID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.busy[deviceID] {
		return false
	}
	r.busy[deviceID] = true
	return true
}

// release clears the in-flight claim. It runs from a defer, so a panic or an
// early return can never leave a device permanently claimed.
func (r *SSHCommandRunner) release(deviceID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.busy, deviceID)
}

var _ CommandRunner = (*SSHCommandRunner)(nil)

// ── the exported gate seam ──────────────────────────────────────────────────
//
// CommandGate is the EXPORTED form of the closed-table question: "could the
// feature this runner serves have rendered this exact command for this device?".
//
// It exists so a SIBLING feature can reuse this whole policy layer — read-only
// shape, closed table, one collection in flight per device, bounded time and
// output — over its OWN closed table, without either widening this package's
// tables or growing a second, subtly different runner somewhere else. The TAC
// escalation pack (internal/tac) is the first such caller: its table is the set
// of commands its reviewed per-dialect plan files authorise, and nothing else.
//
// An implementation MUST be conservative: it is the last thing between a plan
// file and a device, and it answers for a SPECIFIC device, so a platform it does
// not recognise must answer false (there is no fallback dialect) rather than
// borrow another vendor's table.
type CommandGate interface {
	// Allows reports whether command is a rendering of an authored template for
	// this device's dialect.
	Allows(dev Device, command string) bool
	// Name identifies the gate in a refusal message, so an operator reading the
	// error knows WHICH closed table refused.
	Name() string
}

// NewSSHGatedRunner builds the live runner over a caller-supplied closed table.
// It is the same policy layer NewSSHCommandRunner and NewSSHBatteryRunner build;
// only the table differs. Both dependencies are REQUIRED — a nil gate would be a
// runner that allows everything, which is the exact opposite of the point.
func NewSSHGatedRunner(gate CommandGate, gw Gateway, opts ...SSHRunnerOption) (*SSHCommandRunner, error) {
	if gate == nil {
		return nil, errors.New("protocoldiag: nil command gate")
	}
	if gw == nil {
		return nil, errors.New("protocoldiag: nil gateway")
	}
	return newLiveRunner(gw, exportedGate{gate: gate}, opts...), nil
}

// exportedGate adapts an exported CommandGate onto the package's internal
// commandGate seam.
type exportedGate struct{ gate CommandGate }

func (g exportedGate) allows(dev Device, command string) bool { return g.gate.Allows(dev, command) }
func (g exportedGate) name() string                           { return g.gate.Name() }
