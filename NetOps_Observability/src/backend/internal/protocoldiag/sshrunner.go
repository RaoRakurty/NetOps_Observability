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
	table   *commandTable
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
	r := &SSHCommandRunner{
		gw:      gw,
		table:   newCommandTable(catalog),
		max:     MaxOutputBytes,
		timeout: DefaultCommandTimeout,
		busy:    map[string]bool{},
	}
	for _, o := range opts {
		o(r)
	}
	return r, nil
}

// Run implements CommandRunner.
func (r *SSHCommandRunner) Run(ctx context.Context, device Device, command string) (string, error) {
	// (1) read-only shape — belt to the Collector's braces: this runner is also
	// reachable from any future call site, so it re-validates rather than trust.
	if err := ValidateReadOnly(command); err != nil {
		return "", fmt.Errorf("%w: %s", ErrNotReadOnly, err.Error())
	}
	// (2) closed table for THIS device's dialect.
	if !r.table.Allows(device.Vendor(), command) {
		return "", fmt.Errorf("%w: %q", ErrCommandNotInTable, command)
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
