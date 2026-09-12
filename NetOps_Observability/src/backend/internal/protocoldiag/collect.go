// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package protocoldiag

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// CommandRunner runs ONE already-validated read-only show command against ONE
// device and returns its raw text output. It is the narrow input seam between the
// collector and the real command source: the collector never reaches for a
// transport itself, it asks this interface. A non-nil error means THAT command
// could not be run (transport/auth/timeout) — the collector records the error on
// that command and continues, so a partial capture is still useful; it never
// invents output.
//
// The runner MUST honor ctx (deadline/cancel) — all IO is bounded (§9).
//
// The LIVE implementation is SSHCommandRunner (sshrunner.go) over SSHGateway
// (sshgw.go): a read-only `show` from the closed per-vendor table, one in flight
// per device, bounded output and a per-command deadline. It is wired by the
// integrator (backend/protocol_diag_gateway.go) ONLY when
// FEATURE_PROTOCOL_DIAG_COLLECT=true (env.go) — dormant by default, so the
// collect endpoint answers an honest 503 until an operator opts in and
// provisions a least-privilege read-only account. MemCommandRunner stays the
// test/stub implementation, which is what keeps this package decoupled from the
// running stack and every test offline. gNMI, where a device exposes the
// equivalent state path, remains a possible second source behind the same
// interface.
type CommandRunner interface {
	Run(ctx context.Context, device Device, command string) (string, error)
}

// Collector runs an issue's command bundle against a device via an injected
// CommandRunner and an injected clock. It holds no mutable state and starts no
// goroutines, so it is safe under -race by construction and fully deterministic
// given a deterministic runner + clock.
type Collector struct {
	catalog *Catalog
	runner  CommandRunner
	now     func() time.Time
}

// CollectorOption configures a Collector.
type CollectorOption func(*Collector)

// WithClock injects the timestamp source (default time.Now). Tests pin it so
// every command's timestamp is deterministic.
func WithClock(now func() time.Time) CollectorOption {
	return func(c *Collector) {
		if now != nil {
			c.now = now
		}
	}
}

// NewCollector builds a Collector. catalog and runner MUST be non-nil; passing
// nil is a programming error the caller must avoid — the collector does not paper
// over a missing dependency with a silent no-op (fail closed).
func NewCollector(catalog *Catalog, runner CommandRunner, opts ...CollectorOption) (*Collector, error) {
	if catalog == nil {
		return nil, errors.New("protocoldiag: nil catalog")
	}
	if runner == nil {
		return nil, errors.New("protocoldiag: nil command runner")
	}
	c := &Collector{catalog: catalog, runner: runner, now: time.Now}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// CollectedCommand is one command's captured result. Timestamp is stamped
// immediately before the command runs. Err (empty when the command succeeded)
// records a per-command transport failure honestly — Analyze treats a command
// that errored as "no output" and never invents a verdict from it.
type CollectedCommand struct {
	SpecID    string
	Command   string
	Purpose   string
	Output    string
	Timestamp time.Time
	Err       string
}

// ok reports whether the command produced usable output (ran without error).
func (c CollectedCommand) ok() bool { return c.Err == "" }

// Collection is the full point-in-time capture for one (device, issue): the
// rendered bundle and its outputs, stamped with the owning tenant and the exact
// ruleset version. TenantID is stamped from the SUBJECT DEVICE (§3a), never a
// request body. RenderedVendor records which dialect was actually used (an
// unknown device platform falls back to the primary dialect — recorded, never
// silent).
type Collection struct {
	TenantID       string
	DeviceID       string
	Hostname       string
	Platform       string
	Vendor         Vendor
	RenderedVendor Vendor
	Protocol       Protocol
	IssueID        string
	IssueTitle     string
	RulesetVersion string
	CollectedAt    time.Time
	Commands       []CollectedCommand
}

// ErrUnknownIssue is returned when an issue id is not in the catalog.
var ErrUnknownIssue = errors.New("protocoldiag: unknown issue")

// ErrNotReadOnly is returned (wrapping the offending command) when a rendered
// command fails the read-only guard. It ABORTS the whole collection — a command
// that is not a read-only show can never be run, even if the rest of the bundle
// is fine (fail-closed safety, §8). This should be impossible for the curated
// catalog and is a hard guard against a future/dynamic command source.
var ErrNotReadOnly = errors.New("protocoldiag: command is not read-only")

// Collect renders the issue's bundle in the device's dialect and runs every
// command through the injected runner, in stable bundle order, each stamped with
// the clock. It VALIDATES each rendered command as read-only BEFORE running it;
// a non-read-only command aborts the whole collection (nothing is run past it).
// A per-command runner error is recorded on that command and collection
// continues (a partial capture is still shareable). The tenant is stamped from
// the device.
func (c *Collector) Collect(ctx context.Context, device Device, issueID string, tgt Target) (*Collection, error) {
	issue, ok := c.catalog.Issue(issueID)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownIssue, issueID)
	}
	vendor := device.Vendor()
	rendered := renderVendor(vendor)

	col := &Collection{
		TenantID:       device.TenantID, // §3a: owner from the resolved device
		DeviceID:       device.ID,
		Hostname:       device.Hostname,
		Platform:       device.Platform,
		Vendor:         vendor,
		RenderedVendor: rendered,
		Protocol:       issue.Protocol,
		IssueID:        issue.ID,
		IssueTitle:     issue.Title,
		RulesetVersion: RulesetVersion,
		CollectedAt:    c.now().UTC(),
	}

	for _, s := range issue.Bundle() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		cmd := s.Render(vendor, tgt)
		// Read-only guard FIRST — a non-read-only command is never run.
		if err := ValidateReadOnly(cmd); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrNotReadOnly, err.Error())
		}
		cc := CollectedCommand{
			SpecID:    s.ID,
			Command:   cmd,
			Purpose:   s.Purpose,
			Timestamp: c.now().UTC(),
		}
		out, err := c.runner.Run(ctx, device, cmd)
		if err != nil {
			cc.Err = err.Error()
		} else {
			cc.Output = out
		}
		col.Commands = append(col.Commands, cc)
	}
	return col, nil
}

// ── Read-only guard (§8) ────────────────────────────────────────────────────

// readOnlyLead is the allowlist of first tokens that denote a read-only,
// non-mutating command across the supported dialects: Cisco/Juniper/Nokia "show",
// Huawei "display", gNMI-style "get", and SR Linux "info".
var readOnlyLead = map[string]struct{}{
	"show": {}, "display": {}, "get": {}, "info": {},
}

// readOnlyFilter is the allowlist of pipe-filter verbs a read-only command may
// pipe into (display filters only — none mutate state or write files).
var readOnlyFilter = map[string]struct{}{
	"include": {}, "i": {}, "exclude": {}, "e": {}, "begin": {}, "b": {},
	"section": {}, "count": {}, "match": {}, "except": {}, "find": {},
	"last": {}, "first": {}, "trim": {}, "display": {}, "no-more": {},
}

// ValidateReadOnly returns nil iff command is a safe read-only command: its lead
// token is in the read-only allowlist, every pipe segment filters (never
// mutates), and it contains no command-chaining / redirection / substitution
// metacharacters. It is deliberately strict and fail-closed — an unrecognized
// shape is REFUSED, not guessed. This is the safety boundary that guarantees a
// config command can never leave this package (§8).
func ValidateReadOnly(command string) error {
	cmd := strings.TrimSpace(command)
	if cmd == "" {
		return errors.New("empty command")
	}
	// Reject shell/CLI chaining, redirection and substitution outright — these
	// turn a "show" into an action regardless of the lead token.
	for _, bad := range []string{";", "\n", "\r", "&", "`", "$(", "${", ">", "<", "!"} {
		if strings.Contains(cmd, bad) {
			return fmt.Errorf("contains disallowed metacharacter %q", bad)
		}
	}
	segments := strings.Split(cmd, "|")
	// First segment: the command itself.
	lead := firstToken(segments[0])
	if lead == "" {
		return errors.New("no command token")
	}
	if _, ok := readOnlyLead[strings.ToLower(lead)]; !ok {
		return fmt.Errorf("lead token %q is not a read-only verb (show/display/get/info)", lead)
	}
	// Remaining segments must be display filters only.
	for _, seg := range segments[1:] {
		f := firstToken(seg)
		if f == "" {
			return errors.New("empty pipe segment")
		}
		if _, ok := readOnlyFilter[strings.ToLower(f)]; !ok {
			return fmt.Errorf("pipe filter %q is not an allowed read-only filter", f)
		}
	}
	return nil
}

// firstToken returns the first whitespace-delimited token of s, or "".
func firstToken(s string) string {
	fs := strings.Fields(s)
	if len(fs) == 0 {
		return ""
	}
	return fs[0]
}

// ── In-memory stub source (tests + dormant call sites) ──────────────────────

// MemCommandRunner is an in-memory CommandRunner keyed by the exact rendered
// command string. A command with no mapping returns an empty output + nil error
// (an honest "ran, nothing to show" — many show commands are legitimately empty).
// It never mutates anything and is safe for concurrent use.
type MemCommandRunner map[string]string

// Run implements CommandRunner. It ignores the device (the map is the whole
// world) and returns the mapped output, or "" for an unmapped command.
func (m MemCommandRunner) Run(_ context.Context, _ Device, command string) (string, error) {
	return m[command], nil
}

// FailingRunner is a CommandRunner that fails every command with err — the
// fail-closed / no-source test fixture and any deliberate degraded-mode wiring.
type FailingRunner struct{ Err error }

// Run implements CommandRunner, always returning the configured error.
func (f FailingRunner) Run(_ context.Context, _ Device, _ string) (string, error) {
	if f.Err != nil {
		return "", f.Err
	}
	return "", errors.New("protocoldiag: command source unavailable")
}
