// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// captures.go — a CAPTURE is a named list of commands.
//
// Design of record: docs/design/TAC_CAPTURES_2026-09-06.md (owner decision).
// The engine did not change; what the customer SEES did. The escalation no
// longer asks anybody to review a plan: classification, command extraction and
// the vendor default all happen silently, and the operator is offered a short
// list of named command sets — Correlix's own, the ones their team saved, and
// one they upload — with a status bar beside each.
//
// THREE SOURCES, ONE SHAPE. `vendor-default` is derived from the plan the engine
// already built (bound steps only — an unbound intent has no command to run, so
// it can never be a line of a capture). `template` is one of this tenant's saved
// sets, which live in the SAME store the command templates always did (RLS,
// tenant stamped from the token). `uploaded` is a file the customer supplied
// this minute; it is parsed and validated server-side and returned WITHOUT being
// stored, because an upload is a choice for this escalation and becomes a stored
// row only when the operator presses "Save as template".
//
// WHAT IS NOT HERE. There is no second store, no second RLS policy and no second
// isolation model: a saved capture IS a Template. That is deliberate — the
// alternative was a parallel per-tenant table with its own scoping bug to write.
//
// NAMING. `Capture` in this package has meant "one collection's output" since
// collect.go, and it still does. This file's type is CommandCapture: what will
// be run, not what came back.

import (
	"strings"
	"time"
)

// Capture bounds. Every one is a §9 ceiling enforced server-side; a client
// cannot raise one by asking.
const (
	// MaxCaptureUploadBytes bounds an uploaded file BEFORE it is parsed.
	MaxCaptureUploadBytes int64 = 1 << 20
	// MaxCaptureCommands bounds how many commands one uploaded file may yield.
	// It is deliberately larger than MaxTemplateSteps: a customer's own runbook
	// legitimately runs to hundreds of lines, and refusing to READ it because it
	// is longer than one collection may be would be a refusal to look.
	MaxCaptureCommands = 500
	// MaxCaptureCommandBytes bounds ONE command line of an upload.
	MaxCaptureCommandBytes = 512
	// MaxCaptureNameBytes bounds a capture's name.
	MaxCaptureNameBytes = maxTemplateNameBytes
)

// CaptureSource says where a capture's commands came from. It is a CLOSED enum:
// a fourth kind would be a fourth provenance story in the bundle.
type CaptureSource string

const (
	// CaptureVendorDefault — derived from the authored plan for this platform.
	CaptureVendorDefault CaptureSource = "vendor-default"
	// CaptureUploaded — a file the customer supplied, not stored.
	CaptureUploaded CaptureSource = "uploaded"
	// CaptureTemplate — one of this tenant's saved command sets.
	CaptureTemplate CaptureSource = "template"
)

// CaptureCommand is one line of a capture.
type CaptureCommand struct {
	Command string `json:"command"`
	// Note is the customer's own note for the line (the csv second column, a
	// json/yaml `note`). It travels into the bundle MANIFEST unchanged.
	Note string `json:"note,omitempty"`
	// Line is where the command came from in the uploaded file, 1-based. It is
	// what a refusal is reported against, so an operator can find the line in
	// the file they still have open. 0 when the source had no line numbering.
	Line int `json:"line,omitempty"`
}

// CommandCapture is a named list of commands.
type CommandCapture struct {
	ID string `json:"id"`
	// TenantID is the OWNER, stamped from the authenticated principal and never
	// from a request body (§3a rule 2). It is not serialised for the same reason
	// Template.TenantID is not: a caller only ever receives its own rows.
	TenantID string        `json:"-"`
	Name     string        `json:"name"`
	Source   CaptureSource `json:"source"`
	Dialect  string        `json:"dialect"`

	Commands []CaptureCommand `json:"commands"`

	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at,omitzero"`
}

// CommandList returns the capture's commands in order.
func (c CommandCapture) CommandList() []string {
	out := make([]string, 0, len(c.Commands))
	for _, cc := range c.Commands {
		out = append(out, cc.Command)
	}
	return out
}

// CaptureFromTemplate renders a saved template as a capture. A template's steps
// carry titles and intents the capture does not need: a capture is the list of
// lines that will run, and the provenance of each line is already the template's.
func CaptureFromTemplate(t Template) CommandCapture {
	cmds := make([]CaptureCommand, 0, len(t.Steps))
	for _, s := range t.Steps {
		cmds = append(cmds, CaptureCommand{Command: s.Command, Note: s.Note})
	}
	return CommandCapture{
		ID: t.ID, TenantID: t.TenantID, Name: t.Name, Source: CaptureTemplate,
		Dialect: t.Dialect, Commands: cmds, CreatedBy: t.CreatedBy, CreatedAt: t.CreatedAt,
	}
}

// VendorDefaultCaptureID is the stable id of the capture derived from a plan. It
// is not a stored row and it is not addressable: it names the derivation so the
// UI can key a list row and the bundle can say which capture ran.
const VendorDefaultCaptureID = "capture:vendor-default"

// vendorDefaultCaptureName is what the derived capture is called on screen. It
// says WHAT it is, not how it was made — the derivation is behind the
// "What Correlix is doing" control, which is the whole point of this design.
const vendorDefaultCaptureName = "Correlix default"

// VendorDefaultCapture derives the capture Correlix will run from a plan.
//
// BOUND STEPS ONLY. An unbound intent is an honest gap the plan already states;
// it has no command, so it cannot be a line here. Topology rows are model
// context and not commands either. Neither is dropped from the escalation — both
// still travel with the plan and into the bundle — they are simply not commands.
//
// A nil plan yields no capture rather than an empty one: "there is no capture
// yet" and "the capture is empty" are different facts and the UI says different
// things about them.
func VendorDefaultCapture(p *Plan) *CommandCapture {
	if p == nil {
		return nil
	}
	cmds := make([]CaptureCommand, 0, len(p.Steps))
	for _, s := range p.Steps {
		if s.Section == SectionTopology || !s.Bound {
			continue
		}
		if c := strings.TrimSpace(s.Command); c != "" {
			cmds = append(cmds, CaptureCommand{Command: c, Note: s.Title})
		}
	}
	name := vendorDefaultCaptureName
	if d := strings.TrimSpace(p.DialectDisplay); d != "" {
		name = d + " default"
	}
	return &CommandCapture{
		ID: VendorDefaultCaptureID, TenantID: p.TenantID, Name: name,
		Source: CaptureVendorDefault, Dialect: p.Dialect, Commands: cmds,
	}
}

// ── collection status, per capture and per command ──────────────────────────
//
// The owner's rule: "When it's collecting it's good to see the status. Instead
// of showing all the command outputs, just display the ones that didn't work."
// So the state machine that already exists (Job + Capture) is READ here into
// exactly five words and a reason, and nothing else is rendered.

// CaptureStatus is one capture's — or one command's — collection state.
type CaptureStatus string

const (
	// CaptureQueued — nothing has run for this capture yet.
	CaptureQueued CaptureStatus = "queued"
	// CaptureRunning — the collection is in flight.
	CaptureRunning CaptureStatus = "running"
	// CaptureDone — every command came back with output.
	CaptureDone CaptureStatus = "done"
	// CapturePartial — the collection finished and some commands did not.
	CapturePartial CaptureStatus = "partial"
	// CaptureFailed — the collection could not run, or nothing came back.
	CaptureFailed CaptureStatus = "failed"
)

// The five reasons a single command can fail, in the operator's words. They are
// a CLOSED set because "what went wrong" is the only thing shown under a failed
// row, and a raw driver string there would be the wall of text this redesign
// exists to remove. The device's own sentence is not lost: it is in the bundle,
// and in the collection log behind "What Correlix is doing".
const (
	CaptureReasonTimeout   = "timed out"
	CaptureReasonRefused   = "refused by the device"
	CaptureReasonUnknown   = "not on this platform"
	CaptureReasonGateway   = "gateway unavailable"
	CaptureReasonNoOutput  = "the device returned nothing"
	CaptureReasonTruncated = "output over the size cap"
)

// CommandStatus is one command's row.
type CommandStatus struct {
	Command string        `json:"command"`
	Status  CaptureStatus `json:"status"`
	// Reason is one of the closed set above, and is set only on a failure.
	Reason string `json:"reason,omitempty"`
}

// CaptureProgress is one capture's whole collection state.
type CaptureProgress struct {
	CaptureID string        `json:"capture_id"`
	Status    CaptureStatus `json:"status"`
	Total     int           `json:"total"`
	Done      int           `json:"done"`
	Failed    int           `json:"failed"`
	// Commands carries ONLY the commands that failed. The successful ones are in
	// the bundle; rendering them here is what the old panel did and what the
	// owner asked to stop. An empty list on a `done` capture is the whole point.
	Commands []CommandStatus `json:"commands"`
}

// captureFailureReason maps a collector error onto the closed reason set.
//
// It reads the error TEXT because that is what the seam gives us: the runner
// returns driver errors and device output, both already redacted. An error it
// cannot classify is "refused by the device" — the honest default, because
// something on the far side said no and we do not know what.
func captureFailureReason(errText string) string {
	e := strings.ToLower(strings.TrimSpace(errText))
	if e == "" {
		return CaptureReasonNoOutput
	}
	switch {
	case strings.Contains(e, "size cap") || strings.Contains(e, "truncat"):
		return CaptureReasonTruncated
	case strings.Contains(e, "timeout") || strings.Contains(e, "timed out") ||
		strings.Contains(e, "deadline exceeded"):
		return CaptureReasonTimeout
	case strings.Contains(e, "not configured") || strings.Contains(e, "unwired") ||
		strings.Contains(e, "gateway") || strings.Contains(e, "no route to host") ||
		strings.Contains(e, "connection refused") || strings.Contains(e, "unreachable") ||
		strings.Contains(e, "dial "):
		return CaptureReasonGateway
	case strings.Contains(e, "invalid input") || strings.Contains(e, "unknown command") ||
		strings.Contains(e, "syntax error") || strings.Contains(e, "not supported") ||
		strings.Contains(e, "unrecognized"):
		return CaptureReasonUnknown
	default:
		return CaptureReasonRefused
	}
}

// CaptureProgressOf reads the collect state machine for ONE capture.
//
// The rules, and each is a product state rather than a convenience:
//   - no job and no capture              → queued (nothing has been asked for)
//   - the job is running                 → running, with what has finished so far
//   - the job failed before any command  → failed, carrying the job's own reason
//   - the collection finished clean      → done, and the command list is EMPTY
//   - some commands failed               → partial, listing ONLY those
//   - every command failed               → failed, listing them
func CaptureProgressOf(id string, job *Job, capt *CaptureSummary) CaptureProgress {
	pr := CaptureProgress{CaptureID: id, Status: CaptureQueued, Commands: []CommandStatus{}}
	if job == nil && capt == nil {
		return pr
	}
	if capt != nil {
		pr.Total = len(capt.Commands)
		for _, c := range capt.Commands {
			if c.Err != "" || c.Bytes == 0 {
				pr.Failed++
				pr.Commands = append(pr.Commands, CommandStatus{
					Command: c.Command, Status: CaptureFailed, Reason: captureFailureReason(c.Err),
				})
				continue
			}
			pr.Done++
		}
	}
	switch {
	case job != nil && job.Status == JobRunning:
		pr.Status = CaptureRunning
		if job.Total > pr.Total {
			pr.Total = job.Total
		}
	case job != nil && job.Status == JobFailed && pr.Total == 0:
		pr.Status = CaptureFailed
		if reason := strings.TrimSpace(job.Err); reason != "" {
			pr.Commands = append(pr.Commands, CommandStatus{
				Status: CaptureFailed, Reason: captureFailureReason(reason),
			})
		}
	case pr.Total == 0:
		pr.Status = CaptureQueued
	case pr.Failed == 0:
		pr.Status = CaptureDone
	case pr.Done == 0:
		pr.Status = CaptureFailed
	default:
		pr.Status = CapturePartial
	}
	return pr
}
