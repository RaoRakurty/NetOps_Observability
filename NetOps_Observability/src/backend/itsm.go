// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"netops/backend/ai"
	"netops/backend/internal/irisaction"
	"netops/backend/internal/ticketing"
	"netops/backend/notify"
)

// ---- Iris approval-gated writes: the ticket note (tracker 337 N-I4) ---------
//
// propose_itsm_update adds ONE note to the ticket already linked to the
// investigation's case — the ticket the RCA view opened through the tenant's
// own ticketing connection (internal/ticketing). The ticket comes from that
// link, never from a model; the note from the investigation's cited evidence.
// It is sent through the same typed adapter the RCA ticketing worker uses
// (Adapter.AddWorkNote: a ServiceNow work note / one Jira comment), only after
// a DIFFERENT person approved the exact text on /api/ai/actions.

// irisTicketNoteExec is the itsm_note executor. adapters is injectable so
// tests drive it against an httptest-backed adapter.
type irisTicketNoteExec struct {
	srv      *server
	adapters map[string]ticketing.Adapter
}

func newIrisTicketNoteExec(s *server) *irisTicketNoteExec {
	return &irisTicketNoteExec{srv: s, adapters: map[string]ticketing.Adapter{
		irisaction.SystemServiceNow: ticketing.NewServiceNowAdapter(),
		irisaction.SystemJira:       ticketing.NewJiraAdapter(),
	}}
}

func itsmSystemLabel(system string) string {
	if system == irisaction.SystemJira {
		return "Jira"
	}
	return "ServiceNow"
}

// Describe renders the summary and the EXACT note the approver approves.
func (e *irisTicketNoteExec) Describe(p irisaction.ITSMNote) (string, string) {
	return fmt.Sprintf("Add Iris's finding as a note on %s %s", itsmSystemLabel(p.System), p.TicketRef), p.Note
}

// linkFor re-reads the case's open link to this ticket and the tenant's
// connection for its system. Every failure is a reason, never a silent skip.
func (e *irisTicketNoteExec) linkFor(ctx context.Context, tenant string, p irisaction.ITSMNote) (ticketing.Link, ticketing.SystemConfig, ticketing.Adapter, error) {
	s := e.srv
	if s == nil || s.ticketing == nil {
		return ticketing.Link{}, ticketing.SystemConfig{}, nil, errors.New("ticketing is not available on this deployment")
	}
	link, found, err := s.ticketing.GetLink(ctx, canonicalCorrTenant(tenant), false, p.CorrelationID, p.System)
	switch {
	case err != nil:
		return ticketing.Link{}, ticketing.SystemConfig{}, nil, fmt.Errorf("the case's ticket link could not be read: %w", err)
	case !found || link.TicketNumber != p.TicketRef:
		return ticketing.Link{}, ticketing.SystemConfig{}, nil, fmt.Errorf("ticket %s is no longer linked to this case", p.TicketRef)
	case !link.Open():
		return ticketing.Link{}, ticketing.SystemConfig{}, nil, fmt.Errorf("ticket %s is not open (%s)", p.TicketRef, link.Status)
	case link.SysID == "":
		return ticketing.Link{}, ticketing.SystemConfig{}, nil, fmt.Errorf("ticket %s has no system id recorded", p.TicketRef)
	}
	if s.itsmCfg == nil {
		return ticketing.Link{}, ticketing.SystemConfig{}, nil, errors.New("no ticketing connection is configured for this workspace")
	}
	cfg, ok := s.itsmCfg.SystemConfigFor(canonicalCorrTenant(tenant), p.System)
	if !ok {
		return ticketing.Link{}, ticketing.SystemConfig{}, nil, fmt.Errorf("no %s connection is configured for this workspace", itsmSystemLabel(p.System))
	}
	a := e.adapters[p.System]
	if a == nil {
		return ticketing.Link{}, ticketing.SystemConfig{}, nil, fmt.Errorf("no adapter for %s", p.System)
	}
	return link, cfg, a, nil
}

// DryRun is read-only: the link still points at an open ticket, and the
// ticket still exists in the ITSM system (one read).
func (e *irisTicketNoteExec) DryRun(ctx context.Context, tenant string, p irisaction.ITSMNote) irisaction.DryRun {
	link, cfg, a, err := e.linkFor(ctx, tenant, p)
	if err != nil {
		return irisaction.DryRun{Performed: false, OK: false, Description: "Checked the case's ticket link.", Problem: err.Error()}
	}
	_, found, err := a.FetchIncident(ctx, cfg, ticketing.Ref{Number: link.TicketNumber, SysID: link.SysID})
	switch {
	case err != nil:
		return irisaction.DryRun{Performed: true, OK: false,
			Description: fmt.Sprintf("Asked %s whether ticket %s exists.", itsmSystemLabel(p.System), p.TicketRef),
			Problem:     "the ticketing system did not answer: " + err.Error()}
	case !found:
		return irisaction.DryRun{Performed: true, OK: false,
			Description: fmt.Sprintf("Asked %s whether ticket %s exists.", itsmSystemLabel(p.System), p.TicketRef),
			Problem:     "the ticket no longer exists"}
	}
	return irisaction.DryRun{Performed: true, OK: true,
		Description: fmt.Sprintf("Ticket %s exists in %s and is linked to this case; approving adds this one note and changes nothing else.", p.TicketRef, itsmSystemLabel(p.System))}
}

// Execute adds the note. The Service guarantees one call per request.
func (e *irisTicketNoteExec) Execute(ctx context.Context, tenant string, p irisaction.ITSMNote, _ string) (irisaction.Result, error) {
	link, cfg, a, err := e.linkFor(ctx, tenant, p)
	if err != nil {
		return irisaction.Result{}, err
	}
	if err := a.AddWorkNote(ctx, cfg, ticketing.Ref{Number: link.TicketNumber, SysID: link.SysID}, p.Note); err != nil {
		return irisaction.Result{}, fmt.Errorf("%s did not accept the note: %w", itsmSystemLabel(p.System), err)
	}
	return irisaction.Result{ExternalRef: link.TicketNumber, Message: "note added to " + link.TicketNumber}, nil
}

// irisTicketNotePayload builds the propose_itsm_update payload for a
// concluded investigation: the case's open, linked ticket on a system this
// workspace has a connection for, and a note drawn from the investigation's
// own evidence. ok=false with a reason when there is nothing to note on.
func (s *server) irisTicketNotePayload(ctx context.Context, tenant string, seed ai.ActionSeed) (irisaction.ITSMNote, bool, string) {
	corr := strings.TrimSpace(seed.Target.CorrelationID)
	if s.ticketing == nil || corr == "" {
		return irisaction.ITSMNote{}, false, ""
	}
	links, err := s.ticketing.ListLinksForCorr(ctx, canonicalCorrTenant(tenant), false, corr)
	if err != nil {
		return irisaction.ITSMNote{}, false, "the case's ticket links could not be read, so Iris proposes no ticket note"
	}
	for _, l := range links {
		if !l.Open() || l.SysID == "" || (l.ExternalSystem != irisaction.SystemServiceNow && l.ExternalSystem != irisaction.SystemJira) {
			continue
		}
		if s.itsmCfg == nil {
			break
		}
		if _, ok := s.itsmCfg.SystemConfigFor(canonicalCorrTenant(tenant), l.ExternalSystem); !ok {
			continue
		}
		p := irisaction.ITSMNote{
			System: l.ExternalSystem, TicketRef: l.TicketNumber, CorrelationID: corr,
			Title: irisNoteTitle(seed), Note: irisTicketNoteText(seed),
		}
		if irisaction.Validate(p) != nil {
			continue
		}
		return p, true, ""
	}
	return irisaction.ITSMNote{}, false, "no open ticket is linked to this case — open one from the RCA view and Iris can propose notes on it"
}

func irisNoteTitle(seed ai.ActionSeed) string {
	t := strings.TrimSpace(seed.Title)
	if t == "" {
		t = "Investigation finding"
	}
	return clampRunes("Iris: "+t, irisaction.MaxTitleChars)
}

// irisTicketNoteText is the note, built from the investigation's own parts:
// the grounded answer, the correlation engine's verdict and the evidence it
// cited. It names no person.
func irisTicketNoteText(seed ai.ActionSeed) string {
	var b strings.Builder
	b.WriteString("Iris investigation finding (Correlix case " + seed.Target.CorrelationID + ")\n\n")
	b.WriteString(clampRunes(strings.TrimSpace(seed.Text), 2400))
	if seed.Engine != nil && strings.TrimSpace(seed.Engine.Statement) != "" {
		b.WriteString("\n\nCorrelation engine")
		if seed.Engine.Tier != "" {
			b.WriteString(" (" + seed.Engine.Tier + ")")
		}
		b.WriteString(": " + clampRunes(ai.OneLine(seed.Engine.Statement), 300))
	}
	var ev []string
	for _, c := range seed.Citations {
		label := strings.TrimSpace(c.Label)
		if label == "" {
			label = c.ID
		}
		ev = append(ev, clampRunes(ai.OneLine(label), 120))
		if len(ev) == 8 {
			break
		}
	}
	if len(ev) > 0 {
		b.WriteString("\n\nEvidence: " + strings.Join(ev, "; "))
	}
	b.WriteString("\n\nProposed by Iris; sent from Correlix only after a second person approved it.")
	return clampRunes(b.String(), irisaction.MaxNoteChars)
}

func clampRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// itsm.go — read-only status for the ITSM connectors, backing Administration →
// ITSM. Gated on alerts:read (viewing incident state is an alerts concern). The
// status is scoped to the caller's tenant: each tenant sees only its OWN
// ServiceNow/Jira connector (the platform owner sees the global one).
// Configuration lives in itsm_config.go (admin-editable, per-tenant).

func (s *server) handleITSMServiceNow(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePerm(w, r, "alerts", LevelRead)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenant, _ := principalTenant(claims)
	sn := s.serviceNowFor(tenant)
	if sn == nil || !sn.Configured() {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":    false,
			"configured": false,
			"open":       []notify.ServiceNowTicket{},
		})
		return
	}
	tickets := sn.Tickets()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":    true,
		"configured": true,
		"threshold":  sn.ThresholdName(),
		"open":       tickets,
		"open_count": len(tickets),
		"auto_close": true,
	})
}

func (s *server) handleITSMJira(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePerm(w, r, "alerts", LevelRead)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tenant, _ := principalTenant(claims)
	j := s.jiraFor(tenant)
	if j == nil || !j.Configured() {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":    false,
			"configured": false,
			"open":       []notify.JiraTicket{},
		})
		return
	}
	tickets := j.Tickets()
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":    true,
		"configured": true,
		"project":    j.ProjectKey(),
		"threshold":  j.ThresholdName(),
		"open":       tickets,
		"open_count": len(tickets),
		"auto_close": true,
	})
}
