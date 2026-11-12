// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// ai_iris_route.go — the server side of the Iris routing policy
// (ai/route_policy.go, owner 2026-11-12): the caller's scope and inventory
// facts a multi-part question is answered from, and the model-with-tools path
// a question no deterministic arm covers is handed to. Every read here is the
// caller's own: the scope comes from the token, the inventory from
// visibleDevicesFor (the tenant/visibility filter every device surface uses),
// and the agent loop runs on the request's own registry and policy engine.

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"netops/backend/ai"
)

// aiScopeFacts is the caller's scope, from the authenticated token only.
func (s *server) aiScopeFacts(claims jwtClaims) *ai.ScopeFacts {
	tenant, cross := principalTenant(claims)
	sf := &ai.ScopeFacts{TenantID: tenant, AllTenants: cross}
	if !cross && isPlatformOwner(claims) && (tenant == TenantGlobal || tenant == "") {
		sf.Provider = true
	}
	if !cross && s.tenants != nil && tenant != "" {
		if t, ok := s.tenants.Get(tenant); ok {
			sf.TenantName = t.Name
		}
	}
	return sf
}

// aiInventoryFacts counts the caller's visible devices by discovery source.
func (s *server) aiInventoryFacts(claims jwtClaims) func(context.Context, ai.Principal) (ai.InventoryFacts, error) {
	return func(context.Context, ai.Principal) (ai.InventoryFacts, error) {
		devs := s.visibleDevicesFor(claims)
		counts := map[string]int{}
		for _, d := range devs {
			counts[strings.ToLower(strings.TrimSpace(d.Source))]++
		}
		inv := ai.InventoryFacts{Total: len(devs)}
		for src, n := range counts {
			inv.BySource = append(inv.BySource, ai.SourceCount{Source: src, Label: deviceSourceLabel(src), Count: n})
		}
		sort.Slice(inv.BySource, func(i, j int) bool {
			if inv.BySource[i].Count != inv.BySource[j].Count {
				return inv.BySource[i].Count > inv.BySource[j].Count
			}
			return inv.BySource[i].Source < inv.BySource[j].Source
		})
		return inv, nil
	}
}

// integrationNames are the operator's names for NMS integrations a device can
// be sourced from ("api:<system>").
var integrationNames = map[string]string{
	"vmanage": "Cisco vManage", "sdwan": "Cisco SD-WAN Manager", "meraki": "Cisco Meraki", "dnac": "Cisco Catalyst Center",
	"catalyst_center": "Cisco Catalyst Center", "mist": "Juniper Mist", "apstra": "Juniper Apstra", "nsp": "Nokia NSP",
	"cloudvision": "Arista CloudVision", "cvp": "Arista CloudVision", "netbox": "NetBox", "orchestrator": "VeloCloud Orchestrator",
}

// deviceSourceLabel is the operator's words for a device's discovery source.
func deviceSourceLabel(src string) string {
	switch src {
	case "snmp":
		return "SNMP discovery"
	case "lldp", "cdp":
		return "neighbour discovery (" + strings.ToUpper(src) + ")"
	case "manual", "static", "human_created", "field":
		return "manual entry"
	case "api":
		return "the Correlix API"
	case "netbox":
		return "a NetBox import"
	case "cloud", "cloud_api":
		return "a cloud integration"
	case "trap", "syslog", "flow", "bmp", "feed":
		return "its own telemetry (" + src + ")"
	case "":
		return "an unrecorded source"
	}
	if name, ok := strings.CutPrefix(src, "api:"); ok {
		if label, known := integrationNames[name]; known {
			return "the " + label + " integration"
		}
		return "the " + name + " integration"
	}
	return src
}

// aiAgentAnswerBudget bounds a whole model-with-tools answer on /api/ai/ask
// (several model rounds and tool reads), well inside the stream's budget.
const aiAgentAnswerBudget = 45 * time.Second

// aiAgentAnswer is the model-with-tools path for a question the deterministic
// arms do not cover (ai.AgentAnswerFunc): the bounded agent loop
// (copilot_agent.go) on the orchestrator's own registry and policy engine —
// the model chooses governed read-only tools, every call is re-authorized and
// run with the caller's principal, and the narrative passes the grounding
// verifier. nil when the caller is not entitled to it (ai.investigate): the
// orchestrator's single grounded answer runs instead.
func (s *server) aiAgentAnswer(r *http.Request, claims jwtClaims, orch *ai.Orchestrator) ai.AgentAnswerFunc {
	if !s.agentLoopEligible(claims) {
		return nil
	}
	return func(ctx context.Context, p ai.Principal, question string, prior []string) (ai.Answer, error) {
		name, key, model := s.firstConfiguredProvider(claims)
		if key == "" {
			return ai.Answer{}, ai.ErrAgentUnavailable
		}
		tenant, _ := principalTenant(claims)
		if s.aiToolBudget != nil && !s.aiToolBudget.Allow(tenant, s.dailyTokensFor(tenant)) {
			return ai.Answer{}, ai.ErrAgentUnavailable // the single grounded call reports the spent budget
		}
		// One strike per request, and the breaker's verdict across requests.
		if serr := ai.ModelStruck(ctx, name); serr != nil {
			return ai.Answer{}, serr
		}
		if s.aiBreaker != nil && !s.aiBreaker.Peek(tenant, name) {
			return ai.Answer{}, ai.ErrProviderBreakerOpen
		}
		reg, pol := agentToolbox(orch)
		specs := ai.Toolbox{Registry: reg, Policy: pol}.Manifest(p)
		if len(specs) == 0 {
			return ai.Answer{}, ai.ErrAgentUnavailable
		}
		// Server-owned prompt (LLM01): the persona, the brevity contract and
		// the data fence, then the investigation doctrine. Only the operator's
		// own questions are turns; no assistant reply is replayed.
		system := s.copilotSystemPrompt(s.orgContextBlock(ctx, claims)) + "\n\n" + ai.AgentDoctrine(time.Now().UTC())
		msgs := make([]copilotMessage, 0, len(prior)+1)
		for _, q := range prior {
			if q = strings.TrimSpace(q); q != "" {
				msgs = append(msgs, copilotMessage{Role: "user", Content: ai.RedactSecrets(q)})
			}
		}
		msgs = append(msgs, copilotMessage{Role: "user", Content: ai.RedactSecrets(question)})
		ctx, cancel := context.WithTimeout(ctx, aiAgentAnswerBudget)
		defer cancel()
		call := func(cctx context.Context, sys string, turns []ai.AgentTurn, sp []ai.ToolSpec) (string, []ai.ToolCall, error) {
			return ai.CallTools(s.egressCtx(cctx, claims), ai.ProviderDo, name, key, model, sys, turns, sp)
		}
		res, err := s.runAgentLoop(ctx, claims, p, reg, pol, specs, system, msgs, nil, call)
		if err != nil {
			ai.NoteModelFailed(ctx, name, err)
			return ai.Answer{}, err
		}
		ai.NoteModelUsed(ctx, name, model)
		lookups := make([]string, 0, len(res.Lookups))
		for _, l := range res.Lookups {
			lookups = append(lookups, l.Tool)
		}
		disc := append([]string{"Answered by the AI model, which looked up your Correlix data itself; check the cited items before acting."}, res.Disclaimers...)
		if res.Truncated {
			disc = append(disc, "The lookups were cut short at this workspace's limit.")
		}
		cites := res.Citations
		if cites == nil {
			cites = []ai.Citation{}
		}
		return ai.Answer{Mode: ai.ModeModelAnswer, Modules: []string{}, Text: res.Text, Citations: cites,
			Disclaimers: disc, Provider: name, Model: model, Statements: res.Statements, Lookups: lookups}, nil
	}
}

// aiPriorQuestions are the operator's own earlier questions in a conversation
// (newest last, at most four) — context for a model answer, never the
// assistant's replies.
func aiPriorQuestions(turns []string) []string {
	if len(turns) > 4 {
		turns = turns[len(turns)-4:]
	}
	return append([]string(nil), turns...)
}
