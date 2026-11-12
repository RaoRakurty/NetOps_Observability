// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

// rca_topology_context_stub.go — a PLACEHOLDER for the topology workstream's
// contract (RCA document v2, docs/design/RCA_DOCUMENT_V2_2026-11-12.md §2/§6).
//
// The wording/document workstream (WS-B) places section 6's call site,
//
//	{{template "topologyContext" .TopologyContext}}
//
// before the topology workstream (WS-A) has merged. This file supplies the two
// names that call site needs so the branch builds and renders:
//
//   - type TopologyContext — WS-A's topology_context.go defines the real one;
//   - rcaTopologyContextPartialSrc — WS-A's partial file defines the real
//     {{define "topologyContext"}} (+ SVG).
//
// DELETE THIS FILE when WS-A lands: its files declare the same two names, so the
// build fails until this stub is gone — the merge cannot silently keep it. The
// Report field (Report.TopologyContext) and the call site stay as they are.

// TopologyContext — stub; see the file comment. Only the fields the stub
// partial reads.
type TopologyContext struct {
	State       string `json:"state"`
	Reason      string `json:"reason,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// rcaTopologyContextPartialSrc — stub partial. The call site only invokes it
// with a non-nil context, so the stub just states the context's state.
const rcaTopologyContextPartialSrc = `{{define "topologyContext"}}<div class="note topo-ctx" data-state="{{.State}}">{{.Reason}}{{if .Remediation}} {{.Remediation}}{{end}}</div>{{end}}`
