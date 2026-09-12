// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	_ "embed"
	"encoding/json"
	"strings"
)

// oidindex.go — MIB-backed OID registry. Replaces the hand-curated maps that used
// to live in snmptrap.go (the "curated map" hack the owner flagged) with a single
// data-driven index. The index is generated at BUILD time (pysmi over a vendored
// MIB tree → mibs/index/oididx.json — see mibs/README.md + the design doc
// docs/design/research/telemetry-normalization-architecture.md §6) and embedded
// here, so the RUNTIME stays stdlib-only (CLAUDE.md §6: no runtime MIB compiler;
// build-time codegen + go:embed is allowed). Adding vendor OIDs = drop .mib files,
// `make mib-index`, rebuild — never edit Go.

//go:embed mibs/index/oididx.json
var oidIndexJSON []byte

// OIDNode is one resolved MIB object/notification (the (name,type,enum,index,
// module) tuple a decode needs — mirrors gosmi's node model).
type OIDNode struct {
	Name         string            `json:"name"`
	MIB          string            `json:"mib"`
	Kind         string            `json:"kind"` // "scalar" | "column" | "notification"
	Type         string            `json:"type,omitempty"`
	Enum         map[string]string `json:"enum,omitempty"`  // integer value → label
	Index        []string          `json:"index,omitempty"` // table INDEX clause
	SeverityHint string            `json:"severity_hint,omitempty"`
}

type oidIndex struct {
	Version string             `json:"version"`
	Nodes   map[string]OIDNode `json:"nodes"`
}

var oidIdx oidIndex

func init() {
	// A malformed embedded index must not crash the binary; fall back to an empty
	// index (callers then return the raw OID — honest, never a panic).
	_ = json.Unmarshal(oidIndexJSON, &oidIdx) // best-effort: embedded JSON; a failure leaves the index empty
	if oidIdx.Nodes == nil {
		oidIdx.Nodes = map[string]OIDNode{}
	}
}

// lookupOID resolves a dotted OID. Scalars/notifications match exactly; table
// columns match by longest dotted-prefix (the trailing arcs are the row index),
// returning the index suffix. ok=false ⇒ unknown OID (caller keeps it raw).
func lookupOID(oid string) (node OIDNode, indexSuffix string, ok bool) {
	if n, found := oidIdx.Nodes[oid]; found {
		return n, "", true
	}
	// longest-prefix for columns: strip trailing arcs at dot boundaries
	s := oid
	for {
		i := strings.LastIndex(s, ".")
		if i < 0 {
			break
		}
		s = s[:i]
		if n, found := oidIdx.Nodes[s]; found && n.Kind == "column" {
			return n, oid[len(s)+1:], true
		}
	}
	return OIDNode{}, "", false
}
