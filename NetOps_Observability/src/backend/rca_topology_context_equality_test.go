// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// rca_topology_context_equality_test.go — RCA document v2 §2/§7: ONE builder,
// two endpoints. The RCA report and the rca-path-view must carry the
// byte-identical topology_context for the same object and principal, or the
// document and the workspace would draw two different topologies again (the
// three-derivation defect P-3E0400 exposed).

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"netops/backend/internal/rca"
)

func TestRCATopologyContextSameInReportAndPathView(t *testing.T) {
	f := newTopoCtxFixture(t)
	for name, tok := range map[string]string{"tenant user": f.a.token, "platform owner": f.owner} {
		st1, rep, raw1 := f.topo(t, tok, topoCorrA, "rca-report", "")
		st2, pv, raw2 := f.topo(t, tok, topoCorrA, "rca-path-view", "")
		if st1 != http.StatusOK || st2 != http.StatusOK {
			t.Fatalf("%s: report %d (%s) / path view %d (%s)", name, st1, raw1, st2, raw2)
		}
		a, _ := json.Marshal(rep)
		b, _ := json.Marshal(pv)
		if !bytes.Equal(a, b) {
			t.Fatalf("%s: the report and the path view built different topology contexts:\nreport:    %s\npath view: %s", name, a, b)
		}
		if rep.State != rca.TopoStateTopologyOnly || len(rep.Edges) == 0 || len(rep.Faults) == 0 || len(rep.Causal) == 0 {
			t.Fatalf("%s: the equality must be over a populated context, got %+v", name, rep)
		}
	}
}
