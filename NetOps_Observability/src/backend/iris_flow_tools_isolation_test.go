// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// Iris flow tools with link and window arguments (tracker 406, §3a.5).
//
// The fake ClickHouse records every statement and the tenant_scope it ran at.
// Pinned here: a device the caller cannot see (another tenant's, or none at
// all) answers ai.ErrNotFound and NO statement runs; the caller's own device
// scopes by the Flows page's stricter link rule plus its own exporter address
// only; an interface name resolves through the caller's interface-name rows
// and never another tenant's; a bad window or an interface without its device
// is refused (ai.ErrBadArgs) before any query; Correlix's own monitoring
// traffic is left out and said so; the answer links to the Flows page on the
// same device, interface and window; ?as_tenant cannot widen any of it.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"netops/backend/ai"
	"netops/backend/internal/flownames"
)

func flowToolDS(t *testing.T, claims jwtClaims, scope string) (aiDataSource, *server) {
	t.Helper()
	s := flowsTestServer(t)
	s.ifaceNames = flownames.NewExporter()
	s.ifaceNames.Install([]flownames.Row{
		{TenantID: "acme", ExporterAddr: "10.1.0.1", IfIndex: 7, IfName: "GigabitEthernet7"},
		// globex names an interface the same on its own router: it must never
		// resolve for acme.
		{TenantID: "globex", ExporterAddr: "10.2.0.1", IfIndex: 3, IfName: "WAN-Uplink"},
	})
	return aiDataSource{srv: s, ctx: context.Background(), scope: scope, claims: claims}, s
}

const flowTotalsReply = `{"meta":[],"data":[{"bytes_total":"2048","packets_total":"10","flows":"4","sources":"2","rate_reported":"0"}],"rows":1}`

func TestIrisFlowToolForeignDeviceIsNotFoundAndNeverQueries(t *testing.T) {
	for _, q := range []string{"top_talkers", "flow_summary", "service_flow_summary"} {
		calls := fakeCHScoped(t, flowTotalsReply)
		d, _ := flowToolDS(t, acme(), "acme")
		for _, dev := range []string{"globex-core", "10.2.0.1", "GLOBEX-CORE", "no-such-device"} {
			_, err := d.ModuleQuery(context.Background(), ai.Principal{Tenant: "acme"}, q, ai.ToolArgs{"device": dev})
			if !errors.Is(err, ai.ErrNotFound) {
				t.Fatalf("%s device=%q: want ai.ErrNotFound (never reveal another tenant's device), got %v", q, dev, err)
			}
		}
		if len(*calls) != 0 {
			t.Fatalf("%s: a device the caller cannot see ran %d statements:\n%v", q, len(*calls), *calls)
		}
	}
}

func TestIrisFlowToolOwnDeviceUsesTheLinkRuleAndOwnExporterOnly(t *testing.T) {
	t.Setenv("CX_PLATFORM_ADDRESSES", "10.70.0.5")
	calls := fakeCHScoped(t, flowTotalsReply)
	d, _ := flowToolDS(t, acme(), "acme")
	res, err := d.ModuleQuery(context.Background(), ai.Principal{Tenant: "acme"}, "flow_summary",
		ai.ToolArgs{"device": "acme-core", "interface": "gigabitethernet7", "window": "1h"})
	if err != nil {
		t.Fatalf("own device: %v", err)
	}
	if len(*calls) != 1 {
		t.Fatalf("want one statement, got %d", len(*calls))
	}
	c := (*calls)[0]
	if c.scope != "acme" {
		t.Errorf("ran at tenant_scope %q, want acme", c.scope)
	}
	for _, want := range []string{
		acmeLinkClause,                   // the stricter link ownership rule (tracker 400 (a))
		"sampler_address = '10.1.0.1'",   // the device's own inventory address
		"(in_if = 7 OR out_if = 7)",      // the interface resolved by name
		"NOT (src_addr IN ('10.70.0.5')", // Correlix's own monitoring traffic left out (c)
		"ts >= toDateTime64(",            // an explicit, parsed window
	} {
		if !strings.Contains(c.sql, want) {
			t.Errorf("statement lacks %q:\n%s", want, c.sql)
		}
	}
	if strings.Contains(c.sql, "src_addr IN ('10.1.0.1')") || strings.Contains(c.sql, "dst_addr IN ('10.1.0.1')") {
		t.Errorf("a device-scoped read must not admit endpoint-only records:\n%s", c.sql)
	}
	if strings.Contains(c.sql, "globex") || strings.Contains(c.sql, "10.2.0.1") {
		t.Errorf("TENANT LEAK: another tenant reached the statement:\n%s", c.sql)
	}
	for _, alias := range []string{" AS bytes,", " AS packets,", " AS ts,", " AS bytes\n", " AS packets\n"} {
		if strings.Contains(c.sql, alias) {
			t.Errorf("ClickHouse 24.8 trap: an output aliased %q:\n%s", strings.TrimSpace(alias), c.sql)
		}
	}
	if len(res.Items) != 1 {
		t.Fatalf("want one summary item, got %+v", res)
	}
	it := res.Items[0]
	if !strings.Contains(it.Text, "on acme-core interface GigabitEthernet7") || !strings.Contains(it.Text, "the last 1 hour") {
		t.Errorf("summary must name the device, interface and window: %q", it.Text)
	}
	if !strings.HasPrefix(it.Href, "#/explore/flows?") || !strings.Contains(it.Href, "device=10.1.0.1") || !strings.Contains(it.Href, "if=7") ||
		!strings.Contains(it.Href, "from=") || !strings.Contains(it.Href, "to=") {
		t.Errorf("href must open the Flows page on the same link and window: %q", it.Href)
	}
	notes := strings.Join(res.Notes, " | ")
	if !strings.Contains(notes, "monitoring traffic is left out") {
		t.Errorf("the platform exclusion must be said: %q", notes)
	}
	if !strings.Contains(notes, "did not report a sampling rate") {
		t.Errorf("a not-reported sampling basis must be said: %q", notes)
	}
}

func TestIrisFlowToolInterfaceNameNeverResolvesThroughAnotherTenant(t *testing.T) {
	calls := fakeCHScoped(t, flowTotalsReply)
	d, _ := flowToolDS(t, acme(), "acme")
	// "WAN-Uplink" is globex's interface name on globex's router; on acme-core
	// it names nothing, so the call is refused — never mapped to globex's index.
	_, err := d.ModuleQuery(context.Background(), ai.Principal{Tenant: "acme"}, "top_talkers",
		ai.ToolArgs{"device": "acme-core", "interface": "WAN-Uplink"})
	if !errors.Is(err, ai.ErrBadArgs) {
		t.Fatalf("unknown interface name: want ai.ErrBadArgs, got %v", err)
	}
	if len(*calls) != 0 {
		t.Fatalf("a refused interface ran %d statements", len(*calls))
	}
}

func TestIrisFlowToolBadArgumentsAreRefusedBeforeAnyQuery(t *testing.T) {
	calls := fakeCHScoped(t, flowTotalsReply)
	d, _ := flowToolDS(t, acme(), "acme")
	for name, args := range map[string]ai.ToolArgs{
		"window not on the list":       {"window": "90d"},
		"window and from/to together":  {"window": "1h", "from": "2026-11-13T00:00:00Z", "to": "2026-11-13T01:00:00Z"},
		"from without to":              {"from": "2026-11-13T00:00:00Z"},
		"span over seven days":         {"from": "2026-11-01T00:00:00Z", "to": "2026-11-13T00:00:00Z"},
		"interface without its device": {"interface": "7"},
		"garbage instant":              {"from": "yesterday'; DROP TABLE x", "to": "now"},
	} {
		_, err := d.ModuleQuery(context.Background(), ai.Principal{Tenant: "acme"}, "flow_summary", args)
		if !errors.Is(err, ai.ErrBadArgs) {
			t.Errorf("%s: want ai.ErrBadArgs, got %v", name, err)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("refused arguments ran %d statements", len(*calls))
	}
}

func TestIrisFlowToolNoDeviceTenantNeverQueries(t *testing.T) {
	calls := fakeCHScoped(t, flowTotalsReply)
	nobody := jwtClaims{Sub: "n@nobody", Role: RoleOperator, Tenant: "nobody"}
	d, _ := flowToolDS(t, nobody, "nobody")
	for _, q := range []string{"top_talkers", "flow_summary", "service_flow_summary"} {
		res, err := d.ModuleQuery(context.Background(), ai.Principal{Tenant: "nobody"}, q, ai.ToolArgs{"window": "6h"})
		if err != nil || len(res.Items) != 0 {
			t.Fatalf("%s: a no-device tenant must read an honest empty, got %+v / %v", q, res, err)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("default-closed: a tenant with no devices ran %d statements", len(*calls))
	}
}

func TestIrisFlowToolAsTenantCannotWiden(t *testing.T) {
	calls := fakeCHScoped(t, flowTotalsReply)
	// A scoped caller whose request named another org: the data source is built
	// from the caller's own claims (as_tenant is a cross-tenant-only narrowing),
	// so globex's router still reads as not found and its rows stay out.
	claims := acme()
	d, _ := flowToolDS(t, claims, "acme")
	if _, err := d.ModuleQuery(context.Background(), ai.Principal{Tenant: "acme"}, "top_talkers",
		ai.ToolArgs{"device": "globex-core"}); !errors.Is(err, ai.ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}
	if _, err := d.ModuleQuery(context.Background(), ai.Principal{Tenant: "acme"}, "top_talkers", ai.ToolArgs{}); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 {
		t.Fatalf("want exactly the whole-view statement, got %d", len(*calls))
	}
	c := (*calls)[0]
	if c.scope != "acme" || strings.Contains(c.sql, "globex") || strings.Contains(c.sql, "10.2.0.1") {
		t.Fatalf("TENANT LEAK in the whole-view read (scope %q):\n%s", c.scope, c.sql)
	}
}

func TestIrisFlowToolCrossTenantReadsAnyDevice(t *testing.T) {
	calls := fakeCHScoped(t, flowTotalsReply)
	d, _ := flowToolDS(t, superA(), "__all__")
	if _, err := d.ModuleQuery(context.Background(), ai.Principal{Cross: true}, "flow_summary",
		ai.ToolArgs{"device": "globex-core", "interface": "WAN-Uplink"}); err != nil {
		t.Fatalf("the platform owner may read any device: %v", err)
	}
	if len(*calls) != 1 || !strings.Contains((*calls)[0].sql, "sampler_address = '10.2.0.1'") ||
		!strings.Contains((*calls)[0].sql, "(in_if = 3 OR out_if = 3)") {
		t.Fatalf("cross-tenant device read: %v", *calls)
	}
}
