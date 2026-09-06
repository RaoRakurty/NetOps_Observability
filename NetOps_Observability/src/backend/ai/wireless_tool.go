// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// wireless_tool.go — the Iris wireless module's read-only tools (#128 Phase 6,
// design docs/Wireslessdesign.md §18). v1 ships the PII-FREE surfaces only:
// AP/radio inventory and controller state carry no client identifier, so no
// redaction question arises. The client-history tools (session timeline, roam
// history — the SensitivityRestricted question, report Q5) stay unregistered
// until the pseudonymization contract lands; the module answers about them
// with a clean "not available yet" rather than an unredacted leak.
//
// Same seam pattern as WindowDataSource: an optional interface the real server
// implements; a DataSource without it simply doesn't register the tools.

import (
	"context"
	"fmt"
)

// WirelessAPSummary is the PII-free AP projection the assistant may see.
type WirelessAPSummary struct {
	Name          string
	Model         string
	SiteID        string
	ControllerRef string
	RadioCount    int
	RadiosDown    int
	Stale         bool
	UplinkSwitch  string
	UplinkPort    string
}

// WirelessControllerSummary is the PII-free controller projection.
type WirelessControllerSummary struct {
	Name        string
	Vendor      string
	ClusterRole string
	Visibility  string
	Members     int
	APCount     int
	Stale       bool
}

// WirelessDataSource is the optional seam for wireless inventory reads. All
// implementations MUST scope by the principal's tenant (the wireless store
// enforces it; TestWirelessCrossTenantIsolation proves it end-to-end).
type WirelessDataSource interface {
	ListWirelessAPs(ctx context.Context, p Principal, limit int) ([]WirelessAPSummary, error)
	ListWirelessControllers(ctx context.Context, p Principal) ([]WirelessControllerSummary, error)
}

type wirelessAPInventoryTool struct{ ds WirelessDataSource }

func (t wirelessAPInventoryTool) Name() string            { return "get_wireless_ap_inventory" }
func (t wirelessAPInventoryTool) Module() string          { return "wireless" }
func (t wirelessAPInventoryTool) Capability() Capability  { return CapRead }
func (t wirelessAPInventoryTool) RequiredPerms() []string { return []string{"infrastructure:read"} }
func (t wirelessAPInventoryTool) Freshness() Freshness    { return FreshnessLive }
func (t wirelessAPInventoryTool) Run(ctx context.Context, p Principal, _ ToolArgs) (ToolResult, error) {
	aps, err := t.ds.ListWirelessAPs(ctx, p, 200)
	if err != nil {
		return ToolResult{}, err
	}
	if len(aps) == 0 {
		return ToolResult{Items: []EvidenceItem{{
			CitationID: "wifi-ap-none", Kind: "device",
			Text: "No wireless access points are in the inventory for this tenant.",
		}}}, nil
	}
	var items []EvidenceItem
	var down, stale int
	for i, ap := range aps {
		state := "ok"
		if ap.RadiosDown > 0 {
			state = fmt.Sprintf("%d/%d radios down", ap.RadiosDown, ap.RadioCount)
			down++
		}
		if ap.Stale {
			state += " (stale: not seen by the last poll)"
			stale++
		}
		uplink := ""
		if ap.UplinkSwitch != "" {
			uplink = " uplink " + ap.UplinkSwitch + ":" + ap.UplinkPort
		}
		items = append(items, EvidenceItem{
			CitationID: fmt.Sprintf("wifi-ap-%d", i+1), Kind: "device",
			Text: fmt.Sprintf("AP %s (%s) site=%s%s — %s", ap.Name, ap.Model, ap.SiteID, uplink, state),
			Href: "#/wireless",
		})
	}
	return ToolResult{
		Items: items,
		Notes: []string{fmt.Sprintf("%d AP(s): %d with radio faults, %d stale", len(aps), down, stale)},
	}, nil
}

type wirelessControllersTool struct{ ds WirelessDataSource }

func (t wirelessControllersTool) Name() string            { return "get_wireless_controllers" }
func (t wirelessControllersTool) Module() string          { return "wireless" }
func (t wirelessControllersTool) Capability() Capability  { return CapRead }
func (t wirelessControllersTool) RequiredPerms() []string { return []string{"infrastructure:read"} }
func (t wirelessControllersTool) Freshness() Freshness    { return FreshnessLive }
func (t wirelessControllersTool) Run(ctx context.Context, p Principal, _ ToolArgs) (ToolResult, error) {
	cs, err := t.ds.ListWirelessControllers(ctx, p)
	if err != nil {
		return ToolResult{}, err
	}
	if len(cs) == 0 {
		return ToolResult{Items: []EvidenceItem{{
			CitationID: "wifi-wlc-none", Kind: "device",
			Text: "No wireless controllers are configured for this tenant.",
		}}}, nil
	}
	var items []EvidenceItem
	for i, c := range cs {
		items = append(items, EvidenceItem{
			CitationID: fmt.Sprintf("wifi-wlc-%d", i+1), Kind: "device",
			Text: fmt.Sprintf("Controller %s (%s, %s) — %d member(s), %d AP(s), visibility %s",
				c.Name, c.Vendor, c.ClusterRole, c.Members, c.APCount, c.Visibility),
			Href: "#/wireless",
		})
	}
	return ToolResult{Items: items}, nil
}
