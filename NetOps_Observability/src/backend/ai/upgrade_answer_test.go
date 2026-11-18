// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"strings"
	"testing"
)

func TestUpgradeProcedureFromTheQuestion(t *testing.T) {
	o := reviewOrch(t, &reviewCalls{})
	ans, err := o.answerUpgradeProcedure(context.Background(), tenantA(), "how do I upgrade a Catalyst 9300?", Plan{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeUpgradeProcedure || !strings.Contains(ans.Title, "IOS XE") {
		t.Fatalf("mode/title: %s %q", ans.Mode, ans.Title)
	}
	for _, want := range []string{"1. Performed by the engineer:", "Iris can confirm it read-only with: show version",
		"https://www.cisco.com/", "Written in Correlix's own words"} {
		if !strings.Contains(ans.Text, want) {
			t.Errorf("procedure lacks %q:\n%s", want, ans.Text)
		}
	}
	if len(ans.Citations) != 1 || !strings.HasPrefix(ans.Citations[0].Href, "https://www.cisco.com/") || ans.Citations[0].Class != ClassDocumentation {
		t.Fatalf("source citation: %+v", ans.Citations)
	}
	if !hasDisc(ans, NoActionNotice) || len(ans.NextActions) != 0 {
		t.Fatalf("a procedure executes nothing and proposes no action: %v %v", ans.Disclaimers, ans.NextActions)
	}
}

func TestUpgradeProcedureFromTheCallersDevice(t *testing.T) {
	calls := &reviewCalls{}
	o := reviewOrch(t, calls)
	ans, _ := o.answerUpgradeProcedure(context.Background(), tenantA(), "what are the steps to upgrade core-sw-1",
		Plan{Entities: map[string]string{"device": "core-sw-1"}}, nil)
	if !strings.Contains(ans.Text, "core-sw-1 runs Juniper") || !strings.Contains(ans.Text, "juniper.net") {
		t.Fatalf("the device's platform did not pick the procedure:\n%s", ans.Text)
	}
	// §3a: another tenant's device is not resolved, so no platform is inferred.
	ans, _ = o.answerUpgradeProcedure(context.Background(), tenantB(), "what are the steps to upgrade core-sw-1",
		Plan{Entities: map[string]string{"device": "core-sw-1"}}, nil)
	if strings.Contains(ans.Text, "core-sw-1 runs") || !strings.Contains(ans.Text, "say which one") {
		t.Fatalf("tenant B learned tenant A's device platform:\n%s", ans.Text)
	}
}

func TestUpgradeProcedureNeverGuesses(t *testing.T) {
	o := reviewOrch(t, &reviewCalls{})
	ans, _ := o.answerUpgradeProcedure(context.Background(), tenantA(), "how do I upgrade my router", Plan{}, nil)
	if ans.Mode == ModeUnavailable || IsDeadEnd(ans) {
		t.Fatalf("the list of procedures is an answer, not a dead end: %+v", ans)
	}
	for _, want := range []string{"IOS XE", "NX-OS", "Junos", "EOS"} {
		if !strings.Contains(ans.Text, want) {
			t.Errorf("list lacks %s:\n%s", want, ans.Text)
		}
	}
}

// The dialect comes from the vendor registry (the one vendor vocabulary); a
// profile with no procedure (IOS XR, classic IOS) picks none.
func TestDeviceDialect(t *testing.T) {
	for _, c := range []struct {
		d    DeviceRef
		want string
	}{
		{DeviceRef{Vendor: "Juniper Networks"}, "juniper/junos"},
		{DeviceRef{Vendor: "Arista"}, "arista/eos"},
		{DeviceRef{Vendor: "Cisco", Platform: "ASR 9000 IOS-XR"}, "cisco/ios_xr"},
		{DeviceRef{Platform: "Mystery OS"}, ""},
	} {
		if got := deviceDialect(c.d); got != c.want {
			t.Errorf("%+v → %q, want %q", c.d, got, c.want)
		}
	}
}

// A device whose platform label names the family ("Catalyst 9300") gets that
// family's procedure even when the registry only knows it as Cisco.
func TestUpgradeProcedureFromThePlatformLabel(t *testing.T) {
	o := reviewOrch(t, &reviewCalls{})
	ans, _ := o.answerUpgradeProcedure(context.Background(), tenantA(), "how do I upgrade edge-1",
		Plan{Entities: map[string]string{"device": "edge-1"}}, nil)
	if !strings.Contains(ans.Title, "IOS XE") || !strings.Contains(ans.Text, "edge-1 runs Cisco") {
		t.Fatalf("the platform label did not pick the procedure: %q\n%s", ans.Title, ans.Text)
	}
}
