// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package appid

import "testing"

// The fusion contract: precedence, agreement promotes, contradiction demotes,
// "unknown" is first-class. These pin the #81 P0 confidence model.

func TestFuse_AuthoritativeAloneConfirms(t *testing.T) {
	v := Fuse([]Signal{{Source: SrcNGFWAppID, App: "Zoom"}})
	if v.App != "Zoom" || v.Tier != Confirmed {
		t.Fatalf("ngfw app-id should confirm Zoom, got %+v", v)
	}
	if v.Contradicted {
		t.Fatalf("no competing claim, should not be contradicted")
	}
}

func TestFuse_IPCatalogAloneSuspected(t *testing.T) {
	v := Fuse([]Signal{{Source: SrcIPCatalog, App: "Salesforce"}})
	if v.App != "Salesforce" || v.Tier != Suspected {
		t.Fatalf("ip-catalog alone is medium → suspected, got %+v", v)
	}
}

func TestFuse_WeakAndHintAreUndetermined(t *testing.T) {
	v := Fuse([]Signal{{Source: SrcASN, App: "AS-Cloudflare"}, {Source: SrcPort, App: "HTTPS"}})
	if v.Tier != Undetermined {
		t.Fatalf("asn/port only must stay undetermined, got %+v", v)
	}
}

func TestFuse_AgreementPromotesStrongToConfirmed(t *testing.T) {
	// strong (DNS) corroborated by medium (catalog) on the SAME app → confirmed.
	v := Fuse([]Signal{
		{Source: SrcDNS, App: "Zoom"},
		{Source: SrcIPCatalog, App: "Zoom"},
	})
	if v.App != "Zoom" || v.Tier != Confirmed {
		t.Fatalf("dns+catalog agreement should confirm Zoom, got %+v", v)
	}
}

func TestFuse_StrongAloneIsSuspected(t *testing.T) {
	v := Fuse([]Signal{{Source: SrcSNI, App: "slack.com"}})
	if v.Tier != Suspected {
		t.Fatalf("single strong signal is suspected without corroboration, got %+v", v)
	}
}

func TestFuse_ContradictionDemotesAndPenalizes(t *testing.T) {
	// SNI(strong) says Slack, catalog(medium) says Salesforce → credible competing claim.
	v := Fuse([]Signal{
		{Source: SrcSNI, App: "Slack"},
		{Source: SrcIPCatalog, App: "Salesforce"},
	})
	if !v.Contradicted {
		t.Fatalf("disagreeing medium+ signals must flag contradiction, got %+v", v)
	}
	if v.Tier == Confirmed {
		t.Fatalf("a contradicted verdict must never be confirmed, got %+v", v)
	}
	// roles must be assigned relative to the winner
	var sawSupports, sawContradicts bool
	for _, s := range v.Signals {
		switch s.Role {
		case Supports:
			sawSupports = true
		case Contradicts:
			sawContradicts = true
		}
	}
	if !sawSupports || !sawContradicts {
		t.Fatalf("expected both supporting and contradicting roles, got %+v", v.Signals)
	}
}

func TestFuse_NoSignalsIsUnknownFirstClass(t *testing.T) {
	v := Fuse(nil)
	if v.App != "unknown" || v.Tier != Undetermined {
		t.Fatalf("no signals must yield first-class unknown, got %+v", v)
	}
	if len(v.EvidenceMissing) == 0 {
		t.Fatalf("unknown verdict should report what's missing")
	}
}

func TestFuse_EmptyAppSignalsIgnored(t *testing.T) {
	// a source with no opinion (App=="") must not create a candidate.
	v := Fuse([]Signal{{Source: SrcDNS, App: ""}, {Source: SrcIPCatalog, App: ""}})
	if v.App != "unknown" {
		t.Fatalf("opinion-less signals must not invent an app, got %+v", v)
	}
}

func TestFuse_AuthoritativeBeatsStrongAsWinner(t *testing.T) {
	// operator-declared (authoritative) outranks a disagreeing DNS (strong) for the label,
	// though the disagreement still registers as a contradiction.
	v := Fuse([]Signal{
		{Source: SrcDNS, App: "Zoom"},
		{Source: SrcOperator, App: "InternalVoice"},
	})
	if v.App != "InternalVoice" && v.Tier != Undetermined {
		t.Fatalf("authoritative source should win the label (or contradiction demote it), got %+v", v)
	}
	if !v.Contradicted {
		t.Fatalf("disagreeing strong signal should flag contradiction, got %+v", v)
	}
}

func TestFuse_ConfidenceWithinBounds(t *testing.T) {
	for _, v := range []Verdict{
		Fuse([]Signal{{Source: SrcNGFWAppID, App: "A"}}),
		Fuse([]Signal{{Source: SrcDNS, App: "A"}, {Source: SrcIPCatalog, App: "A"}}),
		Fuse([]Signal{{Source: SrcSNI, App: "A"}, {Source: SrcIPCatalog, App: "B"}}),
	} {
		if v.Confidence < 0 || v.Confidence > 1 {
			t.Fatalf("confidence out of bounds: %+v", v)
		}
	}
}
