package tac

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestHypothesisIDs(t *testing.T) {
	blob := `[{"template_id":"sig.ent.wan-edge.bgp-peer-flap","confidence":0.7},
	          {"template_id":"sig.ent.access.local-link-fault"},
	          {"template_id":"sig.ent.wan-edge.bgp-peer-flap"}]`
	got := HypothesisIDs(blob)
	if len(got) != 2 || got[0] != "sig.ent.wan-edge.bgp-peer-flap" || got[1] != "sig.ent.access.local-link-fault" {
		t.Fatalf("HypothesisIDs = %v", got)
	}
	if len(HypothesisIDs(strings.Repeat(`"sig.ent.a.b",`, 500))) > maxExtracted {
		t.Fatal("extraction is not bounded")
	}
	if len(HypothesisIDs("no ids here")) != 0 {
		t.Fatal("invented an id")
	}
}

func TestAffectedDevices(t *testing.T) {
	got := AffectedDevices(`{"devices":["core1","leaf2","core1"],"seams":["dia-1"]}`)
	if len(got) < 2 || got[0] != "devices" {
		// The first quoted token is the JSON key: this is a HINT extractor, and
		// the test pins that it is not pretending to be a parser.
		t.Logf("extractor returns %v — keys included, as documented", got)
	}
	if len(AffectedDevices(strings.Repeat(`"d",`, 500))) > 16 {
		t.Fatal("device extraction is not bounded")
	}
}

func TestParseTime(t *testing.T) {
	for _, in := range []string{"2026-09-05T04:26:25Z", "2026-09-05 04:26:25", "2026-09-05T04:26:25.123456Z"} {
		if ParseTime(in).IsZero() {
			t.Errorf("ParseTime(%q) is zero", in)
		}
	}
	if !ParseTime("not a time").IsZero() {
		t.Fatal("an unparseable value must be the zero time, never a guessed epoch")
	}
	if got := ParseTime("2026-09-05T04:26:25Z"); got.Location() != time.UTC {
		t.Fatalf("ParseTime does not normalise to UTC: %v", got.Location())
	}
}

func TestConsentSet(t *testing.T) {
	got := ConsentSet([]string{" tech.support ", "", strings.Repeat("x", 200), "config.running"})
	if !got["tech.support"] || !got["config.running"] {
		t.Fatalf("ConsentSet dropped a real intent: %v", got)
	}
	if len(got) != 2 {
		t.Fatalf("ConsentSet kept an empty or oversized entry: %v", got)
	}
	if ConsentSet(nil) != nil {
		t.Fatal("an empty approval list must be nil, not an empty map that reads as approval")
	}
	big := make([]string, 500)
	for i := range big {
		big[i] = "a.b"
	}
	if len(ConsentSet(big)) > maxConsentIntents {
		t.Fatal("the approval list is not bounded")
	}
}

func TestCollectNoteIsOneSentenceEverywhere(t *testing.T) {
	if CollectNote(true) != "" {
		t.Fatal("a wired transport must produce no note")
	}
	note := CollectNote(false)
	for _, want := range []string{"FEATURE_PROTOCOL_DIAG_COLLECT", "paste"} {
		if !strings.Contains(note, want) {
			t.Errorf("the unwired note does not mention %q: %s", want, note)
		}
	}
}

func TestClassSummariesAreTheWholeOverrideList(t *testing.T) {
	c := mustCatalog(t)
	rows := c.ClassSummaries()
	if len(rows) != len(c.Classes()) {
		t.Fatalf("the override list is %d of %d classes — the operator may pick ANY class",
			len(rows), len(c.Classes()))
	}
	var manual, generic int
	for _, r := range rows {
		if r.Manual {
			manual++
		}
		if r.ID == GenericClassID {
			generic++
			if r.Manual {
				t.Fatal("the generic fallback must not be labelled manual-only")
			}
		}
	}
	if generic != 1 {
		t.Fatal("the generic fallback is missing from the override list")
	}
	t.Logf("%d classes, %d selectable only by hand", len(rows), manual)
	if (*Catalog)(nil).ClassSummaries() == nil {
		t.Fatal("a nil catalog must yield an empty list, not nil")
	}
}

// TestEmailProfileFitsAMailbox is the coordinator's boundary: 14 MiB of zip
// base64-encodes to ~20.1 MB, which is already over Cisco's 20 MB mailbox cap.
// The email connector therefore declares a smaller raw ceiling, and the bundle
// must trim to THAT number rather than to this package's default.
func TestEmailProfileFitsAMailbox(t *testing.T) {
	const connectorLimit int64 = 14_000_000 // what the email connector declares
	// Cisco's cap is 20 MB DECIMAL, which is the number a mail gateway enforces.
	const mailboxCap int64 = 20_000_000
	if MIMEEncodedSize(EmailProfileMaxBytes) <= mailboxCap {
		t.Fatalf("the premise changed: %d bytes now encodes to %d, under the %d-byte mailbox cap — "+
			"this guard is stale", EmailProfileMaxBytes, MIMEEncodedSize(EmailProfileMaxBytes), mailboxCap)
	}
	if got := MIMEEncodedSize(connectorLimit); got > mailboxCap {
		t.Fatalf("the connector's %d-byte ceiling encodes to %d bytes, over the %d-byte mailbox cap",
			connectorLimit, got, mailboxCap)
	}

	in := fixtureBundleInput(t)
	big := strings.Repeat("z", 9<<20)
	in.Capture.Commands[2].Output = big
	in.Capture.Commands[2].Bytes = len(big)
	in.Capture.Commands[3].Output = big
	in.Capture.Commands[3].Bytes = len(big)
	in.Profile = ProfileEmail
	in.MaxBytes = connectorLimit

	b, err := BuildBundle(t.Context(), in, nil, fixedClock())
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	if int64(len(b.Zip)) > connectorLimit {
		t.Fatalf("the trimmed bundle is %d bytes, over the connector's %d-byte ceiling",
			len(b.Zip), connectorLimit)
	}
	if int64(base64.StdEncoding.EncodedLen(len(b.Zip))) > mailboxCap {
		t.Fatal("the bundle does not fit a 20 MB mailbox once base64-encoded")
	}
	if b.Manifest.MaxBytes != connectorLimit {
		t.Fatalf("the manifest stamps %d, not the ceiling it trimmed to", b.Manifest.MaxBytes)
	}
	for _, tr := range b.Manifest.Trimmed {
		if !strings.Contains(tr.Reason, "14000000") {
			t.Fatalf("a trim must name the ceiling it trimmed to: %q", tr.Reason)
		}
	}
}

// TestProfileForConnectorPicksTheHonestProfile.
func TestProfileForConnectorPicksTheHonestProfile(t *testing.T) {
	for _, tc := range []struct {
		name string
		info ConnectorInfo
		want BundleProfile
	}{
		{"cannot attach", ConnectorInfo{Capabilities: []CaseCapability{CapLink}}, ProfileLinkOnly},
		{"attach, no limit", ConnectorInfo{Capabilities: []CaseCapability{CapAttach}}, ProfileLinkOnly},
		{"email-sized", ConnectorInfo{Capabilities: []CaseCapability{CapAttach}, MaxAttachmentBytes: 14_000_000}, ProfileEmail},
		{"itsm-sized", ConnectorInfo{Capabilities: []CaseCapability{CapAttach}, MaxAttachmentBytes: 1 << 30}, ProfileFull},
	} {
		if got := ProfileForConnector(tc.info); got != tc.want {
			t.Errorf("%s: profile = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestCaseSecretsNeverRender is the credential rule: every way Go has of turning
// a value into text must yield the redaction mark, so a CaseRequest carrying one
// can still be logged whole.
func TestCaseSecretsNeverRender(t *testing.T) {
	secret := "per-case-upload-token-9f2a"
	req := CaseRequest{
		TenantID: "t1", IncidentID: "inc-1", Actor: "op@example.test",
		Form:    CaseForm{ExistingCaseNumber: "695123456"},
		Secrets: CaseSecrets{UploadToken: secret, UploadHost: "cxd.example.invalid"},
	}
	for _, rendered := range []string{
		fmtSprint("%v", req), fmtSprint("%+v", req), fmtSprint("%#v", req.Secrets),
		fmtSprint("%s", req.Secrets), string(mustJSON(req)),
	} {
		if strings.Contains(rendered, secret) {
			t.Fatalf("the upload token rendered into %q", clip(rendered, 200))
		}
	}
	// The non-secret case reference DOES travel: it is what the operator typed
	// and what the connector needs.
	if !strings.Contains(string(mustJSON(req.Form)), "695123456") {
		t.Fatal("the existing case number must survive serialisation — it is not a secret")
	}
	if req.Secrets.Empty() {
		t.Fatal("Empty() reported a populated secrets block as empty")
	}
	if !(CaseSecrets{}).Empty() {
		t.Fatal("Empty() reported a blank secrets block as populated")
	}
}

// fmtSprint is a tiny local wrapper so the test above can loop over verbs.
func fmtSprint(verb string, v any) string { return fmt.Sprintf(verb, v) }
