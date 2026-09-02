package notify

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"netops/backend/models"
)

// fakeSNS is a stand-in for the SNS endpoint that records every signed request.
type fakeSNS struct {
	mu     sync.Mutex
	auths  []string
	forms  []url.Values
	hashes []string
	dates  []string
	status int
}

func newFakeSNS(t *testing.T) (*fakeSNS, *httptest.Server) {
	t.Helper()
	f := &fakeSNS{status: http.StatusOK}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(b))
		f.mu.Lock()
		f.auths = append(f.auths, r.Header.Get("Authorization"))
		f.forms = append(f.forms, form)
		f.hashes = append(f.hashes, r.Header.Get("X-Amz-Content-Sha256"))
		f.dates = append(f.dates, r.Header.Get("X-Amz-Date"))
		st := f.status
		f.mu.Unlock()
		if st >= 300 {
			http.Error(w, "<ErrorResponse>bad request</ErrorResponse>", st)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return f, srv
}

// authRe is the SigV4 Authorization grammar AWS requires. Anything that does not
// match is rejected by SNS with a signature error — so asserting the SHAPE here
// is asserting the contract, not the implementation.
var authRe = regexp.MustCompile(`^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/[0-9]{8}/us-east-1/sns/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature=[0-9a-f]{64}$`)

// TestSNSPublishSignsAndShapesRequest is the request-signing/shape proof: a
// SigV4 Authorization header with the right credential scope and signed-header
// set, a payload hash that actually matches the body, and the Publish form
// parameters SNS expects.
func TestSNSPublishSignsAndShapesRequest(t *testing.T) {
	f, srv := newFakeSNS(t)
	s := NewSNS("AKIDEXAMPLE", "SECRETEXAMPLEKEY", "us-east-1", "", "arn:aws:sns:us-east-1:123456789012:correlix-alerts").
		WithEndpoint(srv.URL + "/")

	if err := s.Send(models.Alert{Rule: "HostOOM", Severity: "critical", Summary: "host memory exhausted"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(f.auths) != 1 {
		t.Fatalf("publish calls = %d, want 1", len(f.auths))
	}
	if !authRe.MatchString(f.auths[0]) {
		t.Fatalf("Authorization header is not a well-formed SigV4 header:\n%s", f.auths[0])
	}
	if f.dates[0] == "" || !strings.HasSuffix(f.dates[0], "Z") {
		t.Errorf("X-Amz-Date = %q, want an ISO8601 basic UTC timestamp", f.dates[0])
	}
	form := f.forms[0]
	if form.Get("Action") != "Publish" || form.Get("Version") != "2010-03-31" {
		t.Errorf("unexpected action/version: %v", form)
	}
	if got := form.Get("TopicArn"); got != "arn:aws:sns:us-east-1:123456789012:correlix-alerts" {
		t.Errorf("TopicArn = %q", got)
	}
	if msg := form.Get("Message"); !strings.Contains(msg, "HostOOM") {
		t.Errorf("Message = %q, want the rule in it", msg)
	}
	// The signed payload hash must be the hash of the body that was actually
	// sent — a mismatch is the classic SigV4 bug and AWS rejects it outright.
	want := sha256.Sum256([]byte(form.Encode()))
	if f.hashes[0] != hex.EncodeToString(want[:]) {
		// form.Encode() re-sorts identically to url.Values.Encode on the client,
		// so this is a fair comparison.
		t.Errorf("X-Amz-Content-Sha256 = %s does not match sha256(body) = %s", f.hashes[0], hex.EncodeToString(want[:]))
	}
}

// TestSNSSignatureBindsToTheBody proves the signature is over the payload: two
// different alerts must not produce the same signature (a signature that
// ignored the body would let a proxy rewrite the message).
func TestSNSSignatureBindsToTheBody(t *testing.T) {
	f, srv := newFakeSNS(t)
	s := NewSNS("AKIDEXAMPLE", "SECRETEXAMPLEKEY", "us-east-1", "+14155550123", "").WithEndpoint(srv.URL + "/")
	if err := s.Send(models.Alert{Rule: "A", Severity: "critical", Summary: "one"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if err := s.Send(models.Alert{Rule: "B", Severity: "critical", Summary: "two"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(f.auths) != 2 {
		t.Fatalf("calls = %d, want 2", len(f.auths))
	}
	if f.auths[0] == f.auths[1] {
		t.Fatal("two different messages produced an identical signature — the body is not being signed")
	}
}

// TestSNSFansOutToTopicAndNumbers: a topic AND phone numbers means one Publish
// per destination.
func TestSNSFansOutToTopicAndNumbers(t *testing.T) {
	f, srv := newFakeSNS(t)
	s := NewSNS("AKIDEXAMPLE", "SECRETEXAMPLEKEY", "us-east-1", "+14155550123, +442071838750", "arn:aws:sns:us-east-1:123456789012:t").
		WithEndpoint(srv.URL + "/")
	if err := s.Send(models.Alert{Rule: "R", Severity: "critical", Summary: "s"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(f.forms) != 3 {
		t.Fatalf("publish calls = %d, want 3 (1 topic + 2 numbers)", len(f.forms))
	}
	var phones []string
	for _, form := range f.forms {
		if p := form.Get("PhoneNumber"); p != "" {
			phones = append(phones, p)
		}
	}
	if len(phones) != 2 || phones[0] != "+14155550123" || phones[1] != "+442071838750" {
		t.Fatalf("phone destinations = %v", phones)
	}
}

func TestSNSSendRefusesIncompleteConfiguration(t *testing.T) {
	_, srv := newFakeSNS(t)
	cases := []struct {
		name                        string
		ak, sk, region, nums, topic string
	}{
		{"no access key", "", "sk", "us-east-1", "+14155550123", ""},
		{"no secret key", "ak", "", "us-east-1", "+14155550123", ""},
		{"no region", "ak", "sk", "", "+14155550123", ""},
		{"no destination", "ak", "sk", "us-east-1", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := NewSNS(c.ak, c.sk, c.region, c.nums, c.topic).WithEndpoint(srv.URL + "/")
			if err := s.Send(models.Alert{Rule: "R", Severity: "critical"}); err == nil {
				t.Fatal("an incompletely configured SNS channel must error, never silently drop the page")
			}
		})
	}
}

// TestSNSRejectsAnUnsafeRegion: the region is interpolated into the endpoint
// host, so a region that is not a region must not produce a dialable endpoint.
func TestSNSRejectsAnUnsafeRegion(t *testing.T) {
	for _, bad := range []string{"us-east-1/@evil.example.com", "evil.example.com", "us-east-1:8080", "US-EAST-1"} {
		if ep := snsEndpointFor(bad); ep != "" {
			t.Errorf("region %q produced endpoint %q — must be refused", bad, ep)
		}
		s := NewSNS("ak", "sk", bad, "+14155550123", "")
		if err := s.Send(models.Alert{Rule: "R", Severity: "critical"}); err == nil {
			t.Errorf("region %q must not be dialable", bad)
		}
	}
	if ep := snsEndpointFor("us-gov-west-1"); ep != "https://sns.us-gov-west-1.amazonaws.com/" {
		t.Errorf("legitimate region rejected: %q", ep)
	}
}

func TestSNSSurfacesAPIError(t *testing.T) {
	f, srv := newFakeSNS(t)
	f.status = http.StatusForbidden
	s := NewSNS("ak", "sk", "us-east-1", "+14155550123", "").WithEndpoint(srv.URL + "/")
	err := s.Send(models.Alert{Rule: "R", Severity: "critical"})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want a 403-bearing error, got %v", err)
	}
}

// TestSNSWithEndpointDoesNotMutateTheOriginal guards the copy semantics of the
// builder (a shared *SNS must not be retargeted by one caller's WithEndpoint).
func TestSNSWithEndpointDoesNotMutateTheOriginal(t *testing.T) {
	s := NewSNS("ak", "sk", "us-east-1", "+14155550123", "")
	orig := s.endpoint
	_ = s.WithEndpoint("https://example.invalid/")
	if s.endpoint != orig {
		t.Fatalf("WithEndpoint mutated the receiver: %q", s.endpoint)
	}
}
