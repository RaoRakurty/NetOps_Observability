// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bgpdepth

// aspa_leak_test.go — a failing ASPA provider must not publish its own URL.
//
// The defect this guards (3.4-04): HTTPProvider.ASPA wrapped the transport
// error verbatim. Go's http.Client wraps every transport failure in a
// *url.Error whose Error() prints the FULL request URL, and an operator points
// BGP_ASPA_PROVIDER_URL at their own validator, which may authenticate with a
// query-string token. The handler puts that error in a 200 body for any
// infrastructure:read caller. The sibling ASPAStatus already publishes the
// HOSTNAME only, for exactly this reason.
//
// Every credential below is fabricated.

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
)

const (
	// A provider URL shaped like a real validator endpoint that authenticates
	// with a query parameter. The token is fabricated.
	aspaCredURL   = "https://validator.example.net/aspa?token=FAKE-ASPA-TOKEN-0000"
	aspaCredValue = "FAKE-ASPA-TOKEN-0000"
	aspaCredHost  = "validator.example.net"
)

// urlErrorFetcher fails the way net/http actually fails: a *url.Error carrying
// the full request URL.
type urlErrorFetcher struct{ *fakeFetcher }

func (urlErrorFetcher) Get(_ context.Context, rawURL string, _ int64) ([]byte, error) {
	return nil, &url.Error{Op: "Get", URL: rawURL, Err: errors.New("dial tcp 203.0.113.9:443: connect: connection refused")}
}

func TestASPAProviderFailureNeverCarriesTheProviderURL(t *testing.T) {
	cases := map[string]Fetcher{
		// The realistic shape: net/http's own *url.Error.
		"url.Error from the transport": urlErrorFetcher{newFake()},
		// A Fetcher that formats the URL into its own message. No interface can
		// stop an implementation doing this, so the boundary must survive it.
		"a fetcher that quotes the URL itself": newFake(),
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			p := NewASPAProvider(aspaCredURL, f, fixedNow())
			res, err := p.ASPA(context.Background(), "AS64500")
			if err == nil {
				t.Fatalf("a failed fetch produced a verdict: %+v", res)
			}
			msg := err.Error()
			if strings.Contains(msg, aspaCredValue) {
				t.Errorf("the provider credential is in the error: %q", msg)
			}
			if strings.Contains(msg, "token=") || strings.Contains(msg, "?") {
				t.Errorf("a query string is in the error: %q", msg)
			}
			if strings.Contains(msg, aspaCredURL) {
				t.Errorf("the full provider URL is in the error: %q", msg)
			}
			// The operator still has to be able to tell WHICH upstream failed.
			if !strings.Contains(msg, aspaCredHost) {
				t.Errorf("the error does not name the provider host, so it is not actionable: %q", msg)
			}
			if !strings.Contains(msg, "aspa provider") {
				t.Errorf("the failure is not attributed to the provider: %q", msg)
			}
			if res.Found || len(res.Providers) != 0 {
				t.Fatalf("a failed fetch returned partial data: %+v", res)
			}
		})
	}
}

// SafeErrorText is the boundary itself. It has to hold for callers that have
// not been written yet.
func TestSafeErrorTextStripsEveryTraceOfTheURL(t *testing.T) {
	full := aspaCredURL + "&asn=64500"
	cases := []struct {
		name string
		err  error
	}{
		{"url.Error", &url.Error{Op: "Get", URL: full, Err: errors.New("connection reset by peer")}},
		{"a plain error quoting the URL", errors.New("no scripted body for " + full)},
		{"a wrapped url.Error", errors.New("outer: " + (&url.Error{Op: "Get", URL: full, Err: errors.New("boom")}).Error())},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := SafeErrorText(c.err, aspaCredURL, full)
			if strings.Contains(got, aspaCredValue) {
				t.Errorf("the credential survived: %q", got)
			}
			if strings.Contains(got, full) || strings.Contains(got, aspaCredURL) {
				t.Errorf("the URL survived: %q", got)
			}
			if got == "" {
				t.Error("the error was reduced to nothing; an unexplained failure is a silent failure")
			}
		})
	}
	if SafeErrorText(nil) != "" {
		t.Error("a nil error must render as nothing")
	}
}

// The failure reason must still distinguish the cases an operator acts on
// differently: a refused URL is a configuration mistake, a timeout is not.
func TestSafeErrorTextKeepsTheReasonReadable(t *testing.T) {
	err := &url.Error{Op: "Get", URL: aspaCredURL, Err: context.DeadlineExceeded}
	got := SafeErrorText(err, aspaCredURL)
	if !strings.Contains(got, "deadline exceeded") {
		t.Errorf("the reason was thrown away with the URL: %q", got)
	}
	if !strings.Contains(got, aspaCredHost) {
		t.Errorf("the host was thrown away with the URL: %q", got)
	}
}
