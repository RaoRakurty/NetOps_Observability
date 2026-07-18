package main

// cloud_connectors_metrics_test.go — Wave 4 #13 slice 4: per-provider exchange
// counters recorded by the Identity Broker and exposed in Prometheus text.

import (
	"context"
	"strings"
	"testing"
	"time"

	"netops/backend/cloudconn"
)

// failingAdapter returns a fixed error from every exchange.
type failingAdapter struct {
	fakeAdapter
	err error
}

func (f *failingAdapter) ExchangeCredential(context.Context, cloudconn.ExchangeRequest) (cloudconn.ScopedToken, error) {
	return cloudconn.ScopedToken{}, f.err
}

func TestExchangeOutcomeMapping(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, exOutcomeSuccess},
		{&cloudconn.ExchangeError{Provider: cloudconn.ProviderAWS, Code: "denied"}, exOutcomeAuthFail},
		{&cloudconn.ExchangeError{Provider: cloudconn.ProviderAWS, Code: "throttled"}, exOutcomeThrottled},
		{&cloudconn.ExchangeError{Provider: cloudconn.ProviderAWS, Code: "provider_error"}, exOutcomeAPIError},
		{&cloudconn.ExchangeError{Provider: cloudconn.ProviderAWS, Code: "network"}, exOutcomeAPIError},
		{cloudconn.ErrPlatformCredentialsMissing, exOutcomeDeferred},
		{cloudconn.ErrWorkloadAssertionMissing, exOutcomeDeferred},
		{cloudconn.ErrProviderExchangeDeferred, exOutcomeDeferred},
	}
	for i, c := range cases {
		if got := exchangeOutcome(c.err); got != c.want {
			t.Errorf("case %d: exchangeOutcome(%v) = %q want %q", i, c.err, got, c.want)
		}
	}
}

func TestBrokerRecordsExchangeMetrics(t *testing.T) {
	fake := &fakeAdapter{provider: cloudconn.ProviderAWS, ttl: time.Hour}
	b, store := newTestBroker(t, fake)
	c := mkActiveConnector(t, store, "tenant-m", "arn:aws:iam::123456789012:role/correlix-observer")
	req := scopedTokenRequest{Tenant: "tenant-m", ConnectorID: c.ConnectorID, ProviderAccount: "123456789012", CapabilitySetID: "aws-observer-v1"}

	// One fresh mint + one cache hit.
	if _, err := b.TokenFor(context.Background(), req); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := b.TokenFor(context.Background(), req); err != nil {
		t.Fatalf("cache hit: %v", err)
	}

	// One denied exchange through a failing adapter (fresh broker, same metrics
	// type — assert counters roll up independently per outcome).
	deny := &failingAdapter{err: &cloudconn.ExchangeError{Provider: cloudconn.ProviderAWS, Code: "denied", Msg: "no"}}
	b.adapter = func(cloudconn.Provider) cloudconn.CloudIdentityProvider { return deny }
	b.Invalidate(c.ConnectorID)
	if _, err := b.TokenFor(context.Background(), req); err == nil {
		t.Fatal("denied exchange must error")
	}

	var sb strings.Builder
	b.metrics.write(&sb)
	out := sb.String()
	for _, want := range []string{
		`netops_cloudconn_exchange_total{provider="aws",outcome="auth_success"} 1`,
		`netops_cloudconn_exchange_total{provider="aws",outcome="auth_fail"} 1`,
		`netops_cloudconn_exchange_latency_seconds_count{provider="aws"} 2`,
		`netops_cloudconn_exchange_cache_hits_total{provider="aws"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q\n---\n%s", want, out)
		}
	}
	// No secret/token material in the exposition.
	if strings.Contains(out, "tok-") {
		t.Fatal("metrics output leaked token material")
	}
}
