// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// caseconn_cisco_sharedclient_test.go — the Smart Bonding connector must not
// write on the wire client every tenant shares (§3a, §11).
//
// CreateCase and FetchCase used to set StagingHost on the shared *cisco.Client
// before each call. Two tenants escalating at the same moment therefore wrote
// and read that field on two handler goroutines with no lock: a real data race,
// and a cross-tenant environment swap in which one tenant's staging host
// decides where another tenant's real case is filed. The environment now lives
// on a per-call copy.

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/ticketing/vendors/cisco"
)

// ciscoEnvStub answers the token exchange and the pull/call poll in process and
// records the HOST each request went to, so a test can see which Cisco
// environment a tenant's request actually reached.
type ciscoEnvStub struct {
	mu    sync.Mutex
	hosts map[string]int
}

func newCiscoEnvStub() *ciscoEnvStub { return &ciscoEnvStub{hosts: map[string]int{}} }

func (s *ciscoEnvStub) RoundTrip(r *http.Request) (*http.Response, error) {
	_, _ = io.Copy(io.Discard, r.Body)
	s.mu.Lock()
	s.hosts[r.URL.Host]++
	s.mu.Unlock()

	body := `{"access_token":"cisco-bearer","expires_in":3600}`
	switch r.URL.Path {
	case cisco.PullPath:
		body = `{"srNumber":"695123456","status":"Open","lastUpdatedDate":"2026-09-05T10:00:00Z"}`
	case cisco.PushPath:
		body = `{"srNumber":"695123456","Field80":"cxd.cisco.com","Field81":"per-case-token"}`
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Request:    r,
	}, nil
}

func (s *ciscoEnvStub) sawHost(host string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hosts[host]
}

func ciscoEnvConnector(s *ciscoEnvStub) (*CiscoSmartBondingConnector, *cisco.Client) {
	cl := &cisco.Client{HTTP: &http.Client{Transport: s}}
	return NewCiscoSmartBondingConnector(cl), cl
}

func TestCiscoFetchCaseKeepsTheTenantEnvironmentOffTheSharedClient(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	stub := newCiscoEnvStub()
	c, shared := ciscoEnvConnector(stub)
	cfg := ciscoTenantCfg("acme-client", "acme-secret",
		"sb-staging.cisco.com", "https://sb-staging.cisco.com/oauth2/token")

	got, found, err := c.FetchCase(context.Background(), cfg, CaseRef{Number: "695123456"})
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !found || got.Status != "Open" {
		t.Fatalf("fetch = %+v found=%v, want the polled SR", got, found)
	}
	// The tenant's environment reached the wire...
	if n := stub.sawHost("sb-staging.cisco.com"); n == 0 {
		t.Fatalf("the poll never reached the tenant's staging host (hosts seen: %v)", stub.hosts)
	}
	// ...without being written onto the client every other tenant uses.
	if shared.StagingHost != "" {
		t.Fatalf("the connector wrote %q onto the shared client; the next tenant's case would go to that environment", shared.StagingHost)
	}
}

func TestCiscoCreateCaseKeepsTheTenantEnvironmentOffTheSharedClient(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	stub := newCiscoEnvStub()
	c, shared := ciscoEnvConnector(stub)
	cfg := ciscoTenantCfg("acme-client", "acme-secret",
		"sb-staging.cisco.com", "https://sb-staging.cisco.com/oauth2/token")

	if _, err := c.CreateCase(context.Background(), cfg, CaseRequest{
		Synopsis: "OSPF adjacency stuck in ExStart on ae0", Description: "Evidence only.",
		Severity: "S3", ContactEmail: "jane.doe@customer.example", ContactName: "Jane Doe",
		SerialNumber: "FDO123", IdempotencyKey: "txn-1",
		Approval: Approval{Actor: "user:42", ApprovedAt: time.Now()},
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if n := stub.sawHost("sb-staging.cisco.com"); n == 0 {
		t.Fatalf("the create never reached the tenant's staging host (hosts seen: %v)", stub.hosts)
	}
	if shared.StagingHost != "" {
		t.Fatalf("the connector wrote %q onto the shared client; the next tenant's case would be opened in that environment", shared.StagingHost)
	}
}

// Two tenants polling at the same moment, as two handler goroutines do. Run
// under -race: before the fix this is a genuine write/read data race on the one
// *cisco.Client the whole server shares.
func TestCiscoConcurrentTenantsDoNotRaceOnTheSharedClient(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	stub := newCiscoEnvStub()
	c, _ := ciscoEnvConnector(stub)
	tenants := []TACConnectorConfig{
		ciscoTenantCfg("acme-client", "acme-secret",
			"sb-staging.cisco.com", "https://sb-staging.cisco.com/oauth2/token"),
		ciscoTenantCfg("globex-client", "globex-secret", "", ""),
	}

	var wg sync.WaitGroup
	for _, cfg := range tenants {
		wg.Add(1)
		go func(cfg TACConnectorConfig) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if _, _, err := c.FetchCase(context.Background(), cfg, CaseRef{Number: "695123456"}); err != nil {
					t.Errorf("fetch: %v", err)
					return
				}
			}
		}(cfg)
	}
	wg.Wait()

	// Each tenant's polls went to its OWN environment, and neither count is
	// short: a swap would show up as one host taking the other's traffic.
	if n := stub.sawHost("sb-staging.cisco.com"); n < 20 {
		t.Fatalf("the staging tenant's polls reached its host %d times, want at least 20 (hosts seen: %v)", n, stub.hosts)
	}
	if n := stub.sawHost(cisco.SmartBondingHost); n < 20 {
		t.Fatalf("the production tenant's polls reached its host %d times, want at least 20 (hosts seen: %v)", n, stub.hosts)
	}
}
