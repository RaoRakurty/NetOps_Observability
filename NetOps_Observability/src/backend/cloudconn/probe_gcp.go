package cloudconn

// probe_gcp.go — LIVE GCP identity + permission probes (Wave 4 #13), stdlib-only.
//
//   - GET  /v1/projects                      — the reachable project scopes
//     (also proves the exchanged token works).
//   - POST /v1/projects/{id}:testIamPermissions — GCP's CANONICAL dry
//     permission check: the API returns exactly the subset of the requested
//     permissions the caller holds. No target API is invoked; read-only.
//
// All calls go through doExchangeHTTP (deadline, capped body, bounded retry)
// and map failures onto the sanitized ExchangeError surface.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

const gcpCRMBase = "https://cloudresourcemanager.googleapis.com"

// GCPProject is one reachable project scope. Non-secret.
type GCPProject struct {
	ProjectID string `json:"projectId"`
	Name      string `json:"name"`
}

// GCPProbeClient performs the live Cloud Resource Manager probes. Injectable;
// zero values use the real endpoint and a bounded default client.
type GCPProbeClient struct {
	Client  *http.Client
	CRMBase string // override for tests
}

// NewGCPProbeClient returns the production probe client.
func NewGCPProbeClient() *GCPProbeClient {
	return &GCPProbeClient{Client: newExchangeHTTPClient()}
}

func (p *GCPProbeClient) base() string {
	if p.CRMBase != "" {
		return p.CRMBase
	}
	return gcpCRMBase
}

// doCRM runs one bearer-authenticated CRM call, returning the 200 body.
func (p *GCPProbeClient) doCRM(ctx context.Context, method, path, bearer string, jsonBody []byte) ([]byte, error) {
	if strings.TrimSpace(bearer) == "" {
		return nil, &ExchangeError{Provider: ProviderGCP, Code: "request_invalid", Msg: "no GCP token to probe with"}
	}
	endpoint := p.base() + path
	status, body, attempts, err := doExchangeHTTP(ctx, p.Client, ProviderGCP, func() (*http.Request, error) {
		var rd *strings.Reader
		if jsonBody != nil {
			rd = strings.NewReader(string(jsonBody))
		} else {
			rd = strings.NewReader("")
		}
		hreq, err := http.NewRequestWithContext(ctx, method, endpoint, rd)
		if err != nil {
			return nil, err
		}
		hreq.Header.Set("Authorization", "Bearer "+bearer)
		if jsonBody != nil {
			hreq.Header.Set("Content-Type", "application/json")
		}
		return hreq, nil
	})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, gcpTokenError(status, body, attempts)
	}
	return body, nil
}

// Projects lists the ACTIVE projects the token can reach (one bounded page —
// a connector's scope probe needs reachability, not an exhaustive crawl).
func (p *GCPProbeClient) Projects(ctx context.Context, bearer string) ([]GCPProject, error) {
	body, err := p.doCRM(ctx, http.MethodGet,
		"/v1/projects?pageSize=100&filter="+url.QueryEscape("lifecycleState:ACTIVE"), bearer, nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Projects []GCPProject `json:"projects"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &ExchangeError{Provider: ProviderGCP, Code: "malformed_response", Msg: "projects response unparseable"}
	}
	return resp.Projects, nil
}

// TestPermissions runs projects.testIamPermissions for the given permission set
// and returns permission → granted (absent from the response = not granted).
func (p *GCPProbeClient) TestPermissions(ctx context.Context, bearer, projectID string, permissions []string) (map[string]bool, error) {
	proj := strings.TrimSpace(projectID)
	if proj == "" || len(permissions) == 0 {
		return nil, &ExchangeError{Provider: ProviderGCP, Code: "request_invalid", Msg: "project id and at least one permission are required"}
	}
	reqBody, err := json.Marshal(map[string]any{"permissions": permissions})
	if err != nil {
		return nil, &ExchangeError{Provider: ProviderGCP, Code: "request_invalid", Msg: "permission probe request unserializable"}
	}
	body, err := p.doCRM(ctx, http.MethodPost, "/v1/projects/"+url.PathEscape(proj)+":testIamPermissions", bearer, reqBody)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Permissions []string `json:"permissions"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &ExchangeError{Provider: ProviderGCP, Code: "malformed_response", Msg: "testIamPermissions response unparseable"}
	}
	granted := make(map[string]bool, len(permissions))
	for _, perm := range permissions {
		granted[perm] = false
	}
	for _, perm := range resp.Permissions {
		granted[perm] = true
	}
	return granted, nil
}
