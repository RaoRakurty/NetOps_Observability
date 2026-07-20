package cloudconn

// probe_azure.go — LIVE Azure identity + permission probes (Wave 4 #13),
// stdlib-only.
//
//   - GET /subscriptions               — the cheapest authenticated ARM read:
//     proves the token works AND enumerates the reachable subscription scopes.
//   - GET /subscriptions/{id}/providers/Microsoft.Authorization/permissions —
//     the RBAC actions the principal actually holds at that scope; the pack's
//     declared permissions are evaluated against actions/notActions with
//     Azure wildcard semantics. Read-only; no target API is invoked.
//
// All calls go through doExchangeHTTP (deadline, capped body, bounded retry)
// and map failures onto the sanitized ExchangeError surface.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	azureARMBase               = "https://management.azure.com"
	azureSubscriptionsAPIVer   = "2022-12-01"
	azureAuthPermissionsAPIVer = "2022-04-01"
	azureMgmtGroupsAPIVer      = "2020-05-01"
	// One bounded enumeration page (§9) — same contract as the other probes.
	azureMgmtGroupDescendantsTop = 100
)

// AzureSubscription is one reachable subscription scope. Non-secret.
type AzureSubscription struct {
	SubscriptionID string `json:"subscriptionId"`
	DisplayName    string `json:"displayName"`
	State          string `json:"state"`
}

// AzureRBACPermission is one granted RBAC permission set (from the
// Microsoft.Authorization/permissions read).
type AzureRBACPermission struct {
	Actions    []string `json:"actions"`
	NotActions []string `json:"notActions"`
}

// AzureARMProbeClient performs the live ARM probes. Injectable; zero values use
// the real ARM endpoint and a bounded default client.
type AzureARMProbeClient struct {
	Client  *http.Client
	BaseURL string // override for tests
}

// NewAzureARMProbeClient returns the production probe client.
func NewAzureARMProbeClient() *AzureARMProbeClient {
	return &AzureARMProbeClient{Client: newExchangeHTTPClient()}
}

func (p *AzureARMProbeClient) base() string {
	if p.BaseURL != "" {
		return p.BaseURL
	}
	return azureARMBase
}

// getARM runs one bearer-authenticated ARM GET, returning the 200 body.
func (p *AzureARMProbeClient) getARM(ctx context.Context, path, bearer string) ([]byte, error) {
	if strings.TrimSpace(bearer) == "" {
		return nil, &ExchangeError{Provider: ProviderAzure, Code: "request_invalid", Msg: "no Azure token to probe with"}
	}
	endpoint := p.base() + path
	status, body, attempts, err := doExchangeHTTP(ctx, p.Client, ProviderAzure, func() (*http.Request, error) {
		hreq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		hreq.Header.Set("Authorization", "Bearer "+bearer)
		return hreq, nil
	})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, armProbeError(status, body, attempts)
	}
	return body, nil
}

// Subscriptions lists the subscriptions the token can reach.
func (p *AzureARMProbeClient) Subscriptions(ctx context.Context, bearer string) ([]AzureSubscription, error) {
	body, err := p.getARM(ctx, "/subscriptions?api-version="+azureSubscriptionsAPIVer, bearer)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Value []AzureSubscription `json:"value"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &ExchangeError{Provider: ProviderAzure, Code: "malformed_response", Msg: "subscriptions response unparseable"}
	}
	return resp.Value, nil
}

// Permissions returns the RBAC permission sets the principal holds at the
// subscription scope.
func (p *AzureARMProbeClient) Permissions(ctx context.Context, bearer, subscriptionID string) ([]AzureRBACPermission, error) {
	sub := strings.TrimSpace(subscriptionID)
	if sub == "" {
		return nil, &ExchangeError{Provider: ProviderAzure, Code: "request_invalid", Msg: "subscription id required for the permission probe"}
	}
	path := "/subscriptions/" + url.PathEscape(sub) +
		"/providers/Microsoft.Authorization/permissions?api-version=" + azureAuthPermissionsAPIVer
	body, err := p.getARM(ctx, path, bearer)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Value []AzureRBACPermission `json:"value"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &ExchangeError{Provider: ProviderAzure, Code: "malformed_response", Msg: "permissions response unparseable"}
	}
	return resp.Value, nil
}

// ManagementGroupSubscriptions lists the member SUBSCRIPTIONS under a
// management group (org-level onboarding, Wave 5 #17): one bounded page of the
// group's descendants, filtered to subscription entries. Read-only; requires
// the Management Group Reader role at the group scope.
func (p *AzureARMProbeClient) ManagementGroupSubscriptions(ctx context.Context, bearer, groupID string) ([]AzureSubscription, error) {
	g := strings.TrimSpace(groupID)
	if g == "" {
		return nil, &ExchangeError{Provider: ProviderAzure, Code: "request_invalid", Msg: "management group id required for the org enumeration probe"}
	}
	path := "/providers/Microsoft.Management/managementGroups/" + url.PathEscape(g) +
		"/descendants?api-version=" + azureMgmtGroupsAPIVer + "&%24top=" + strconv.Itoa(azureMgmtGroupDescendantsTop)
	body, err := p.getARM(ctx, path, bearer)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Value []struct {
			Name       string `json:"name"` // subscription id for subscription entries
			Type       string `json:"type"`
			Properties struct {
				DisplayName string `json:"displayName"`
			} `json:"properties"`
		} `json:"value"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, &ExchangeError{Provider: ProviderAzure, Code: "malformed_response", Msg: "management-group descendants response unparseable"}
	}
	subs := make([]AzureSubscription, 0, len(resp.Value))
	for _, v := range resp.Value {
		if strings.EqualFold(v.Type, "Microsoft.Management/managementGroups/subscriptions") {
			subs = append(subs, AzureSubscription{SubscriptionID: v.Name, DisplayName: v.Properties.DisplayName, State: "Enabled"})
		}
	}
	return subs, nil
}

// AzureActionGranted evaluates one required RBAC action against the granted
// permission sets: granted when some set's actions match it and none of that
// set's notActions do (Azure evaluation semantics, wildcard-aware).
func AzureActionGranted(perms []AzureRBACPermission, required string) bool {
	for _, ps := range perms {
		allowed := false
		for _, a := range ps.Actions {
			if azureActionMatch(a, required) {
				allowed = true
				break
			}
		}
		if !allowed {
			continue
		}
		denied := false
		for _, na := range ps.NotActions {
			if azureActionMatch(na, required) {
				denied = true
				break
			}
		}
		if !denied {
			return true
		}
	}
	return false
}

// azureActionMatch reports whether a granted action PATTERN (may contain '*',
// matching any sequence) covers the required action string. Case-insensitive.
// A required string that itself contains '*' (a pack-declared wildcard like
// "*/read") is treated literally — so "*" and an identical pattern cover it.
func azureActionMatch(pattern, action string) bool {
	p := strings.ToLower(strings.TrimSpace(pattern))
	a := strings.ToLower(strings.TrimSpace(action))
	if p == "*" || p == a {
		return true
	}
	parts := strings.Split(p, "*")
	if len(parts) == 1 {
		return p == a
	}
	// Anchored wildcard match: first part is a prefix, last a suffix, middles in order.
	if !strings.HasPrefix(a, parts[0]) {
		return false
	}
	rest := a[len(parts[0]):]
	for _, mid := range parts[1 : len(parts)-1] {
		i := strings.Index(rest, mid)
		if i < 0 {
			return false
		}
		rest = rest[i+len(mid):]
	}
	return strings.HasSuffix(rest, parts[len(parts)-1])
}

// armProbeError maps a non-200 ARM response to a sanitized ExchangeError.
func armProbeError(status int, body []byte, attempts int) error {
	var er struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &er) // best-effort: fall through to status mapping
	code := "provider_error"
	switch {
	case strings.EqualFold(er.Error.Code, "AuthorizationFailed"),
		strings.EqualFold(er.Error.Code, "InvalidAuthenticationToken"),
		status == http.StatusUnauthorized, status == http.StatusForbidden:
		code = "denied"
	case status == http.StatusBadRequest, status == http.StatusNotFound:
		code = "request_invalid"
	}
	msg := er.Error.Code
	if er.Error.Message != "" {
		msg += ": " + truncateForError(er.Error.Message)
	}
	if msg == "" {
		msg = "ARM returned status " + strconv.Itoa(status)
	}
	return &ExchangeError{Provider: ProviderAzure, Code: code, HTTPStatus: status, Msg: msg, Attempts: attempts}
}
