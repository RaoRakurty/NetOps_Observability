package cloudconn

import "errors"

// ContractError is a stable, machine-readable contract violation. Code is a
// stable token the API/UI can branch on; Msg is human text. It never carries a
// secret, token or assertion.
type ContractError struct {
	Code string
	Msg  string
}

func (e *ContractError) Error() string {
	if e == nil {
		return ""
	}
	if e.Code == "" {
		return e.Msg
	}
	return e.Code + ": " + e.Msg
}

// ErrProviderExchangeDeferred is returned by a provider adapter's live-network
// methods (ExchangeCredential/DiscoverScopes/ValidateCapabilities/Revoke) that are
// not wired to the real provider in this build. The framework, broker, cache,
// storage, templates and validation are fully implemented; the live provider call
// is the documented follow-up. Callers must treat this as "not yet available",
// NOT as an auth failure.
var ErrProviderExchangeDeferred = errors.New("cloudconn: live provider exchange not wired in this build (deferred phase)")
