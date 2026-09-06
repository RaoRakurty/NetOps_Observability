// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package processors

// seal.go — the `seal` action: REVERSIBLE masking.
//
// mask and hash destroy. seal encrypts, so an operator holding
// `sensitive_data.unmask` can recover the original later through an audited
// reveal, while everyone else sees a masked display form. That is the whole
// difference, and it is why seal is the only action whose output is a token
// rather than a rendering.
//
// This file contains NO CRYPTOGRAPHY. It does not know the cipher, the key
// hierarchy, the token format or the VRL that implements them — all of that
// lives in package sealing, behind the SealEngine seam below. The processor
// framework compiles and simulates; it must never learn how to encrypt, or
// swapping AES-CTR for a KMS becomes a change to the compiler, the simulator,
// the API and the UI instead of a change to one provider.

import (
	"fmt"
	"sync"
)

// SealEngine is the seam to package sealing. It is deliberately the smallest
// surface that lets seal compile and simulate:
//
//   - EdgeSnippet renders the VRL the router executes for one field;
//   - SealValue seals one value in-process, for the PREVIEW path.
//
// Both must produce values readable by the same unseal path, which is the
// property package sealing's parity tests hold up.
type SealEngine interface {
	// EdgeSnippet returns VRL sealing `path` for the given binding, or an error
	// if this tenant cannot seal (no key custody, unusable tenant id).
	EdgeSnippet(tenant, processorID, field, dataType, path string) (string, error)
	// SealValue seals a single value, used by the simulator so preview shows a
	// REAL token rather than a plausible-looking placeholder.
	SealValue(tenant, processorID, field, dataType, plaintext string) (string, error)
	// DisplayForm renders what a viewer without unmask permission sees.
	DisplayForm(plaintext string, keepLast int) string
}

var (
	sealMu     sync.RWMutex
	sealEngine SealEngine
)

// SetSealEngine installs the sealing implementation. Called once at startup
// when the feature is configured; left nil otherwise, which makes seal rules
// compile to nothing and refuse validation rather than half-work.
func SetSealEngine(e SealEngine) {
	sealMu.Lock()
	defer sealMu.Unlock()
	sealEngine = e
}

func currentSealEngine() SealEngine {
	sealMu.RLock()
	defer sealMu.RUnlock()
	return sealEngine
}

// SealAvailable reports whether sealing is configured, so the catalog can mark
// the action unavailable instead of offering an option that will fail on save.
func SealAvailable() bool { return currentSealEngine() != nil }

type sealAction struct{}

func (sealAction) Type() string       { return TypeSeal }
func (sealAction) Label() string      { return TypeLabel[TypeSeal] }
func (sealAction) UsesPattern() bool  { return false }
func (sealAction) TargetsField() bool { return true }

func (sealAction) Validate(r Rule) error {
	if currentSealEngine() == nil {
		return fmt.Errorf("sealing is not configured on this deployment")
	}
	if r.KeepLast < 0 || r.KeepLast > 64 {
		return fmt.Errorf("keep_last must be 0..64")
	}
	// A whole-event sweep cannot be sealed: FieldAll rewrites every string it
	// finds, and a token is only meaningful bound to ONE field (the field name
	// is part of what the MAC covers). Sealing "everything" would produce values
	// that cannot be unsealed under any single binding.
	if r.Field == FieldAll {
		return fmt.Errorf("seal requires a specific field — %q sweeps every field and a sealed value is bound to the field it came from", FieldAll)
	}
	if r.TenantID == "" {
		return fmt.Errorf("seal requires a tenant-owned processor")
	}
	return nil
}

func (sealAction) CompileVRL(r Rule) string {
	e := currentSealEngine()
	if e == nil {
		return "" // not expressible at the edge — same convention as an unknown managed rule
	}
	snippet, err := e.EdgeSnippet(r.TenantID, r.ID, r.Field, r.DataTypeOrField(), vrlPath(r.Field))
	if err != nil {
		// A tenant without key custody must not silently ship a config that drops
		// the rule AND leaves the data unprotected. Compiling to nothing is the
		// safe outcome here only because the rule never claimed to run: the
		// caller surfaces the error through validation before save.
		return ""
	}
	return snippet
}

// Apply seals in the SIMULATOR so preview shows the real thing — an actual
// token, produced by the same engine the edge uses. Showing a fake placeholder
// would hide exactly the failures preview exists to catch.
func (sealAction) Apply(ev map[string]any, r Rule) bool {
	e := currentSealEngine()
	if e == nil {
		return false
	}
	v, ok := getPath(ev, r.Field)
	if !ok {
		return false
	}
	plaintext := toStr(v)
	if plaintext == "" {
		return false
	}
	parent, leaf, ok := parentOf(ev, r.Field)
	if !ok {
		return false
	}
	sealed, err := e.SealValue(r.TenantID, r.ID, r.Field, r.DataTypeOrField(), plaintext)
	if err != nil {
		// A BROKEN sealer is not "nothing to seal". Returning false here would
		// render an unchanged event and read as "this rule matched nothing" —
		// so an operator whose key custody is down would preview a field sitting
		// in the clear and conclude the rule was simply too narrow, then ship it.
		// Preview must show the failure (§10: no silent failures).
		parent[leaf] = SealFailureMarker
		return true
	}
	if sealed == "" {
		return false // genuinely nothing to seal
	}
	parent[leaf] = sealed
	return true
}

// SealFailureMarker is what preview shows when sealing could not be performed.
// Deliberately NOT token-shaped: it must be impossible to mistake for a real
// sealed value, either by an operator reading it or by IsSealed().
const SealFailureMarker = "[seal unavailable — key custody error]"

// SealPreset is a recommended configuration for sealing a known kind of value.
//
// These are NOT managed rules. A managed rule is a DETECTOR — a pattern that
// finds sensitive values anywhere in an event. A seal preset is the opposite
// shape: sealing is bound to ONE named field (see Validate), so there is
// nothing to detect and a pattern would be meaningless. Modelling them as
// managed rules would have forced a fake pattern into the catalog and made the
// two concepts indistinguishable in the UI.
//
// What a preset carries is the part operators get wrong unaided: the DataType
// string (which is cryptographically bound into every token, so a typo today is
// unreadable data tomorrow) and a keep-last that matches the convention for
// that kind of value.
type SealPreset struct {
	DataType string `json:"data_type"`
	Label    string `json:"label"`
	KeepLast int    `json:"keep_last"`
	// Hint explains the retained tail to the operator, because "keep last 4" is
	// meaningless without knowing what the tail is FOR.
	Hint string `json:"hint"`
}

// SealPresets is the catalog the wizard renders. Deliberately short: each entry
// is a convention worth standardising, not an attempt to enumerate every kind
// of sensitive value.
var SealPresets = []SealPreset{
	{DataType: "card", Label: "Payment card", KeepLast: 4,
		Hint: "Last 4 stays readable — the industry convention for reconciling a charge without exposing the number."},
	{DataType: "ssn", Label: "National ID / SSN", KeepLast: 4,
		Hint: "Last 4 stays readable, which is what support desks verify against."},
	{DataType: "email", Label: "Email address", KeepLast: 0,
		Hint: "Nothing retained: a partial address is often enough to identify a person."},
	{DataType: "phone", Label: "Phone number", KeepLast: 4,
		Hint: "Last 4 stays readable for call-back verification."},
	{DataType: "account", Label: "Account / customer id", KeepLast: 4,
		Hint: "Last 4 stays readable so an operator can match a ticket without reading the identifier."},
	{DataType: "credential", Label: "Credential or token", KeepLast: 0,
		Hint: "Nothing retained. A partial credential is still a credential."},
}
