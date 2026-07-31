package processors

// managed.go — the MANAGED RULES catalog and the SensitiveDataDetector
// extension point.
//
// Managed rules are platform-curated detectors (email, JWT, API token, AWS key,
// credit card, password field). They are:
//   - READ-ONLY — a tenant enables/disables them or CLONES one into a custom
//     processor; the catalog entry itself is never edited by a tenant;
//   - VERSIONED — each carries a Version that bumps when the pattern changes, so
//     a tenant can see it moved and re-adopt deliberately;
//   - EXECUTED BY THE SAME ENGINE — a managed rule is compiled through the very
//     same generator/simulator path as a custom processor (Rule with
//     PatternKind=builtin). There is no second execution path to keep in sync.
//
// Future Sensitive Data Scanner: SensitiveDataDetector below is the extension
// point. Detectors whose logic is expressible at the edge (regex, checksum)
// compile down like any processor; detectors that are not (ML scoring,
// cross-field correlation) will run in the future SDS service and feed the same
// Detection shape back. Nothing in the engine needs redesigning for either —
// which is the whole point of declaring the interface now.

import (
	"regexp"
	"sort"
	"strings"
)

// ManagedRule is one curated, versioned detector.
type ManagedRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"` // pii | secret | financial | auth
	Description string `json:"description"`
	// Pattern is RE2 (both engines are RE2-family, so one source of truth).
	Pattern string `json:"pattern"`
	// Version bumps whenever Pattern changes. Cloned processors record the id;
	// the catalog can then surface "this rule moved to v2".
	Version int `json:"version"`
	// Replacement is the catalog's suggested token, pre-filled when cloning.
	Replacement string `json:"replacement"`
	// Checksum names an optional validator a future SDS detector applies to a
	// candidate match (e.g. "luhn" for card numbers) to cut false positives.
	// The edge engine ignores it today — declared so adding it later is not a
	// schema change.
	Checksum string `json:"checksum,omitempty"`
}

// managedRules is the catalog. Ordered deterministically by id at read time.
//
// Patterns are deliberately conservative — a managed rule that over-matches
// silently destroys good data, which is worse than one that under-matches and
// leaves a visible gap the operator can close with a custom processor.
var managedRules = []ManagedRule{
	{
		ID: "email", Name: "Email Detector", Category: "pii", Version: 1,
		Description: "RFC-shaped email addresses in a field value.",
		Pattern:     `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`,
		Replacement: "[EMAIL]",
	},
	{
		ID: "ipv4", Name: "IPv4 Address Detector", Category: "pii", Version: 1,
		Description: "Dotted-quad IPv4 addresses.",
		Pattern:     `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`,
		Replacement: "[IP]",
	},
	{
		ID: "mac", Name: "MAC Address Detector", Category: "pii", Version: 1,
		Description: "Colon- or hyphen-separated MAC addresses.",
		Pattern:     `\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`,
		Replacement: "[MAC]",
	},
	{
		ID: "jwt", Name: "JWT Detector", Category: "secret", Version: 1,
		Description: "JSON Web Tokens (three base64url segments).",
		Pattern:     `eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`,
		Replacement: "[JWT]",
	},
	{
		ID: "bearer_token", Name: "API Token Detector", Category: "auth", Version: 1,
		Description: "Authorization bearer tokens.",
		Pattern:     `(?i)bearer\s+[A-Za-z0-9._~+/-]{12,}`,
		Replacement: "[TOKEN]",
	},
	{
		ID: "aws_access_key", Name: "AWS Access Key Detector", Category: "secret", Version: 1,
		Description: "AWS access key ids (AKIA/ASIA/AIDA/AROA prefixes).",
		Pattern:     `\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b`,
		Replacement: "[AWS_KEY]",
	},
	{
		ID: "credit_card", Name: "Credit Card Detector", Category: "financial", Version: 1,
		Description: "13–16 digit card numbers, optionally space/hyphen grouped.",
		// Checksum (Luhn) is where a future SDS detector removes the false
		// positives a regex alone cannot.
		Pattern:     `\b(?:[0-9]{4}[ -]?){3}[0-9]{1,4}\b`,
		Replacement: "[CARD]",
		Checksum:    "luhn",
	},
	{
		ID: "password_field", Name: "Password Field Detector", Category: "secret", Version: 1,
		Description: "key=value pairs whose key names a secret (password/passwd/secret/api_key).",
		Pattern:     `(?i)(password|passwd|pwd|secret|api[_-]?key)\s*[=:]\s*\S+`,
		Replacement: "[REDACTED]",
	},
}

// ManagedRules returns the catalog, ordered by id (deterministic).
func ManagedRules() []ManagedRule {
	out := append([]ManagedRule(nil), managedRules...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ManagedRuleByID looks a rule up.
func ManagedRuleByID(id string) (ManagedRule, bool) {
	for _, r := range managedRules {
		if r.ID == strings.TrimSpace(id) {
			return r, true
		}
	}
	return ManagedRule{}, false
}

// managedCompiled caches the compiled catalog patterns (compile once — the
// engine's hot path never recompiles).
var managedCompiled = func() map[string]*regexp.Regexp {
	m := make(map[string]*regexp.Regexp, len(managedRules))
	for _, r := range managedRules {
		m[r.ID] = regexp.MustCompile(r.Pattern)
	}
	return m
}()

// CloneManagedRule builds an editable processor from a catalog entry. The
// clone is a NORMAL processor from then on (the tenant owns it); it keeps
// ManagedRuleID so the catalog can show adoption and offer version upgrades.
func CloneManagedRule(id, lane, field string) (Rule, bool) {
	mr, ok := ManagedRuleByID(id)
	if !ok {
		return Rule{}, false
	}
	return Rule{
		Name:          mr.Name,
		Lane:          lane,
		Type:          TypeRedactPattern,
		Field:         field,
		PatternKind:   PatternBuiltin,
		Pattern:       mr.ID,
		Replacement:   mr.Replacement,
		Description:   mr.Description,
		ManagedRuleID: mr.ID,
		Enabled:       true,
	}, true
}

// ── Sensitive Data Scanner extension point (interfaces only) ────────────────

// Detection is one sensitive-data finding. Shape is fixed now so detectors can
// be added later without touching callers.
type Detection struct {
	Detected   bool    `json:"detected"`
	Type       string  `json:"type"`       // EMAIL | JWT | CARD | …
	Confidence float64 `json:"confidence"` // 0..1
	Location   string  `json:"location"`   // dot-path of the field it was found in
	// Sample is a REDACTED excerpt for evidence — never the raw secret (§8:
	// findings must not become a second copy of the data they protect).
	Sample string `json:"sample,omitempty"`
}

// SensitiveDataDetector is the future SDS contract. A detector inspects a
// decoded event and reports findings; it never mutates. Implementations may be
// regex-backed (compilable to the edge), checksum-validated, or model-backed
// (service-side only) — the engine consumes them identically.
type SensitiveDataDetector interface {
	// ID is the stable detector id (matches a managed rule id where one exists).
	ID() string
	// Detect returns findings for one event. An empty slice means "clean";
	// nil is also valid and means the same.
	Detect(event map[string]any) []Detection
}

// ManagedRuleDetector adapts a catalog entry to the detector interface — proof
// the extension point is real, and the seam a future SDS reuses for its
// regex-expressible detectors. Confidence is 1.0 for a pattern hit with no
// checksum, and left to the future checksum validator otherwise.
type ManagedRuleDetector struct{ RuleID string }

func (d ManagedRuleDetector) ID() string { return d.RuleID }

func (d ManagedRuleDetector) Detect(event map[string]any) []Detection {
	re, ok := managedCompiled[d.RuleID]
	if !ok || event == nil {
		return nil
	}
	mr, _ := ManagedRuleByID(d.RuleID)
	var out []Detection
	var walk func(prefix string, m map[string]any)
	walk = func(prefix string, m map[string]any) {
		for k, v := range m {
			path := k
			if prefix != "" {
				path = prefix + "." + k
			}
			switch t := v.(type) {
			case map[string]any:
				walk(path, t)
			case string:
				if re.MatchString(t) {
					out = append(out, Detection{
						Detected: true, Type: strings.ToUpper(d.RuleID),
						// A checksum-bearing rule is a CANDIDATE until the future
						// validator runs — reporting 1.0 would overstate it.
						Confidence: map[bool]float64{true: 0.6, false: 1}[mr.Checksum != ""],
						Location:   path,
						Sample:     re.ReplaceAllString(t, mr.Replacement),
					})
				}
			}
		}
	}
	walk("", event)
	sort.Slice(out, func(i, j int) bool { return out[i].Location < out[j].Location })
	return out
}

var _ SensitiveDataDetector = ManagedRuleDetector{}
