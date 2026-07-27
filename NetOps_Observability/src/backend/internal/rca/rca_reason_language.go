package rca

// rca_reason_language.go — operator-language rewriting of engine verdict
// vocabulary, and the §11 non-production signal classifier. Shared by the
// report/wording family here and by the path-view integrator in package main.

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// IsValidationSignal: the signal declares a non-production purpose (§11 of the
// truthfulness spec) — validation | lab | fault_injection | debug | demo |
// staging, or a non-prod environment. Read from attrs; absent = production.
func IsValidationSignal(sig map[string]any) bool {
	a, _ := sig["attrs"].(string)
	if a == "" {
		return false
	}
	var at struct {
		Purpose string `json:"signal_purpose"`
		Env     string `json:"environment"`
	}
	if json.Unmarshal([]byte(a), &at) != nil {
		return false
	}
	switch strings.ToLower(at.Purpose) {
	case "validation", "lab", "fault_injection", "debug", "demo", "staging":
		return true
	}
	switch strings.ToLower(at.Env) {
	case "", "prod", "production":
		return false
	}
	return true
}

// reasonTokenLabel maps raw engine vocabulary that appears inside verdict-reason
// strings to operator language (no schema tokens in customer-facing text).
var reasonTokenLabel = map[string]string{
	"active_probe":        "active path measurement",
	"control_plane":       "routing",
	"device_telemetry":    "device telemetry",
	"passive_flow":        "traffic flow",
	"internal_self_probe": "internal self-probe",
	"customer_path":       "customer-path probe",
	"synthetic_lab_probe": "lab probe",
}

// FriendlyReasons rewrites engine reason strings into operator language. The
// known verdict-gate shapes are rewritten WHOLE (owner directive 2026-07-18: a
// NOC admin needs the operational consequence — "only probes saw this, needs a
// second independent source" — not "single modality class; need ≥2 — every
// modality has a blind spot"). Anything unrecognized falls back to raw-token
// replacement and ≥-notation cleanup. Honesty is unchanged — the verbatim
// engine reasons stay in the hypotheses JSON for the debug/audit surfaces.
func FriendlyReasons(reasons []string) []string {
	out := make([]string, 0, len(reasons))
	for _, r := range reasons {
		out = append(out, friendlyReason(r))
	}
	return out
}

var (
	reSoloModality    = regexp.MustCompile(`(?i)single modality class \((\w+)\)`)
	reNoIndepPair     = regexp.MustCompile(`(?i)no independent cross-modality pair(?: \(fate-shared: ([^)]+)\))?`)
	reLowAuthority    = regexp.MustCompile(`(?i)required modality (\w+) present but only low-authority`)
	reModalityMissing = regexp.MustCompile(`(?i)required modality missing[^:]*:\s*(\w+)`)
	reGteNotation     = regexp.MustCompile(`≥\s*(\d+)`)
)

// friendlyReason rewrites one engine reason into operator language.
func friendlyReason(r string) string {
	tok := func(t string) string {
		if l, ok := reasonTokenLabel[t]; ok {
			return l
		}
		return strings.ReplaceAll(t, "_", " ")
	}
	if m := reSoloModality.FindStringSubmatch(r); m != nil {
		return fmt.Sprintf("Only %s saw this — a second independent source is needed to confirm.", tok(m[1]))
	}
	if m := reNoIndepPair.FindStringSubmatch(r); m != nil {
		if m[1] != "" {
			return fmt.Sprintf("The sources that saw this share a failure point (%s), so they cannot confirm each other independently.",
				strings.ReplaceAll(m[1], "_", " "))
		}
		return "The sources that saw this share a failure point, so they cannot confirm each other independently."
	}
	if m := reLowAuthority.FindStringSubmatch(r); m != nil {
		return fmt.Sprintf("Only low-trust %s saw this — not enough on their own to confirm.", tok(m[1]))
	}
	if m := reModalityMissing.FindStringSubmatch(r); m != nil {
		return fmt.Sprintf("No trusted %s evidence in this window.", tok(m[1]))
	}
	if strings.Contains(strings.ToLower(r), "cannot confirm without an independent trusted modality") {
		return "A second independent source is needed to confirm."
	}
	for t, label := range reasonTokenLabel {
		r = strings.ReplaceAll(r, t, label)
	}
	r = reGteNotation.ReplaceAllString(r, "$1 or more")
	return strings.ReplaceAll(strings.ReplaceAll(r, "modality", "source"), "Modality", "Source")
}
