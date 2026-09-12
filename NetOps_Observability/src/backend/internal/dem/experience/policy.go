// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package experience

// policy.go — loading the versioned score policy.
//
// WHY A HAND-WRITTEN READER AND NOT A YAML LIBRARY: CLAUDE.md §6 defaults to
// the standard library and no YAML module is on the allowlist. The repository's
// precedent is a strict, closed-grammar reader for exactly the shape it needs
// (alerts/engine.go parseRulesYAML). This one accepts ONLY:
//
//	# comment
//	name: <token>
//	version: <int>
//	classes:
//	  <class>:
//	    <dimension>: <float>
//
// Anything else — a list, a nested map deeper than this, a tab, an unknown
// dimension, a duplicate key — is REFUSED with the line number. It is not a
// YAML parser and does not pretend to be one; it is a reader for a file whose
// grammar this package owns, and refusing everything it does not understand is
// what keeps that honest.
//
// The embedded policy is the product's policy and always loads. An operator
// override (DEM_SCORE_POLICY_FILE) is applied only if it parses AND validates;
// a bad override is LOUD and the embedded policy stands — a scoring policy that
// silently half-applied would be worse than one that was ignored.

import (
	_ "embed"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

//go:embed score-policy.yaml
var embeddedPolicy string

// EnvScorePolicyFile is the operator override path.
const EnvScorePolicyFile = "DEM_SCORE_POLICY_FILE"

// weightSumTolerance is how far a class's weights may sum from 1.0. Floating
// point makes exact equality a trap; 1e-6 is far tighter than any weight a
// human would write and far looser than binary representation error.
const weightSumTolerance = 1e-6

// EmbeddedScorePolicy returns the policy shipped with the product. It is parsed
// once at init; a parse failure here is a BUILD defect, not a runtime one, and
// the package test proves the embedded file loads.
func EmbeddedScorePolicy() (ScorePolicy, error) {
	p, err := ParseScorePolicy(embeddedPolicy)
	if err != nil {
		return ScorePolicy{}, fmt.Errorf("embedded score policy: %w", err)
	}
	p.Source = "embedded"
	return p, nil
}

// ParseScorePolicy reads the closed grammar described above.
func ParseScorePolicy(src string) (ScorePolicy, error) {
	p := ScorePolicy{Classes: map[string]map[string]float64{}}
	class := ""
	seenName, seenVersion := false, false
	for i, raw := range strings.Split(src, "\n") {
		line := i + 1
		if strings.ContainsRune(raw, '\t') {
			return ScorePolicy{}, fmt.Errorf("line %d: tabs are not allowed (indent with spaces)", line)
		}
		body := raw
		if h := strings.IndexByte(body, '#'); h >= 0 {
			body = body[:h]
		}
		if strings.TrimSpace(body) == "" {
			continue
		}
		indent := len(body) - len(strings.TrimLeft(body, " "))
		key, val, ok := strings.Cut(strings.TrimSpace(body), ":")
		if !ok {
			return ScorePolicy{}, fmt.Errorf("line %d: expected `key: value`", line)
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch indent {
		case 0:
			class = ""
			switch key {
			case "name":
				if seenName {
					return ScorePolicy{}, fmt.Errorf("line %d: duplicate `name`", line)
				}
				seenName, p.Name = true, val
			case "version":
				if seenVersion {
					return ScorePolicy{}, fmt.Errorf("line %d: duplicate `version`", line)
				}
				n, err := strconv.Atoi(val)
				if err != nil || n <= 0 {
					return ScorePolicy{}, fmt.Errorf("line %d: version must be a positive integer", line)
				}
				seenVersion, p.Version = true, n
			case "classes":
				if val != "" {
					return ScorePolicy{}, fmt.Errorf("line %d: `classes:` takes no inline value", line)
				}
			default:
				return ScorePolicy{}, fmt.Errorf("line %d: unknown top-level key %q", line, clip(key, 40))
			}
		case 2:
			if val != "" {
				return ScorePolicy{}, fmt.Errorf("line %d: a class takes no inline value", line)
			}
			c := labelSafe(strings.ToLower(key))
			if c == "" {
				return ScorePolicy{}, fmt.Errorf("line %d: empty class name", line)
			}
			if _, dup := p.Classes[c]; dup {
				return ScorePolicy{}, fmt.Errorf("line %d: duplicate class %q", line, clip(c, 40))
			}
			p.Classes[c] = map[string]float64{}
			class = c
		case 4:
			if class == "" {
				return ScorePolicy{}, fmt.Errorf("line %d: a weight outside any class", line)
			}
			if !ValidDimension(key) {
				return ScorePolicy{}, fmt.Errorf("line %d: unknown dimension %q (a dimension nothing computes would silently drop its weight)", line, clip(key, 40))
			}
			if _, dup := p.Classes[class][key]; dup {
				return ScorePolicy{}, fmt.Errorf("line %d: duplicate dimension %q in class %q", line, clip(key, 40), clip(class, 40))
			}
			w, err := strconv.ParseFloat(val, 64)
			if err != nil || w <= 0 || w > 1 {
				return ScorePolicy{}, fmt.Errorf("line %d: weight must be a number in (0, 1]", line)
			}
			p.Classes[class][key] = w
		default:
			return ScorePolicy{}, fmt.Errorf("line %d: unexpected indent %d (this grammar has exactly three levels)", line, indent)
		}
	}
	return p, p.Validate()
}

// Validate refuses a policy that cannot produce an auditable score.
func (p ScorePolicy) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("score policy: name is required")
	}
	if p.Version <= 0 {
		return errors.New("score policy: a positive version is required (a score whose policy version is unknown is not auditable)")
	}
	if len(p.Classes) == 0 {
		return errors.New("score policy: at least one class is required")
	}
	if _, ok := p.Classes[DefaultAppClass]; !ok {
		return fmt.Errorf("score policy: the %q class is required — it is what an unknown application class falls back to", DefaultAppClass)
	}
	for _, name := range p.ClassNames() {
		w := p.Classes[name]
		if len(w) == 0 {
			return fmt.Errorf("score policy: class %q declares no weights", name)
		}
		sum := 0.0
		for _, v := range w {
			sum += v
		}
		if sum < 1-weightSumTolerance || sum > 1+weightSumTolerance {
			return fmt.Errorf("score policy: class %q weights sum to %.4f, not 1.0 — a composite that does not sum to its parts is not decomposable", name, sum)
		}
	}
	return nil
}
