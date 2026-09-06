package osprobe

// gnmivalue.go — turning what a gNMI Get hands back into the leaf's VALUE.
//
// There is no single shape. Depending on the client, the encoding the target
// negotiated and whether the path addressed a leaf or its parent container, the
// same software-version read comes back as any of:
//
//	v26.3.2-426-g2b38957bbca                                  (a bare scalar)
//	"v26.3.2-426-g2b38957bbca"                                (a JSON scalar)
//	{"software-version":"v26.3.2-426-g2b38957bbca"}           (json_ietf leaf)
//	{"srl_nokia-platform:software-version":"v26.3.2-…"}       (module-qualified)
//	{"state":{"software-version":"4.32.0F"}}                  (the container)
//
// Handling all of them HERE, once and generically, is what keeps the vendor
// profiles free of encoding trivia: a profile declares a PATH, not a decoder.
// The rule is deliberately narrow — find the value of the leaf the path named,
// anywhere in the decoded object, matching either the bare leaf name or a
// `module:leaf` qualification of it, and refuse to guess at anything else.

import (
	"encoding/json"
	"strconv"
	"strings"
)

// maxGNMIValueBytes bounds the payload this package will decode (§9). A
// software-version leaf is tens of bytes; this is headroom, not a target, and a
// target that answers with more is answering with something that is not a leaf.
const maxGNMIValueBytes = 64 << 10

// maxLeafDepth bounds the search through a decoded container. gNMI state
// containers are shallow; an unbounded walk over an adversarial payload is not
// something a probe needs to be able to do.
const maxLeafDepth = 8

// LeafOf returns the leaf name a gNMI path addresses: its last element with any
// `[key=value]` predicate and any module qualification stripped.
// "/platform/control[slot=A]/software-version" → "software-version".
func LeafOf(path string) string {
	p := strings.TrimSpace(path)
	if i := strings.LastIndex(p, "/"); i >= 0 {
		p = p[i+1:]
	}
	if i := strings.Index(p, "["); i >= 0 {
		p = p[:i]
	}
	if i := strings.LastIndex(p, ":"); i >= 0 {
		p = p[i+1:]
	}
	return strings.TrimSpace(p)
}

// ExtractLeaf returns the scalar value of leaf inside raw. A raw payload that
// is not JSON is returned as-is (trimmed of a surrounding quote pair), which is
// the bare-scalar case; a JSON object is searched for the leaf; anything that
// does not yield a scalar returns "" — never a guessed value.
func ExtractLeaf(raw, leaf string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if len(s) > maxGNMIValueBytes {
		return ""
	}
	var decoded any
	if err := json.Unmarshal([]byte(s), &decoded); err != nil {
		// Not JSON: the client handed back the scalar itself.
		return strings.TrimSpace(s)
	}
	switch v := decoded.(type) {
	case string:
		return strings.TrimSpace(v)
	case float64, bool, nil:
		if scalar, ok := scalarOf(decoded); ok {
			return scalar
		}
		return ""
	case map[string]any:
		if leaf == "" {
			return ""
		}
		if found, ok := findLeaf(v, leaf, 0); ok {
			return found
		}
		return ""
	default:
		return ""
	}
}

// findLeaf walks a decoded gNMI container looking for the leaf, matching either
// its bare name or a `module:leaf` qualification of it. Depth-bounded; the first
// match in map-key order at the shallowest level wins, and a nested container is
// only descended into after the whole level has been checked, so a same-named
// leaf deeper in the tree can never shadow the one the path addressed.
func findLeaf(obj map[string]any, leaf string, depth int) (string, bool) {
	if depth > maxLeafDepth {
		return "", false
	}
	for k, v := range obj {
		if !leafKeyMatches(k, leaf) {
			continue
		}
		if s, ok := scalarOf(v); ok {
			return s, true
		}
	}
	for _, v := range obj {
		child, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if s, found := findLeaf(child, leaf, depth+1); found {
			return s, true
		}
	}
	return "", false
}

// leafKeyMatches reports whether a JSON key names the leaf, bare or
// module-qualified ("srl_nokia-platform:software-version").
func leafKeyMatches(key, leaf string) bool {
	k := strings.TrimSpace(key)
	if strings.EqualFold(k, leaf) {
		return true
	}
	if i := strings.LastIndex(k, ":"); i >= 0 {
		return strings.EqualFold(strings.TrimSpace(k[i+1:]), leaf)
	}
	return false
}

// scalarOf renders a decoded JSON scalar as text. Objects, arrays and null are
// not scalars and yield ok=false — a probe reports "no version" rather than
// stringifying a structure into something that looks like one.
func scalarOf(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return "", false
		}
		return s, true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(t), true
	default:
		return "", false
	}
}
