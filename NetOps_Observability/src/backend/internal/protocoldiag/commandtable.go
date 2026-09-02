package protocoldiag

// commandtable.go — the CLOSED per-vendor command table.
//
// ValidateReadOnly (collect.go) answers "is this command SHAPED like a read?".
// This file answers the stricter question the live transport needs: "is this
// command one the CATALOG could have rendered for this device's dialect?".
//
// The two are different guards and both are load-bearing. `show running-config`
// is a perfectly read-only command that is NOT in this catalog, and a live SSH
// runner that accepted it would have widened the feature from "15 curated
// diagnostic bundles" into "arbitrary device reads". The table closes that: the
// only strings the SSH runner will ever put on a wire are the authored
// templates, with their {if}/{peer}/{prefix}/{vrf-scope} placeholders filled by
// operator arguments that are themselves shape-checked one token at a time.
//
// The matcher works on TOKENS, not on the rendered string, because Render
// collapses whitespace and an empty placeholder vanishes entirely: a template's
// token list is matched against the command's token list with each placeholder
// consuming zero or one argument token ({vrf-scope}: zero, one, or the two-token
// `vrf X` / `instance X` qualifier). It backtracks, so an argument that happens
// to look like the next literal cannot desynchronize the match.

import (
	"regexp"
	"strings"
)

// maxArgToken bounds one substituted argument token. An interface name, peer
// address, prefix or VRF name is far below this; anything longer is refused
// rather than shipped to a device (§9 bound everything).
const maxArgToken = 128

// argTokenRE is the shape ONE substituted argument may take: interface names
// (GigabitEthernet0/0.100), IPv4/IPv6 addresses and prefixes (2001:db8::1,
// 192.0.2.0/24), VRF/instance names. Deliberately narrow — no whitespace, no
// quoting, and none of the shell/CLI metacharacters ValidateReadOnly rejects.
var argTokenRE = regexp.MustCompile(`^[A-Za-z0-9._:/+@,%\[\]-]{1,` + itoa(maxArgToken) + `}$`)

// itoa is a tiny local int→string so the regexp above can be a package-level
// compiled constant without pulling strconv into the pattern build.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// placeholders is the set of substitutable tokens a template may carry. It is
// the authoritative list — a template token that looks like a placeholder but is
// not in this set is treated as a LITERAL, so a typo fails closed (the command
// simply never matches) rather than opening a wildcard.
var placeholders = map[string]struct{}{
	"{if}": {}, "{peer}": {}, "{prefix}": {}, "{vrf-scope}": {},
}

// vrfQualifiers are the dialect keywords vrfScopeToken can emit ahead of the
// instance name. Kept in sync with vrfScopeToken by TestCommandTable_VRFScope.
var vrfQualifiers = map[string]struct{}{"vrf": {}, "instance": {}}

// commandTable is the compiled, immutable closed table: per rendered dialect,
// the token list of every template the catalog can produce. It is built once
// from a Catalog and never mutated, so it is safe to share across goroutines.
type commandTable struct {
	byVendor map[Vendor][][]string
}

// newCommandTable compiles the closed table from a catalog. Every issue's whole
// bundle contributes, for each of the three rendered dialects (an unbound vendor
// contributes the primary template it would fall back to), so the table is
// exactly the set of shapes Collect can emit.
func newCommandTable(cat *Catalog) *commandTable {
	t := &commandTable{byVendor: map[Vendor][][]string{}}
	if cat == nil {
		return t
	}
	seen := map[Vendor]map[string]bool{}
	for _, v := range []Vendor{VendorCiscoIOSXE, VendorJuniper, VendorNokia} {
		seen[v] = map[string]bool{}
	}
	for _, is := range cat.Issues() {
		for _, s := range is.Bundle() {
			for _, v := range []Vendor{VendorCiscoIOSXE, VendorJuniper, VendorNokia} {
				tmpl, ok := s.templates[v]
				if !ok || strings.TrimSpace(tmpl) == "" {
					tmpl = s.templates[VendorCiscoIOSXE]
				}
				toks := strings.Fields(tmpl)
				if len(toks) == 0 {
					continue
				}
				key := strings.Join(toks, " ")
				if seen[v][key] {
					continue
				}
				seen[v][key] = true
				t.byVendor[v] = append(t.byVendor[v], toks)
			}
		}
	}
	return t
}

// Allows reports whether command is a rendering of one of the catalog's
// templates in vendor v's dialect. It is the closed-table membership test; it
// does NOT replace ValidateReadOnly, which the caller runs as well.
func (t *commandTable) Allows(v Vendor, command string) bool {
	cmd := strings.Fields(command)
	if len(cmd) == 0 {
		return false
	}
	for _, tmpl := range t.byVendor[renderVendor(v)] {
		if matchTemplate(tmpl, cmd) {
			return true
		}
	}
	return false
}

// matchTemplate reports whether the command token list cmd is a rendering of the
// template token list tmpl. Literals must match exactly; a placeholder consumes
// zero or one argument token; {vrf-scope} may additionally consume the two-token
// `vrf X` / `instance X` qualifier. Backtracking is bounded by the template
// length (never more than a dozen tokens), so recursion is cheap and terminates.
func matchTemplate(tmpl, cmd []string) bool {
	if len(tmpl) == 0 {
		return len(cmd) == 0
	}
	head := tmpl[0]
	if _, isPlaceholder := placeholders[head]; !isPlaceholder {
		if len(cmd) == 0 || cmd[0] != head {
			return false
		}
		return matchTemplate(tmpl[1:], cmd[1:])
	}
	// Empty argument: the placeholder collapsed to nothing.
	if matchTemplate(tmpl[1:], cmd) {
		return true
	}
	// One argument token.
	if len(cmd) >= 1 && argTokenRE.MatchString(cmd[0]) && matchTemplate(tmpl[1:], cmd[1:]) {
		return true
	}
	// {vrf-scope} only: the dialect qualifier plus the instance name.
	if head == "{vrf-scope}" && len(cmd) >= 2 {
		if _, ok := vrfQualifiers[strings.ToLower(cmd[0])]; ok && argTokenRE.MatchString(cmd[1]) {
			return matchTemplate(tmpl[1:], cmd[2:])
		}
	}
	return false
}
