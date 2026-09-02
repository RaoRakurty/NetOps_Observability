package pcap

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// bpf.go — the capture-filter grammar.
//
// THIS FILE IS THE INJECTION BOUNDARY. A capture filter is the only free-form
// string an operator hands us that ends up inside a command executed on a
// production network device, and on one of the supported platforms (Arista) that
// command runs under `bash`. The rule this file enforces is therefore not
// "escape the input" but "the input cannot express anything to escape":
//
//	ACCEPT a filter only if EVERY token is drawn from a CLOSED vocabulary of
//	pcap-filter primitives, and every value token parses as an IP, a CIDR, a
//	port, a port range or a small integer.
//
// An allowlist grammar, not a metacharacter denylist. A denylist is a promise
// that you thought of every byte that means something to every CLI parser on
// every network OS; this is a proof that no byte outside [a-z0-9./:-] and
// parentheses survives validation at all. `Validate` returns the CANONICAL,
// re-rendered expression — the string the command table interpolates is one this
// package built out of validated tokens, never the caller's bytes echoed back.

// Filter operator and primitive vocabulary. Anything outside this set is
// refused, with the offending token named so the operator can fix it.
var (
	// filterKeywords are the standalone protocol/type primitives.
	filterKeywords = map[string]bool{
		"ip": true, "ip6": true, "arp": true, "rarp": true,
		"tcp": true, "udp": true, "icmp": true, "icmp6": true, "sctp": true,
		"broadcast": true, "multicast": true,
	}
	// filterQualifiers are direction/type qualifiers that must be followed by a
	// value primitive (they never stand alone).
	filterQualifiers = map[string]bool{
		"src": true, "dst": true, "ether": true,
	}
	// filterValueKeywords take exactly one value argument.
	filterValueKeywords = map[string]bool{
		"host": true, "net": true, "port": true, "portrange": true, "vlan": true,
	}
	// filterLogic are the boolean connectives.
	filterLogic = map[string]bool{"and": true, "or": true, "not": true}
)

// ErrEmptyFilter is returned for a filter that is only whitespace. Callers treat
// "no filter" as the absent case; a blank string is a mistake, not a filter.
var ErrEmptyFilter = errors.New("capture filter is empty")

// ValidateFilter parses and re-renders a capture filter. It returns the
// canonical expression, or an error naming what was refused.
//
// The empty string means "no filter" and is returned unchanged — the caller
// decides whether an unfiltered capture is allowed on that platform.
func ValidateFilter(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}
	if len(raw) > MaxFilterLen {
		return "", fmt.Errorf("capture filter is longer than %d characters", MaxFilterLen)
	}
	// Character gate FIRST, before any structure is inferred. Every byte a
	// shell, a device CLI or a quoting layer could act on — quotes, backticks,
	// $ ; | & < > \ newline, comment marks, braces, wildcards — is absent from
	// this set, so nothing downstream has anything to escape.
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.' || c == ':' || c == '/' || c == '-' || c == '(' || c == ')' || c == ' ':
		default:
			return "", fmt.Errorf("capture filter contains a forbidden character %q — "+
				"filters may use only host/net/port/portrange/vlan/proto primitives, "+
				"and/or/not, and parentheses", string(rune(c)))
		}
	}
	toks := tokenizeFilter(raw)
	if len(toks) == 0 {
		return "", ErrEmptyFilter
	}
	if len(toks) > 64 {
		return "", errors.New("capture filter has too many terms")
	}
	if err := parseFilter(toks); err != nil {
		return "", err
	}
	return strings.Join(toks, " "), nil
}

// tokenizeFilter splits on whitespace and makes parentheses their own tokens.
// Case is folded to lower: the vocabulary is case-insensitive, the canonical
// rendering is not.
func tokenizeFilter(raw string) []string {
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, strings.ToLower(cur.String()))
			cur.Reset()
		}
	}
	for _, r := range raw {
		switch r {
		case ' ':
			flush()
		case '(', ')':
			flush()
			out = append(out, string(r))
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

// parseFilter walks the token stream, checking the grammar and the balance of
// parentheses. It is a validator, not an evaluator: it proves the expression is
// drawn from the closed vocabulary, and leaves the semantics to the device.
func parseFilter(toks []string) error {
	depth := 0
	// wantTerm tracks whether the next non-paren token must start a term (true
	// after a connective or at the start) — this is what rejects "host 1.2.3.4
	// host" and "and and".
	wantTerm := true
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch {
		case t == "(":
			if !wantTerm {
				return errors.New("capture filter: unexpected '('")
			}
			depth++
			if depth > 8 {
				return errors.New("capture filter: too deeply nested")
			}
		case t == ")":
			if wantTerm {
				return errors.New("capture filter: unexpected ')'")
			}
			depth--
			if depth < 0 {
				return errors.New("capture filter: unbalanced ')'")
			}
		case filterLogic[t]:
			if t == "not" {
				// `not` prefixes a term; it does not close one.
				if !wantTerm {
					return errors.New("capture filter: 'not' must precede a term")
				}
				continue
			}
			if wantTerm {
				return fmt.Errorf("capture filter: %q must join two terms", t)
			}
			wantTerm = true
		case filterQualifiers[t]:
			if !wantTerm {
				return fmt.Errorf("capture filter: unexpected %q", t)
			}
			// A qualifier must be followed by another qualifier or a value
			// keyword — never by a bare value and never by a connective.
			if i+1 >= len(toks) || !(filterQualifiers[toks[i+1]] || filterValueKeywords[toks[i+1]]) {
				return fmt.Errorf("capture filter: %q must be followed by host, net, port or portrange", t)
			}
		case filterValueKeywords[t]:
			if !wantTerm {
				return fmt.Errorf("capture filter: unexpected %q", t)
			}
			if i+1 >= len(toks) {
				return fmt.Errorf("capture filter: %q needs a value", t)
			}
			if err := validFilterValue(t, toks[i+1]); err != nil {
				return err
			}
			i++
			wantTerm = false
		case filterKeywords[t]:
			if !wantTerm {
				return fmt.Errorf("capture filter: unexpected %q", t)
			}
			wantTerm = false
		default:
			// The catch-all is deliberate and final: an unknown token is
			// REFUSED, never passed through "just in case the device
			// understands it". That pass-through is how a filter becomes a
			// command.
			return fmt.Errorf("capture filter: unsupported term %q", t)
		}
	}
	if depth != 0 {
		return errors.New("capture filter: unbalanced '('")
	}
	if wantTerm {
		return errors.New("capture filter ends with an incomplete term")
	}
	return nil
}

// validFilterValue checks the argument of a value keyword. Every one of these
// parses through the stdlib rather than a regex, so "1.2.3.4.5" and
// "10.0.0.0/99" are refused by the same code that would refuse them at a socket.
func validFilterValue(keyword, v string) error {
	switch keyword {
	case "host":
		if _, err := netip.ParseAddr(v); err != nil {
			return fmt.Errorf("capture filter: %q is not an IP address", v)
		}
	case "net":
		if _, err := netip.ParsePrefix(v); err != nil {
			// A bare address is a legal `net` argument in pcap-filter syntax.
			if _, aerr := netip.ParseAddr(v); aerr != nil {
				return fmt.Errorf("capture filter: %q is not a network or address", v)
			}
		}
	case "port":
		if err := validPort(v); err != nil {
			return err
		}
	case "portrange":
		lo, hi, ok := strings.Cut(v, "-")
		if !ok {
			return fmt.Errorf("capture filter: %q is not a port range (use lo-hi)", v)
		}
		if err := validPort(lo); err != nil {
			return err
		}
		if err := validPort(hi); err != nil {
			return err
		}
		// Both endpoints already parsed cleanly inside validPort just above, so
		// neither Atoi can fail here; the ordering check below is the only
		// remaining question.
		l, _ := strconv.Atoi(lo) // best-effort: validPort(lo) already parsed it — cannot fail
		h, _ := strconv.Atoi(hi) // best-effort: validPort(hi) already parsed it — cannot fail
		if l > h {
			return fmt.Errorf("capture filter: port range %q is inverted", v)
		}
	case "vlan":
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 4094 {
			return fmt.Errorf("capture filter: %q is not a VLAN id", v)
		}
	default:
		return fmt.Errorf("capture filter: unsupported term %q", keyword)
	}
	return nil
}

func validPort(v string) error {
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("capture filter: %q is not a port", v)
	}
	// Atoi accepts "+80" and "-1"; the canonical rendering must be the digits.
	if strconv.Itoa(n) != v {
		return fmt.Errorf("capture filter: %q is not a port", v)
	}
	return nil
}

// ValidateInterface checks a device interface name. It is the SECOND untrusted
// string that reaches a rendered command, and it gets the same treatment: a
// closed character set, a leading letter, and a length bound. Vendor interface
// names are e.g. "GigabitEthernet0/0/1", "Ethernet1/1", "ge-0/0/0.100",
// "et1", "xe-0/0/0:1" — all inside this set; a shell metacharacter is not.
func ValidateInterface(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", errors.New("interface is required")
	}
	if len(name) > MaxInterfaceLen {
		return "", fmt.Errorf("interface name is longer than %d characters", MaxInterfaceLen)
	}
	first := name[0]
	if !(first >= 'a' && first <= 'z' || first >= 'A' && first <= 'Z') {
		return "", errors.New("interface name must start with a letter")
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '/' || c == '.' || c == '-' || c == '_' || c == ':':
		default:
			return "", fmt.Errorf("interface name contains a forbidden character %q", string(rune(c)))
		}
	}
	return name, nil
}

// ValidateCaptureID checks an id from a URL path. Ids are minted by this package
// as 32 lower-case hex characters; anything else is refused before it can reach
// a store key or a filesystem path.
func ValidateCaptureID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
