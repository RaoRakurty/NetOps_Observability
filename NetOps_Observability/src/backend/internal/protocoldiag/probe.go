package protocoldiag

// probe.go — the BOUNDED REACHABILITY PROBE grammar.
//
// Owner decision, 2026-09-05: "Ping and traceroute are good examples, should be
// allowed." Everything else about the command policy is a refusal (see
// ai/tac/forbidden.yaml); this file is the one place something that TRANSMITS
// rather than reads is admitted, and it is admitted only in a shape that cannot
// become a load test.
//
// ValidateReadOnly answers "is this command SHAPED like a read?" by its lead
// token, and ping/traceroute can never pass it — they are not reads. So they get
// their OWN grammar rather than a hole in that one:
//
//	· the lead token is exactly ping/ping6/traceroute/traceroute6, optionally
//	  behind FortiOS's `execute`;
//	· every remaining token is a keyword this file knows, a NUMBER INSIDE THE
//	  BOUND that keyword carries, an argument-shaped token, or a placeholder;
//	· the flood/sweep/rapid/pattern modifiers — the ones that turn a probe into
//	  a packet generator — are refused by name;
//	· a probe with no destination is refused, because on several platforms a
//	  bare `ping` opens an INTERACTIVE dialog that would hang the session.
//
// The bounds are deliberately small. A TAC engineer asking "does it answer?"
// needs five echoes, not a thousand; a Correlix collection must never be the
// reason a device under investigation gets worse.
//
// This is a SHAPE check, exactly like ValidateReadOnly. The per-dialect closed
// table (CommandGate) still decides whether this specific probe is one an
// authored plan could have rendered for this device — no plan, no probe.

import (
	"fmt"
	"regexp"
	"strings"
)

// Probe bounds. They are constants, not configuration: a bound an operator can
// raise is not a bound.
const (
	// MaxProbeCount is the echo/repeat ceiling (count · repeat · -c).
	MaxProbeCount = 5
	// MaxProbeSize is the payload ceiling in bytes (size · packet-size · -s).
	MaxProbeSize = 1500
	// MaxProbeTimeoutSeconds is the per-probe wait ceiling.
	MaxProbeTimeoutSeconds = 5
	// MaxProbeHops is the traceroute TTL / max-hops ceiling.
	MaxProbeHops = 30
	// MaxProbeProbes is the per-hop probe ceiling for traceroute.
	MaxProbeProbes = 3
	// maxProbeTokens bounds the whole command (§9 bound everything).
	maxProbeTokens = 16
)

// probeLead is the closed set of probe verbs.
var probeLead = map[string]struct{}{
	"ping": {}, "ping6": {}, "traceroute": {}, "traceroute6": {},
}

// probeNumericKeyword maps a keyword that takes a NUMBER onto that number's
// ceiling. A keyword here without a number after it, or with a number above the
// ceiling, is a refusal.
var probeNumericKeyword = map[string]int{
	"count": MaxProbeCount, "repeat": MaxProbeCount, "-c": MaxProbeCount,
	"ntimes": MaxProbeCount,
	"size":   MaxProbeSize, "packet-size": MaxProbeSize, "datalen": MaxProbeSize,
	"data-size": MaxProbeSize, "-s": MaxProbeSize,
	"timeout": MaxProbeTimeoutSeconds, "wait-time": MaxProbeTimeoutSeconds,
	"-w":  MaxProbeTimeoutSeconds,
	"ttl": MaxProbeHops, "hop-limit": MaxProbeHops, "max-hops": MaxProbeHops,
	"maximum-hops": MaxProbeHops, "first-ttl": MaxProbeHops, "-m": MaxProbeHops,
	"probe": MaxProbeProbes, "probes": MaxProbeProbes, "queries": MaxProbeProbes,
	"-q": MaxProbeProbes,
}

// probeArgKeyword is the set of keywords that take an ARGUMENT-SHAPED token: a
// destination, a source, or the routing context to probe from.
var probeArgKeyword = map[string]struct{}{
	"host": {}, "source": {}, "source-address": {}, "source-interface": {},
	"source-ip": {}, "-a": {}, "interface": {}, "egress": {},
	"vrf": {}, "vpn-instance": {}, "instance": {}, "routing-instance": {},
	"network-instance": {}, "vdom": {}, "vsys": {}, "logical-router": {},
	"virtual-router": {},
}

// probeDestKeyword names the arg-taking keywords whose argument is the
// DESTINATION rather than a source or a routing context. PAN-OS writes
// `ping count 5 host 192.0.2.1`; without this the probe would look destinationless.
var probeDestKeyword = map[string]struct{}{"host": {}}

// probeFlag is the set of bare flags a probe may carry. `df-bit` is here on
// purpose: with the size capped at 1500 and the count at 5 it cannot be a flood,
// and the DF-bit probe is the standard path-MTU test every vendor's TAC asks
// for. The flood/sweep/rapid/pattern modifiers are NOT here — see probeBanned.
var probeFlag = map[string]struct{}{
	"df-bit": {}, "do-not-fragment": {}, "donotfragment": {}, "dont-fragment": {},
	"numeric": {}, "no-resolve": {}, "brief": {}, "detail": {},
	"inet": {}, "inet6": {}, "ipv4": {}, "ipv6": {}, "ip": {},
}

// probeBanned names the modifiers that turn a bounded probe into a packet
// generator or an unbounded run. They are refused by name so that a future
// bound-widening cannot let one in by accident.
var probeBanned = map[string]struct{}{
	"flood": {}, "-f": {}, "sweep": {}, "sweep-min": {}, "sweep-max": {},
	"sweep-incr": {}, "rapid": {}, "pattern": {}, "data-pattern": {},
	"continuous": {}, "infinite": {}, "-t": {}, "interval": {}, "-i": {},
	"adaptive": {}, "validate": {}, "bypass-routing": {}, "loose-source": {},
	"strict-source": {}, "record-route": {}, "verbose": {},
}

var (
	probeNumRE         = regexp.MustCompile(`^[0-9]{1,9}$`)
	probePlaceholderRE = regexp.MustCompile(`^\{[a-z][a-z0-9-]*\}$`)
)

// IsProbeCommand reports whether command LEADS like a bounded probe. It says
// nothing about whether the probe is in bounds — that is ValidateBoundedProbe —
// and exists so a caller can tell "not a probe at all" from "a probe out of
// bounds" when it reports a refusal.
func IsProbeCommand(command string) bool {
	toks := strings.Fields(command)
	if len(toks) > 0 && strings.EqualFold(toks[0], "execute") {
		toks = toks[1:]
	}
	if len(toks) == 0 {
		return false
	}
	_, ok := probeLead[strings.ToLower(toks[0])]
	return ok
}

// ValidateBoundedProbe returns nil iff command is a ping or traceroute whose
// every parameter is inside the bounds above. It is fail-closed: a token it does
// not recognise is a refusal, never a pass-through.
func ValidateBoundedProbe(command string) error {
	cmd := strings.TrimSpace(command)
	if cmd == "" {
		return fmt.Errorf("empty command")
	}
	// The structural refusals stand for a probe exactly as they do for a read:
	// they are about what the string can DO, not what it is called.
	for _, bad := range []string{";", "\n", "\r", "&", "`", "$(", "${", ">", "<", "!", "|"} {
		if strings.Contains(cmd, bad) {
			return fmt.Errorf("contains disallowed metacharacter %q", bad)
		}
	}
	toks := strings.Fields(cmd)
	if len(toks) > maxProbeTokens {
		return fmt.Errorf("probe carries %d tokens, more than the %d a bounded probe may", len(toks), maxProbeTokens)
	}
	if strings.EqualFold(toks[0], "execute") {
		// FortiOS spells `ping` as `execute ping`; the rest of the grammar is
		// identical, so the prefix is consumed and nothing else changes.
		toks = toks[1:]
		if len(toks) == 0 {
			return fmt.Errorf("`execute` with no probe verb after it")
		}
	}
	if _, ok := probeLead[strings.ToLower(toks[0])]; !ok {
		return fmt.Errorf("lead token %q is not a bounded probe verb (ping/ping6/traceroute/traceroute6)", toks[0])
	}
	destinations := 0
	for i := 1; i < len(toks); i++ {
		tok := toks[i]
		lower := strings.ToLower(tok)
		if _, banned := probeBanned[lower]; banned {
			return fmt.Errorf("modifier %q is not permitted on a bounded probe", tok)
		}
		if limit, ok := probeNumericKeyword[lower]; ok {
			if i+1 >= len(toks) {
				return fmt.Errorf("%q carries no value", tok)
			}
			i++
			n, nerr := probeNumber(toks[i])
			if nerr != nil {
				return fmt.Errorf("%q must be followed by a plain number, got %q", tok, toks[i])
			}
			if n < 1 || n > limit {
				return fmt.Errorf("%s %s is outside the bound (1..%d)", tok, toks[i], limit)
			}
			continue
		}
		if _, ok := probeArgKeyword[lower]; ok {
			if i+1 >= len(toks) {
				return fmt.Errorf("%q carries no value", tok)
			}
			i++
			if !probeArgOK(toks[i]) {
				return fmt.Errorf("%q is followed by %q, which is not an argument-shaped token", tok, toks[i])
			}
			if _, names := probeDestKeyword[lower]; names {
				// PAN-OS spells the destination `host <addr>`, so the argument
				// this keyword consumed IS the destination.
				destinations++
			}
			continue
		}
		if _, ok := probeFlag[lower]; ok {
			continue
		}
		if probeNumRE.MatchString(tok) {
			// A bare number is a per-dialect repeat count on some platforms and
			// a payload size on others. Which one it is cannot be told from the
			// string, so it is refused rather than guessed at.
			return fmt.Errorf("bare number %q: a probe's counts and sizes must be written with their keyword", tok)
		}
		if !probeArgOK(tok) {
			return fmt.Errorf("token %q is outside the bounded-probe grammar", tok)
		}
		destinations++
	}
	if destinations == 0 {
		return fmt.Errorf("probe names no destination; a bare ping/traceroute opens an interactive dialog on several platforms")
	}
	return nil
}

// probeNumber parses a bounded, plain decimal token. It refuses anything that is
// not digits, so a value can never carry a unit, a sign or a placeholder.
func probeNumber(tok string) (int, error) {
	if !probeNumRE.MatchString(tok) {
		return 0, fmt.Errorf("not a plain number")
	}
	n := 0
	for _, ch := range tok {
		n = n*10 + int(ch-'0')
	}
	return n, nil
}

// probeArgOK reports whether tok is shaped like a destination, a source or a
// routing-context name — or is an unrendered placeholder, which the caller's own
// closed grammar validates separately.
func probeArgOK(tok string) bool {
	if probePlaceholderRE.MatchString(tok) {
		return true
	}
	return argTokenRE.MatchString(tok)
}
