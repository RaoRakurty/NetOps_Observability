package protocoldiag

// typedbridge.go — the SIGNATURE ↔ PARSER bridge (design
// IRIS_TROUBLESHOOTING_MODEL_2026-09-02 §3.2, "protocoldiag signatures consume
// typed fields where available and fall back to regex").
//
// A signature that reads a BGP FSM state with `(?i)\bidle\b` is matching a WORD
// somewhere in the capture. That is good enough to fire, and it is exactly why
// it can fire on the wrong thing: the word "Idle" appears in a neighbour
// description, in a log line, in an unrelated column. A signature that reads
// BGPPeer.State from a parsed row is matching a FIELD, and a field cannot be
// somewhere else.
//
// The bridge is therefore TYPED-FIRST, REGEX-FALLBACK, and never typed-only:
//
//	1. try the parser for this command on this device's dialect;
//	2. if it produced typed rows, decide on the fields and cite the row's own
//	   source line;
//	3. if the parse SKIPPED (an unknown dialect, an unrecognized layout, a
//	   truncated capture), fall through to the regex matcher unchanged.
//
// Step 3 is what keeps every existing signature test green and what keeps a
// platform we have no parser for exactly as diagnosable as it was before. The
// bridge never makes a verdict MORE likely than the regex would have: a typed
// row that says "not Idle" refuses the finding rather than deferring to the
// regex, which is the whole point.

import (
	"strings"

	"netops/backend/internal/showparse"
)

// collectionDialect resolves the CLI dialect a Collection was captured from.
// It reads the device PLATFORM string (the same free-form label the vendor
// registry keys on), NOT the three-value catalog Vendor: the catalog collapses
// IOS-XE, NX-OS, IOS-XR and EOS into one "cisco-iosxe" rendering dialect, and
// the parsers do not — reading the platform back is what keeps a NX-OS capture
// from being handed to the IOS-XE parser.
//
// ok=false means the platform is unassessed and the caller must use the regex
// path. There is no default dialect.
func collectionDialect(col *Collection) (showparse.Dialect, bool) {
	if col == nil {
		return "", false
	}
	return showparse.DialectFromPlatform(col.Platform)
}

// typedBGPPeers parses the named command's captured output into typed BGP peer
// rows. ok=false means "no typed view is available" — an unassessed platform, a
// command that errored or was never captured, or a parse that honestly skipped.
func typedBGPPeers(col *Collection, specID string) ([]showparse.BGPPeer, bool) {
	dialect, ok := collectionDialect(col)
	if !ok {
		return nil, false
	}
	cc, ok := col.command(specID)
	if !ok {
		return nil, false
	}
	res, err := showparse.Parse(showparse.CmdBGPSummary, dialect, cc.Output)
	if err != nil || res.Skipped || len(res.BGPPeers) == 0 {
		return nil, false
	}
	return res.BGPPeers, true
}

// bgpPeerLine finds the captured line the typed peer row came from, so a typed
// finding cites the SAME kind of evidence a regex finding does: the operator
// still reads the device's own text, not a struct dump.
func bgpPeerLine(cc CollectedCommand, peer string) (string, bool) {
	for _, ln := range strings.Split(cc.Output, "\n") {
		fs := strings.Fields(ln)
		if len(fs) > 0 && fs[0] == peer {
			return strings.TrimSpace(ln), true
		}
	}
	return "", false
}

// typedBGPStateEvidence finds the first typed peer row whose state satisfies
// want, and returns the evidence line for it.
//
// The three-valued return is the contract that makes the fallback safe:
//
//	(ev, true,  true)  — a typed row matched: fire on the field
//	(_,  false, true)  — a typed view EXISTS and NO row matched: refuse, and do
//	                     NOT fall back (the parser has already answered)
//	(_,  false, false) — no typed view: the caller runs its regex matcher
func typedBGPStateEvidence(col *Collection, specID string, want func(showparse.BGPPeer) bool) (Evidence, bool, bool) {
	peers, ok := typedBGPPeers(col, specID)
	if !ok {
		return Evidence{}, false, false
	}
	cc, ok := col.command(specID)
	if !ok {
		return Evidence{}, false, false
	}
	for _, p := range peers {
		if !want(p) {
			continue
		}
		line, found := bgpPeerLine(cc, p.Peer)
		if !found {
			// The row exists but its source line cannot be located. A finding
			// without its evidence line is not allowed (analyze.go's contract),
			// so this is treated as "no typed answer" and the regex path runs.
			return Evidence{}, false, false
		}
		return evidenceOf(cc, line), true, true
	}
	return Evidence{}, false, true
}

// bgpStateIs returns a predicate matching a typed peer whose FSM state is any of
// the named states. Comparison is on the parser's NORMALIZED state vocabulary
// (showparse maps "Estab"/"Establ"/"established" onto "Established" and the
// admin-shut spellings onto "Idle (Admin)"), so a caller names a state once and
// gets every dialect's spelling of it.
func bgpStateIs(states ...string) func(showparse.BGPPeer) bool {
	return func(p showparse.BGPPeer) bool {
		for _, s := range states {
			if strings.EqualFold(p.State, s) {
				return true
			}
		}
		return false
	}
}
