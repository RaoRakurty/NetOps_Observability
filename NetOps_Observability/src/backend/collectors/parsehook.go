package collectors

// parsehook.go — the PARSER DECISION TRACE for the Go collectors
// (docs/design/PIPELINE_DEBUGGER_2026-09-04.md §2, stage 2).
//
// WHAT IT ADDS THAT A TAP CANNOT. `correlix-debug` already shows the EVENT that
// left each hop. What no tap can show is the DECISION: which trap OID matched
// which MIB entry, what severity that mapping implied, which varbinds were
// resolved to names and which stayed raw OIDs, and — the line that ends
// incidents — WHY something was dropped. "The trap is not in the store" and
// "the varbind cap dropped 4 bindings past the 64th" are different findings.
//
// COST WHEN NOTHING IS BEING TRACED. One strings.Index for the marker token,
// then an atomic-guarded read of the armed needle. No map is built and nothing
// is formatted unless a record actually matches: the fields arrive as a closure
// for exactly that reason. A trap receiver under a storm must not pay for a
// debug facility nobody armed.
//
// WHY THE HOOK IS HERE AND NOT IN snmptrap.go. snmptrap.go is the SNMP wire
// decoder; the debugger is a separate concern with its own lifetime and its own
// removal rule. Keeping the hook in its own file means the decoder gains one
// call and the whole feature can be lifted out by deleting this file and that
// call — the same deletability the DEBUG-ROUTES markers give main.go (§2).

import (
	"fmt"
	"strings"

	"netops/backend/internal/parsetrace"
)

// TrapParseComponent is the component name every trap decision line carries.
// The `parse:` prefix is what files the line under the trace's PARSER stage
// rather than its api stage (internal/pipedebug.ParseComponentPrefix).
const TrapParseComponent = "parse:snmptrap"

// traceTrapDecision records how one decoded trap was interpreted.
//
// It is called AFTER finalizeTrap has resolved the trap OID, the MIB name, the
// severity and the varbind set, because those resolutions ARE the decision path
// — recording the raw PDU instead would just be the tap's evidence again.
func traceTrapDecision(ev *TrapEvent) {
	if ev == nil {
		return
	}
	f := parsetrace.Default()
	// The marker travels in the trap's own message (the probe puts it in an
	// OCTET STRING varbind, which finalizeTrap concatenates into ev.Message),
	// so the message is what is matched. Matching the whole struct would mean
	// serialising every trap just to decide whether to trace it.
	marker, ok := f.Match(ev.Message)
	if !ok {
		return
	}
	f.Emit(marker, TrapParseComponent, "trap decoded", func() map[string]any {
		names := make([]string, 0, len(ev.Varbinds))
		unresolved := 0
		for _, vb := range ev.Varbinds {
			if vb.Name == "" {
				unresolved++
				names = append(names, vb.OID)
				continue
			}
			names = append(names, vb.Name)
		}
		fields := map[string]any{
			"matched_trap_oid":  ev.TrapOID,
			"matched_trap_name": orUnmatched(ev.TrapName),
			"severity":          ev.Severity,
			"vendor":            ev.Vendor,
			"device":            ev.Device,
			"source_ip":         ev.Host,
			"extracted_fields":  names,
			"varbinds_kept":     len(ev.Varbinds),
			"unresolved_oids":   unresolved,
			"parser_status":     ev.ParserStatus,
			"event_type":        ev.EventType,
			"category":          ev.Category,
			"family":            ev.Family,
		}
		// EVERY DROP GETS A REASON. A count with no reason is the shape that
		// makes an operator guess, which is what this hook exists to stop.
		if ev.VarbindsDropped > 0 {
			fields["dropped"] = ev.VarbindsDropped
			fields["drop_reason"] = fmt.Sprintf(
				"the trap carried more than the %d-varbind cap; bindings past it were not decoded (collectors.parseVarbinds)", maxTrapVarbinds)
		}
		if ev.Truncated {
			fields["truncated"] = true
			fields["truncation_reason"] = fmt.Sprintf(
				"the assembled message exceeded the %d-character cap and was clamped (collectors.boundMessage)", maxTrapMessageChars)
		}
		if ev.TrapName == "" {
			fields["no_match_reason"] = "no MIB entry matched this trap OID, so the event carries the OID verbatim and the default severity — a correlation rule keyed on a trap NAME will not fire for it"
		}
		return fields
	})
}

// TraceParseDrop records a record the collector REFUSED, with the reason.
//
// A refusal is the single most valuable line a parser trace can carry, and it
// is also the one a tap can never show: a dropped record leaves no event to
// tap. `text` is whatever carries the marker (a message, a frame); `reason`
// must name the rule that refused it, not merely that something did.
func TraceParseDrop(text, component, reason string, fields map[string]any) {
	f := parsetrace.Default()
	marker, ok := f.Match(text)
	if !ok {
		return
	}
	f.Emit(marker, component, "record DROPPED: "+reason, func() map[string]any {
		out := map[string]any{"dropped": true, "drop_reason": reason}
		for k, v := range fields {
			out[k] = v
		}
		return out
	})
}

func orUnmatched(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(no MIB match)"
	}
	return s
}
