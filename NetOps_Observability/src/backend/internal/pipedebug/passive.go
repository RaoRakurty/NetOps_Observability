package pipedebug

// passive.go — following REAL traffic instead of injecting one (design §2).
//
// THE RULE THIS FILE ENFORCES, AND WHY IT IS A RULE AND NOT A PREFERENCE.
// A gNMI update originates on the DEVICE: the collector dials in and the device
// streams. There is no wire form the debugger could send to the stack that
// would produce one, and the only way to mint a gNMI update at all would be to
// write a leaf on a live router. The debugger never writes to a device (§5), so
// gNMI is PASSIVE-ONLY — and the failure mode this file exists to make
// impossible is the opposite one: a `--passive` request that quietly degrades
// into an injection, putting a synthetic record into a customer's pipeline that
// the operator explicitly asked not to be created. Every path here is
// read-only, and RunPassive is reached only after HandleTrace has refused to
// inject.
//
// WHAT PASSIVE EVIDENCE CAN AND CANNOT PROVE. A marked trace proves that ONE
// named record crossed a hop. A passive follow proves that SOME traffic from a
// device crossed a hop inside a window. That is a genuinely weaker claim, and
// every verdict this file produces says so in its reason rather than borrowing
// the marked trace's stronger wording.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// PassiveSpec is a marker-less follow of real traffic for one device.
type PassiveSpec struct {
	// Kind is the telemetry class. Only gNMI is supported (PassiveOnly).
	Kind Kind `json:"kind"`
	// Device is the collector's target NAME (gnmic `name:`), which is also the
	// `source` label on the raw lane and the `device` label on the canonical
	// one. Validated by ValidDeviceKey before it reaches a selector.
	Device string `json:"device"`
	// Path narrows to one gNMI path family, as the metric-name fragment gnmic
	// derives from the path. "" follows every path the device streams.
	Path string `json:"path,omitempty"`
	// Since is how far back to look, clamped to MaxPassiveSince.
	Since time.Duration `json:"since"`
}

// ClampSince bounds a requested passive window into (0, MaxPassiveSince].
func ClampSince(d time.Duration) time.Duration {
	if d <= 0 {
		return 10 * time.Minute
	}
	if d > MaxPassiveSince {
		return MaxPassiveSince
	}
	return d
}

// NormalizePathFilter turns an operator's gNMI path into the metric-name
// fragment gnmic mints, under a CLOSED grammar.
//
// The value ends up inside a PromQL regex, so it is not merely trimmed: every
// character that is not [a-z0-9_] is rejected AFTER the separators gnmic itself
// folds (`/`, `-`, `.`, `:`) have been folded to `_`. That leaves no regex
// metacharacter that could reach the selector, which is what makes the
// interpolation in PassiveSeriesSelector safe rather than merely tidy (§3).
func NormalizePathFilter(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", nil
	}
	if len(s) > 128 {
		return "", errors.New("path filter must be at most 128 characters")
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		case r == '/', r == '-', r == '.', r == ':':
			b.WriteRune('_')
		default:
			return "", fmt.Errorf("path filter may contain only letters, digits and _-/.: (got %q)", r)
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "", errors.New("path filter reduced to nothing")
	}
	return out, nil
}

// PassiveSeriesSelector renders the VictoriaMetrics selector for a passive
// follow.
//
// The RAW lane is the one queried (`gnmi_*`, gnmic's `metric-prefix: gnmi`):
// it carries every subscribed path verbatim, whereas the canonical lane is
// deliberately narrowed by the ownership gate — a family withheld there is
// absent by DESIGN, and querying it would render a working subscription as a
// missing one.
func PassiveSeriesSelector(device, path string) string {
	name := "gnmi_.*"
	if path != "" {
		name = "gnmi_.*" + path + ".*"
	}
	return fmt.Sprintf(`{__name__=~"%s",source="%s"}`, name, device)
}

// PassiveVictoriaStage is the ONE stage a passive gNMI follow can prove
// positively: did this device's subscribed paths actually land in the metric
// store inside the window.
func (a *API) PassiveVictoriaStage(ctx context.Context, spec PassiveSpec) Entry {
	e := Entry{Stage: StageVictoria, Module: string(StageVictoria)}
	sel := PassiveSeriesSelector(spec.Device, spec.Path)
	now := a.deps.now()
	start := now.Add(-ClampSince(spec.Since))
	e.Query = fmt.Sprintf("GET /api/v1/export?match[]=%s&start=%d&end=%d", sel, start.Unix(), now.Unix())
	if a.deps.VictoriaExport == nil {
		return notObservable(e, "no VictoriaMetrics client is wired into this API build")
	}
	raw, err := a.deps.VictoriaExport(ctx, sel, start, now)
	if err != nil {
		return notObservable(e, "VictoriaMetrics export failed: "+err.Error())
	}
	series, newest, samples := summarizeExport(raw)
	if series == 0 {
		e.Verdict = VerdictNotSeen
		e.Reason = fmt.Sprintf(
			"no gNMI series for device %q in the last %s. That is the device's whole raw lane, so an empty answer means gnmic delivered nothing for it — check the target's state in `docker logs gnmic` (ingress.log) before suspecting a later hop",
			spec.Device, ClampSince(spec.Since).Round(time.Second))
		return e
	}
	e.Verdict = VerdictSeen
	e.FirstSeen = newest
	e.EvidenceRef = StageVictoria.LogFile()
	e.Detail = map[string]any{
		"series": series, "samples": samples, "selector": sel,
		"newest_sample": newest.Format(time.RFC3339),
		"claim":         "SOME gNMI traffic from this device reached the metric store inside the window. A passive follow cannot name ONE update the way a marked trace names one record — the marked kinds carry a per-record marker and this one cannot",
	}
	return e
}

// summarizeExport counts the series and samples in a VictoriaMetrics
// /api/v1/export body (newline-delimited JSON, one object per series) and finds
// the newest sample timestamp.
//
// A line that does not decode is COUNTED as undecodable rather than skipped:
// silently dropping it would let a garbled export read as a smaller-but-fine
// result set.
func summarizeExport(raw []byte) (series int, newest time.Time, samples int) {
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var row struct {
			Timestamps []int64 `json:"timestamps"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			// Undecodable lines still prove SOMETHING was exported; they are
			// counted as a series so the stage never reports "no series" for a
			// body that plainly had content.
			series++
			continue
		}
		series++
		samples += len(row.Timestamps)
		for _, ms := range row.Timestamps {
			if t := time.UnixMilli(ms).UTC(); t.After(newest) {
				newest = t
			}
		}
	}
	return series, newest, samples
}

// passiveFollow runs every server-side stage for a passive follow, in pipeline
// order. It is the passive twin of API.follow — and, unlike that one, it does
// NOT poll: the evidence is already in the stores, so there is nothing to wait
// for and waiting would only make an operator think something was in flight.
func (a *API) passiveFollow(ctx context.Context, p Principal, spec PassiveSpec, marker string) []Entry {
	// Every server-side stage is queried, including the ones that can only
	// answer "not observable, because …" for this kind. Skipping them would
	// leave those rows ABSENT from the timeline, and an absent row reads as a
	// hop that was fine — the same defect as an empty module file.
	return []Entry{
		a.KafkaStage(ctx, spec.Kind, marker),
		a.OpenSearchStage(ctx, p, spec.Kind, marker, ""),
		a.PassiveVictoriaStage(ctx, spec),
		a.ClickHouseStage(ctx, p, spec.Kind, marker),
		a.CorrelationStage(ctx, p, spec.Kind, marker),
		a.APIStage(marker),
	}
}

// PassiveRefusal is the message a kind that is NOT passive-followable gets.
func PassiveRefusal(k Kind) error { return errors.New(PassiveReason(k)) }
