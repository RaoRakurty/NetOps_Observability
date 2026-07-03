package portintel

import (
	"errors"
	"testing"
)

func TestDetectFromExplicitFormFactor(t *testing.T) {
	d := Detect(DetectInput{FormFactorHint: "QSFP-DD", MediaHint: "smf", PMDAppCode: "400GBASE-DR4"})
	if d.Family != FamQSFPDD || d.Method != "form_factor_field" {
		t.Fatalf("explicit form factor should win: %+v", d)
	}
	if d.OpticPMD != "DR4" {
		t.Fatalf("PMD normalize wrong: %q", d.OpticPMD)
	}
}

func TestDetectFromPMDAppCode(t *testing.T) {
	// No form-factor field; PMD app code carries media + drives family via speed.
	d := Detect(DetectInput{PMDAppCode: "400GBASE-DR4", SpeedBps: 400_000_000_000, LaneCount: 8})
	if d.Method != "pmd_app_code" || d.Media != MediaSMF || d.OpticPMD != "DR4" {
		t.Fatalf("pmd path wrong: %+v", d)
	}
}

func TestDetectFromPartNumber(t *testing.T) {
	d := Detect(DetectInput{PartNumber: "QDD-400G-DR4-S"})
	if d.Family != FamQSFPDD || d.Method != "part_number" {
		t.Fatalf("part-number decode wrong: %+v", d)
	}
	z := Detect(DetectInput{PartNumber: "QDD-400G-ZR-S"})
	if z.Family != FamQSFPDDZR || z.Media != MediaCoherent {
		t.Fatalf("coherent PN decode wrong: %+v", z)
	}
}

func TestDetectHeuristicAndUnknown(t *testing.T) {
	// Only speed+lane → heuristic, flagged as such.
	d := Detect(DetectInput{SpeedBps: 25_000_000_000})
	if d.Family != FamSFP28 || d.Method != "heuristic" {
		t.Fatalf("speed heuristic wrong: %+v", d)
	}
	// Nothing usable → unknown, never a wrong guess.
	u := Detect(DetectInput{})
	if u.Family != FamUnknown || u.Media != MediaUnknown || u.Method != "unknown" {
		t.Fatalf("empty input must be unknown: %+v", u)
	}
}

func TestDetectNeverTrustsDescription(t *testing.T) {
	// A description-like string in no field influences detection; only real
	// evidence does. (Regression guard for the owner rule.)
	d := Detect(DetectInput{SpeedBps: 100_000_000_000, LaneCount: 4})
	if d.Family != FamQSFP28 {
		t.Fatalf("100G/4-lane should infer QSFP28: %+v", d)
	}
}

func TestInventoryValidate(t *testing.T) {
	ok := InventoryPayload{DeviceID: "leaf1", PortID: "leaf1:Et1", Family: FamQSFP28, MediaType: MediaMMF, Supported: SupSupported}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid payload rejected: %v", err)
	}
	if err := (InventoryPayload{PortID: "x"}).Validate(); !errors.Is(err, ErrNoDevice) {
		t.Fatalf("missing device must fail")
	}
	if err := (InventoryPayload{DeviceID: "d", PortID: "p", Family: "BOGUS"}).Validate(); !errors.Is(err, ErrBadFamily) {
		t.Fatalf("unknown family must fail")
	}
	if err := (InventoryPayload{DeviceID: "d", PortID: "p", MediaType: "plasma"}).Validate(); !errors.Is(err, ErrBadMedia) {
		t.Fatalf("unknown media must fail")
	}
	// Empty family/media normalize (present-but-unread optic) — not an error.
	if err := (InventoryPayload{DeviceID: "d", PortID: "p"}).Validate(); err != nil {
		t.Fatalf("empty enums should be allowed: %v", err)
	}
}

func TestLaneValidate(t *testing.T) {
	if err := (LanePayload{DeviceID: "d", PortID: "p", LaneID: 3}).Validate(); err != nil {
		t.Fatalf("valid lane rejected: %v", err)
	}
	if err := (LanePayload{DeviceID: "d", PortID: "p", LaneID: 99}).Validate(); !errors.Is(err, ErrLaneRange) {
		t.Fatalf("out-of-range lane must fail")
	}
}

func TestPathAndEventValidate(t *testing.T) {
	if err := (FiberPathPayload{PathID: "path-1"}).Validate(); err != nil {
		t.Fatalf("valid path rejected: %v", err)
	}
	if err := (FiberPathPayload{}).Validate(); !errors.Is(err, ErrNoPath) {
		t.Fatalf("missing path id must fail")
	}
	if err := (EventPayload{DeviceID: "d", EventType: "link_down"}).Validate(); err != nil {
		t.Fatalf("valid event rejected: %v", err)
	}
	if err := (EventPayload{DeviceID: "d"}).Validate(); !errors.Is(err, ErrNoEventType) {
		t.Fatalf("missing event type must fail")
	}
}

func TestTopicsRegistered(t *testing.T) {
	if len(AllTopics()) != 6 {
		t.Fatalf("expected 6 port topics, got %d", len(AllTopics()))
	}
}
