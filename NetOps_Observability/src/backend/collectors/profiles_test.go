package collectors

import (
	"reflect"
	"testing"
)

func TestParseDottedOID(t *testing.T) {
	if got := parseDottedOID("1.3.6.1.2.1.1.3"); !reflect.DeepEqual(got, []int{1, 3, 6, 1, 2, 1, 1, 3}) {
		t.Errorf("got %v", got)
	}
	if got := parseDottedOID(" 1.3.6 "); !reflect.DeepEqual(got, []int{1, 3, 6}) {
		t.Errorf("trim: got %v", got)
	}
	if parseDottedOID("1.3.x.4") != nil {
		t.Error("non-numeric arc should be nil")
	}
	if parseDottedOID("9") != nil {
		t.Error("single arc should be nil")
	}
}

func TestSelectProfiles(t *testing.T) {
	profs := builtinProfiles()
	names := func(ps []SNMPProfile) []string {
		out := make([]string, len(ps))
		for i, p := range ps {
			out[i] = p.Name
		}
		return out
	}

	// Cisco (ent 9): generic + cisco, not juniper.
	got := names(selectProfiles(profs, 9, true))
	if !reflect.DeepEqual(got, []string{"generic", "cisco"}) {
		t.Errorf("cisco selection=%v", got)
	}
	// Juniper (ent 2636): generic + juniper.
	got = names(selectProfiles(profs, 2636, true))
	if !reflect.DeepEqual(got, []string{"generic", "juniper"}) {
		t.Errorf("juniper selection=%v", got)
	}
	// Unknown enterprise / detection failed: generic only.
	if got = names(selectProfiles(profs, 99999, true)); !reflect.DeepEqual(got, []string{"generic"}) {
		t.Errorf("unknown enterprise selection=%v", got)
	}
	if got = names(selectProfiles(profs, 0, false)); !reflect.DeepEqual(got, []string{"generic"}) {
		t.Errorf("no-detection selection=%v", got)
	}
}

func TestVendorLabel(t *testing.T) {
	if got := vendorLabel(9, true); got != "cisco" {
		t.Errorf("cisco=%q", got)
	}
	if got := vendorLabel(2636, true); got != "juniper" {
		t.Errorf("juniper=%q", got)
	}
	if got := vendorLabel(99999, true); got != "unknown" {
		t.Errorf("unknown ent=%q", got)
	}
	if got := vendorLabel(0, false); got != "generic" {
		t.Errorf("no detection=%q", got)
	}
}

func TestValueInt(t *testing.T) {
	if v := valueInt(berVal{tag: 0x02, raw: []byte{0xFF}}); v != -1 {
		t.Errorf("INTEGER -1 => %d", v)
	}
	if v := valueInt(berVal{tag: 0x42, raw: []byte{0x01, 0x00}}); v != 256 {
		t.Errorf("Gauge32 256 => %d", v)
	}
	if v := valueInt(berVal{tag: 0x46, raw: []byte{0x01, 0x00, 0x00}}); v != 65536 {
		t.Errorf("Counter64 65536 => %d", v)
	}
}
