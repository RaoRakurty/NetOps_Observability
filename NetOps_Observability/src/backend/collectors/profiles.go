package collectors

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
)

// profiles.go — vendor SNMP metric profiles, the multivendor lever (the same
// idea as Datadog NDM "profiles"). A profile is a set of OID→metric definitions
// selected by the device's sysObjectID enterprise number. The generic profile
// (Enterprise 0) applies to every device using standard MIBs; vendor profiles
// layer vendor-specific health OIDs on top. Built-ins ship in code; an operator
// can extend/override them with a JSON file (SNMP_PROFILES_FILE) — no recompile,
// no MIB compiler, exactly the curated OID-catalog approach we settled on.

// SNMPMetric is one pollable object. For a scalar the instance ".0" is appended
// at poll time; for a table the column is walked and each row labelled by index.
type SNMPMetric struct {
	Name  string
	OID   []int
	Table bool
}

// SNMPProfile is a named OID set matched by sysObjectID enterprise number.
type SNMPProfile struct {
	Name       string
	Enterprise int // 0 = generic (matches every device)
	Metrics    []SNMPMetric
}

// builtinProfiles is the shipped catalog. OIDs are numeric (no MIB files
// needed) and follow published standard/vendor MIBs; verify against a given
// platform and extend via the JSON override when needed.
func builtinProfiles() []SNMPProfile {
	return []SNMPProfile{
		{
			Name:       "generic",
			Enterprise: 0,
			Metrics: []SNMPMetric{
				{Name: "device_sysuptime", OID: []int{1, 3, 6, 1, 2, 1, 1, 3}},                           // sysUpTime
				{Name: "device_if_oper_status", OID: []int{1, 3, 6, 1, 2, 1, 2, 2, 1, 8}, Table: true},   // ifOperStatus
				{Name: "device_if_in_octets", OID: []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6}, Table: true}, // ifHCInOctets
				{Name: "device_if_out_octets", OID: []int{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 10}, Table: true},
				{Name: "device_cpu_percent", OID: []int{1, 3, 6, 1, 2, 1, 25, 3, 3, 1, 2}, Table: true},  // hrProcessorLoad (HOST-RESOURCES-MIB)
				{Name: "device_sensor_value", OID: []int{1, 3, 6, 1, 2, 1, 99, 1, 1, 1, 4}, Table: true}, // entPhySensorValue (ENTITY-SENSOR-MIB)
			},
		},
		{
			Name:       "cisco",
			Enterprise: 9,
			Metrics: []SNMPMetric{
				{Name: "device_cpu_percent", OID: []int{1, 3, 6, 1, 4, 1, 9, 9, 109, 1, 1, 1, 1, 8}, Table: true}, // cpmCPUTotal5minRev
				{Name: "device_mem_used_bytes", OID: []int{1, 3, 6, 1, 4, 1, 9, 9, 48, 1, 1, 1, 5}, Table: true},  // ciscoMemoryPoolUsed
				{Name: "device_temp_celsius", OID: []int{1, 3, 6, 1, 4, 1, 9, 9, 13, 1, 3, 1, 3}, Table: true},    // ciscoEnvMonTemperatureValue
			},
		},
		{
			Name:       "juniper",
			Enterprise: 2636,
			Metrics: []SNMPMetric{
				{Name: "device_cpu_percent", OID: []int{1, 3, 6, 1, 4, 1, 2636, 3, 1, 13, 1, 8}, Table: true},  // jnxOperatingCPU
				{Name: "device_temp_celsius", OID: []int{1, 3, 6, 1, 4, 1, 2636, 3, 1, 13, 1, 7}, Table: true}, // jnxOperatingTemp
				{Name: "device_mem_percent", OID: []int{1, 3, 6, 1, 4, 1, 2636, 3, 1, 13, 1, 11}, Table: true}, // jnxOperatingBuffer
			},
		},
	}
}

// loadProfiles returns the built-in catalog merged with an optional JSON
// override file (SNMP_PROFILES_FILE, default /config/snmp_profiles.json). A
// file profile with the same Name as a built-in replaces it; new names are
// appended. Missing/invalid file → built-ins only.
func loadProfiles() []SNMPProfile {
	profs := builtinProfiles()
	path := os.Getenv("SNMP_PROFILES_FILE")
	if path == "" {
		path = "/config/snmp_profiles.json"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return profs
	}
	var ext []profileJSON
	if json.Unmarshal(b, &ext) != nil {
		return profs
	}
	idxByName := make(map[string]int, len(profs))
	for i, p := range profs {
		idxByName[p.Name] = i
	}
	for _, pj := range ext {
		conv := SNMPProfile{Name: pj.Name, Enterprise: pj.Enterprise}
		for _, m := range pj.Metrics {
			oid := parseDottedOID(m.OID)
			if oid == nil {
				continue
			}
			conv.Metrics = append(conv.Metrics, SNMPMetric{Name: m.Name, OID: oid, Table: m.Table})
		}
		if i, ok := idxByName[conv.Name]; ok {
			profs[i] = conv
		} else {
			idxByName[conv.Name] = len(profs)
			profs = append(profs, conv)
		}
	}
	return profs
}

type profileJSON struct {
	Name       string `json:"name"`
	Enterprise int    `json:"enterprise"`
	Metrics    []struct {
		Name  string `json:"name"`
		OID   string `json:"oid"`
		Table bool   `json:"table"`
	} `json:"metrics"`
}

// selectProfiles returns every profile that applies to a device: the generic
// profile always, plus the vendor profile matching the enterprise number.
func selectProfiles(profiles []SNMPProfile, enterprise int, ok bool) []SNMPProfile {
	var out []SNMPProfile
	for _, p := range profiles {
		if p.Enterprise == 0 || (ok && p.Enterprise == enterprise) {
			out = append(out, p)
		}
	}
	return out
}

// parseDottedOID converts "1.3.6.1.2.1.1.3" to arcs, or nil if malformed.
func parseDottedOID(s string) []int {
	parts := strings.Split(strings.TrimSpace(s), ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	if len(out) < 2 {
		return nil
	}
	return out
}
