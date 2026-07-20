// Package portintel is the Port Intelligence / physical-layer domain (#94,
// design docs/design/port-intelligence.md). It holds the normalized models for
// ports, transceivers, lanes, DDM/DOM, FEC/BER, coherent PM and fiber paths,
// plus the module-detection resolver and payload validators. It is a pure
// domain package: no DB driver, no HTTP, no SNMP — the server wires storage,
// collectors and API around these types (same boundary discipline as appid).
package portintel

import (
	"errors"
	"strings"
)

// ---- enums (owner spec 2026-07-02) --------------------------------------------
// Normalized taxonomies. Detection NEVER trusts interface-description text — the
// resolver (module.go) derives these from part number / EEPROM-CMIS / OpenConfig
// transceiver data / ENTITY-MIB / speed / connector / lane count / wavelength.

// ModuleFamily is the transceiver form-factor family.
type ModuleFamily string

const (
	// Legacy
	FamGBIC   ModuleFamily = "GBIC"
	FamXFP    ModuleFamily = "XFP"
	FamXENPAK ModuleFamily = "XENPAK"
	FamX2     ModuleFamily = "X2"
	FamXPAK   ModuleFamily = "XPAK"
	FamCFP    ModuleFamily = "CFP"
	FamCFP2   ModuleFamily = "CFP2"
	FamCFP4   ModuleFamily = "CFP4"
	FamCFP8   ModuleFamily = "CFP8"
	FamCXP    ModuleFamily = "CXP"
	FamCDFP   ModuleFamily = "CDFP"
	// SFP family
	FamSFP    ModuleFamily = "SFP"
	FamSFPP   ModuleFamily = "SFP+"
	FamSFP28  ModuleFamily = "SFP28"
	FamSFP56  ModuleFamily = "SFP56"
	FamSFP112 ModuleFamily = "SFP112"
	FamSFPDD  ModuleFamily = "SFP-DD"
	FamCSFP   ModuleFamily = "CSFP"
	// QSFP family
	FamQSFP       ModuleFamily = "QSFP"
	FamQSFPP      ModuleFamily = "QSFP+"
	FamQSFP14     ModuleFamily = "QSFP14"
	FamQSFP28     ModuleFamily = "QSFP28"
	FamQSFP56     ModuleFamily = "QSFP56"
	FamQSFP112    ModuleFamily = "QSFP112"
	FamQSFPDD     ModuleFamily = "QSFP-DD"
	FamQSFPDD800  ModuleFamily = "QSFP-DD800"
	FamQSFPDD1600 ModuleFamily = "QSFP-DD1600"
	// OSFP family
	FamOSFP     ModuleFamily = "OSFP"
	FamOSFPRHS  ModuleFamily = "OSFP-RHS"
	FamOSFP800  ModuleFamily = "OSFP800"
	FamOSFP1600 ModuleFamily = "OSFP1600"
	FamOSFPXD   ModuleFamily = "OSFP-XD"
	// Coherent / DCO
	FamCFP2DCO      ModuleFamily = "CFP2-DCO"
	FamQSFPDDZR     ModuleFamily = "QSFP-DD-ZR"
	FamQSFPDDZRP    ModuleFamily = "QSFP-DD-ZR+"
	FamQSFPDDOpenZR ModuleFamily = "QSFP-DD-OpenZR+"
	FamOSFPZR       ModuleFamily = "OSFP-ZR"
	FamOSFPZRP      ModuleFamily = "OSFP-ZR+"
	FamOSFPOpenZR   ModuleFamily = "OSFP-OpenZR+"
	Fam800ZR        ModuleFamily = "800ZR"
	Fam1600ZR       ModuleFamily = "1600ZR"
	// Cable
	FamDAC         ModuleFamily = "DAC"
	FamAOC         ModuleFamily = "AOC"
	FamAEC         ModuleFamily = "AEC"
	FamACC         ModuleFamily = "ACC"
	FamRJ45Copper  ModuleFamily = "RJ45-copper"
	FamFixedCopper ModuleFamily = "fixed-copper"
	FamFixedFiber  ModuleFamily = "fixed-fiber"
	FamUnknown     ModuleFamily = "unknown"
)

// MediaType is the physical medium class.
type MediaType string

const (
	MediaCopper   MediaType = "copper"
	MediaMMF      MediaType = "multimode_fiber"
	MediaSMF      MediaType = "singlemode_fiber"
	MediaDAC      MediaType = "dac"
	MediaAOC      MediaType = "aoc"
	MediaAEC      MediaType = "aec"
	MediaCoherent MediaType = "coherent"
	MediaUnknown  MediaType = "unknown"
)

// SupportedStatus classifies a transceiver against the platform's qualified list.
type SupportedStatus string

const (
	SupSupported   SupportedStatus = "supported"
	SupThirdParty  SupportedStatus = "third_party"
	SupUnsupported SupportedStatus = "unsupported"
	SupUnknown     SupportedStatus = "unknown"
)

// knownFamilies / knownMedia / knownSupported are the validation allowlists.
var (
	knownFamilies = buildSet([]ModuleFamily{
		FamGBIC, FamXFP, FamXENPAK, FamX2, FamXPAK, FamCFP, FamCFP2, FamCFP4, FamCFP8, FamCXP, FamCDFP,
		FamSFP, FamSFPP, FamSFP28, FamSFP56, FamSFP112, FamSFPDD, FamCSFP,
		FamQSFP, FamQSFPP, FamQSFP14, FamQSFP28, FamQSFP56, FamQSFP112, FamQSFPDD, FamQSFPDD800, FamQSFPDD1600,
		FamOSFP, FamOSFPRHS, FamOSFP800, FamOSFP1600, FamOSFPXD,
		FamCFP2DCO, FamQSFPDDZR, FamQSFPDDZRP, FamQSFPDDOpenZR, FamOSFPZR, FamOSFPZRP, FamOSFPOpenZR, Fam800ZR, Fam1600ZR,
		FamDAC, FamAOC, FamAEC, FamACC, FamRJ45Copper, FamFixedCopper, FamFixedFiber, FamUnknown,
	})
	knownMedia = buildSet([]MediaType{
		MediaCopper, MediaMMF, MediaSMF, MediaDAC, MediaAOC, MediaAEC, MediaCoherent, MediaUnknown,
	})
	knownSupported = buildSet([]SupportedStatus{SupSupported, SupThirdParty, SupUnsupported, SupUnknown})
)

func buildSet[T ~string](vals []T) map[T]bool {
	m := make(map[T]bool, len(vals))
	for _, v := range vals {
		m[v] = true
	}
	return m
}

// ---- normalized payloads (validated at every ingestion boundary) --------------

// InventoryPayload is a normalized transceiver+port inventory record from a
// collector (gNMI/OpenConfig, SNMP ENTITY-MIB, or a vendor adapter). The
// high-cardinality identity fields (serial/part) land in relational storage,
// never TSDB labels (cardinality law).
type InventoryPayload struct {
	TenantID     string          `json:"tenant_id"`
	DeviceID     string          `json:"device_id"`
	PortID       string          `json:"port_id"`
	IfName       string          `json:"if_name"`
	Present      bool            `json:"transceiver_present"`
	Family       ModuleFamily    `json:"form_factor"`
	MediaType    MediaType       `json:"media_type"`
	OpticPMD     string          `json:"optic_pmd"`
	Connector    string          `json:"connector_type"`
	VendorName   string          `json:"vendor_name"`
	VendorOUI    string          `json:"vendor_oui"`
	PartNumber   string          `json:"part_number"`
	SerialNumber string          `json:"serial_number"`
	WavelengthNm float64         `json:"wavelength_nm"`
	ReachM       int64           `json:"reach_meters"`
	LaneCount    int             `json:"lane_count"`
	Supported    SupportedStatus `json:"supported_status"`
	CMISVersion  string          `json:"cmis_version"`
}

// LanePayload is a per-lane metric snapshot.
type LanePayload struct {
	TenantID   string  `json:"tenant_id"`
	DeviceID   string  `json:"device_id"`
	PortID     string  `json:"port_id"`
	LaneID     int     `json:"lane_id"`
	RxPowerDBM float64 `json:"lane_rx_power_dbm"`
	TxPowerDBM float64 `json:"lane_tx_power_dbm"`
	TxBiasMA   float64 `json:"lane_tx_bias_ma"`
	PreFECBER  float64 `json:"lane_pre_fec_ber"`
	PostFECBER float64 `json:"lane_post_fec_ber"`
	LaneState  string  `json:"lane_state"`
}

// CoherentPMPayload is a coherent-optic performance sample (carrier handoff).
type CoherentPMPayload struct {
	TenantID      string  `json:"tenant_id"`
	DeviceID      string  `json:"device_id"`
	PortID        string  `json:"port_id"`
	OSNRdB        float64 `json:"osnr_db"`
	ESNRdB        float64 `json:"esnr_db"`
	CDpsnm        float64 `json:"cd_ps_nm"`
	DGDps         float64 `json:"dgd_ps"`
	PDLdB         float64 `json:"pdl_db"`
	FreqOffsetHz  float64 `json:"carrier_freq_offset_hz"`
	OpticalFreqHz float64 `json:"optical_frequency_hz"`
	InputPowerDBM float64 `json:"input_power_dbm"`
	MinRxOSNRdB   float64 `json:"min_rx_osnr_db"`
	PreFECThresh  float64 `json:"pre_fec_threshold"`
}

// FiberPathPayload is a physical-path object (relational-only).
type FiberPathPayload struct {
	TenantID       string `json:"tenant_id"`
	PathID         string `json:"path_id"`
	CircuitID      string `json:"circuit_id"`
	PolarityMethod string `json:"polarity_method"`
	PanelID        string `json:"panel_id"`
	CassetteID     string `json:"cassette_id"`
	ADevice        string `json:"a_device_id"`
	ZDevice        string `json:"z_device_id"`
}

// EventPayload is a physical-layer event (insert/remove/link/threshold).
type EventPayload struct {
	TenantID  string `json:"tenant_id"`
	DeviceID  string `json:"device_id"`
	PortID    string `json:"port_id"`
	EventType string `json:"event_type"`
	Severity  string `json:"severity"`
	Summary   string `json:"summary"`
}

// ---- validators (zero-trust boundary: every payload is validated) -------------

var (
	ErrNoTenant    = errors.New("portintel: tenant_id required")
	ErrNoDevice    = errors.New("portintel: device_id required")
	ErrNoPort      = errors.New("portintel: port_id required")
	ErrBadFamily   = errors.New("portintel: unknown module family")
	ErrBadMedia    = errors.New("portintel: unknown media type")
	ErrBadSupport  = errors.New("portintel: unknown supported_status")
	ErrLaneRange   = errors.New("portintel: lane_id out of range")
	ErrNoPath      = errors.New("portintel: path_id required")
	ErrNoEventType = errors.New("portintel: event_type required")
)

func (p InventoryPayload) Validate() error {
	if strings.TrimSpace(p.TenantID) == "" && p.TenantID != "" {
		return ErrNoTenant
	}
	if p.DeviceID == "" {
		return ErrNoDevice
	}
	if p.PortID == "" {
		return ErrNoPort
	}
	// Empty family normalizes to unknown, not an error (a present-but-unread optic).
	if p.Family != "" && !knownFamilies[p.Family] {
		return ErrBadFamily
	}
	if p.MediaType != "" && !knownMedia[p.MediaType] {
		return ErrBadMedia
	}
	if p.Supported != "" && !knownSupported[p.Supported] {
		return ErrBadSupport
	}
	return nil
}

func (p LanePayload) Validate() error {
	if p.DeviceID == "" {
		return ErrNoDevice
	}
	if p.PortID == "" {
		return ErrNoPort
	}
	if p.LaneID < 0 || p.LaneID > 63 { // OSFP-XD/QSFP-DD1600 top out well under this
		return ErrLaneRange
	}
	return nil
}

func (p CoherentPMPayload) Validate() error {
	if p.DeviceID == "" {
		return ErrNoDevice
	}
	if p.PortID == "" {
		return ErrNoPort
	}
	return nil
}

func (p FiberPathPayload) Validate() error {
	if p.PathID == "" {
		return ErrNoPath
	}
	return nil
}

func (p EventPayload) Validate() error {
	if p.DeviceID == "" {
		return ErrNoDevice
	}
	if p.EventType == "" {
		return ErrNoEventType
	}
	return nil
}
