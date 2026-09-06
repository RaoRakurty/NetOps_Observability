// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package portintel

import (
	"strings"
)

// module.go — module-type detection resolver (owner rule: NEVER trust the
// interface description; derive from part number / EEPROM-CMIS / OpenConfig /
// ENTITY-MIB / speed / connector / lane count / wavelength / PMD app code).
//
// The resolver is deliberately layered by evidence strength: a CMIS/OpenConfig
// media-type or an explicit form-factor field is authoritative; a vendor part
// number's decoded family is strong; speed+lane+connector heuristics are the
// last-resort inference (recorded as such). Unknown is a first-class outcome —
// we normalize to FamUnknown/MediaUnknown rather than guess wrong.

// DetectInput is the raw evidence a collector gathered for one transceiver.
type DetectInput struct {
	FormFactorHint string  // OpenConfig/CMIS form-factor string if present
	PartNumber     string  // vendor PN
	MediaHint      string  // CMIS media / OpenConfig media-type
	Connector      string  // reported connector
	SpeedBps       int64   // interface speed
	LaneCount      int     // host/optical lane count
	WavelengthNm   float64 // 0 if unknown
	PMDAppCode     string  // reported PMD / application code (e.g. "400GBASE-DR4")
}

// Detected is the normalized result plus how it was derived (transparency).
type Detected struct {
	Family   ModuleFamily
	Media    MediaType
	OpticPMD string
	Method   string // "form_factor_field" | "part_number" | "pmd_app_code" | "heuristic" | "unknown"
}

// Detect resolves a normalized module family/media/PMD from the strongest
// available evidence. Order matters: explicit fields beat decoded part numbers
// beat heuristics.
func Detect(in DetectInput) Detected {
	// 1. Explicit form-factor field (CMIS/OpenConfig) — authoritative.
	if f := normalizeFamily(in.FormFactorHint); f != FamUnknown {
		return Detected{Family: f, Media: mediaFor(f, in), OpticPMD: normalizePMD(in.PMDAppCode), Method: "form_factor_field"}
	}
	// 2. PMD / application code (e.g. "400GBASE-DR4") — strong, carries media+reach.
	if pmd := normalizePMD(in.PMDAppCode); pmd != "" {
		fam := familyFromSpeedLane(in.SpeedBps, in.LaneCount)
		return Detected{Family: fam, Media: mediaFromPMD(pmd, in), OpticPMD: pmd, Method: "pmd_app_code"}
	}
	// 3. Part-number decode (vendor prefixes carry the family) — strong.
	if f := familyFromPartNumber(in.PartNumber); f != FamUnknown {
		return Detected{Family: f, Media: mediaFor(f, in), OpticPMD: normalizePMD(in.PMDAppCode), Method: "part_number"}
	}
	// 4. Speed + lane + connector heuristic — last resort, marked as such.
	if f := familyFromSpeedLane(in.SpeedBps, in.LaneCount); f != FamUnknown {
		return Detected{Family: f, Media: mediaHeuristic(in), OpticPMD: "", Method: "heuristic"}
	}
	return Detected{Family: FamUnknown, Media: MediaUnknown, Method: "unknown"}
}

// normalizeFamily canonicalizes a free-text form-factor string to a known family.
func normalizeFamily(s string) ModuleFamily {
	k := strings.ToUpper(strings.TrimSpace(s))
	k = strings.ReplaceAll(k, "_", "-")
	k = strings.ReplaceAll(k, " ", "")
	switch k {
	case "SFP":
		return FamSFP
	case "SFP+", "SFPPLUS":
		return FamSFPP
	case "SFP28":
		return FamSFP28
	case "SFP56":
		return FamSFP56
	case "SFP-DD", "SFPDD":
		return FamSFPDD
	case "QSFP", "QSFP+", "QSFPPLUS":
		return FamQSFPP
	case "QSFP28":
		return FamQSFP28
	case "QSFP56":
		return FamQSFP56
	case "QSFP-DD", "QSFPDD":
		return FamQSFPDD
	case "QSFP-DD800", "QSFPDD800":
		return FamQSFPDD800
	case "OSFP":
		return FamOSFP
	case "OSFP800":
		return FamOSFP800
	case "OSFP-XD", "OSFPXD":
		return FamOSFPXD
	case "CFP":
		return FamCFP
	case "CFP2":
		return FamCFP2
	case "CFP2-DCO", "CFP2DCO":
		return FamCFP2DCO
	case "DAC":
		return FamDAC
	case "AOC":
		return FamAOC
	case "AEC":
		return FamAEC
	}
	// Coherent ZR variants embedded in the string.
	if strings.Contains(k, "800ZR") {
		return Fam800ZR
	}
	if strings.Contains(k, "ZR") && strings.Contains(k, "QSFP-DD") {
		return FamQSFPDDZR
	}
	if knownFamilies[ModuleFamily(k)] {
		return ModuleFamily(k)
	}
	return FamUnknown
}

// familyFromPartNumber decodes common vendor PN prefixes to a family. This is a
// starter set — the vendor adapters (P3) extend it; unknown PN → FamUnknown so
// a later heuristic still runs.
func familyFromPartNumber(pn string) ModuleFamily {
	u := strings.ToUpper(pn)
	switch {
	case strings.HasPrefix(u, "QDD-") || strings.Contains(u, "QSFP-DD") || strings.Contains(u, "QSFPDD"):
		if strings.Contains(u, "ZR") {
			return FamQSFPDDZR
		}
		return FamQSFPDD
	case strings.HasPrefix(u, "QSFP28") || strings.Contains(u, "-QSFP28") || strings.HasPrefix(u, "QSFP-100G"):
		return FamQSFP28
	case strings.HasPrefix(u, "QSFP56") || strings.HasPrefix(u, "QSFP-200G"):
		return FamQSFP56
	case strings.HasPrefix(u, "OSFP"):
		return FamOSFP
	case strings.Contains(u, "SFP-25G") || strings.HasPrefix(u, "SFP28"):
		return FamSFP28
	case strings.Contains(u, "SFP-10G") || strings.HasPrefix(u, "SFP+"):
		return FamSFPP
	case strings.HasPrefix(u, "CFP2"):
		if strings.Contains(u, "DCO") {
			return FamCFP2DCO
		}
		return FamCFP2
	case strings.Contains(u, "-CU") || strings.Contains(u, "DAC"):
		return FamDAC
	case strings.Contains(u, "AOC"):
		return FamAOC
	}
	return FamUnknown
}

// familyFromSpeedLane is the last-resort inference from speed + lane count.
func familyFromSpeedLane(speedBps int64, lanes int) ModuleFamily {
	g := speedBps / 1_000_000_000
	switch {
	case g >= 800:
		return FamOSFP800
	case g >= 400:
		if lanes >= 8 {
			return FamQSFPDD
		}
		return FamQSFPDD
	case g >= 200:
		return FamQSFP56
	case g >= 100:
		if lanes <= 1 {
			return FamSFP112
		}
		return FamQSFP28
	case g >= 40:
		return FamQSFPP
	case g >= 25:
		return FamSFP28
	case g >= 10:
		return FamSFPP
	case g >= 1:
		return FamSFP
	}
	return FamUnknown
}

// mediaFor infers media from family + hints when no explicit media field exists.
func mediaFor(f ModuleFamily, in DetectInput) MediaType {
	if m := normalizeMedia(in.MediaHint); m != MediaUnknown {
		return m
	}
	switch f {
	case FamDAC, FamRJ45Copper, FamFixedCopper:
		return MediaCopper
	case FamAOC:
		return MediaAOC
	case FamAEC:
		return MediaAEC
	case FamCFP2DCO, FamQSFPDDZR, FamQSFPDDZRP, FamOSFPZR, Fam800ZR, Fam1600ZR:
		return MediaCoherent
	}
	return mediaHeuristic(in)
}

func mediaHeuristic(in DetectInput) MediaType {
	c := strings.ToUpper(in.Connector)
	switch {
	case c == "RJ45":
		return MediaCopper
	case strings.HasPrefix(c, "MPO") || strings.HasPrefix(c, "MTP"):
		return MediaSMF // parallel SM is the DC norm; adapter refines for SR
	case c == "LC" && in.WavelengthNm >= 1300:
		return MediaSMF
	case c == "LC" && in.WavelengthNm > 0:
		return MediaMMF
	}
	return MediaUnknown
}

func normalizeMedia(s string) MediaType {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "copper", "cu":
		return MediaCopper
	case "mmf", "multimode", "multimode_fiber", "sr":
		return MediaMMF
	case "smf", "singlemode", "singlemode_fiber":
		return MediaSMF
	case "dac":
		return MediaDAC
	case "aoc":
		return MediaAOC
	case "aec":
		return MediaAEC
	case "coherent":
		return MediaCoherent
	}
	return MediaUnknown
}

func mediaFromPMD(pmd string, in DetectInput) MediaType {
	u := strings.ToUpper(pmd)
	switch {
	case strings.Contains(u, "ZR"):
		return MediaCoherent
	case strings.HasPrefix(u, "SR") || strings.Contains(u, "BASE-SR"):
		return MediaMMF
	case strings.HasPrefix(u, "LR") || strings.HasPrefix(u, "DR") || strings.HasPrefix(u, "FR") ||
		strings.HasPrefix(u, "ER") || strings.Contains(u, "BASE-LR") || strings.Contains(u, "BASE-DR"):
		return MediaSMF
	case strings.HasPrefix(u, "CR") || strings.Contains(u, "BASE-CR"):
		return MediaCopper
	}
	return mediaFor(FamUnknown, in)
}

// normalizePMD uppercases and strips the "NNNGBASE-" speed prefix to the PMD
// suffix (DR4, LR4, ZR, …).
func normalizePMD(s string) string {
	u := strings.ToUpper(strings.TrimSpace(s))
	if u == "" {
		return ""
	}
	if i := strings.Index(u, "BASE-"); i >= 0 {
		return u[i+len("BASE-"):]
	}
	return u
}
