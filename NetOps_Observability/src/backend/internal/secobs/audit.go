package secobs

// audit.go names the security audit-event types once (SEC-020.1, T22).
//
// The audit store (internal/audit) deliberately has no Type column — the type
// axis rides in Event.Detail. Security-relevant records set
// Detail["sec_event"] to one of the constants below so the trail is queryable
// by event type without a schema migration, and so no two epics invent two
// spellings for the same action.
//
// Rules for values put in Detail alongside SecEventKey: identifiers and
// enumerations only — never a secret, token, key material, or credential
// (CLAUDE.md §8); the audit redaction test enforces the constants themselves
// stay in this closed set.

// SecEventKey is the Detail key carrying the security event type.
const SecEventKey = "sec_event"

// The security audit-event vocabulary. Reserved entries are named here by the
// epic that will emit them — same single-vocabulary rule as the metrics table.
const (
	// SecEventPostureExport — a transport-posture report was generated for
	// download (SEC-021.1; emitted).
	SecEventPostureExport = "transport_posture_export"
	// SecEventConfigChange — a security-relevant configuration surface was
	// mutated (gates, TLS knobs, trust bundles). Emitted by the epics that own
	// those surfaces as they land their write paths.
	SecEventConfigChange = "security_config_change"
	// SecEventExceptionReview — a declared plaintext exception was reviewed,
	// re-accepted, or retired (SEC-021.2, Phase 2+; reserved).
	SecEventExceptionReview = "security_exception_review"
	// SecEventCredentialRotation — a platform credential or SVID surface was
	// rotated outside the automatic re-issue loop (SEC-019; reserved).
	SecEventCredentialRotation = "security_credential_rotation"
	// SecEventQuarantineRestore — an operator re-attributed sealed quarantine
	// envelopes back into the pipeline (F-11 D5; emitted by the
	// /api/quarantine/reattribute handler). Detail carries identifiers and
	// counts only — never payload contents.
	SecEventQuarantineRestore = "quarantine_reattribute"
)

// SecEventTypes is the closed set, for tests and for the audit view's filter
// enumeration.
var SecEventTypes = []string{
	SecEventPostureExport,
	SecEventConfigChange,
	SecEventExceptionReview,
	SecEventCredentialRotation,
	SecEventQuarantineRestore,
}
