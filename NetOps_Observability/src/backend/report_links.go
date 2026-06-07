package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"html"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// report_links.go — secure-link delivery (delivery_mode="link"). Instead of
// emailing the report body, the pipeline emails a tamper-proof, short-lived link
// to a read-only view of the stored artifact. The token is an HMAC over
// (execution id, expiry) — unguessable and self-validating, so the view endpoint
// needs no session (it is the capability). This replaces the phase-1 stub that
// recorded link delivery as "pending" without leaking the body.

const reportLinkTTL = 7 * 24 * time.Hour

func reportLinkSecret() string {
	if v := os.Getenv("REPORT_LINK_SECRET"); v != "" {
		return v
	}
	return jwtSecret() // falls back to the app signing secret
}

// signReportLink mints "b64(execID).b64(tenant).b64(expiryUnix).b64(hmac)".
// SR-018: the tenant is bound INTO the token (like export links) so a leaked
// token can't be replayed against another tenant's execution id.
func signReportLink(execID, tenant string, ttl time.Duration) string {
	exp := strconv.FormatInt(time.Now().Add(ttl).Unix(), 10)
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(execID)) + "." + enc([]byte(tenant)) + "." + enc([]byte(exp)) + "." + linkSig(execID, tenant, exp)
}

func linkSig(execID, tenant, exp string) string {
	mac := hmac.New(sha256.New, []byte(reportLinkSecret()))
	mac.Write([]byte("report." + execID + "." + tenant + "." + exp))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// verifyReportLink returns (execID, tenant) if the token is well-formed, the
// signature matches, and it has not expired.
func verifyReportLink(token string) (string, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		return "", "", errors.New("malformed token")
	}
	idB, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", "", err
	}
	tenantB, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", err
	}
	expB, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", "", err
	}
	execID, tenant, exp := string(idB), string(tenantB), string(expB)
	if !hmac.Equal([]byte(linkSig(execID, tenant, exp)), []byte(parts[3])) {
		return "", "", errors.New("bad signature")
	}
	expUnix, err := strconv.ParseInt(exp, 10, 64)
	if err != nil {
		return "", "", err
	}
	if time.Now().Unix() > expUnix {
		return "", "", errors.New("link expired")
	}
	return execID, tenant, nil
}

// ---- export links --------------------------------------------------------
//
// A raw LOG EXPORT is bulk sensitive data (unlike a curated report), and links
// "may be forwarded externally" — so export links expire in MINUTES (not the
// report 7-day window) and are bound to BOTH the execution id AND the tenant id,
// so a leaked token can't be replayed against another tenant's artifact.

// exportLinkTTL is clamped to [5min, 15min] per the hardening policy.
func exportLinkTTL() time.Duration {
	d := envDuration("EXPORT_LINK_TTL", 10*time.Minute)
	if d < 5*time.Minute {
		d = 5 * time.Minute
	}
	if d > 15*time.Minute {
		d = 15 * time.Minute
	}
	return d
}

func exportLinkSig(execID, tenant, exp string) string {
	mac := hmac.New(sha256.New, []byte(reportLinkSecret()))
	mac.Write([]byte("export." + execID + "." + tenant + "." + exp))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// signExportLink mints "b64(execID).b64(tenant).b64(expiryUnix).b64(hmac)".
func signExportLink(execID, tenant string) string {
	exp := strconv.FormatInt(time.Now().Add(exportLinkTTL()).Unix(), 10)
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(execID)) + "." + enc([]byte(tenant)) + "." + enc([]byte(exp)) + "." + exportLinkSig(execID, tenant, exp)
}

// verifyExportLink returns (execID, tenant) iff the token is well-formed, the
// signature matches, and it has not expired.
func verifyExportLink(token string) (string, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		return "", "", errors.New("malformed token")
	}
	dec := base64.RawURLEncoding.DecodeString
	idB, e1 := dec(parts[0])
	tB, e2 := dec(parts[1])
	expB, e3 := dec(parts[2])
	if e1 != nil || e2 != nil || e3 != nil {
		return "", "", errors.New("malformed token")
	}
	execID, tenant, exp := string(idB), string(tB), string(expB)
	if !hmac.Equal([]byte(exportLinkSig(execID, tenant, exp)), []byte(parts[3])) {
		return "", "", errors.New("bad signature")
	}
	expUnix, err := strconv.ParseInt(exp, 10, 64)
	if err != nil {
		return "", "", err
	}
	if time.Now().Unix() > expUnix {
		return "", "", errors.New("link expired")
	}
	return execID, tenant, nil
}

// reportViewLink builds the absolute URL recipients click. REPORT_PUBLIC_BASE_URL
// should be the externally-reachable origin; when unset the link is path-only
// (works behind the same nginx, but set it for email clients).
func reportViewLink(execID, tenant, format string) string {
	base := strings.TrimRight(os.Getenv("REPORT_PUBLIC_BASE_URL"), "/")
	u := base + "/api/reports/view/" + signReportLink(execID, tenant, reportLinkTTL)
	if format != "" && format != "html" {
		u += "?format=" + format
	}
	return u
}

// buildLinkEmail is the small HTML body for a link-mode report email.
func buildLinkEmail(reportName, link string) string {
	rn := html.EscapeString(reportName)
	lk := html.EscapeString(link)
	return `<!DOCTYPE html><html><body style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;color:#1a1a2e;">` +
		`<div style="max-width:520px;margin:24px auto;padding:24px;border:1px solid #ececf2;border-radius:10px;">` +
		`<div style="font-size:16px;font-weight:700;">` + rn + ` is ready</div>` +
		`<p style="font-size:13px;color:#55556a;">Your report has been generated. View or download it with the secure link below (expires in 7 days).</p>` +
		`<p><a href="` + lk + `" style="display:inline-block;background:#5b5bd6;color:#fff;text-decoration:none;padding:10px 18px;border-radius:6px;font-size:14px;">Open report</a></p>` +
		`<p style="font-size:11px;color:#a0a0b0;word-break:break-all;">` + lk + `</p>` +
		`</div></body></html>`
}

// handleReportView serves a stored artifact to anyone holding a valid link token.
// No session required — the signed, expiring token is the authorization.
func (s *server) handleReportView(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.reportPipeline == nil {
		writeError(w, http.StatusConflict, errors.New("report links require the Postgres backend"))
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/api/reports/view/")
	execID, tenant, err := verifyReportLink(token)
	if err != nil {
		writeError(w, http.StatusForbidden, errors.New("invalid or expired report link"))
		return
	}
	// The token authorizes this specific execution; load it at platform scope.
	rec, _, found, err := s.reportPipeline.execs.Get(r.Context(), "", true, execID)
	if err != nil || !found {
		writeError(w, http.StatusNotFound, errors.New("report not found"))
		return
	}
	// SR-018: the token is bound to a tenant — it may only open an execution that
	// actually belongs to that tenant. Defends against a leaked/forwarded token
	// being replayed against another tenant's execution id (defense in depth with
	// the SR-002 authz fix).
	if rec.TenantID != tenant {
		writeError(w, http.StatusForbidden, errors.New("invalid or expired report link"))
		return
	}
	ref := rec.PrimaryArtifact()
	if f := r.URL.Query().Get("format"); f != "" {
		ref = rec.ArtifactByFormat(f)
	}
	if ref == nil {
		writeError(w, http.StatusNotFound, errors.New("no artifact for this format"))
		return
	}
	art, err := s.reportPipeline.artifacts.Load(r.Context(), *ref)
	if err != nil {
		writeError(w, http.StatusNotFound, errors.New("artifact unavailable"))
		return
	}
	w.Header().Set("Content-Type", art.ContentType)
	if ref.Format != "html" {
		w.Header().Set("Content-Disposition", "attachment; filename=\"report."+ref.Format+"\"")
	}
	_, _ = w.Write(art.Bytes)
}
