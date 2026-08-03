package backend

// tacacs_wiring.go — what stays in main after the TACACS+ wire client moved to
// internal/tacacs (Phase-2 W1.9): the login handler and the source-compat
// alias. The kv config store is in auth_config.go.

import (
	"errors"
	"net/http"

	"netops/backend/internal/tacacs"
)

type TACACS = tacacs.Client

func (s *server) handleTACACSLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req loginRequest
	// F-32: PRE-AUTH route — a TACACS+ sign-in is a username/password pair.
	if err := decodeJSONBody(w, r, authCredentialBodyBytes, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	t := s.tacacs.effective().client()
	if !t.Enabled() {
		writeError(w, http.StatusNotFound, errors.New("tacacs authentication not configured"))
		return
	}
	ok, err := t.Authenticate(req.Username, req.Password)
	if err != nil {
		logInfo("auth", "tacacs login error", map[string]any{"user": req.Username, "reason": err.Error()})
		writeError(w, http.StatusBadGateway, errors.New("tacacs authentication unavailable"))
		return
	}
	if !ok {
		logInfo("auth", "tacacs login failed", map[string]any{"user": req.Username})
		writeError(w, http.StatusUnauthorized, errors.New("invalid username or password"))
		return
	}
	user, err := s.users.UpsertFederated(req.Username, "", req.Username, t.DefaultRole(), "tacacs", t.DefaultTenant())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.logBindingSync(user, "tacacs") // PBAC Phase A: mirror the provisioned identity
	if user.Status == "disabled" {
		writeError(w, http.StatusUnauthorized, errors.New("account disabled"))
		return
	}
	logInfo("auth", "login ok", map[string]any{"user": user.Username, "role": user.Role, "src": "tacacs"})
	s.issueSession(w, r, user) // server-side session + tokens (same as password login)
}
