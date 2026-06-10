package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"netops/backend/alerts"
)

// rules_user.go — persistence and API for OPERATOR-CREATED alert rules
// ("monitors"). The engine's rules file (RULES_FILE) holds the curated
// built-in set and is read-only at runtime; rules created through the API
// (the Monitors form / New Monitor wizard) live here, in a kv-persisted list
// that is re-loaded into the engine at startup — previously a POSTed rule
// silently vanished on restart.
//
// Ownership is tracked with the rule label origin=ui (riding the existing
// schema, no model change): only rules carrying it can be deleted through the
// API, so the built-in set can't be mutated remotely.

const userRuleOriginLabel = "ui"

// userRulesStore is the durable list of operator-created rules. The engine
// remains the single evaluation authority — this store only feeds it.
type userRulesStore struct {
	mu   sync.Mutex
	path string
}

func newUserRulesStore(path string) *userRulesStore {
	return &userRulesStore{path: path}
}

func (s *userRulesStore) load() ([]alerts.Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *userRulesStore) loadLocked() ([]alerts.Rule, error) {
	b, err := kvLoad(s.path)
	if err != nil || len(b) == 0 {
		return nil, nil // absent = no user rules yet (first run)
	}
	var rules []alerts.Rule
	if err := json.Unmarshal(b, &rules); err != nil {
		return nil, fmt.Errorf("user rules %s corrupt: %w", s.path, err)
	}
	return rules, nil
}

func (s *userRulesStore) add(r alerts.Rule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rules, err := s.loadLocked()
	if err != nil {
		return err
	}
	rules = append(rules, r)
	return s.saveLocked(rules)
}

// remove deletes the named rule and reports whether it existed here. Only
// rules in this store (origin=ui) are removable — built-ins never enter it.
func (s *userRulesStore) remove(name string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rules, err := s.loadLocked()
	if err != nil {
		return false, err
	}
	kept := rules[:0]
	removed := false
	for _, r := range rules {
		if r.Name == name {
			removed = true
			continue
		}
		kept = append(kept, r)
	}
	if !removed {
		return false, nil
	}
	return true, s.saveLocked(kept)
}

func (s *userRulesStore) saveLocked(rules []alerts.Rule) error {
	b, err := json.Marshal(rules)
	if err != nil {
		return err
	}
	return kvSave(s.path, b)
}

// ---- validation -------------------------------------------------------------

var ruleNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

var ruleSeverities = map[string]bool{"info": true, "warning": true, "critical": true}

// validateUserRule enforces the API contract for operator-created rules. The
// expression is NOT parsed here — it is sent verbatim to VictoriaMetrics, which
// is the PromQL authority; we only bound its size.
func validateUserRule(r alerts.Rule) error {
	switch {
	case !ruleNameRe.MatchString(r.Name):
		return errors.New("name must be 1-128 chars: letters, digits, '-', '_' (leading alphanumeric)")
	case strings.TrimSpace(r.Expr) == "":
		return errors.New("expression is required")
	case len(r.Expr) > 2048:
		return errors.New("expression too long (max 2048 chars)")
	case !ruleSeverities[r.Severity]:
		return errors.New("severity must be info, warning or critical")
	case r.For < 0 || r.For > 24*time.Hour:
		return errors.New("'for' must be between 0s and 24h")
	}
	return nil
}

// ---- server wiring ------------------------------------------------------------

// loadUserRules feeds the persisted operator-created rules into the engine at
// startup. Corruption is logged, never fatal — the built-in rule set must keep
// evaluating regardless.
func (s *server) loadUserRules() {
	rules, err := s.userRules.load()
	if err != nil {
		log.Printf("alerts: %v (operator-created monitors not loaded)", err)
		return
	}
	for _, r := range rules {
		s.alerts.AddRule(r)
	}
	if len(rules) > 0 {
		log.Printf("alerts: loaded %d operator-created monitor(s)", len(rules))
	}
}

// handleRules serves the merged rule list (GET), creates a persistent
// operator rule (POST), and deletes an operator rule (DELETE ?name=).
func (s *server) handleRules(w http.ResponseWriter, r *http.Request) {
	// SR-004: alert rules are PLATFORM-GLOBAL (no TenantID) — they encode device
	// names/thresholds/topology and fire across every tenant. So reading and
	// writing them is platform-owner-only, mirroring handleCollectors. (A future
	// per-tenant rule model would relax the read gate; until then a scoped tenant
	// must neither enumerate global rules nor inject one.)
	if _, ok := s.requireCrossTenant(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.alerts.Rules())
	case http.MethodPost:
		var rule alerts.Rule
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&rule); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := validateUserRule(rule); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		for _, existing := range s.alerts.Rules() {
			if existing.Name == rule.Name {
				writeError(w, http.StatusConflict, fmt.Errorf("a rule named %q already exists", rule.Name))
				return
			}
		}
		if rule.Labels == nil {
			rule.Labels = map[string]string{}
		}
		rule.Labels["origin"] = userRuleOriginLabel
		if err := s.userRules.add(rule); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		s.alerts.AddRule(rule)
		writeJSON(w, http.StatusCreated, rule)
	case http.MethodDelete:
		name := strings.TrimSpace(r.URL.Query().Get("name"))
		if name == "" {
			writeError(w, http.StatusBadRequest, errors.New("missing 'name'"))
			return
		}
		removed, err := s.userRules.remove(name)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !removed {
			// Either unknown, or a built-in (file) rule — both are non-deletable
			// through the API and indistinguishable on purpose.
			writeError(w, http.StatusNotFound, errors.New("no operator-created rule with that name"))
			return
		}
		s.alerts.RemoveRule(name)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
