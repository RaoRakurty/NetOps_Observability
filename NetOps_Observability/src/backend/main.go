// Package main is the entry point for the NetOps Observability backend API.
//
// The binary serves a RESTful JSON API over HTTP plus a WebSocket endpoint
// for real-time event streaming. It is intentionally kept dependency-free
// (stdlib only) so the scaffold compiles in a clean Go environment without
// pulling modules from the network.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"netops/backend/alerts"
	"netops/backend/collectors"
	"netops/backend/models"
	"netops/backend/notify"
)

const version = "0.1.0-scaffold"

// server bundles the HTTP server with the long-running subsystems
// (discovery aggregator, collector pool, alert engine, notifier, user
// store for auth, and the live-events WebSocket hub).
type server struct {
	startedAt  time.Time
	discovery  *DiscoveryAggregator
	collectors *collectors.Pool
	alerts     *alerts.Engine
	notifier   *notify.Dispatcher
	users      *userStore
	roles      *roleStore
	tenants    *tenantStore
	apiKeys    *apiKeyStore
	saved      *savedStore
	reports    *reportScheduler
	hub        *Hub
}

func newServer() *server {
	d := NewDiscoveryAggregator()
	d.Register(NewStaticSource(os.Getenv("STATIC_DEVICES_PATH")))
	if os.Getenv("ENABLE_SNMP_DISCOVERY") == "true" {
		d.Register(NewSNMPSource(os.Getenv("SNMP_CIDR_RANGES")))
	}
	if os.Getenv("NETBOX_TOKEN") != "" {
		d.Register(NewNetboxSource(os.Getenv("NETBOX_URL"), os.Getenv("NETBOX_TOKEN")))
	}

	// Feed collectors the live device inventory so they poll real targets.
	pool := collectors.NewPool(func() []collectors.Target {
		devs := d.Devices()
		out := make([]collectors.Target, 0, len(devs))
		for _, dev := range devs {
			if dev.Address == "" {
				continue
			}
			out = append(out, collectors.Target{
				ID:       dev.ID,
				Address:  dev.Address,
				Protocol: dev.PreferredProtocol,
			})
		}
		return out
	})
	pool.Enable("snmp", os.Getenv("ENABLE_SNMP_COLLECTION") == "true")
	pool.Enable("gnmi", os.Getenv("ENABLE_GNMI_COLLECTION") == "true")
	pool.Enable("netconf", os.Getenv("ENABLE_NETCONF_COLLECTION") == "true")
	pool.Enable("tunnels", os.Getenv("ENABLE_TUNNEL_DISCOVERY") == "true")
	pool.Enable("snmpmetrics", os.Getenv("ENABLE_SNMP_METRICS") == "true")

	notifier := notify.NewDispatcher()
	if os.Getenv("FEATURE_SLACK_NOTIFICATIONS") == "true" {
		notifier.Register(notify.NewSlack(os.Getenv("SLACK_WEBHOOK_URL")))
	}
	if os.Getenv("FEATURE_PAGERDUTY_NOTIFICATIONS") == "true" {
		notifier.Register(notify.NewPagerDuty(os.Getenv("PAGERDUTY_KEY")))
	}
	if os.Getenv("FEATURE_EMAIL_NOTIFICATIONS") == "true" {
		notifier.Register(
			notify.NewEmail(os.Getenv("SMTP_HOST"), os.Getenv("SMTP_FROM")).
				WithAuth(os.Getenv("SMTP_USER"), os.Getenv("SMTP_PASS")).
				WithRecipients(os.Getenv("SMTP_TO")),
		)
	}
	if os.Getenv("FEATURE_TWILIO_NOTIFICATIONS") == "true" {
		notifier.Register(notify.NewTwilio(
			os.Getenv("TWILIO_ACCOUNT_SID"),
			os.Getenv("TWILIO_AUTH_TOKEN"),
			os.Getenv("TWILIO_FROM_NUMBER"),
			os.Getenv("TWILIO_TO_NUMBERS"),
		))
	}
	if os.Getenv("FEATURE_SNS_NOTIFICATIONS") == "true" {
		notifier.Register(notify.NewSNS(
			os.Getenv("AWS_ACCESS_KEY_ID"),
			os.Getenv("AWS_SECRET_ACCESS_KEY"),
			os.Getenv("AWS_REGION"),
			os.Getenv("SNS_PHONE_NUMBERS"),
			os.Getenv("SNS_TOPIC_ARN"),
		))
	}

	engine := alerts.NewEngine(os.Getenv("RULES_FILE"), notifier)

	users, err := newUserStore(envOr("USERS_FILE", "/data/users.json"))
	if err != nil {
		log.Fatalf("user store: %v", err)
	}
	if err := users.SeedAdmin(
		envOr("ADMIN_USERNAME", "admin"),
		os.Getenv("ADMIN_INITIAL_PASSWORD"),
	); err != nil {
		log.Printf("seed admin (non-fatal): %v", err)
	}

	roles, err := newRoleStore(envOr("ROLES_FILE", "/data/roles.json"))
	if err != nil {
		log.Fatalf("role store: %v", err)
	}
	tenants, err := newTenantStore(envOr("TENANTS_FILE", "/data/tenants.json"))
	if err != nil {
		log.Fatalf("tenant store: %v", err)
	}
	apiKeys, err := newAPIKeyStore(envOr("APIKEYS_FILE", "/data/apikeys.json"))
	if err != nil {
		log.Fatalf("api key store: %v", err)
	}

	saved, err := newSavedStore(envOr("SAVED_FILE", "/data/saved.json"))
	if err != nil {
		log.Fatalf("saved store: %v", err)
	}

	srv := &server{
		startedAt:  time.Now().UTC(),
		discovery:  d,
		collectors: pool,
		alerts:     engine,
		notifier:   notifier,
		users:      users,
		roles:      roles,
		tenants:    tenants,
		apiKeys:    apiKeys,
		saved:      saved,
		hub:        NewHub(),
	}
	srv.reports = newReportScheduler(srv, envOr("REPORT_RUNS_FILE", "/data/report_runs.json"))
	return srv
}

func main() {
	addr := envOr("LISTEN_ADDR", ":8080")
	srv := newServer()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.discovery.Start(ctx)
	srv.collectors.Start(ctx)
	srv.alerts.Start(ctx)
	if os.Getenv("ENABLE_REPORT_SCHEDULER") != "false" {
		srv.reports.Start(ctx)
	}
	go srv.startBroadcaster(ctx.Done())
	go srv.watchAlertsForBroadcast(ctx)

	mux := http.NewServeMux()
	srv.routes(mux)

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           withCORS(withLogging(srv.withAuth(mux))),
		ReadHeaderTimeout: 10 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("netops-api %s listening on %s", version, addr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server: %v", err)
		}
	}()

	<-stop
	log.Println("shutdown requested")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	cancel()
	log.Println("goodbye")
}

// routes wires every HTTP handler onto the supplied mux.
//
// The path layout is stable and matches what nginx routes to
// `/api/*` from the user-facing dashboard at port 8000.
func (s *server) routes(mux *http.ServeMux) {
	mux.HandleFunc("/admin/health", s.handleHealth)
	mux.HandleFunc("/admin/version", s.handleVersion)
	mux.HandleFunc("/api/auth/login", s.handleLogin)
	mux.HandleFunc("/api/auth/me", s.handleMe)
	mux.HandleFunc("/api/auth/change-password", s.handleChangePassword)
	mux.HandleFunc("/api/auth/permissions", s.handlePermissions)
	// Identity & access (admin-gated): users, roles, tenants, API keys.
	mux.HandleFunc("/api/users", s.handleUsers)
	mux.HandleFunc("/api/users/", s.handleUserByID)
	mux.HandleFunc("/api/roles", s.handleRoles)
	mux.HandleFunc("/api/roles/", s.handleRoleByID)
	mux.HandleFunc("/api/tenants", s.handleTenants)
	mux.HandleFunc("/api/tenants/", s.handleTenantByID)
	mux.HandleFunc("/api/apikeys", s.handleAPIKeys)
	mux.HandleFunc("/api/apikeys/", s.handleAPIKeyByID)
	mux.HandleFunc("/api/devices", s.handleDevices)
	mux.HandleFunc("/api/devices/", s.handleDeviceByID)
	mux.HandleFunc("/api/collectors", s.handleCollectors)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/rules", s.handleRules)
	mux.HandleFunc("/api/credentials", s.handleCredentials)
	mux.HandleFunc("/api/discovery/refresh", s.handleDiscoveryRefresh)
	mux.HandleFunc("/api/logs/search", s.handleLogsSearch)
	mux.HandleFunc("/api/logs/indices", s.handleLogsIndices)
	mux.HandleFunc("/api/flows/top", s.handleFlowsTopTalkers)
	mux.HandleFunc("/api/flows/by-proto", s.handleFlowsByProto)
	mux.HandleFunc("/api/flows/timeseries", s.handleFlowsTimeseries)
	mux.HandleFunc("/api/tunnels", s.handleTunnels)
	mux.HandleFunc("/api/findings", s.handleFindings)
	mux.HandleFunc("/api/saved", s.handleSaved)
	mux.HandleFunc("/api/saved/", s.handleSavedByID)
	mux.HandleFunc("/api/search/global", s.handleGlobalSearch)
	mux.HandleFunc("/api/reports/runs", s.handleReportRuns)
	mux.HandleFunc("/api/reports/run", s.handleReportRunNow)
	mux.HandleFunc("/api/copilot/chat", s.handleCopilot)
	mux.HandleFunc("/api/graphql", s.handleGraphQL)
	// Dashboard live data
	mux.HandleFunc("/api/metrics", s.handleMetricTiles)
	mux.HandleFunc("/api/metrics/query", s.handleMetricsQuery)
	mux.HandleFunc("/api/metrics/query_range", s.handleMetricsQueryRange)
	mux.HandleFunc("/api/metrics/names", s.handleMetricsNames)
	mux.HandleFunc("/api/events", s.handleEvents)
	// Prometheus scrape endpoint
	mux.HandleFunc("/metrics", s.handlePromMetrics)
}

func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "healthy",
		"version":    version,
		"uptime":     time.Since(s.startedAt).String(),
		"discovery":  s.discovery.Health(),
		"collectors": s.collectors.Health(),
		"alerts":     s.alerts.Health(),
	})
}

func (s *server) handleVersion(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"version": version})
}

func (s *server) handleDevices(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.discovery.Devices())
	case http.MethodPost:
		var d models.Device
		if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		s.discovery.Upsert(d)
		writeJSON(w, http.StatusCreated, d)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleDeviceByID(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/devices/"):]
	if id == "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		d, ok := s.discovery.Get(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, d)
	case http.MethodDelete:
		s.discovery.Delete(id)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleCollectors(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.collectors.Status())
}

func (s *server) handleAlerts(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.alerts.Active())
}

func (s *server) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.alerts.Rules())
	case http.MethodPost:
		var rule alerts.Rule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		s.alerts.AddRule(rule)
		writeJSON(w, http.StatusCreated, rule)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleCredentials(w http.ResponseWriter, _ *http.Request) {
	// Scaffold: credentials live in env / external vault. Never echo secrets back.
	writeJSON(w, http.StatusOK, map[string]any{
		"netbox":     os.Getenv("NETBOX_TOKEN") != "",
		"slack":      os.Getenv("SLACK_WEBHOOK_URL") != "",
		"pagerduty":  os.Getenv("PAGERDUTY_KEY") != "",
		"smtp":       os.Getenv("SMTP_HOST") != "",
		"twilio":     os.Getenv("TWILIO_ACCOUNT_SID") != "",
		"aws_sns":    os.Getenv("AWS_ACCESS_KEY_ID") != "" && os.Getenv("AWS_REGION") != "",
		"opensearch": os.Getenv("OPENSEARCH_URL") != "",
		"clickhouse": os.Getenv("CLICKHOUSE_URL") != "",
		"copilot":    os.Getenv("FEATURE_COPILOT") == "true" && os.Getenv("COPILOT_API_KEY") != "",
	})
}

func (s *server) handleDiscoveryRefresh(w http.ResponseWriter, _ *http.Request) {
	s.discovery.RefreshNow()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "refresh scheduled"})
}

func (s *server) handlePromMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP netops_devices_total Number of known devices.\n")
	fmt.Fprintf(w, "# TYPE netops_devices_total gauge\n")
	fmt.Fprintf(w, "netops_devices_total %d\n", len(s.discovery.Devices()))
	fmt.Fprintf(w, "# HELP netops_alerts_active Currently active alerts.\n")
	fmt.Fprintf(w, "# TYPE netops_alerts_active gauge\n")
	fmt.Fprintf(w, "netops_alerts_active %d\n", len(s.alerts.Active()))
}

// ---- helpers ----------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		logInfo("http", "request", map[string]any{
			"method":      r.Method,
			"path":        r.URL.Path,
			"status":      rw.status,
			"duration_ms": time.Since(start).Milliseconds(),
			"remote":      r.RemoteAddr,
		})
	})
}

// statusRecorder captures the response status code without altering the
// rest of the http.ResponseWriter contract.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Hijack lets the wrapped writer pass through to the underlying connection so
// the WebSocket endpoint (/api/events) can take over the socket. Without this
// the logging wrapper hides http.Hijacker and the upgrade fails with
// "server doesn't support connection hijack".
func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := s.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not support hijacking")
	}
	return hj.Hijack()
}
