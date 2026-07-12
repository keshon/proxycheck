// Package server exposes the check engine over HTTP for use inside a larger
// system. It is deliberately thin: no job queue, no database, no auth. The
// caller owns persistence and scheduling; this endpoint just checks and streams.
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/keshon/proxycheck/internal/presets"
	"github.com/keshon/proxycheck/pkg/check"
)

// Server wires the preset set to HTTP handlers.
type Server struct {
	presets *presets.Set
	localIP string
}

// New builds a Server. localIP (may be "") enables anonymity classification.
func New(p *presets.Set, localIP string) *Server {
	return &Server{presets: p, localIP: localIP}
}

// Handler returns the mux with all routes registered.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/presets", s.handlePresets)
	mux.HandleFunc("POST /v1/check", s.handleCheck)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

// presetInfo is the JSON shape returned by GET /v1/presets.
type presetInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (s *Server) handlePresets(w http.ResponseWriter, _ *http.Request) {
	var out []presetInfo
	for _, spec := range s.presets.All() {
		out = append(out, presetInfo{Name: spec.Name, Description: spec.Description})
	}
	writeJSON(w, http.StatusOK, out)
}

// checkRequest is the POST /v1/check body. Either Preset (by name) or an inline
// Spec must be supplied; Preset wins if both are present.
type checkRequest struct {
	Preset      string       `json:"preset"`
	Spec        *check.Spec  `json:"spec"`
	Proxies     []string     `json:"proxies"`
	Concurrency int          `json:"concurrency"`
	DialTimeout string       `json:"dial_timeout"`
}

// handleCheck streams NDJSON results, one per line, as each proxy finishes.
func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	var req checkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}

	spec, err := s.resolveSpec(req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Proxies) == 0 {
		writeErr(w, http.StatusBadRequest, "no proxies supplied")
		return
	}

	proxies, parseErrs := parseProxies(req.Proxies)
	if len(proxies) == 0 {
		writeErr(w, http.StatusBadRequest, "no valid proxies (all failed to parse)")
		_ = parseErrs
		return
	}

	opts := check.Options{Concurrency: req.Concurrency, LocalIP: s.localIP}
	if req.DialTimeout != "" {
		if d, err := time.ParseDuration(req.DialTimeout); err == nil {
			opts.DialTimeout = d
		}
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	var mu sync.Mutex
	enc := json.NewEncoder(w)
	emit := func(res check.Result) {
		mu.Lock()
		defer mu.Unlock()
		_ = enc.Encode(res) // Encode appends '\n' → NDJSON
		if flusher != nil {
			flusher.Flush()
		}
	}

	check.Run(r.Context(), proxies, spec, opts, emit)
}

func (s *Server) resolveSpec(req checkRequest) (check.Spec, error) {
	if req.Preset != "" {
		spec, ok := s.presets.Get(req.Preset)
		if !ok {
			return check.Spec{}, &httpError{"unknown preset " + req.Preset}
		}
		return spec, nil
	}
	if req.Spec != nil {
		if err := req.Spec.Validate(); err != nil {
			return check.Spec{}, err
		}
		return *req.Spec, nil
	}
	return check.Spec{}, &httpError{"must supply either preset or spec"}
}

func parseProxies(raws []string) ([]check.Proxy, []error) {
	var proxies []check.Proxy
	var errs []error
	for _, raw := range raws {
		p, err := check.ParseProxy(raw)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		proxies = append(proxies, p)
	}
	return proxies, errs
}

type httpError struct{ msg string }

func (e *httpError) Error() string { return e.msg }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// ListenAndServe starts the server with sane timeouts. ctx cancellation triggers
// a graceful shutdown.
func ListenAndServe(ctx context.Context, addr string, h http.Handler) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: /v1/check is a long-lived stream by design.
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	return srv.ListenAndServe()
}
