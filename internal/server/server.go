// Package server exposes a bounded checking API for authenticated or local clients.
package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/keshon/proxycheck/internal/presets"
	"github.com/keshon/proxycheck/pkg/check"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	MaxBodyBytes    = 1 << 20
	MaxProxies      = 1000
	MaxWorkers      = 64
	MaxActiveChecks = 4
	BatchTimeout    = 2 * time.Minute
)

type Config struct {
	Token               string
	AllowPrivateProxies bool
	AllowInlineSpecs    bool
}

type Server struct {
	presets  *presets.Set
	localIP  string
	config   Config
	slots    chan struct{}
	workerMu sync.Mutex
	workers  int
}

func New(p *presets.Set, localIP string, configs ...Config) *Server {
	var config Config
	if len(configs) > 0 {
		config = configs[0]
	}
	return &Server{presets: p, localIP: localIP, config: config, slots: make(chan struct{}, MaxActiveChecks)}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/presets", s.handlePresets)
	mux.HandleFunc("POST /v1/check", s.handleCheck)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path != "/healthz" {
			if r.Header.Get("Origin") != "" {
				writeErr(w, 403, "browser-origin requests are not supported")
				return
			}
			if s.config.Token != "" {
				got := sha256.Sum256([]byte(r.Header.Get("Authorization")))
				want := sha256.Sum256([]byte("Bearer " + s.config.Token))
				if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
					w.Header().Set("WWW-Authenticate", "Bearer")
					writeErr(w, 401, "authentication required")
					return
				}
			} else {
				host, _, err := net.SplitHostPort(r.RemoteAddr)
				ip, parseErr := netip.ParseAddr(host)
				if err != nil || parseErr != nil || !ip.IsLoopback() {
					writeErr(w, 403, "unauthenticated API accepts only loopback clients")
					return
				}
			}
		}
		mux.ServeHTTP(w, r)
	})
}

type presetInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (s *Server) handlePresets(w http.ResponseWriter, _ *http.Request) {
	out := []presetInfo{}
	for _, spec := range s.presets.All() {
		out = append(out, presetInfo{spec.Name, spec.Description})
	}
	writeJSON(w, 200, out)
}

type checkRequest struct {
	Preset      string      `json:"preset"`
	Spec        *check.Spec `json:"spec"`
	Proxies     []string    `json:"proxies"`
	Concurrency int         `json:"concurrency"`
	DialTimeout string      `json:"dial_timeout"`
}

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeErr(w, 415, "Content-Type must be application/json")
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		w.Header().Set("Retry-After", "1")
		writeErr(w, 429, "too many active checks")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), BatchTimeout)
	defer cancel()
	controller := http.NewResponseController(w)
	// Bound slow body uploads and slow stream consumers as well as checking work.
	_ = controller.SetReadDeadline(time.Now().Add(15 * time.Second))
	_ = controller.SetWriteDeadline(time.Now().Add(BatchTimeout))
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req checkRequest
	if err := dec.Decode(&req); err != nil {
		var sizeErr *http.MaxBytesError
		if errors.As(err, &sizeErr) {
			writeErr(w, 413, "request body exceeds 1 MiB")
		} else {
			writeErr(w, 400, "invalid JSON request")
		}
		return
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		var sizeErr *http.MaxBytesError
		if errors.As(err, &sizeErr) {
			writeErr(w, 413, "request body exceeds 1 MiB")
		} else {
			writeErr(w, 400, "request must contain one JSON object")
		}
		return
	}
	if len(req.Proxies) == 0 || len(req.Proxies) > MaxProxies {
		writeErr(w, 400, "supply between 1 and 1000 proxies")
		return
	}
	if req.Concurrency < 0 || req.Concurrency > MaxWorkers {
		writeErr(w, 400, "concurrency must be between 1 and 64, or 0 for the default")
		return
	}
	if req.Concurrency == 0 {
		req.Concurrency = 32
	}
	spec, err := s.resolveSpec(req)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	opts := check.Options{Concurrency: req.Concurrency, LocalIP: s.localIP, PublicProxiesOnly: !s.config.AllowPrivateProxies}
	if req.DialTimeout != "" {
		d, err := time.ParseDuration(req.DialTimeout)
		if err != nil || d <= 0 || d > 30*time.Second {
			writeErr(w, 400, "dial_timeout must be a duration greater than 0 and at most 30s")
			return
		}
		opts.DialTimeout = d
	}
	proxies := make([]check.Proxy, 0, len(req.Proxies))
	for i, raw := range req.Proxies {
		p, err := check.ParseProxy(raw)
		if err != nil {
			writeErr(w, 400, fmt.Sprintf("proxy at index %d is invalid", i))
			return
		}
		if !s.config.AllowPrivateProxies {
			if ip, err := netip.ParseAddr(p.Host); err == nil && !check.IsPublicIP(ip) {
				writeErr(w, 400, fmt.Sprintf("proxy at index %d is not a public address", i))
				return
			}
		}
		proxies = append(proxies, p)
	}
	reserved := min(req.Concurrency, len(proxies))
	s.workerMu.Lock()
	if s.workers+reserved > MaxWorkers {
		s.workerMu.Unlock()
		w.Header().Set("Retry-After", "1")
		writeErr(w, 429, "worker budget is busy")
		return
	}
	s.workers += reserved
	s.workerMu.Unlock()
	defer func() {
		s.workerMu.Lock()
		s.workers -= reserved
		s.workerMu.Unlock()
	}()
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(200)
	var mu sync.Mutex
	enc := json.NewEncoder(w)
	_ = check.Run(ctx, proxies, spec, opts, func(res check.Result) error {
		mu.Lock()
		defer mu.Unlock()
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := enc.Encode(res); err != nil {
			cancel()
			return err
		}
		if err := controller.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
			cancel()
			return err
		}
		return nil
	})
	// After streaming starts errors cannot be replaced by an HTTP error response.
	// Run cancels on sink failure; EOF on a canceled stream may be partial.
}

func (s *Server) resolveSpec(req checkRequest) (check.Spec, error) {
	if req.Preset != "" {
		spec, ok := s.presets.Get(req.Preset)
		if !ok {
			return check.Spec{}, fmt.Errorf("unknown preset")
		}
		return spec, spec.Validate()
	}
	if req.Spec != nil {
		if !s.config.AllowInlineSpecs {
			return check.Spec{}, fmt.Errorf("inline specs are disabled")
		}
		if err := req.Spec.Validate(); err != nil {
			return check.Spec{}, err
		}
		// Inline targets never accept literal or DNS-resolved special-use addresses.
		// Operators must still enforce egress policy at their trusted proxy.
		urls := []string{req.Spec.ExitIPProbe}
		for _, r := range req.Spec.Requests {
			urls = append(urls, r.URL)
		}
		for _, raw := range urls {
			if raw == "" {
				continue
			}
			u, _ := http.NewRequest(http.MethodGet, raw, nil)
			host := u.URL.Hostname()
			ip, err := netip.ParseAddr(host)
			if err != nil {
				return check.Spec{}, fmt.Errorf("inline target hosts must be public IP literals; use an operator preset for DNS targets")
			}
			if !check.IsPublicIP(ip) {
				return check.Spec{}, fmt.Errorf("inline targets must be public addresses")
			}
		}
		return *req.Spec, nil
	}
	return check.Spec{}, fmt.Errorf("supply a preset")
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func ValidateListenAddress(addr, token string) error {
	if token != "" && len(strings.TrimSpace(token)) < 32 {
		return fmt.Errorf("PROXYCHECK_API_TOKEN must have at least 32 characters")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	ip, parseErr := netip.ParseAddr(host)
	if parseErr == nil && ip.IsLoopback() {
		return nil
	}
	if len(strings.TrimSpace(token)) < 32 {
		return fmt.Errorf("non-loopback listeners require PROXYCHECK_API_TOKEN with at least 32 characters")
	}
	return nil
}

func ListenAndServe(ctx context.Context, addr string, h http.Handler) error {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: BatchTimeout, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := srv.Shutdown(shutCtx); err != nil {
				_ = srv.Close()
			}
		case <-done:
		}
	}()
	return srv.ListenAndServe()
}
