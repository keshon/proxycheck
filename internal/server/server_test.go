package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/keshon/proxycheck/internal/presets"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testServer(t *testing.T, config Config) *Server {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte("name: test\nrequests:\n  - url: http://target.invalid/\n"), 0600); err != nil {
		t.Fatal(err)
	}
	set, err := presets.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return New(set, "", config)
}
func request(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", "/v1/check", strings.NewReader(body))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func payload(proxy string) string {
	b, _ := json.Marshal(map[string]any{"preset": "test", "proxies": []string{proxy}, "concurrency": 1})
	return string(b)
}

func TestAuthenticationAndBindDefaults(t *testing.T) {
	token := strings.Repeat("x", 32)
	s := testServer(t, Config{Token: token})
	for _, auth := range []string{"", "Bearer wrong", "Bearer " + token} {
		r := httptest.NewRequest("GET", "/v1/presets", nil)
		r.Header.Set("Authorization", auth)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		want := 401
		if auth == "Bearer "+token {
			want = 200
		}
		if w.Code != want {
			t.Errorf("auth status %d, want %d", w.Code, want)
		}
	}
	local := testServer(t, Config{})
	r := httptest.NewRequest("GET", "/v1/presets", nil)
	r.RemoteAddr = "192.0.2.1:80"
	w := httptest.NewRecorder()
	local.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("non-loopback caller accepted without authentication")
	}
	r = httptest.NewRequest("GET", "/v1/presets", nil)
	r.RemoteAddr = "127.0.0.1:80"
	r.Header.Set("Origin", "https://untrusted.invalid")
	w = httptest.NewRecorder()
	local.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("browser origin accepted")
	}
	for _, c := range []struct {
		addr, token string
		ok          bool
	}{{"127.0.0.1:8080", "", true}, {"[::1]:8080", "", true}, {":8080", "", false}, {"0.0.0.0:8080", token, true}, {"127.0.0.1:8080", "weak", false}, {"bad", "", false}} {
		if got := ValidateListenAddress(c.addr, c.token); (got == nil) != c.ok {
			t.Errorf("bind %s: %v", c.addr, got)
		}
	}
}

func TestRequestValidationBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprint(w, "ok") }))
	defer proxy.Close()
	s := testServer(t, Config{AllowPrivateProxies: true})
	mixed, _ := json.Marshal(map[string]any{"preset": "test", "proxies": []string{proxy.URL, "malformed"}})
	many := make([]string, MaxProxies+1)
	manyJSON, _ := json.Marshal(map[string]any{"preset": "test", "proxies": many})
	cases := []struct {
		name, body string
		status     int
	}{{"mixed", string(mixed), 400}, {"too-many", string(manyJSON), 400}, {"concurrency", `{"preset":"test","proxies":["8.8.8.8:80"],"concurrency":65}`, 400}, {"timeout", `{"preset":"test","proxies":["8.8.8.8:80"],"dial_timeout":"bad"}`, 400}, {"inline-disabled", `{"spec":{"name":"test","requests":[{"url":"http://8.8.8.8"}]},"proxies":["8.8.8.8:80"]}`, 400}, {"unknown-field", `{"preset":"test","proxies":["8.8.8.8:80"],"typo":true}`, 400}, {"trailing", payload(proxy.URL) + ` {}`, 400}, {"oversize", `{"preset":"` + strings.Repeat("x", MaxBodyBytes) + `"}`, 413}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := request(t, s, c.body)
			if w.Code != c.status {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("invalid batch caused network work")
	}
	if w := request(t, testServer(t, Config{}), payload(proxy.URL)); w.Code != 400 {
		t.Fatal("private proxy accepted by default")
	}
	r := httptest.NewRequest("POST", "/v1/check", strings.NewReader(payload(proxy.URL)))
	r.RemoteAddr = "127.0.0.1:80"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 415 {
		t.Fatal("non-JSON content type accepted")
	}
}

func TestStreamHasOneRecordPerAcceptedProxy(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer proxy.Close()
	body, _ := json.Marshal(map[string]any{"preset": "test", "proxies": []string{proxy.URL, proxy.URL}})
	w := request(t, testServer(t, Config{AllowPrivateProxies: true}), string(body))
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w.Header().Get("Content-Type") != "application/x-ndjson" {
		t.Fatal("wrong content type")
	}
	dec := json.NewDecoder(w.Body)
	n := 0
	for {
		var result map[string]any
		err := dec.Decode(&result)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if result["ok"] != true {
			t.Fatal(result)
		}
		n++
	}
	if n != 2 {
		t.Fatalf("got %d records", n)
	}
}

func TestMaximumAcceptedBatch(t *testing.T) {
	var calls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprint(w, "ok") }))
	defer proxy.Close()
	proxies := make([]string, MaxProxies)
	for i := range proxies {
		proxies[i] = proxy.URL
	}
	body, _ := json.Marshal(map[string]any{"preset": "test", "proxies": proxies})
	w := request(t, testServer(t, Config{AllowPrivateProxies: true}), string(body))
	if w.Code != 200 {
		t.Fatalf("maximum batch rejected: %d %s", w.Code, w.Body.String())
	}
	dec := json.NewDecoder(w.Body)
	count := 0
	for {
		var result struct {
			OK bool `json:"ok"`
		}
		err := dec.Decode(&result)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if !result.OK {
			t.Fatal("local check failed")
		}
		count++
	}
	if count != MaxProxies || calls.Load() != MaxProxies {
		t.Fatalf("lost results: got %d records and %d checks", count, calls.Load())
	}
}

func TestInlineSpecPolicy(t *testing.T) {
	s := testServer(t, Config{AllowInlineSpecs: true})
	for _, url := range []string{"http://127.0.0.1/", "http://localhost/", "http://169.254.169.254/"} {
		var r checkRequest
		b := fmt.Sprintf(`{"spec":{"name":"test","timeout":"15s","requests":[{"url":%q}]}}`, url)
		if err := json.Unmarshal([]byte(b), &r); err != nil {
			t.Fatal(err)
		}
		if _, err := s.resolveSpec(r); err == nil {
			t.Errorf("allowed %s", url)
		}
	}
}

func TestConcurrentAdmissionIsBounded(t *testing.T) {
	started := make(chan struct{}, 8)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
		}
		fmt.Fprint(w, "ok")
	}))
	app := httptest.NewServer(testServer(t, Config{AllowPrivateProxies: true}).Handler())
	defer func() { releaseAll(); app.Close(); proxy.Close() }()
	done := make(chan error, 4)
	for i := 0; i < MaxActiveChecks; i++ {
		go func() {
			resp, err := app.Client().Post(app.URL+"/v1/check", "application/json", strings.NewReader(payload(proxy.URL)))
			if err == nil {
				_, err = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			done <- err
		}()
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("request did not start")
		}
	}
	resp, err := app.Client().Post(app.URL+"/v1/check", "application/json", strings.NewReader(payload(proxy.URL)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Fatalf("admission status %d", resp.StatusCode)
	}
	// Release before closing the real servers; keep cleanup safe on test failure.
	releaseAll()
	for i := 0; i < MaxActiveChecks; i++ {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("client did not finish")
		}
	}
}

type brokenResponse struct {
	header http.Header
	writes int
}

func (w *brokenResponse) Header() http.Header       { return w.header }
func (w *brokenResponse) WriteHeader(int)           {}
func (w *brokenResponse) Write([]byte) (int, error) { w.writes++; return 0, io.ErrClosedPipe }
func TestStreamStopsOnBrokenConsumer(t *testing.T) {
	var calls atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprint(w, "ok") }))
	defer proxy.Close()
	proxies := make([]string, 100)
	for i := range proxies {
		proxies[i] = proxy.URL
	}
	body, _ := json.Marshal(map[string]any{"preset": "test", "proxies": proxies, "concurrency": 1})
	r := httptest.NewRequest("POST", "/v1/check", bytes.NewReader(body))
	r.RemoteAddr = "127.0.0.1:80"
	r.Header.Set("Content-Type", "application/json")
	w := &brokenResponse{header: make(http.Header)}
	testServer(t, Config{AllowPrivateProxies: true}).Handler().ServeHTTP(w, r)
	if calls.Load() != 1 || w.writes != 1 {
		t.Fatalf("continued after consumer failure: calls=%d writes=%d", calls.Load(), w.writes)
	}
}

func TestGlobalWorkerAdmissionAndRelease(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer proxy.Close()
	s := testServer(t, Config{AllowPrivateProxies: true})
	s.workers = MaxWorkers
	if w := request(t, s, payload(proxy.URL)); w.Code != 429 {
		t.Fatalf("global budget bypass: %d", w.Code)
	}
	s.workers = MaxWorkers - 1
	if w := request(t, s, payload(proxy.URL)); w.Code != 200 {
		t.Fatalf("single available worker not used: %d %s", w.Code, w.Body.String())
	}
	if s.workers != MaxWorkers-1 {
		t.Fatal("worker budget leaked")
	}
}
