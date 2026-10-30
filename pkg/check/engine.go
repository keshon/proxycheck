package check

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Default byte cap for body scanning when a spec doesn't ask to download more.
// Enough to catch marker strings and block pages without buffering whole videos.
const defaultBodyCap = 256 << 10 // 256 KiB

// Options tunes a Run. Zero value is usable; see sane defaults in Normalize.
type Options struct {
	Concurrency        int           // parallel workers (default 100)
	DialTimeout        time.Duration // TCP/handshake to the proxy (default 8s)
	TLSTimeout         time.Duration // TLS handshake (default 6s)
	LocalIP            string        // validated origin observation for IP comparison
	IncludeCredentials bool          // explicit opt-in for credential-preserving CLI exports
	PublicProxiesOnly  bool          // API default: block special-use addresses at dial time
}

// Normalize fills zero fields with defaults and returns the result.
func (o Options) Normalize() Options {
	if o.Concurrency <= 0 {
		o.Concurrency = 100
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = 8 * time.Second
	}
	if o.TLSTimeout <= 0 {
		o.TLSTimeout = 6 * time.Second
	}
	if o.Concurrency > MaxConcurrency {
		o.Concurrency = MaxConcurrency
	}
	if o.DialTimeout > 30*time.Second {
		o.DialTimeout = 30 * time.Second
	}
	if o.TLSTimeout > 30*time.Second {
		o.TLSTimeout = 30 * time.Second
	}
	return o
}

// Check runs one spec against one proxy and returns a fully classified Result.
// It never returns an error — every failure mode is encoded in the Result so
// callers can stream results uniformly.
func Check(ctx context.Context, p Proxy, spec Spec, opts Options) Result {
	opts = opts.Normalize()
	start := time.Now()
	if err := spec.Validate(); err != nil {
		return fail(p, spec.Name, ErrInput, err, 0, start)
	}

	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tr, err := transportFor(p, opts.DialTimeout, opts.TLSTimeout, opts.PublicProxiesOnly)
	if err != nil {
		return fail(p, spec.Name, ErrInput, err, 0, start)
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		// We assert on status codes ourselves; following redirects would hide a
		// 302-to-blockpage behind a 200. Stop at the first response.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	res := Result{
		Proxy:     p.Redacted(),
		Check:     spec.Name,
		CheckedAt: start,
	}
	if opts.IncludeCredentials {
		res.Proxy = p.String()
	}

	// Optional exit-IP probe first, so ExitIP is populated even if later steps fail.
	if spec.ExitIPProbe != "" {
		ip, step := probeExitIP(ctx, client, spec.ExitIPProbe)
		res.Steps = append(res.Steps, step)
		if !step.OK {
			res.OK = false
			res.ErrorClass = step.ErrorClass
			res.Error = step.Error
			res.TotalMS = msSince(start)
			return res
		}
		res.ExitIP = ip
		res.IPComparison = compareIPs(ip, opts.LocalIP)
	}

	// Each request must pass. First step also captures connect/TTFB timings.
	for i, req := range spec.Requests {
		step, connectMS, ttfbMS := runStep(ctx, client, req)
		res.Steps = append(res.Steps, step)
		if i == 0 {
			res.ConnectMS, res.TTFBMS = connectMS, ttfbMS
		}
		if !step.OK {
			res.OK = false
			res.ErrorClass = step.ErrorClass
			res.Error = step.Error
			res.TotalMS = msSince(start)
			return res
		}
	}

	res.OK = true
	res.TotalMS = msSince(start)
	return res
}

// runStep executes a single request and evaluates its expectations. It returns
// the step result plus connect/TTFB timings observed via httptrace.
func runStep(ctx context.Context, client *http.Client, r Request) (StepResult, int64, int64) {
	step, connect, firstByte, _ := fetchStep(ctx, client, r)
	return step, connect, firstByte
}

func fetchStep(ctx context.Context, client *http.Client, r Request) (StepResult, int64, int64, []byte) {
	step := StepResult{URL: r.URL}
	begin := time.Now()

	var connectAt, firstByteAt time.Time
	var traceMu sync.Mutex
	trace := &httptrace.ClientTrace{
		GotConn:              func(httptrace.GotConnInfo) { traceMu.Lock(); connectAt = time.Now(); traceMu.Unlock() },
		GotFirstResponseByte: func() { traceMu.Lock(); firstByteAt = time.Now(); traceMu.Unlock() },
	}
	tctx := httptrace.WithClientTrace(ctx, trace)

	httpReq, err := http.NewRequestWithContext(tctx, r.method(), r.URL, nil)
	if err != nil {
		step.ErrorClass = ErrInput
		step.Error = err.Error()
		step.DurationMS = msSince(begin)
		return step, 0, 0, nil
	}
	setBrowserHeaders(httpReq)

	resp, err := client.Do(httpReq)
	if err != nil {
		step.ErrorClass = classifyDialError(unwrapURLError(err))
		step.Error = err.Error()
		step.DurationMS = msSince(begin)
		return step, 0, 0, nil
	}
	defer resp.Body.Close()

	step.Status = resp.StatusCode

	limit := int64(defaultBodyCap)
	if r.Expect.MinDownload > limit {
		limit = r.Expect.MinDownload
	}
	// Read one extra byte to distinguish an over-limit body from a complete one.
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	traceMu.Lock()
	connectMS, ttfbMS := timing(begin, connectAt), timing(begin, firstByteAt)
	traceMu.Unlock()
	step.Bytes = int64(len(body))
	step.DurationMS = msSince(begin)

	// A read error after a status is a live-but-flaky path, not a dead proxy.
	if readErr != nil {
		step.ErrorClass = classifyDialError(readErr)
		if step.ErrorClass == ErrProtocol {
			step.ErrorClass = ErrAssert
		}
		step.Error = "download interrupted: " + readErr.Error()
		return step, connectMS, ttfbMS, nil
	}
	// Minimum-download-only checks intentionally sample a bounded prefix. Body
	// assertions require the complete bounded response so absent markers are sound.
	if int64(len(body)) > limit {
		if len(r.Expect.BodyContains) > 0 || len(r.Expect.BodyAbsent) > 0 || r.Expect.MinDownload == 0 {
			step.ErrorClass = ErrAssert
			step.Error = "response exceeds body scan limit"
			return step, connectMS, ttfbMS, nil
		}
		body = body[:limit]
		step.Bytes = limit
	}

	if class, msg := evaluate(r.Expect, resp, body); class != ErrNone {
		step.ErrorClass = class
		step.Error = msg
		return step, connectMS, ttfbMS, nil
	}

	step.OK = true
	return step, connectMS, ttfbMS, body
}

// evaluate applies the expectations to a response, returning ErrNone on success
// or a class+message on the first failed assertion. A wrong status maps to
// target_block for the classic 403/451 cases and assertion otherwise.
func evaluate(e Expect, resp *http.Response, body []byte) (ErrorClass, string) {
	if !e.statusOK(resp.StatusCode) {
		if resp.StatusCode == 403 || resp.StatusCode == 451 || resp.StatusCode == 429 {
			return ErrBlocked, statusMsg(resp.StatusCode)
		}
		return ErrAssert, "unexpected status " + statusMsg(resp.StatusCode)
	}

	text := string(body)
	for _, want := range e.BodyContains {
		if !strings.Contains(text, want) {
			return ErrBlocked, "response missing marker " + quote(want)
		}
	}
	for _, bad := range e.BodyAbsent {
		if strings.Contains(text, bad) {
			return ErrBlocked, "response contains block marker " + quote(bad)
		}
	}
	for name, sub := range e.Header {
		if !strings.Contains(resp.Header.Get(name), sub) {
			return ErrAssert, "header " + name + " missing " + quote(sub)
		}
	}
	if e.MinDownload > 0 && int64(len(body)) < e.MinDownload {
		return ErrAssert, "downloaded too little"
	}
	return ErrNone, ""
}

// probeExitIP fetches a plain-text IP echo endpoint and returns the trimmed IP.
func probeExitIP(ctx context.Context, client *http.Client, url string) (string, StepResult) {
	step, _, _, body := fetchStep(ctx, client, Request{URL: url})
	if !step.OK {
		return "", step
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if err != nil || ip.Zone() != "" {
		step.OK = false
		step.ErrorClass = ErrAssert
		step.Error = "exit_ip_probe did not return an IP address"
		return "", step
	}
	return ip.Unmap().String(), step
}

// compareIPs compares normalized observations without inferring header privacy.
func compareIPs(exitIP, localIP string) IPComparison {
	a, errA := netip.ParseAddr(exitIP)
	b, errB := netip.ParseAddr(localIP)
	if errA != nil || errB != nil || a.Zone() != "" || b.Zone() != "" {
		return IPUnknown
	}
	if a.Unmap() == b.Unmap() {
		return IPSame
	}
	return IPDifferent
}

// Run checks many proxies concurrently against one spec. Results are delivered
// to emit as they complete (unordered). emit is called from worker goroutines
// and must be safe for concurrent use, or guarded by the caller.
func Run(ctx context.Context, proxies []Proxy, spec Spec, opts Options, emit func(Result) error) error {
	opts = opts.Normalize()
	if err := spec.Validate(); err != nil {
		return fmt.Errorf("invalid spec: %w", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var firstErr error
	var once sync.Once

	jobs := make(chan Proxy)
	var wg sync.WaitGroup
	for i := 0; i < min(opts.Concurrency, len(proxies)); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				if ctx.Err() != nil {
					return
				}
				if err := emit(Check(ctx, p, spec, opts)); err != nil {
					once.Do(func() { firstErr = err; cancel() })
					return
				}
			}
		}()
	}

	for _, p := range proxies {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			if firstErr != nil {
				return firstErr
			}
			return ctx.Err()
		case jobs <- p:
		}
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	return ctx.Err()
}

// --- small helpers ---

// A real browser User-Agent, not a bot string. Targets like YouTube serve
// non-browser clients a stripped/consent page that omits the very markers a
// check looks for — so identifying as a browser is what makes HTML-marker
// checks meaningful. Accept-Language reduces consent/interstitial redirects.
const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
	"(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

// setBrowserHeaders makes a request look like it came from a browser.
func setBrowserHeaders(req *http.Request) {
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept", "text/html,application/json,*/*")
}

func msSince(t time.Time) int64 { return time.Since(t).Milliseconds() }

func timing(begin, mark time.Time) int64 {
	if mark.IsZero() {
		return 0
	}
	return mark.Sub(begin).Milliseconds()
}

func statusMsg(code int) string { return http.StatusText(code) + " (" + itoa(code) + ")" }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func quote(s string) string {
	if len(s) > 40 {
		s = s[:40] + "…"
	}
	// Single quotes as the delimiter so markers that themselves contain double
	// quotes (e.g. the JSON key "videoDetails") don't render as ""...".
	return "'" + s + "'"
}

// unwrapURLError peels *url.Error so classifyDialError sees the underlying cause.
func unwrapURLError(err error) error {
	var ue interface{ Unwrap() error }
	if errors.As(err, &ue) {
		if inner := ue.Unwrap(); inner != nil {
			return inner
		}
	}
	return err
}
