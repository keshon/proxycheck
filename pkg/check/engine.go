package check

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"time"
)

// Default byte cap for body scanning when a spec doesn't ask to download more.
// Enough to catch marker strings and block pages without buffering whole videos.
const defaultBodyCap = 256 << 10 // 256 KiB

// Options tunes a Run. Zero value is usable; see sane defaults in Normalize.
type Options struct {
	Concurrency  int           // parallel workers (default 100)
	DialTimeout  time.Duration // TCP/handshake to the proxy (default 8s)
	TLSTimeout   time.Duration // TLS handshake (default 6s)
	LocalIP      string        // origin's public IP, enables anonymity classification
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
	return o
}

// Check runs one spec against one proxy and returns a fully classified Result.
// It never returns an error — every failure mode is encoded in the Result so
// callers can stream results uniformly.
func Check(ctx context.Context, p Proxy, spec Spec, opts Options) Result {
	opts = opts.Normalize()
	start := time.Now()

	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tr, err := transportFor(p, opts.DialTimeout, opts.TLSTimeout)
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
		res.Anonymity = classifyAnonymity(ip, opts.LocalIP)
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
	step := StepResult{URL: r.URL}
	begin := time.Now()

	var connectAt, firstByteAt time.Time
	trace := &httptrace.ClientTrace{
		GotConn:              func(httptrace.GotConnInfo) { connectAt = time.Now() },
		GotFirstResponseByte: func() { firstByteAt = time.Now() },
	}
	tctx := httptrace.WithClientTrace(ctx, trace)

	httpReq, err := http.NewRequestWithContext(tctx, r.method(), r.URL, nil)
	if err != nil {
		step.ErrorClass = ErrInput
		step.Error = err.Error()
		step.DurationMS = msSince(begin)
		return step, 0, 0
	}
	setBrowserHeaders(httpReq)

	resp, err := client.Do(httpReq)
	if err != nil {
		step.ErrorClass = classifyDialError(unwrapURLError(err))
		step.Error = err.Error()
		step.DurationMS = msSince(begin)
		return step, 0, 0
	}
	defer resp.Body.Close()

	step.Status = resp.StatusCode

	limit := int64(defaultBodyCap)
	if r.Expect.MinDownload > limit {
		limit = r.Expect.MinDownload
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, limit))
	step.Bytes = int64(len(body))
	step.DurationMS = msSince(begin)

	// A read error after a status is a live-but-flaky path, not a dead proxy.
	if readErr != nil && r.Expect.MinDownload > 0 {
		step.ErrorClass = classifyDialError(readErr)
		if step.ErrorClass == ErrProtocol {
			step.ErrorClass = ErrAssert
		}
		step.Error = "download interrupted: " + readErr.Error()
		return step, timing(begin, connectAt), timing(begin, firstByteAt)
	}

	if class, msg := evaluate(r.Expect, resp, body); class != ErrNone {
		step.ErrorClass = class
		step.Error = msg
		return step, timing(begin, connectAt), timing(begin, firstByteAt)
	}

	step.OK = true
	return step, timing(begin, connectAt), timing(begin, firstByteAt)
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
	step, _, _ := runStep(ctx, client, Request{URL: url})
	if !step.OK {
		return "", step
	}
	// Re-fetch the body: runStep discards it. Cheap and keeps runStep generic.
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	setBrowserHeaders(req)
	resp, err := client.Do(req)
	if err != nil {
		step.OK = false
		step.ErrorClass = classifyDialError(unwrapURLError(err))
		step.Error = err.Error()
		return "", step
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
	return strings.TrimSpace(string(b)), step
}

// classifyAnonymity compares the exit IP against the origin's known public IP.
// Elite (no proxy-revealing headers) requires header inspection and is out of
// scope for v1, so we honestly report only unknown/transparent/anonymous.
func classifyAnonymity(exitIP, localIP string) Anonymity {
	if localIP == "" || exitIP == "" {
		return AnonUnknown
	}
	if exitIP == localIP {
		return AnonTransparent
	}
	return AnonAnonymous
}

// Run checks many proxies concurrently against one spec. Results are delivered
// to emit as they complete (unordered). emit is called from worker goroutines
// and must be safe for concurrent use, or guarded by the caller.
func Run(ctx context.Context, proxies []Proxy, spec Spec, opts Options, emit func(Result)) {
	opts = opts.Normalize()

	jobs := make(chan Proxy)
	var wg sync.WaitGroup
	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				emit(Check(ctx, p, spec, opts))
			}
		}()
	}

	for _, p := range proxies {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		case jobs <- p:
		}
	}
	close(jobs)
	wg.Wait()
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
