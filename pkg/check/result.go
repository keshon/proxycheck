package check

import (
	"encoding/json"
	"time"
)

// ErrorClass names *why* a check failed. This is the single most useful thing
// the tool produces: "dead proxy" and "live proxy the target rejects" are
// different facts, and collapsing them into a bool is what makes generic
// checkers useless for targeted work (e.g. "find proxies where YouTube works").
type ErrorClass string

const (
	ErrNone     ErrorClass = ""            // success
	ErrDNS      ErrorClass = "dns"         // proxy host or target host did not resolve
	ErrRefused  ErrorClass = "refused"     // TCP connection actively refused
	ErrTimeout  ErrorClass = "timeout"     // deadline hit connecting or reading
	ErrTLS      ErrorClass = "tls"         // TLS handshake failed
	ErrProtocol ErrorClass = "protocol"    // proxy spoke garbage / auth rejected / SOCKS error
	ErrBlocked  ErrorClass = "target_block" // proxy is alive but target refused it (403/451/blockpage)
	ErrAssert   ErrorClass = "assertion"   // reached target, response failed an expectation
	ErrInput    ErrorClass = "input"       // could not even build the request (bad spec/proxy)
)

// Anonymity classifies how much the proxy leaks about the origin. Only meaningful
// when a spec captures the exit IP and headers via an echo endpoint.
type Anonymity string

const (
	AnonUnknown     Anonymity = ""            // not probed
	AnonTransparent Anonymity = "transparent" // exit IP differs but origin IP is forwarded in headers
	AnonAnonymous   Anonymity = "anonymous"   // origin hidden, but proxy announces itself (Via/X-Forwarded-For present)
	AnonElite       Anonymity = "elite"       // origin hidden, no proxy-revealing headers
)

// StepResult records the outcome of a single request within a spec.
type StepResult struct {
	URL        string        `json:"url"`
	OK         bool          `json:"ok"`
	Status     int           `json:"status,omitempty"`
	Bytes      int64         `json:"bytes,omitempty"`
	DurationMS int64         `json:"duration_ms"`
	ErrorClass ErrorClass    `json:"error_class,omitempty"`
	Error      string        `json:"error,omitempty"`
	duration   time.Duration `json:"-"`
}

// Result is the full outcome of running one spec against one proxy. It is the
// public contract: JSON tags here define the API/JSONL schema.
type Result struct {
	Proxy string `json:"proxy"` // redacted canonical URL
	Check string `json:"check"` // spec name
	OK    bool   `json:"ok"`    // every step passed

	ErrorClass ErrorClass `json:"error_class,omitempty"`
	Error      string     `json:"error,omitempty"`

	// Timings (best-effort; zero when a phase was never reached).
	ConnectMS int64 `json:"connect_ms,omitempty"` // proxy TCP+handshake to first byte-ready
	TTFBMS    int64 `json:"ttfb_ms,omitempty"`    // time to first response byte of the first step
	TotalMS   int64 `json:"total_ms"`             // wall time for the whole check

	// Observed facts about the exit path.
	ExitIP    string    `json:"exit_ip,omitempty"`
	Anonymity Anonymity `json:"anonymity,omitempty"`

	Steps []StepResult `json:"steps,omitempty"`

	CheckedAt time.Time `json:"checked_at"`
}

// JSON renders the result as a compact single line (for JSONL / NDJSON).
func (r Result) JSON() ([]byte, error) {
	return json.Marshal(r)
}

// fail builds a terminal failure result carrying the class and message.
func fail(p Proxy, spec string, class ErrorClass, err error, total time.Duration, at time.Time) Result {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	return Result{
		Proxy:      p.Redacted(),
		Check:      spec,
		OK:         false,
		ErrorClass: class,
		Error:      msg,
		TotalMS:    total.Milliseconds(),
		CheckedAt:  at,
	}
}
