package cli

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/keshon/proxycheck/pkg/check"
)

// Writer consumes results as they stream in. Implementations are called
// concurrently from worker goroutines, so they guard shared state.
type Writer interface {
	Write(check.Result)
	Summary()
}

// Output is split into two independent concerns:
//
//   - a Sink writes the result DATA to stdout (text or json). This is what you
//     redirect to a file; it stays clean and, for text, re-ingestable.
//   - a Display renders live PROGRESS to stderr (list, bar, or none) and owns
//     the end-of-run summary.
//
// combo fans each result to both. Keeping them separate is what lets you save a
// json file while watching a progress bar, or a text file while watching the
// results scroll — without the two fighting over one stream.

// combo drives a data sink and a progress display from one result stream.
type combo struct {
	sink    Writer
	display Writer
}

// NewCombo returns a Writer that feeds every result to both sink and display.
func NewCombo(sink, display Writer) Writer {
	return &combo{sink: sink, display: display}
}

func (c *combo) Write(r check.Result) {
	c.sink.Write(r)
	c.display.Write(r)
}

func (c *combo) Summary() {
	c.sink.Summary()  // flush data
	c.display.Summary() // print run summary to stderr
}

// --- data sinks (stdout) ---

// textSink emits one proxy per line with all info in a trailing "# ..." comment.
// The proxy is the first token, so this round-trips: pipe it straight back in.
type textSink struct {
	mu     sync.Mutex
	w      *bufio.Writer
	okOnly bool
}

// NewTextSink writes the "address # comment" format to w.
func NewTextSink(w io.Writer, okOnly bool) Writer {
	return &textSink{w: bufio.NewWriter(w), okOnly: okOnly}
}

func (t *textSink) Write(r check.Result) {
	if t.okOnly && !r.OK {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.w.WriteString(textLine(r))
	t.w.WriteByte('\n')
	t.w.Flush()
}

func (t *textSink) Summary() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.w.Flush()
}

// jsonSink emits one compact JSON object per line (NDJSON).
type jsonSink struct {
	mu     sync.Mutex
	w      *bufio.Writer
	okOnly bool
}

// NewJSONSink writes NDJSON to w.
func NewJSONSink(w io.Writer, okOnly bool) Writer {
	return &jsonSink{w: bufio.NewWriter(w), okOnly: okOnly}
}

func (j *jsonSink) Write(r check.Result) {
	if j.okOnly && !r.OK {
		return
	}
	b, err := r.JSON()
	if err != nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.w.Write(b)
	j.w.WriteByte('\n')
	j.w.Flush()
}

func (j *jsonSink) Summary() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.w.Flush()
}

// --- progress displays (stderr) ---

// noneDisplay shows nothing live; it only prints the final summary.
type noneDisplay struct {
	mu     sync.Mutex
	status io.Writer
	total  int
	ok     int
}

// NewNoneDisplay counts results silently and prints a summary at the end.
func NewNoneDisplay(status io.Writer) Writer {
	return &noneDisplay{status: status}
}

func (n *noneDisplay) Write(r check.Result) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.total++
	if r.OK {
		n.ok++
	}
}

func (n *noneDisplay) Summary() {
	n.mu.Lock()
	defer n.mu.Unlock()
	summarize(n.status, n.total, n.ok)
}

// barDisplay shows a single self-overwriting progress bar.
type barDisplay struct {
	mu       sync.Mutex
	status   io.Writer
	expected int
	done     int
	ok       int
	live     bool
}

// NewBarDisplay renders a progress bar to status. expected is the total count.
func NewBarDisplay(status io.Writer, expected int) Writer {
	return &barDisplay{status: status, expected: expected}
}

func (b *barDisplay) Write(r check.Result) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.done++
	if r.OK {
		b.ok++
	}
	b.draw()
}

func (b *barDisplay) draw() {
	const width = 24
	filled := 0
	if b.expected > 0 {
		filled = b.done * width / b.expected
	}
	bar := strings.Repeat("#", filled) + strings.Repeat("-", width-filled)
	fmt.Fprintf(b.status, "\r[%s] %d/%d  ok=%d\033[K", bar, b.done, b.expected, b.ok)
	b.live = true
}

func (b *barDisplay) Summary() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.live {
		fmt.Fprint(b.status, "\r\033[K")
	}
	summarize(b.status, b.done, b.ok)
}

// textLine renders "proxy # comment" for one result.
func textLine(r check.Result) string {
	if r.OK {
		s := fmt.Sprintf("%s # ok connect=%dms ttfb=%dms total=%dms",
			r.Proxy, r.ConnectMS, r.TTFBMS, r.TotalMS)
		if r.ExitIP != "" {
			s += " exit=" + r.ExitIP
		}
		if r.Anonymity != "" {
			s += " " + string(r.Anonymity)
		}
		return s
	}
	msg := strings.ReplaceAll(r.Error, "\n", " ")
	return fmt.Sprintf("%s # fail %s: %s", r.Proxy, r.ErrorClass, msg)
}

// summarize writes a one-line run summary to status, if non-nil.
func summarize(status io.Writer, total, ok int) {
	if status == nil {
		return
	}
	fmt.Fprintf(status, "done: %d checked, %d ok, %d failed\n", total, ok, total-ok)
}

// humanWriter prints a scrolling line per result with a single progress line
// pinned at the bottom. Both share ONE stream so cursor state is coherent:
// writing results and progress to different streams (stdout vs stderr) makes
// them fight over the same terminal line and garbles the output.
type humanWriter struct {
	mu           sync.Mutex
	w            *bufio.Writer
	color        bool
	okOnly       bool
	total        int
	ok           int
	done         int
	expected     int
	progressLive bool // a pinned progress line is currently on screen
}

// NewHuman writes the human display (results + pinned progress) to w. expected
// is the proxy count for the progress counter; 0 disables the pinned line.
func NewHuman(w io.Writer, color, okOnly bool, expected int) Writer {
	return &humanWriter{
		w:        bufio.NewWriter(w),
		color:    color,
		okOnly:   okOnly,
		expected: expected,
	}
}

func (h *humanWriter) Write(r check.Result) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.total++
	h.done++
	if r.OK {
		h.ok++
	}

	// Erase the pinned progress line so the result prints on a clean line...
	h.clearProgress()
	if !h.okOnly || r.OK {
		h.w.WriteString(h.format(r))
		h.w.WriteByte('\n')
	}
	// ...then redraw progress below the newest result.
	h.drawProgress()
	h.w.Flush()
}

// clearProgress erases the pinned progress line if one is showing.
func (h *humanWriter) clearProgress() {
	if h.progressLive {
		h.w.WriteString("\r\033[K")
		h.progressLive = false
	}
}

// drawProgress writes the transient counter (no trailing newline) and marks it live.
func (h *humanWriter) drawProgress() {
	if h.expected <= 0 {
		return
	}
	fmt.Fprintf(h.w, "checking %d/%d  ok=%d", h.done, h.expected, h.ok)
	h.progressLive = true
}

func (h *humanWriter) format(r check.Result) string {
	icon, col := "x", colRed
	if r.OK {
		icon, col = "+", colGreen
	}
	head := fmt.Sprintf("[%s] %-30s", h.paint(icon, col), r.Proxy)

	if r.OK {
		detail := fmt.Sprintf("ok  connect=%dms ttfb=%dms total=%dms",
			r.ConnectMS, r.TTFBMS, r.TotalMS)
		if r.ExitIP != "" {
			detail += "  exit=" + r.ExitIP
		}
		if r.Anonymity != "" {
			detail += "  " + string(r.Anonymity)
		}
		return head + " " + detail
	}
	msg := r.Error
	if msg == "" {
		msg = "failed"
	}
	return head + " " + h.paint(string(r.ErrorClass), colYellow) + "  " + msg
}

func (h *humanWriter) Summary() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clearProgress()
	fmt.Fprintf(h.w, "done: %d checked, %d ok, %d failed\n",
		h.total, h.ok, h.total-h.ok)
	h.w.Flush()
}

// --- ANSI coloring ---

const (
	colReset  = "\033[0m"
	colRed    = "\033[31m"
	colGreen  = "\033[32m"
	colYellow = "\033[33m"
)

func (h *humanWriter) paint(s, color string) string {
	if !h.color {
		return s
	}
	return color + s + colReset
}
