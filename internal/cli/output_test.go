package cli

import (
	"strings"
	"testing"

	"github.com/keshon/proxycheck/pkg/check"
)

// TestHumanPinnedProgress verifies the pinned progress line is cleared before
// each result and redrawn after — i.e. every result line is preceded by the
// erase sequence once a progress line exists, so nothing gets wedged mid-line.
func TestHumanPinnedProgress(t *testing.T) {
	var buf strings.Builder
	w := NewHuman(&buf, false, false, 2)

	w.Write(check.Result{Proxy: "http://a:80", OK: true, TotalMS: 10})
	w.Write(check.Result{Proxy: "http://b:80", OK: false, ErrorClass: check.ErrTimeout, Error: "i/o timeout"})
	w.Summary()

	out := buf.String()
	const erase = "\r\033[K"

	// First Write: no prior progress to erase, then draws "checking 1/2".
	// Second Write: MUST erase before printing its result line.
	if strings.Count(out, erase) < 2 {
		t.Errorf("expected >=2 erase sequences (2nd result + summary), got:\n%q", out)
	}
	// Each result line must end with a newline (not be glued to progress).
	if !strings.Contains(out, "http://a:80") || !strings.Contains(out, "\n") {
		t.Errorf("result lines missing or unterminated:\n%q", out)
	}
	// No progress fragment should appear on the same line before a result.
	// After stripping erase+progress, result lines should be clean.
	if strings.Contains(out, "checkinghttp") {
		t.Errorf("progress glued to a result line:\n%q", out)
	}
	if !strings.HasSuffix(out, "done: 2 checked, 1 ok, 1 failed\n") {
		t.Errorf("summary missing or not last:\n%q", out)
	}
}

// TestComboSeparatesSinkAndDisplay verifies the sink (data) and display
// (progress) are driven independently: okOnly filters the sink but the display
// still counts every result, and only the display prints the run summary.
func TestComboSeparatesSinkAndDisplay(t *testing.T) {
	var data, status strings.Builder
	w := NewCombo(
		NewTextSink(&data, true),      // okOnly: only passing proxies to the "file"
		NewBarDisplay(&status, 2),     // progress bar + summary to "stderr"
	)
	w.Write(check.Result{Proxy: "http://good:80", OK: true, TotalMS: 5})
	w.Write(check.Result{Proxy: "http://bad:80", OK: false, ErrorClass: check.ErrTimeout})
	w.Summary()

	// Sink (okOnly): only the passing proxy, as a re-ingestable line.
	if strings.Contains(data.String(), "bad:80") {
		t.Errorf("okOnly sink leaked a failure:\n%q", data.String())
	}
	if !strings.HasPrefix(data.String(), "http://good:80 # ok") {
		t.Errorf("sink missing passing proxy:\n%q", data.String())
	}
	// Display: counts BOTH results and owns the summary.
	if !strings.Contains(status.String(), "done: 2 checked, 1 ok, 1 failed") {
		t.Errorf("display summary wrong:\n%q", status.String())
	}
	// Summary must not appear in the data file.
	if strings.Contains(data.String(), "done:") {
		t.Errorf("summary leaked into data sink:\n%q", data.String())
	}
}

// TestHumanOKOnlySuppresses ensures failing results print no line but still
// advance the progress counter.
func TestHumanOKOnlySuppresses(t *testing.T) {
	var buf strings.Builder
	w := NewHuman(&buf, false, true, 2)
	w.Write(check.Result{Proxy: "http://good:80", OK: true})
	w.Write(check.Result{Proxy: "http://bad:80", OK: false, ErrorClass: check.ErrRefused})
	w.Summary()

	out := buf.String()
	if strings.Contains(out, "http://bad:80") {
		t.Errorf("ok-only mode leaked a failing proxy:\n%q", out)
	}
	if !strings.Contains(out, "http://good:80") {
		t.Errorf("ok-only mode dropped a passing proxy:\n%q", out)
	}
}
