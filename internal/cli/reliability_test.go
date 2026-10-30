package cli

import (
	"context"
	"errors"
	"github.com/keshon/proxycheck/pkg/check"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type brokenSink struct{}

func (brokenSink) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func TestSinkErrorsAreObservable(t *testing.T) {
	for name, w := range map[string]Writer{"text": NewTextSink(brokenSink{}, false), "json": NewJSONSink(brokenSink{}, false), "human": NewHuman(brokenSink{}, false, false, 1), "bar": NewBarDisplay(brokenSink{}, 1), "summary": NewNoneDisplay(brokenSink{})} {
		t.Run(name, func(t *testing.T) {
			w.Write(check.Result{Proxy: "http://test:80", OK: true})
			w.Summary()
			if !errors.Is(w.Err(), io.ErrClosedPipe) {
				t.Fatalf("write failure lost: %v", w.Err())
			}
		})
	}
	j := NewJSONSink(io.Discard, false)
	j.Write(check.Result{CheckedAt: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)})
	if j.Err() == nil {
		t.Fatal("JSON serialization failure lost")
	}
}
func TestOriginIPValidation(t *testing.T) {
	for _, c := range []struct {
		body   string
		status int
		want   string
	}{{"::ffff:192.0.2.1\n", 200, "192.0.2.1"}, {"blocked", 200, ""}, {"192.0.2.1", 403, ""}, {strings.Repeat("x", 129), 200, ""}} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(c.status); io.WriteString(w, c.body) }))
		got := detectLocalIP(context.Background(), s.Client(), s.URL)
		s.Close()
		if got != c.want {
			t.Errorf("status %d body=%q got=%q", c.status, c.body, got)
		}
	}
}
