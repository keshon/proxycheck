package check

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// Spec is a declarative description of what "this proxy works" means for one
// target. Presets are just named Specs embedded in the binary; users add cases
// by dropping YAML in a directory. The core never hardcodes a target — YouTube,
// Telegram, and "basic reachability" are all just different Specs.
type Spec struct {
	Name        string        `yaml:"name" json:"name"`
	Description string        `yaml:"description" json:"description"`
	Timeout     time.Duration `yaml:"timeout" json:"timeout"`
	Requests    []Request     `yaml:"requests" json:"requests"`

	// ExitIPProbe, if set, is fetched first; its plain-text body is recorded as
	// the exit IP and (when LocalIP is known) drives anonymity classification.
	// This is a generic property of a proxy, not a target — so it lives in core.
	ExitIPProbe string `yaml:"exit_ip_probe" json:"exit_ip_probe,omitempty"`
}

// Request is a single HTTP call plus what must be true of its response.
type Request struct {
	Method string   `yaml:"method" json:"method"`
	URL    string   `yaml:"url" json:"url"`
	Expect Expect   `yaml:"expect" json:"expect"`
}

// Expect is the set of assertions applied to one response. Zero-valued fields
// are simply not checked, so a spec asserts only what it cares about.
type Expect struct {
	// Status, if non-empty, is the set of acceptable status codes. Empty means
	// "any 2xx" (the common case, encoded once so specs stay terse).
	Status []int `yaml:"status" json:"status,omitempty"`

	// BodyContains requires every listed substring to appear in the response
	// body (case-sensitive). This is the marker-string check that separates
	// "got a page" from "got the *right* page / a block page".
	BodyContains []string `yaml:"body_contains" json:"body_contains,omitempty"`

	// BodyAbsent requires none of the listed substrings to appear — useful for
	// catching captive-portal / "blocked in your country" interstitials.
	BodyAbsent []string `yaml:"body_absent" json:"body_absent,omitempty"`

	// MinDownload, if > 0, requires at least this many bytes to be read within
	// the timeout. This is the throughput probe that stands in for "can I
	// actually stream" without dragging a media SDK into the core.
	MinDownload int64 `yaml:"min_download" json:"min_download,omitempty"`

	// Header requires each named response header to contain the given substring.
	Header map[string]string `yaml:"header" json:"header,omitempty"`
}

// specYAML mirrors Spec but takes Timeout as a string so YAML authors can write
// "10s" instead of a nanosecond count.
type specYAML struct {
	Name        string    `yaml:"name"`
	Description string    `yaml:"description"`
	Timeout     string    `yaml:"timeout"`
	ExitIPProbe string    `yaml:"exit_ip_probe"`
	Requests    []Request `yaml:"requests"`
}

// ParseSpec decodes a Spec from YAML and validates it.
func ParseSpec(data []byte) (Spec, error) {
	var raw specYAML
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return Spec{}, fmt.Errorf("parse spec yaml: %w", err)
	}

	spec := Spec{
		Name:        raw.Name,
		Description: raw.Description,
		ExitIPProbe: raw.ExitIPProbe,
		Requests:    raw.Requests,
	}
	if raw.Timeout != "" {
		d, err := time.ParseDuration(raw.Timeout)
		if err != nil {
			return Spec{}, fmt.Errorf("spec %q: bad timeout %q: %w", raw.Name, raw.Timeout, err)
		}
		spec.Timeout = d
	}
	if err := spec.Validate(); err != nil {
		return Spec{}, err
	}
	return spec, nil
}

// Validate enforces the invariants the engine relies on.
func (s Spec) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("spec has no name")
	}
	if len(s.Requests) == 0 && s.ExitIPProbe == "" {
		return fmt.Errorf("spec %q has no requests and no exit_ip_probe", s.Name)
	}
	for i, r := range s.Requests {
		if r.URL == "" {
			return fmt.Errorf("spec %q request %d has no url", s.Name, i)
		}
	}
	return nil
}

// method returns the request method, defaulting to GET.
func (r Request) method() string {
	if r.Method == "" {
		return "GET"
	}
	return r.Method
}

// statusOK reports whether code satisfies the Expect's status rule.
func (e Expect) statusOK(code int) bool {
	if len(e.Status) == 0 {
		return code >= 200 && code < 300
	}
	for _, want := range e.Status {
		if want == code {
			return true
		}
	}
	return false
}
