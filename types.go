package main

import (
	"context"
	"encoding/json"
	"net/url"
)

type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
)

func (s Severity) String() string {
	switch s {
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityLow:
		return "LOW"
	default:
		return "INFO"
	}
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

type Finding struct {
	Checker  string   `json:"checker"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
}

// CheckOutcome is the result of one Checker run. SkipNote is set when the
// checker deliberately did nothing (e.g. missing API key); Error is set on
// an unexpected failure (network error, bad response, etc). Both are
// non-fatal to the overall report.
type CheckOutcome struct {
	Checker  string    `json:"checker"`
	Findings []Finding `json:"findings,omitempty"`
	SkipNote string    `json:"skipped,omitempty"`
	Error    string    `json:"error,omitempty"`
	// Unreachable is set by the redirect-chain checker when the domain
	// doesn't resolve at all (DNS NXDOMAIN), so the report can say "this
	// link doesn't exist" instead of implying it was checked and found clean.
	Unreachable bool `json:"unreachable,omitempty"`
}

type Checker interface {
	Name() string
	Check(ctx context.Context, target *url.URL) CheckOutcome
}
