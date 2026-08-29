package main

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// knownBrands are registrable (2-label) domains used for typosquat
// (edit-distance) comparison. Keep this to actual registrable domains —
// registrableDomain() only ever produces 2-label output, so a 3-label
// entry here would never match exactly and would skew edit distances.
var knownBrands = []string{
	"microsoft.com", "office.com", "microsoftonline.com",
	"live.com", "outlook.com",
	"apple.com", "icloud.com",
	"zoom.us", "slack.com", "webex.com",
	"google.com",
	"github.com", "dropbox.com",
}

// brandWords are short identifying words checked for spoofed use as a fake
// subdomain label, e.g. "microsoft" in teams.microsoft.com.evil.net.
var brandWords = []string{
	"microsoft", "teams", "office", "outlook",
	"apple", "icloud",
	"zoom", "slack", "webex",
	"google", "accounts",
	"github", "dropbox",
}

// legitimateBrandHosts are real, multi-label hostnames that legitimately
// contain a brandWord as a subdomain label (e.g. accounts.google.com,
// teams.microsoft.com) — exempted from the brand-in-subdomain check below
// so the real thing isn't flagged as spoofing itself.
var legitimateBrandHosts = map[string]bool{
	"teams.microsoft.com":       true,
	"login.microsoftonline.com": true,
	"accounts.google.com":       true,
	"appleid.apple.com":         true,
}

var urlShorteners = map[string]bool{
	"bit.ly": true, "tinyurl.com": true, "t.co": true, "is.gd": true,
	"goo.gl": true, "ow.ly": true, "buff.ly": true, "rebrand.ly": true,
}

type HeuristicsChecker struct{}

func (c *HeuristicsChecker) Name() string { return "heuristics" }

func (c *HeuristicsChecker) Check(ctx context.Context, target *url.URL) CheckOutcome {
	out := CheckOutcome{Checker: c.Name()}
	host := strings.ToLower(target.Hostname())

	if net.ParseIP(host) != nil {
		out.Findings = append(out.Findings, Finding{Checker: c.Name(), Severity: SeverityHigh, Message: "host is a raw IP address rather than a domain name"})
	}

	labels := strings.Split(host, ".")
	if len(labels) > 4 {
		out.Findings = append(out.Findings, Finding{Checker: c.Name(), Severity: SeverityLow, Message: fmt.Sprintf("unusually deep subdomain chain (%d labels): %s", len(labels), host)})
	}

	for _, l := range labels {
		if strings.HasPrefix(l, "xn--") {
			out.Findings = append(out.Findings, Finding{Checker: c.Name(), Severity: SeverityMedium, Message: fmt.Sprintf("punycode label present (%q) — possible homograph/IDN spoofing, decode and inspect manually", l)})
		}
	}

	if urlShorteners[host] {
		out.Findings = append(out.Findings, Finding{Checker: c.Name(), Severity: SeverityMedium, Message: "known URL shortener — real destination is hidden until you follow it"})
	}

	registrable := registrableDomain(host)
	for _, brand := range knownBrands {
		if registrable == brand {
			continue
		}
		if d := levenshtein(registrable, brand); d > 0 && d <= 2 {
			out.Findings = append(out.Findings, Finding{
				Checker: c.Name(), Severity: SeverityHigh,
				Message: fmt.Sprintf("domain %q closely resembles known brand %q (edit distance %d) — likely typosquat", registrable, brand, d),
			})
		}
	}

	if !legitimateBrandHosts[host] && len(labels) > 2 {
		subLabels := labels[:len(labels)-2]
		for _, w := range brandWords {
			if containsLabel(subLabels, w) {
				out.Findings = append(out.Findings, Finding{
					Checker: c.Name(), Severity: SeverityHigh,
					Message: fmt.Sprintf("brand name %q appears as a subdomain, but the real registrable domain is %q — classic brand-in-subdomain spoofing", w, registrable),
				})
			}
		}
	}

	return out
}

func containsLabel(labels []string, needle string) bool {
	for _, l := range labels {
		if l == needle {
			return true
		}
	}
	return false
}

// registrableDomain is a naive best-effort extraction of the last two
// labels. It does not handle multi-part public suffixes (e.g. co.uk); it's
// a heuristic signal, not a source of truth.
func registrableDomain(host string) string {
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return host
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			curr[j] = min3(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}
