package main

import (
	"context"
	"net/url"
	"testing"
)

func TestRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"www.google.com":      "google.com",
		"google.com":          "google.com",
		"accounts.google.com": "google.com",
		"localhost":           "localhost",
		"a.b.c.example.com":   "example.com",
	}
	for host, want := range cases {
		if got := registrableDomain(host); got != want {
			t.Errorf("registrableDomain(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestLevenshtein(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"microsoft.com", "microsoft.com", 0},
		{"micros0ft.com", "microsoft.com", 1},
		{"", "abc", 3},
		{"abc", "", 3},
		{"google.com", "gooogle.com", 1},
	}
	for _, c := range cases {
		if got := levenshtein(c.a, c.b); got != c.want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestHeuristicsChecker_Check(t *testing.T) {
	checker := &HeuristicsChecker{}

	t.Run("legitimate multi-label brand hosts are not flagged", func(t *testing.T) {
		// Regression: these used to fire "brand name X appears as a
		// subdomain" HIGH findings against themselves.
		for _, target := range []string{
			"https://accounts.google.com",
			"https://teams.microsoft.com",
			"https://appleid.apple.com",
			"https://login.microsoftonline.com",
		} {
			u, _ := url.Parse(target)
			out := checker.Check(context.Background(), u)
			if hasSeverity(out.Findings, SeverityHigh) {
				t.Errorf("%s: expected no HIGH findings, got %+v", target, out.Findings)
			}
		}
	})

	t.Run("plain legitimate domains are clean", func(t *testing.T) {
		for _, target := range []string{"https://google.com", "https://example.com"} {
			u, _ := url.Parse(target)
			out := checker.Check(context.Background(), u)
			if len(out.Findings) != 0 {
				t.Errorf("%s: expected no findings, got %+v", target, out.Findings)
			}
		}
	})

	t.Run("brand name used as a fake subdomain is flagged HIGH", func(t *testing.T) {
		u, _ := url.Parse("http://teams.microsoft.com.security-update-portal.net")
		out := checker.Check(context.Background(), u)
		if !hasFinding(out.Findings, SeverityHigh, `brand name "microsoft"`) {
			t.Errorf("expected HIGH finding mentioning microsoft, got %+v", out.Findings)
		}
		if !hasFinding(out.Findings, SeverityHigh, `brand name "teams"`) {
			t.Errorf("expected HIGH finding mentioning teams, got %+v", out.Findings)
		}
	})

	t.Run("close typosquat of a known brand is flagged HIGH", func(t *testing.T) {
		u, _ := url.Parse("https://micros0ft.com")
		out := checker.Check(context.Background(), u)
		if !hasFinding(out.Findings, SeverityHigh, "likely typosquat") {
			t.Errorf("expected typosquat HIGH finding, got %+v", out.Findings)
		}
	})

	t.Run("raw IP host is flagged HIGH", func(t *testing.T) {
		u, _ := url.Parse("http://192.0.2.10/update")
		out := checker.Check(context.Background(), u)
		if !hasFinding(out.Findings, SeverityHigh, "raw IP address") {
			t.Errorf("expected raw-IP HIGH finding, got %+v", out.Findings)
		}
	})

	t.Run("known URL shortener is flagged MEDIUM", func(t *testing.T) {
		u, _ := url.Parse("https://bit.ly/abc123")
		out := checker.Check(context.Background(), u)
		if !hasFinding(out.Findings, SeverityMedium, "URL shortener") {
			t.Errorf("expected shortener MEDIUM finding, got %+v", out.Findings)
		}
	})

	t.Run("punycode label is flagged MEDIUM", func(t *testing.T) {
		u, _ := url.Parse("https://xn--80ak6aa92e.com")
		out := checker.Check(context.Background(), u)
		if !hasFinding(out.Findings, SeverityMedium, "punycode label present") {
			t.Errorf("expected punycode MEDIUM finding, got %+v", out.Findings)
		}
	})

	t.Run("deep subdomain chain is flagged LOW", func(t *testing.T) {
		u, _ := url.Parse("https://a.b.c.d.example.com")
		out := checker.Check(context.Background(), u)
		if !hasFinding(out.Findings, SeverityLow, "unusually deep subdomain chain") {
			t.Errorf("expected deep-subdomain LOW finding, got %+v", out.Findings)
		}
	})
}
