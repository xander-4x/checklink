package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestIsCrossDomainRedirect(t *testing.T) {
	cases := []struct {
		start, final string
		want         bool
	}{
		{"google.com", "www.google.com", false},
		{"www.google.com", "google.com", false},
		{"bit.ly", "evil.ru", true},
		{"example.com", "example.com", false},
	}
	for _, c := range cases {
		if got := isCrossDomainRedirect(c.start, c.final); got != c.want {
			t.Errorf("isCrossDomainRedirect(%q, %q) = %v, want %v", c.start, c.final, got, c.want)
		}
	}
}

func TestRedirectChecker_ExecutablePayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Disposition", `attachment; filename="TeamsSetup.exe"`)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte("not-a-real-binary"))
	}))
	defer server.Close()

	checker := &RedirectChecker{Client: &http.Client{Timeout: 5 * time.Second}}
	target, _ := url.Parse(server.URL)
	out := checker.Check(context.Background(), target)

	if !hasFinding(out.Findings, SeverityHigh, "serves an executable file (TeamsSetup.exe)") {
		t.Errorf("expected executable HIGH finding, got %+v", out.Findings)
	}
}

func TestRedirectChecker_SameDomainRedirectIsClean(t *testing.T) {
	// Regression: google.com -> www.google.com used to be flagged as a
	// "different host" MEDIUM finding.
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
	}))
	defer final.Close()

	start := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	defer start.Close()

	checker := &RedirectChecker{Client: &http.Client{Timeout: 5 * time.Second}}
	target, _ := url.Parse(start.URL)
	out := checker.Check(context.Background(), target)

	// The test servers are plain http://, so a MEDIUM "not served over
	// HTTPS" finding is expected — what must NOT appear is a "different
	// domain" finding, since both hops are on the same host.
	if hasFinding(out.Findings, SeverityMedium, "different domain") {
		t.Errorf("expected no different-domain finding for a same-host redirect, got %+v", out.Findings)
	}
	if hasSeverity(out.Findings, SeverityHigh) {
		t.Errorf("expected no HIGH findings for a same-host redirect, got %+v", out.Findings)
	}
}

func TestRedirectChecker_HTTPSDowngrade(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer plain.Close()

	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer tlsServer.Close()

	// tlsServer.Client() trusts tlsServer's self-signed cert; RedirectChecker
	// now inherits Client.Transport, so this actually gets used.
	client := tlsServer.Client()
	client.Timeout = 5 * time.Second

	checker := &RedirectChecker{Client: client}
	target, _ := url.Parse(tlsServer.URL)
	out := checker.Check(context.Background(), target)

	if !hasFinding(out.Findings, SeverityHigh, "TLS-stripping") {
		t.Errorf("expected HIGH TLS-stripping downgrade finding, got %+v", out.Findings)
	}
}

func TestRedirectChecker_PlainHTTPNoDowngradeClaim(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	checker := &RedirectChecker{Client: &http.Client{Timeout: 5 * time.Second}}
	target, _ := url.Parse(server.URL) // already http, not https
	out := checker.Check(context.Background(), target)

	if hasFinding(out.Findings, SeverityHigh, "TLS-stripping") {
		t.Errorf("plain http:// target should not claim a downgrade, got %+v", out.Findings)
	}
	if !hasFinding(out.Findings, SeverityMedium, "not served over HTTPS") {
		t.Errorf("expected the plain MEDIUM http finding, got %+v", out.Findings)
	}
}

func TestRedirectChecker_DNSNotFound(t *testing.T) {
	checker := &RedirectChecker{Client: &http.Client{Timeout: 5 * time.Second}}
	target, _ := url.Parse("https://this-domain-should-not-exist-checklink-test.invalid")
	out := checker.Check(context.Background(), target)

	if !out.Unreachable {
		t.Error("expected Unreachable=true for a non-existent domain")
	}
	if out.Error == "" {
		t.Error("expected a human-readable error message")
	}
}
