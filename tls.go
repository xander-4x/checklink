package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"
)

type TLSChecker struct {
	Timeout time.Duration
}

func (c *TLSChecker) Name() string { return "tls-cert" }

func (c *TLSChecker) Check(ctx context.Context, target *url.URL) CheckOutcome {
	out := CheckOutcome{Checker: c.Name()}
	if target.Scheme != "https" {
		out.SkipNote = "not an https URL"
		return out
	}

	host := target.Hostname()
	port := target.Port()
	if port == "" {
		port = "443"
	}

	d := &net.Dialer{Timeout: c.Timeout}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(host, port), &tls.Config{ServerName: host})
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			out.SkipNote = "domain does not exist (see above)"
		} else {
			out.Error = err.Error()
		}
		return out
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		out.Findings = append(out.Findings, Finding{Checker: c.Name(), Severity: SeverityMedium, Message: "no peer certificate presented"})
		return out
	}
	cert := state.PeerCertificates[0]

	age := time.Since(cert.NotBefore)
	out.Findings = append(out.Findings, Finding{
		Checker: c.Name(), Severity: SeverityInfo,
		Message: fmt.Sprintf("cert issuer: %s, issued: %s (%s ago), expires: %s",
			cert.Issuer.CommonName, cert.NotBefore.Format("2006-01-02"), age.Round(24*time.Hour), cert.NotAfter.Format("2006-01-02")),
	})

	if age < 7*24*time.Hour {
		out.Findings = append(out.Findings, Finding{
			Checker: c.Name(), Severity: SeverityMedium,
			Message: fmt.Sprintf("certificate is very new (issued %s ago) — common for freshly stood-up phishing infrastructure", age.Round(time.Hour)),
		})
	}

	return out
}
