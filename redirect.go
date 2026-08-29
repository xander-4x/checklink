package main

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
)

const maxRedirects = 10

var executableExts = map[string]bool{
	".exe": true, ".msi": true, ".dmg": true, ".pkg": true,
	".sh": true, ".bat": true, ".cmd": true, ".ps1": true,
	".scr": true, ".apk": true, ".jar": true, ".vbs": true,
}

// RedirectChecker follows the redirect chain and inspects only headers of
// the final response — it never reads the response body, so it is safe to
// point at a URL that serves a malware payload.
type RedirectChecker struct {
	Client *http.Client
}

func (c *RedirectChecker) Name() string { return "redirect-chain" }

func (c *RedirectChecker) Check(ctx context.Context, target *url.URL) CheckOutcome {
	out := CheckOutcome{Checker: c.Name()}

	var chain []string
	client := &http.Client{
		Timeout: c.Client.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			chain = append(chain, req.URL.String())
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	req.Header.Set("User-Agent", "antifish-check-url/1.0 (+internal phishing-link checker)")

	resp, err := client.Do(req)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			out.Unreachable = true
			out.Error = fmt.Sprintf("this domain does not exist (%s)", target.Hostname())
		} else {
			out.Error = err.Error()
		}
		return out
	}
	defer resp.Body.Close()

	if len(chain) > 0 {
		out.Findings = append(out.Findings, Finding{
			Checker: c.Name(), Severity: SeverityLow,
			Message: fmt.Sprintf("redirected %d time(s), final URL: %s", len(chain), resp.Request.URL.String()),
		})
		finalHost := strings.ToLower(resp.Request.URL.Hostname())
		startHost := strings.ToLower(target.Hostname())
		if registrableDomain(finalHost) != registrableDomain(startHost) {
			out.Findings = append(out.Findings, Finding{
				Checker: c.Name(), Severity: SeverityMedium,
				Message: fmt.Sprintf("redirects to a different domain: %q -> %q", startHost, finalHost),
			})
		}
	}

	if finalScheme := resp.Request.URL.Scheme; finalScheme != "https" {
		if target.Scheme == "https" {
			out.Findings = append(out.Findings, Finding{
				Checker: c.Name(), Severity: SeverityHigh,
				Message: "redirected from HTTPS down to plain HTTP — possible TLS-stripping downgrade",
			})
		} else {
			out.Findings = append(out.Findings, Finding{Checker: c.Name(), Severity: SeverityMedium, Message: "not served over HTTPS"})
		}
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "" {
		out.Findings = append(out.Findings, Finding{Checker: c.Name(), Severity: SeverityInfo, Message: "Content-Type: " + ct})
	}

	filename := ""
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		if _, params, err := mime.ParseMediaType(cd); err == nil {
			filename = params["filename"]
		}
	}
	if filename == "" {
		filename = path.Base(resp.Request.URL.Path)
	}
	if ext := strings.ToLower(path.Ext(filename)); executableExts[ext] {
		out.Findings = append(out.Findings, Finding{
			Checker: c.Name(), Severity: SeverityHigh,
			Message: fmt.Sprintf("response serves an executable file (%s) — do not run it manually, verify with IT/security first", filename),
		})
	}

	return out
}
