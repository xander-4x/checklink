package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

type SafeBrowsingChecker struct {
	APIKey string
	Client *http.Client
}

func (c *SafeBrowsingChecker) Name() string { return "google-safe-browsing" }

func (c *SafeBrowsingChecker) Check(ctx context.Context, target *url.URL) CheckOutcome {
	out := CheckOutcome{Checker: c.Name()}
	if c.APIKey == "" {
		out.SkipNote = "GOOGLE_SAFE_BROWSING_API_KEY not set"
		return out
	}

	body := map[string]any{
		"client": map[string]string{"clientId": "checklink", "clientVersion": "1.0"},
		"threatInfo": map[string]any{
			"threatTypes":      []string{"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"},
			"platformTypes":    []string{"ANY_PLATFORM"},
			"threatEntryTypes": []string{"URL"},
			"threatEntries":    []map[string]string{{"url": target.String()}},
		},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		out.Error = err.Error()
		return out
	}

	endpoint := "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + url.QueryEscape(c.APIKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		out.Error = err.Error()
		return out
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Client.Do(req)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		out.Error = fmt.Sprintf("safe browsing API returned status %s", resp.Status)
		return out
	}

	var result struct {
		Matches []struct {
			ThreatType string `json:"threatType"`
		} `json:"matches"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		out.Error = err.Error()
		return out
	}

	if len(result.Matches) == 0 {
		out.Findings = append(out.Findings, Finding{Checker: c.Name(), Severity: SeverityInfo, Message: "no known threats matched"})
		return out
	}

	for _, m := range result.Matches {
		out.Findings = append(out.Findings, Finding{Checker: c.Name(), Severity: SeverityHigh, Message: fmt.Sprintf("flagged by Google Safe Browsing: %s", m.ThreatType)})
	}
	return out
}
