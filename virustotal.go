package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type VirusTotalChecker struct {
	APIKey string
	Client *http.Client
	// Submit, when true, submits URLs VirusTotal has never seen for fresh
	// analysis and polls for the result. Off by default so a routine run
	// never silently burns the free-tier quota (4 req/min, 500/day).
	Submit bool
}

func (c *VirusTotalChecker) Name() string { return "virustotal" }

func (c *VirusTotalChecker) Check(ctx context.Context, target *url.URL) CheckOutcome {
	out := CheckOutcome{Checker: c.Name()}
	if c.APIKey == "" {
		out.SkipNote = "VT_API_KEY not set"
		return out
	}

	id := base64.RawURLEncoding.EncodeToString([]byte(target.String()))

	stats, found, err := vtLookupURL(ctx, c.Client, c.APIKey, id)
	if err != nil {
		out.Error = err.Error()
		return out
	}

	if !found {
		if !c.Submit {
			out.Findings = append(out.Findings, Finding{Checker: c.Name(), Severity: SeverityInfo, Message: "not previously analyzed by VirusTotal (run with -vt-submit to submit it now)"})
			return out
		}
		analysisID, err := vtSubmitURL(ctx, c.Client, c.APIKey, target.String())
		if err != nil {
			out.Error = err.Error()
			return out
		}
		stats, err = vtPollAnalysis(ctx, c.Client, c.APIKey, analysisID)
		if err != nil {
			out.Error = err.Error()
			return out
		}
	}

	out.Findings = append(out.Findings, vtStatsFinding(c.Name(), "", stats))
	return out
}

func vtLookupURL(ctx context.Context, client *http.Client, apiKey, id string) (map[string]int, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.virustotal.com/api/v3/urls/"+id, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("x-apikey", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("virustotal lookup returned status %s", resp.Status)
	}

	var payload struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats map[string]int `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, false, err
	}
	return payload.Data.Attributes.LastAnalysisStats, true, nil
}

func vtSubmitURL(ctx context.Context, client *http.Client, apiKey, target string) (string, error) {
	form := url.Values{"url": {target}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://www.virustotal.com/api/v3/urls", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("virustotal submit returned status %s", resp.Status)
	}
	return decodeVTAnalysisID(resp.Body)
}

func decodeVTAnalysisID(body io.Reader) (string, error) {
	var payload struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(body).Decode(&payload); err != nil {
		return "", err
	}
	return payload.Data.ID, nil
}

// vtPollAnalysis polls a submitted analysis (of either a URL or a file)
// until VirusTotal finishes processing it.
func vtPollAnalysis(ctx context.Context, client *http.Client, apiKey, analysisID string) (map[string]int, error) {
	endpoint := "https://www.virustotal.com/api/v3/analyses/" + analysisID
	for attempt := 0; attempt < 10; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("x-apikey", apiKey)

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			status := resp.Status
			resp.Body.Close()
			return nil, fmt.Errorf("virustotal analysis poll returned status %s", status)
		}

		var payload struct {
			Data struct {
				Attributes struct {
					Status string         `json:"status"`
					Stats  map[string]int `json:"stats"`
				} `json:"attributes"`
			} `json:"data"`
		}
		decodeErr := json.NewDecoder(resp.Body).Decode(&payload)
		resp.Body.Close()
		if decodeErr != nil {
			return nil, decodeErr
		}

		if payload.Data.Attributes.Status == "completed" {
			return payload.Data.Attributes.Stats, nil
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return nil, fmt.Errorf("virustotal analysis did not complete in time")
}

// minConfidentMalicious is the number of engines that must agree before a
// "malicious" verdict is treated as HIGH rather than noise: on any
// popular, entirely legitimate domain (google.com, microsoft.com, ...) it's
// routine for a single low-quality engine out of ~90 to false-positive.
// One or two flags is still worth a look, just not a "don't open this" verdict.
const minConfidentMalicious = 3

// vtStatsFinding renders a VirusTotal engine-stats map into one Finding.
// prefix distinguishes a file result ("file: ") from a URL result ("").
func vtStatsFinding(checker, prefix string, stats map[string]int) Finding {
	total := 0
	for _, v := range stats {
		total += v
	}
	switch {
	case stats["malicious"] >= minConfidentMalicious:
		return Finding{Checker: checker, Severity: SeverityHigh, Message: fmt.Sprintf("%s%d/%d engines flagged as malicious", prefix, stats["malicious"], total)}
	case stats["malicious"] > 0:
		return Finding{Checker: checker, Severity: SeverityMedium, Message: fmt.Sprintf("%s%d/%d engine(s) flagged as malicious — could be an isolated false positive, but worth a second look", prefix, stats["malicious"], total)}
	case stats["suspicious"] > 0:
		return Finding{Checker: checker, Severity: SeverityMedium, Message: fmt.Sprintf("%s%d/%d engines flagged as suspicious", prefix, stats["suspicious"], total)}
	default:
		return Finding{Checker: checker, Severity: SeverityInfo, Message: fmt.Sprintf("%sclean across %d engines", prefix, total)}
	}
}
