package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// jsonReport is the -json output shape: the same per-checker outcomes plus
// the reduced verdict, so scripted consumers don't have to re-derive it.
type jsonReport struct {
	URL         string         `json:"url"`
	ResolvedURL string         `json:"resolved_url,omitempty"`
	Verdict     string         `json:"verdict"`
	Checks      []CheckOutcome `json:"checks"`
}

func main() {
	loadDotEnv(".env")

	var (
		jsonOut       bool
		noColor       bool
		timeout       time.Duration
		vtSubmit      bool
		vtSubmitFile  bool
		setKeyName    string
		deleteKeyName string
	)
	flag.BoolVar(&jsonOut, "json", false, "output machine-readable JSON instead of a text report")
	flag.BoolVar(&noColor, "no-color", false, "disable ANSI colors in the text report")
	flag.DurationVar(&timeout, "timeout", 15*time.Second, "per-check network timeout")
	flag.BoolVar(&vtSubmit, "vt-submit", false, "submit the URL to VirusTotal for fresh analysis if it has no cached report (consumes API quota)")
	flag.BoolVar(&vtSubmitFile, "vt-submit-file", false, "upload a downloaded file to VirusTotal for scanning if its hash has no cached report (consumes more quota, makes the file visible to other VT users)")
	flag.StringVar(&setKeyName, "set-key", "", "prompt for a secret's value and save it to the OS keychain, e.g. -set-key VT_API_KEY, then exit")
	flag.StringVar(&deleteKeyName, "delete-key", "", "remove a secret previously saved with -set-key, then exit")
	flag.Parse()

	if setKeyName != "" {
		if err := setKeyInteractive(setKeyName); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if deleteKeyName != "" {
		if err := deleteKey(deleteKeyName); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if timeout <= 0 {
		fmt.Fprintln(os.Stderr, "-timeout must be positive")
		os.Exit(2)
	}

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: checklink [flags] <url>")
		flag.PrintDefaults()
		os.Exit(2)
	}

	raw := flag.Arg(0)
	target, err := url.Parse(raw)
	if err != nil || target.Host == "" || (target.Scheme != "http" && target.Scheme != "https") {
		fmt.Fprintf(os.Stderr, "invalid URL: %s\n", raw)
		os.Exit(2)
	}

	httpClient := &http.Client{Timeout: timeout}

	ctx, cancel := context.WithTimeout(context.Background(), timeout*2)
	defer cancel()

	checkTarget := resolveCloudShareLink(ctx, httpClient, target)

	vtAPIKey := resolveSecret("VT_API_KEY")
	checkers := []Checker{
		&RedirectChecker{Client: httpClient},
		&TLSChecker{Timeout: timeout},
		&HeuristicsChecker{},
		&SafeBrowsingChecker{APIKey: resolveSecret("GOOGLE_SAFE_BROWSING_API_KEY"), Client: httpClient},
		&VirusTotalChecker{APIKey: vtAPIKey, Client: httpClient, Submit: vtSubmit},
		&FileHashChecker{Client: httpClient, VTAPIKey: vtAPIKey, VTSubmit: vtSubmitFile},
	}

	outcomes := make([]CheckOutcome, len(checkers))
	var wg sync.WaitGroup
	for i, chk := range checkers {
		wg.Add(1)
		go func(i int, chk Checker) {
			defer wg.Done()
			outcomes[i] = chk.Check(ctx, checkTarget)
		}(i, chk)
	}
	wg.Wait()

	verdict, reasons := computeVerdict(outcomes)
	unreachable := isUnreachable(outcomes)

	resolvedURL := ""
	if checkTarget.String() != target.String() {
		resolvedURL = checkTarget.String()
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		report := jsonReport{URL: target.String(), ResolvedURL: resolvedURL, Verdict: verdictCode(verdict, unreachable), Checks: outcomes}
		if err := enc.Encode(report); err != nil {
			fmt.Fprintln(os.Stderr, "error writing JSON output:", err)
			os.Exit(1)
		}
	} else {
		var sb strings.Builder
		printReport(&sb, target, resolvedURL, outcomes, verdict, reasons, unreachable, newPalette(noColor))
		fmt.Print(sb.String())
	}

	os.Exit(exitCodeForVerdict(verdict, unreachable))
}
