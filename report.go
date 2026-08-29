package main

import (
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

type Verdict int

const (
	VerdictSafe Verdict = iota
	VerdictCaution
	VerdictDangerous
)

// computeVerdict reduces every finding across all checkers into one verdict
// plus the specific findings that drove it, so the report can show a short
// "why" list under the banner instead of forcing the reader through every
// section.
func computeVerdict(outcomes []CheckOutcome) (Verdict, []Finding) {
	var reasons []Finding
	max := SeverityInfo
	for _, o := range outcomes {
		for _, f := range o.Findings {
			if f.Severity > max {
				max = f.Severity
			}
			if f.Severity >= SeverityMedium {
				reasons = append(reasons, f)
			}
		}
	}
	sort.SliceStable(reasons, func(i, j int) bool { return reasons[i].Severity > reasons[j].Severity })

	switch {
	case max >= SeverityHigh:
		return VerdictDangerous, reasons
	case max >= SeverityMedium:
		return VerdictCaution, reasons
	default:
		return VerdictSafe, reasons
	}
}

// isUnreachable reports whether the domain simply doesn't resolve (per the
// redirect-chain checker), as distinct from "checked and found no issues".
func isUnreachable(outcomes []CheckOutcome) bool {
	for _, o := range outcomes {
		if o.Checker == "redirect-chain" && o.Unreachable {
			return true
		}
	}
	return false
}

// verdictCode is the short machine-friendly form used in JSON output.
func verdictCode(v Verdict, unreachable bool) string {
	if v == VerdictSafe && unreachable {
		return "UNKNOWN"
	}
	switch v {
	case VerdictDangerous:
		return "DANGEROUS"
	case VerdictCaution:
		return "CAUTION"
	default:
		return "LOOKS SAFE"
	}
}

// verdictLabel is the full sentence shown on the banner line.
func verdictLabel(v Verdict, unreachable bool) string {
	switch v {
	case VerdictDangerous:
		if unreachable {
			return "DANGEROUS — do not open this link (the domain also could not be resolved right now)"
		}
		return "DANGEROUS — do not open this link"
	case VerdictCaution:
		if unreachable {
			return "CAUTION — looks suspicious, and the domain does not exist"
		}
		return "CAUTION — looks suspicious, verify before opening"
	default:
		if unreachable {
			return "UNKNOWN — this domain does not exist, so the link can't be verified"
		}
		return "LOOKS SAFE — no red flags found by automated checks"
	}
}

func exitCodeForVerdict(v Verdict, unreachable bool) int {
	switch v {
	case VerdictDangerous:
		return 2
	case VerdictCaution:
		return 1
	default:
		if unreachable {
			return 1
		}
		return 0
	}
}

// friendlyNames maps internal checker identifiers to section headings a
// non-technical reader can make sense of.
var friendlyNames = map[string]string{
	"redirect-chain":       "Where the link actually goes",
	"tls-cert":             "Connection security",
	"heuristics":           "Domain name analysis",
	"google-safe-browsing": "Google Safe Browsing",
	"virustotal":           "VirusTotal (URL)",
	"file-hash":            "Downloaded file",
}

func friendlyName(checker string) string {
	if n, ok := friendlyNames[checker]; ok {
		return n
	}
	return checker
}

// palette colors only the verdict line. Body text stays the terminal's
// default foreground so it stays readable across light/dark themes; the
// findings' severity is conveyed with a text tag ([HIGH]/[MEDIUM]/...)
// instead of color.
type palette struct{ enabled bool }

func newPalette(forceOff bool) palette {
	if forceOff || os.Getenv("NO_COLOR") != "" {
		return palette{enabled: false}
	}
	info, err := os.Stdout.Stat()
	if err != nil {
		return palette{enabled: false}
	}
	return palette{enabled: (info.Mode() & os.ModeCharDevice) != 0}
}

func (p palette) wrap(code, text string) string {
	if !p.enabled {
		return text
	}
	return "\033[" + code + "m" + text + "\033[0m"
}

func (p palette) bold(text string) string { return p.wrap("1", text) }

func (p palette) verdict(v Verdict, unreachable bool, text string) string {
	code := "1;32" // bold green
	switch {
	case v == VerdictDangerous:
		code = "1;31" // bold red
	case v == VerdictCaution:
		code = "1;33" // bold yellow
	case unreachable: // safe verdict, but nothing could actually be checked
		code = "1;36" // bold cyan
	}
	return p.wrap(code, text)
}

func printReport(w *strings.Builder, target *url.URL, resolvedURL string, outcomes []CheckOutcome, verdict Verdict, reasons []Finding, unreachable bool, p palette) {
	fmt.Fprintf(w, "Checking: %s\n", target.String())
	if resolvedURL != "" {
		fmt.Fprintf(w, "Resolved cloud-storage share link to: %s\n", resolvedURL)
	}
	fmt.Fprintln(w)

	for _, o := range outcomes {
		fmt.Fprintf(w, "%s\n", p.bold(friendlyName(o.Checker)))
		switch {
		case o.SkipNote != "":
			fmt.Fprintf(w, "  skipped — %s\n", o.SkipNote)
		case o.Error != "":
			fmt.Fprintf(w, "  could not check — %s\n", o.Error)
		case len(o.Findings) == 0:
			fmt.Fprintln(w, "  nothing notable")
		default:
			for _, f := range o.Findings {
				fmt.Fprintf(w, "  [%s] %s\n", f.Severity, f.Message)
			}
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, p.verdict(verdict, unreachable, verdictLabel(verdict, unreachable)))
	fmt.Fprintln(w)

	if len(reasons) > 0 {
		fmt.Fprintln(w, "Why:")
		for _, r := range reasons {
			fmt.Fprintf(w, "  [%s] %s\n", r.Severity, r.Message)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "This is an automatic signal, not a guarantee - be wary of urgent messages and")
	fmt.Fprintln(w, "social engineering techniques")
}
