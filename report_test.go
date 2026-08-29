package main

import (
	"net/url"
	"strings"
	"testing"
)

func outcome(checker string, unreachable bool, findings ...Finding) CheckOutcome {
	return CheckOutcome{Checker: checker, Unreachable: unreachable, Findings: findings}
}

func finding(sev Severity, msg string) Finding {
	return Finding{Severity: sev, Message: msg}
}

func TestComputeVerdict(t *testing.T) {
	cases := []struct {
		name    string
		out     []CheckOutcome
		want    Verdict
		reasons int
	}{
		{
			name: "no findings is safe",
			out:  []CheckOutcome{outcome("heuristics", false)},
			want: VerdictSafe,
		},
		{
			name: "only info/low findings is safe",
			out: []CheckOutcome{
				outcome("redirect-chain", false, finding(SeverityInfo, "x"), finding(SeverityLow, "y")),
			},
			want: VerdictSafe,
		},
		{
			name: "a medium finding is caution",
			out: []CheckOutcome{
				outcome("virustotal", false, finding(SeverityMedium, "1/92 flagged")),
			},
			want:    VerdictCaution,
			reasons: 1,
		},
		{
			name: "a high finding is dangerous",
			out: []CheckOutcome{
				outcome("heuristics", false, finding(SeverityHigh, "typosquat")),
			},
			want:    VerdictDangerous,
			reasons: 1,
		},
		{
			name: "high beats medium across checkers",
			out: []CheckOutcome{
				outcome("virustotal", false, finding(SeverityMedium, "isolated flag")),
				outcome("heuristics", false, finding(SeverityHigh, "typosquat")),
			},
			want:    VerdictDangerous,
			reasons: 2,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, reasons := computeVerdict(c.out)
			if got != c.want {
				t.Errorf("verdict = %v, want %v", got, c.want)
			}
			if len(reasons) != c.reasons {
				t.Errorf("len(reasons) = %d, want %d", len(reasons), c.reasons)
			}
		})
	}
}

func TestIsUnreachable(t *testing.T) {
	if isUnreachable([]CheckOutcome{outcome("redirect-chain", false)}) {
		t.Error("expected false when redirect-chain is reachable")
	}
	if !isUnreachable([]CheckOutcome{outcome("redirect-chain", true)}) {
		t.Error("expected true when redirect-chain reports unreachable")
	}
	// Unreachable on an unrelated checker shouldn't count.
	if isUnreachable([]CheckOutcome{outcome("tls-cert", true)}) {
		t.Error("expected false when only a non-redirect-chain checker is unreachable")
	}
}

func TestVerdictCodeAndExitCode(t *testing.T) {
	cases := []struct {
		v           Verdict
		unreachable bool
		code        string
		exit        int
	}{
		{VerdictSafe, false, "LOOKS SAFE", 0},
		{VerdictSafe, true, "UNKNOWN", 1},
		{VerdictCaution, false, "CAUTION", 1},
		{VerdictCaution, true, "CAUTION", 1},
		{VerdictDangerous, false, "DANGEROUS", 2},
		{VerdictDangerous, true, "DANGEROUS", 2},
	}
	for _, c := range cases {
		if got := verdictCode(c.v, c.unreachable); got != c.code {
			t.Errorf("verdictCode(%v, %v) = %q, want %q", c.v, c.unreachable, got, c.code)
		}
		if got := exitCodeForVerdict(c.v, c.unreachable); got != c.exit {
			t.Errorf("exitCodeForVerdict(%v, %v) = %d, want %d", c.v, c.unreachable, got, c.exit)
		}
	}
}

func TestVerdictLabel(t *testing.T) {
	cases := []struct {
		v           Verdict
		unreachable bool
		substr      string
	}{
		{VerdictDangerous, false, "do not open this link"},
		{VerdictDangerous, true, "could not be resolved"},
		{VerdictCaution, false, "verify before opening"},
		{VerdictCaution, true, "does not exist"},
		{VerdictSafe, false, "no red flags"},
		{VerdictSafe, true, "can't be verified"},
	}
	for _, c := range cases {
		got := verdictLabel(c.v, c.unreachable)
		if !strings.Contains(got, c.substr) {
			t.Errorf("verdictLabel(%v, %v) = %q, want it to contain %q", c.v, c.unreachable, got, c.substr)
		}
	}
}

func TestFriendlyName(t *testing.T) {
	if got := friendlyName("redirect-chain"); got != "Where the link actually goes" {
		t.Errorf("friendlyName(redirect-chain) = %q", got)
	}
	// Unknown checker names should pass through unchanged rather than
	// panicking or returning an empty label.
	if got := friendlyName("some-future-checker"); got != "some-future-checker" {
		t.Errorf("friendlyName(unknown) = %q, want the input unchanged", got)
	}
}

func TestPrintReport_SmokeTest(t *testing.T) {
	target, _ := url.Parse("http://teams.microsoft.com.security-update-portal.net")
	outcomes := []CheckOutcome{
		outcome("redirect-chain", true),
		outcome("heuristics", false,
			finding(SeverityHigh, `brand name "microsoft" appears as a subdomain`),
		),
	}
	verdict, reasons := computeVerdict(outcomes)

	var sb strings.Builder
	printReport(&sb, target, "", outcomes, verdict, reasons, isUnreachable(outcomes), newPalette(true))
	out := sb.String()

	for _, want := range []string{
		"Checking: http://teams.microsoft.com.security-update-portal.net",
		"Where the link actually goes",
		"DANGEROUS",
		`brand name "microsoft"`,
		"Why:",
		"automatic signal, not a guarantee",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report output missing %q\n--- full output ---\n%s", want, out)
		}
	}

	// newPalette(true) forces color off — no ANSI escape codes should leak
	// into the plain-text report.
	if strings.Contains(out, "\x1b[") {
		t.Error("expected no ANSI escape codes with color forced off")
	}
}
