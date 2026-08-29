package main

import (
	"strings"
	"testing"
)

func TestVtStatsFinding(t *testing.T) {
	cases := []struct {
		name   string
		stats  map[string]int
		prefix string
		sev    Severity
		substr string
	}{
		{
			name:   "clean",
			stats:  map[string]int{"harmless": 90, "undetected": 2},
			sev:    SeverityInfo,
			substr: "clean across 92 engines",
		},
		{
			// Regression: google.com was flagged DANGEROUS by a single
			// noisy vendor out of ~90 engines before this threshold existed.
			name:   "single engine flag is not confident enough for HIGH",
			stats:  map[string]int{"malicious": 1, "harmless": 91},
			sev:    SeverityMedium,
			substr: "isolated false positive",
		},
		{
			name:   "two engines still below the confidence threshold",
			stats:  map[string]int{"malicious": 2, "harmless": 90},
			sev:    SeverityMedium,
			substr: "isolated false positive",
		},
		{
			name:   "three or more engines agreeing is HIGH",
			stats:  map[string]int{"malicious": 3, "harmless": 89},
			sev:    SeverityHigh,
			substr: "flagged as malicious",
		},
		{
			name:   "many engines agreeing is HIGH",
			stats:  map[string]int{"malicious": 10, "harmless": 82},
			sev:    SeverityHigh,
			substr: "flagged as malicious",
		},
		{
			name:   "suspicious with no malicious is MEDIUM",
			stats:  map[string]int{"suspicious": 2, "harmless": 90},
			sev:    SeverityMedium,
			substr: "flagged as suspicious",
		},
		{
			name:   "file prefix is applied",
			stats:  map[string]int{"malicious": 5, "harmless": 87},
			prefix: "file: ",
			sev:    SeverityHigh,
			substr: "file: 5/92 engines flagged as malicious",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := vtStatsFinding("virustotal", c.prefix, c.stats)
			if f.Severity != c.sev {
				t.Errorf("severity = %v, want %v (message: %q)", f.Severity, c.sev, f.Message)
			}
			if !strings.Contains(f.Message, c.substr) {
				t.Errorf("message %q does not contain %q", f.Message, c.substr)
			}
		})
	}
}
