package main

import (
	"encoding/json"
	"testing"
)

func TestSeverityString(t *testing.T) {
	cases := map[Severity]string{
		SeverityInfo:   "INFO",
		SeverityLow:    "LOW",
		SeverityMedium: "MEDIUM",
		SeverityHigh:   "HIGH",
		Severity(99):   "INFO", // unknown values fall back to INFO
	}
	for sev, want := range cases {
		if got := sev.String(); got != want {
			t.Errorf("Severity(%d).String() = %q, want %q", sev, got, want)
		}
	}
}

func TestSeverityMarshalJSON(t *testing.T) {
	b, err := json.Marshal(SeverityHigh)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(b) != `"HIGH"` {
		t.Errorf("MarshalJSON = %s, want \"HIGH\"", b)
	}
}
