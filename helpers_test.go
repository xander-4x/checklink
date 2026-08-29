package main

import "strings"

// hasFinding reports whether findings contains one with the given severity
// whose message contains substr (case-sensitive, substring match).
func hasFinding(findings []Finding, severity Severity, substr string) bool {
	for _, f := range findings {
		if f.Severity == severity && strings.Contains(f.Message, substr) {
			return true
		}
	}
	return false
}

// hasSeverity reports whether any finding has exactly this severity.
func hasSeverity(findings []Finding, severity Severity) bool {
	for _, f := range findings {
		if f.Severity == severity {
			return true
		}
	}
	return false
}
