package main

import (
	"bufio"
	"os"
	"strings"
)

// loadDotEnv applies simple KEY=VALUE lines from a .env file into the
// process environment, without overriding variables already set there —
// so an explicit `export VT_API_KEY=...` always wins over the file. A
// missing file or malformed line is silently skipped; this is a plain
// convenience, not a strict parser (no multi-line values, no $VAR expansion).
func loadDotEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if key == "" {
			continue
		}
		if _, exists := os.LookupEnv(key); !exists {
			os.Setenv(key, value)
		}
	}
}
