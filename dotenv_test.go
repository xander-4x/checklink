package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDotEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := `# a comment
VT_API_KEY=abc123

QUOTED="value with spaces"
SINGLE_QUOTED='another value'
MALFORMED_LINE_NO_EQUALS
EMPTY_VALUE=
   PADDED_KEY = padded value
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	for _, key := range []string{"VT_API_KEY", "QUOTED", "SINGLE_QUOTED", "EMPTY_VALUE", "PADDED_KEY", "ALREADY_SET"} {
		os.Unsetenv(key)
	}
	t.Setenv("ALREADY_SET", "from-real-env")

	loadDotEnv(path)

	cases := map[string]string{
		"VT_API_KEY":    "abc123",
		"QUOTED":        "value with spaces",
		"SINGLE_QUOTED": "another value",
		"EMPTY_VALUE":   "",
		"PADDED_KEY":    "padded value",
		"ALREADY_SET":   "from-real-env", // real env must win over .env
	}
	for key, want := range cases {
		if got := os.Getenv(key); got != want {
			t.Errorf("os.Getenv(%q) = %q, want %q", key, got, want)
		}
	}

	if v := os.Getenv("MALFORMED_LINE_NO_EQUALS"); v != "" {
		t.Errorf("malformed line should not set anything, got %q", v)
	}
}

func TestLoadDotEnv_MissingFileIsNoop(t *testing.T) {
	// Must not panic or error out loudly when there's no .env.
	loadDotEnv(filepath.Join(t.TempDir(), "does-not-exist.env"))
}
