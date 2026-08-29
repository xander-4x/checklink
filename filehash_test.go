package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newTestResponse(t *testing.T, reqPath string, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://example.com"+reqPath, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return &http.Response{Header: h, Request: req}
}

func TestDetectFile(t *testing.T) {
	cases := []struct {
		name       string
		reqPath    string
		headers    map[string]string
		wantFile   bool
		wantSubstr string
	}{
		{
			name:       "content-disposition attachment with exe filename",
			reqPath:    "/download",
			headers:    map[string]string{"Content-Disposition": `attachment; filename="TeamsSetup.exe"`},
			wantFile:   true,
			wantSubstr: "TeamsSetup.exe",
		},
		{
			name:     "octet-stream content type with no useful extension",
			reqPath:  "/download",
			headers:  map[string]string{"Content-Type": "application/octet-stream"},
			wantFile: true,
		},
		{
			name:     "zip extension in the URL path",
			reqPath:  "/files/archive.zip",
			headers:  map[string]string{"Content-Type": "application/zip"},
			wantFile: true,
		},
		{
			name:     "plain html page",
			reqPath:  "/",
			headers:  map[string]string{"Content-Type": "text/html; charset=utf-8"},
			wantFile: false,
		},
		{
			name:     "no headers at all",
			reqPath:  "/",
			headers:  map[string]string{},
			wantFile: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := newTestResponse(t, c.reqPath, c.headers)
			filename, looksLikeFile := detectFile(resp)
			if looksLikeFile != c.wantFile {
				t.Errorf("looksLikeFile = %v, want %v (filename=%q)", looksLikeFile, c.wantFile, filename)
			}
			if c.wantSubstr != "" && !strings.Contains(filename, c.wantSubstr) {
				t.Errorf("filename = %q, want it to contain %q", filename, c.wantSubstr)
			}
		})
	}
}

func TestReadCapped(t *testing.T) {
	t.Run("under the limit", func(t *testing.T) {
		body, truncated, err := readCapped(strings.NewReader("hello"), 10)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if truncated {
			t.Error("expected truncated=false")
		}
		if string(body) != "hello" {
			t.Errorf("body = %q, want %q", body, "hello")
		}
	})

	t.Run("over the limit", func(t *testing.T) {
		body, truncated, err := readCapped(strings.NewReader("hello world"), 5)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !truncated {
			t.Error("expected truncated=true")
		}
		if body != nil {
			t.Errorf("expected nil body when truncated, got %q", body)
		}
	})

	t.Run("exactly at the limit", func(t *testing.T) {
		_, truncated, err := readCapped(strings.NewReader("12345"), 5)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if truncated {
			t.Error("expected truncated=false when body size equals the limit exactly")
		}
	})
}

func TestFileHashChecker_Check(t *testing.T) {
	t.Run("hashes a recognized file without a VT key", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Disposition", `attachment; filename="setup.exe"`)
			w.Write([]byte("fake-binary-content"))
		}))
		defer server.Close()

		checker := &FileHashChecker{Client: &http.Client{Timeout: 5 * time.Second}}
		target, _ := url.Parse(server.URL)
		out := checker.Check(context.Background(), target)

		if !hasFinding(out.Findings, SeverityInfo, "SHA-256:") {
			t.Errorf("expected a SHA-256 INFO finding, got %+v (skip=%q err=%q)", out.Findings, out.SkipNote, out.Error)
		}
		if !hasFinding(out.Findings, SeverityInfo, "VT_API_KEY not set") {
			t.Errorf("expected a note that VT wasn't checked, got %+v", out.Findings)
		}
	})

	t.Run("skips a plain webpage", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<html></html>"))
		}))
		defer server.Close()

		checker := &FileHashChecker{Client: &http.Client{Timeout: 5 * time.Second}}
		target, _ := url.Parse(server.URL)
		out := checker.Check(context.Background(), target)

		if out.SkipNote == "" {
			t.Errorf("expected a skip note for a non-file response, got findings=%+v", out.Findings)
		}
		if len(out.Findings) != 0 {
			t.Errorf("expected no findings when skipped, got %+v", out.Findings)
		}
	})
}
