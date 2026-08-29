package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestResolveCloudShareLink_Rewrites(t *testing.T) {
	client := &http.Client{}
	cases := map[string]string{
		"https://www.dropbox.com/s/abc123/report.docx?dl=0":          "https://www.dropbox.com/s/abc123/report.docx?dl=1",
		"https://www.dropbox.com/s/abc123/report.docx":               "https://www.dropbox.com/s/abc123/report.docx?dl=1",
		"https://www.dropbox.com/scl/fi/xyz/file.zip?rlkey=abc&dl=0": "https://www.dropbox.com/scl/fi/xyz/file.zip?dl=1&rlkey=abc",
		"https://onedrive.live.com/embed?resid=ABC123":               "https://onedrive.live.com/embed?download=1&resid=ABC123",
		// already has download=1 — withQueryParam short-circuits and
		// returns the URL untouched, so param order is preserved as-is.
		"https://onedrive.live.com/embed?resid=ABC123&download=1":    "https://onedrive.live.com/embed?resid=ABC123&download=1",
		"https://drive.google.com/file/d/FILEID123/view?usp=sharing": "https://drive.google.com/uc?export=download&id=FILEID123",
		"https://drive.google.com/open?id=FILEID456":                 "https://drive.google.com/uc?export=download&id=FILEID456",
		"https://drive.google.com/drive/folders/notafile":            "https://drive.google.com/drive/folders/notafile",
		"https://example.com/some/unrelated/link":                    "https://example.com/some/unrelated/link",
	}

	for in, want := range cases {
		u, err := url.Parse(in)
		if err != nil {
			t.Fatalf("parse %q: %v", in, err)
		}
		got := resolveCloudShareLink(context.Background(), client, u)
		if got.String() != want {
			t.Errorf("resolveCloudShareLink(%q) = %q, want %q", in, got.String(), want)
		}
	}
}

func TestResolveCloudShareLink_OneDriveShortLink(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer target.Close()

	targetURL, _ := url.Parse(target.URL)

	shortener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer shortener.Close()

	shortURL, _ := url.Parse(shortener.URL)
	// followRedirectsRaw doesn't care that the host isn't literally
	// "1drv.ms" — exercise it directly against the short-link server.
	final := followRedirectsRaw(context.Background(), &http.Client{}, shortURL, 5)
	if final == nil {
		t.Fatal("expected a resolved URL, got nil")
	}
	if final.Hostname() != targetURL.Hostname() || final.Port() != targetURL.Port() {
		t.Errorf("resolved to %q, want host:port %s:%s", final.String(), targetURL.Hostname(), targetURL.Port())
	}
}

func TestWithQueryParam(t *testing.T) {
	u, _ := url.Parse("https://example.com/x?a=1")
	got := withQueryParam(u, "b", "2")
	want := "https://example.com/x?a=1&b=2"
	if got.String() != want {
		t.Errorf("withQueryParam = %q, want %q", got.String(), want)
	}

	// Already-correct value should return the same URL unchanged.
	u2, _ := url.Parse("https://example.com/x?a=1")
	got2 := withQueryParam(u2, "a", "1")
	if got2.String() != u2.String() {
		t.Errorf("withQueryParam with existing value changed URL: %q", got2.String())
	}
}
