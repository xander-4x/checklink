package main

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

// resolveCloudShareLink rewrites a small set of well-known cloud-storage
// "share page" URLs (Google Drive, Dropbox, OneDrive) into their direct
// file-download form. Attackers increasingly host payloads on these
// trusted domains specifically because a share link — the thing actually
// sent to a victim — renders an HTML viewer/preview page, not the file
// itself, so URL-only checks and hash-based file checks never reach the
// real bytes.
//
// If a link doesn't match a known share-page pattern, or resolution fails,
// it's returned unchanged — this is a best-effort convenience, not a
// requirement for the rest of the checks to run.
func resolveCloudShareLink(ctx context.Context, client *http.Client, u *url.URL) *url.URL {
	switch strings.ToLower(u.Hostname()) {
	case "drive.google.com":
		if resolved := resolveGoogleDrive(u); resolved != nil {
			return resolved
		}
	case "dropbox.com", "www.dropbox.com":
		return withQueryParam(u, "dl", "1")
	case "onedrive.live.com":
		return withQueryParam(u, "download", "1")
	case "1drv.ms":
		if final := followRedirectsRaw(ctx, client, u, 5); final != nil && strings.EqualFold(final.Hostname(), "onedrive.live.com") {
			return withQueryParam(final, "download", "1")
		}
	}
	return u
}

// resolveGoogleDrive turns a Drive share/view URL (drive.google.com/file/d/{id}/view,
// .../open?id={id}, .../uc?id={id}, ...) into the direct-download form. Returns
// nil if no file ID could be found in the URL.
func resolveGoogleDrive(u *url.URL) *url.URL {
	id := u.Query().Get("id")
	if id == "" {
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		for i, p := range parts {
			if p == "d" && i+1 < len(parts) {
				id = parts[i+1]
				break
			}
		}
	}
	if id == "" {
		return nil
	}
	resolved, err := url.Parse("https://drive.google.com/uc?export=download&id=" + url.QueryEscape(id))
	if err != nil {
		return nil
	}
	return resolved
}

func withQueryParam(u *url.URL, key, value string) *url.URL {
	if u.Query().Get(key) == value {
		return u
	}
	q := u.Query()
	q.Set(key, value)
	rewritten := *u
	rewritten.RawQuery = q.Encode()
	return &rewritten
}

// followRedirectsRaw resolves short links (e.g. 1drv.ms) to their final
// destination without running any of the actual checks against it.
func followRedirectsRaw(ctx context.Context, client *http.Client, u *url.URL, maxHops int) *url.URL {
	c := &http.Client{
		Timeout: client.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxHops {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "antifish-check-url/1.0 (+internal phishing-link checker)")

	resp, err := c.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	return resp.Request.URL
}
