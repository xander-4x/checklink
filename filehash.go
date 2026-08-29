package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"path"
	"strings"
)

// maxHashBytes caps how much of a response body we'll actually download to
// hash — enough for a typical installer/document without risking a huge or
// slow transfer.
const maxHashBytes = 50 * 1024 * 1024 // 50MB

// maxVTUploadBytes is VirusTotal's limit for a direct (non-resumable)
// file upload via POST /api/v3/files.
const maxVTUploadBytes = 32 * 1024 * 1024 // 32MB

// downloadableExts is executableExts plus archive/office formats that are
// also common malware delivery vehicles but aren't directly executable.
var downloadableExts = func() map[string]bool {
	m := map[string]bool{
		".zip": true, ".rar": true, ".7z": true, ".iso": true,
		".docm": true, ".xlsm": true, ".pptm": true,
	}
	for ext := range executableExts {
		m[ext] = true
	}
	return m
}()

// FileHashChecker downloads the response body (up to maxHashBytes, fully in
// memory, never written to disk or executed), hashes it, and — if a
// VT_API_KEY is configured — checks that hash against VirusTotal.
type FileHashChecker struct {
	Client   *http.Client
	VTAPIKey string
	// VTSubmit, when true, uploads files VirusTotal has no cached report
	// for (still off by default: uploading, unlike a hash lookup, consumes
	// much more quota and makes the file itself visible to other VT users).
	VTSubmit bool
}

func (c *FileHashChecker) Name() string { return "file-hash" }

func (c *FileHashChecker) Check(ctx context.Context, target *url.URL) CheckOutcome {
	out := CheckOutcome{Checker: c.Name()}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	req.Header.Set("User-Agent", "checklink/1.0 (+internal phishing-link checker)")

	resp, err := c.Client.Do(req)
	if err != nil {
		out.SkipNote = "could not fetch response (see \"Where the link actually goes\" above)"
		return out
	}
	defer resp.Body.Close()

	filename, looksLikeFile := detectFile(resp)
	if !looksLikeFile {
		out.SkipNote = "response doesn't look like a downloadable file, nothing to hash"
		return out
	}

	body, truncated, err := readCapped(resp.Body, maxHashBytes)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	if truncated {
		out.Findings = append(out.Findings, Finding{
			Checker: c.Name(), Severity: SeverityMedium,
			Message: fmt.Sprintf("file exceeds %dMB, skipped hashing — download and scan it with your local antivirus before opening", maxHashBytes/1024/1024),
		})
		return out
	}

	sum := sha256.Sum256(body)
	hash := hex.EncodeToString(sum[:])
	out.Findings = append(out.Findings, Finding{
		Checker: c.Name(), Severity: SeverityInfo,
		Message: fmt.Sprintf("%s (%d bytes) SHA-256: %s", filename, len(body), hash),
	})

	if c.VTAPIKey == "" {
		out.Findings = append(out.Findings, Finding{Checker: c.Name(), Severity: SeverityInfo, Message: "VT_API_KEY not set — hash not checked against VirusTotal"})
		return out
	}

	stats, found, err := vtLookupFile(ctx, c.Client, c.VTAPIKey, hash)
	if err != nil {
		out.Error = err.Error()
		return out
	}

	if !found {
		switch {
		case !c.VTSubmit:
			out.Findings = append(out.Findings, Finding{Checker: c.Name(), Severity: SeverityInfo, Message: "file not previously seen by VirusTotal (run with -vt-submit-file to upload and scan it now)"})
			return out
		case len(body) > maxVTUploadBytes:
			out.Findings = append(out.Findings, Finding{
				Checker: c.Name(), Severity: SeverityMedium,
				Message: fmt.Sprintf("file exceeds VirusTotal's %dMB direct-upload limit — hash was only checked against cached reports", maxVTUploadBytes/1024/1024),
			})
			return out
		default:
			analysisID, err := vtUploadFile(ctx, c.Client, c.VTAPIKey, filename, body)
			if err != nil {
				out.Error = err.Error()
				return out
			}
			stats, err = vtPollAnalysis(ctx, c.Client, c.VTAPIKey, analysisID)
			if err != nil {
				out.Error = err.Error()
				return out
			}
		}
	}

	out.Findings = append(out.Findings, vtStatsFinding(c.Name(), "file: ", stats))
	return out
}

// detectFile decides whether a response looks like a file download worth
// hashing, based on the same signals RedirectChecker uses to flag
// executables (Content-Disposition filename, else URL path; extension or
// a binary-ish Content-Type).
func detectFile(resp *http.Response) (filename string, looksLikeFile bool) {
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		if _, params, err := mime.ParseMediaType(cd); err == nil {
			filename = params["filename"]
		}
	}
	if filename == "" {
		filename = path.Base(resp.Request.URL.Path)
	}

	ext := strings.ToLower(path.Ext(filename))
	if downloadableExts[ext] {
		return filename, true
	}

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		mt, _, _ := mime.ParseMediaType(ct)
		if mt == "application/octet-stream" || mt == "application/x-msdownload" {
			return filename, true
		}
	}

	return filename, false
}

// readCapped reads at most limit bytes and reports whether the body had
// more data beyond that (in which case the returned bytes are discarded —
// a partial hash isn't useful for matching against a reputation database).
func readCapped(r io.Reader, limit int64) ([]byte, bool, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(body)) > limit {
		return nil, true, nil
	}
	return body, false, nil
}

func vtLookupFile(ctx context.Context, client *http.Client, apiKey, sha256Hash string) (map[string]int, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.virustotal.com/api/v3/files/"+sha256Hash, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("x-apikey", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("virustotal file lookup returned status %s", resp.Status)
	}

	var payload struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats map[string]int `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, false, err
	}
	return payload.Data.Attributes.LastAnalysisStats, true, nil
}

func vtUploadFile(ctx context.Context, client *http.Client, apiKey, filename string, body []byte) (string, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, err := mw.CreateFormFile("file", filename)
	if err != nil {
		return "", err
	}
	if _, err := part.Write(body); err != nil {
		return "", err
	}
	if err := mw.Close(); err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://www.virustotal.com/api/v3/files", &buf)
	if err != nil {
		return "", err
	}
	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("Content-Type", mw.FormDataContentType())

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("virustotal file upload returned status %s", resp.Status)
	}
	return decodeVTAnalysisID(resp.Body)
}
