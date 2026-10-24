package catnet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// AppsScriptSource is the last-resort layer: a minimal Google Apps Script web
// app that carries the document back as plain text.
//
// It is deliberately the plainest possible contract, so it stays inside Apps
// Script's free quotas: one GET, no custom headers, no streaming, tiny body.
// The script only needs to return the raw servers.json text:
//
//	function doGet(e) {
//	  var url = "https://raw.githubusercontent.com/<owner>/<repo>/main/servers.json";
//	  var r = UrlFetchApp.fetch(url, {muteHttpExceptions: true});
//	  return ContentService.createTextOutput(r.getContentText())
//	    .setMimeType(ContentService.MimeType.TEXT);
//	}
//
// Because Google's edge is usually reachable when Iranian filtering blocks
// GitHub and its mirrors directly, this layer rescues the case where every
// earlier layer is blocked but Google is not. It is slow (cold starts, and the
// script itself fetches upstream), so it is tried last.
type AppsScriptSource struct {
	// URL is the deployment URL,
	// "https://script.google.com/macros/s/<id>/exec".
	URL string
	// Token is an optional shared secret the script checks against e.token.
	// Empty sends none.
	Token string
	// Timeout bounds the whole request. Default 6s, which allows one cold start.
	Timeout time.Duration
}

func (s AppsScriptSource) Name() string { return "apps-script:" + hostOf(s.URL) }

func (s AppsScriptSource) Fetch(ctx context.Context) ([]byte, error) {
	if s.URL == "" {
		return nil, fmt.Errorf("apps-script: no URL configured")
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 6 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	u := s.URL + freshPathSeparator(s.URL) + "b=" + itoa(timeBucket())
	if s.Token != "" {
		u += "&k=" + s.Token
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "catnet/1")
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("apps-script: status %d", resp.StatusCode)
	}
	body, err := readLimited(resp, s.Name())
	if err != nil {
		return nil, err
	}
	return unwrapAppsScript(body), nil
}

// Apps Script sometimes answers with an HTML "script function not found"
// page and status 200; the signature check rejects it downstream.

// AppsScriptEnvelope is an alternative response shape: the script may return
// JSON {"d":"<document text>"}, which keeps the document out of the HTML
// wrapper some Apps Script responses add. Both shapes are accepted.
func unwrapAppsScript(body []byte) []byte {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return body
	}
	var probe struct {
		D string `json:"d"`
	}
	if json.Unmarshal(trimmed, &probe) == nil && probe.D != "" {
		return []byte(probe.D)
	}
	return body
}
