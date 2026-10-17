package api

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"browseforge/internal/humanize"

	"github.com/go-chi/chi/v5"
	"github.com/playwright-community/playwright-go"
)

// --- Session endpoints ---

func (h *handler) createSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProfileID       string          `json:"profile_id"`
		LaunchOverrides json.RawMessage `json:"launch_overrides"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeError(w, 400, "INVALID_BODY", err.Error())
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		writeError(w, 400, "INVALID_BODY", "request body must contain one JSON object")
		return
	}
	overrides, err := decodeSessionLaunchOverrides(req.LaunchOverrides)
	if err != nil {
		writeError(w, 400, "INVALID_LAUNCH_OVERRIDES", err.Error())
		return
	}
	p, err := h.store.Get(req.ProfileID)
	if err != nil {
		writeError(w, 404, "PROFILE_NOT_FOUND", err.Error())
		return
	}
	launchProfile, err := profileForSessionLaunch(p, overrides)
	if err != nil {
		writeError(w, 500, "PREPARE_LAUNCH_FAILED", err.Error())
		return
	}
	sess, err := h.mgr.LaunchSession(launchProfile)
	if err != nil {
		writeSessionLaunchError(w, err)
		return
	}
	writeJSON(w, 201, map[string]any{"data": map[string]any{
		"session_id":  sess.ID,
		"instance_id": sess.InstanceID,
		"profile_id":  sess.ProfileID,
		"runtime_id":  sess.RuntimeID,
		"privacy":     sess.Privacy.Snapshot(),
	}})
}

func writeSessionLaunchError(w http.ResponseWriter, err error) {
	code := "LAUNCH_FAILED"
	if c := browserErrorCode(err); c != "" {
		code = c
	}
	writeError(w, 500, code, err.Error())
}

type browserErrorCoder interface {
	ErrorCode() string
}

func browserErrorCode(err error) string {
	var coded browserErrorCoder
	if errors.As(err, &coded) {
		return coded.ErrorCode()
	}
	return ""
}

func (h *handler) listSessions(w http.ResponseWriter, r *http.Request) {
	sessions := h.mgr.ListSessions()
	var result []map[string]any
	for _, s := range sessions {
		result = append(result, map[string]any{
			"session_id":  s.ID,
			"instance_id": s.InstanceID,
			"profile_id":  s.ProfileID,
			"runtime_id":  s.RuntimeID,
			"privacy":     s.Privacy.Snapshot(),
		})
	}
	writeJSON(w, 200, map[string]any{"data": result, "total": len(result)})
}

func (h *handler) deleteSession(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.mgr.CloseSession(id); err != nil {
		writeError(w, 404, "NOT_FOUND", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"data": "closed"})
}

// --- Browser operation endpoints (via Playwright) ---

func (h *handler) getSessionPage(r *http.Request) (playwright.Page, error) {
	return h.mgr.SessionPage(chi.URLParam(r, "id"))
}

func (h *handler) navigate(w http.ResponseWriter, r *http.Request) {
	page, err := h.getSessionPage(r)
	if err != nil {
		writeError(w, 404, "NOT_FOUND", err.Error())
		return
	}
	var req struct {
		URL       string `json:"url"`
		WaitUntil string `json:"wait_until,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "INVALID_BODY", err.Error())
		return
	}

	if req.URL == "" {
		writeError(w, 400, "INVALID_URL", "url is required")
		return
	}
	if !strings.HasPrefix(req.URL, "http://") && !strings.HasPrefix(req.URL, "https://") {
		req.URL = "https://" + req.URL
	}

	opts := playwright.PageGotoOptions{}
	if req.WaitUntil != "" {
		wu := playwright.WaitUntilState(req.WaitUntil)
		opts.WaitUntil = &wu
	}

	resp, err := page.Goto(req.URL, opts)
	if err != nil {
		writeError(w, 500, "NAVIGATE_FAILED", err.Error())
		return
	}
	status := 0
	if resp != nil {
		status = resp.Status()
	}
	writeJSON(w, 200, map[string]any{"data": map[string]any{"status": status, "url": page.URL()}})
}

func (h *handler) click(w http.ResponseWriter, r *http.Request) {
	page, err := h.getSessionPage(r)
	if err != nil {
		writeError(w, 404, "NOT_FOUND", err.Error())
		return
	}
	var req struct {
		Selector string `json:"selector"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "INVALID_BODY", err.Error())
		return
	}
	if req.Selector == "" {
		writeError(w, 400, "INVALID_SELECTOR", "selector is required")
		return
	}

	if err := humanize.Click(page, req.Selector, h.hcfg); err != nil {
		writeError(w, 500, "CLICK_FAILED", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"data": "clicked"})
}

func (h *handler) typeText(w http.ResponseWriter, r *http.Request) {
	page, err := h.getSessionPage(r)
	if err != nil {
		writeError(w, 404, "NOT_FOUND", err.Error())
		return
	}
	var req struct {
		Selector string `json:"selector"`
		Text     string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "INVALID_BODY", err.Error())
		return
	}
	if req.Selector == "" {
		writeError(w, 400, "INVALID_SELECTOR", "selector is required")
		return
	}

	if err := humanize.Type(page, req.Selector, req.Text, h.hcfg); err != nil {
		writeError(w, 500, "TYPE_FAILED", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"data": "typed"})
}

func (h *handler) evaluate(w http.ResponseWriter, r *http.Request) {
	page, err := h.getSessionPage(r)
	if err != nil {
		writeError(w, 404, "NOT_FOUND", err.Error())
		return
	}
	var req struct {
		Script string `json:"script"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "INVALID_BODY", err.Error())
		return
	}
	if req.Script == "" {
		writeError(w, 400, "INVALID_SCRIPT", "script is required")
		return
	}

	result, err := page.Evaluate(req.Script)
	if err != nil {
		writeError(w, 500, "EVAL_FAILED", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"data": result})
}

func (h *handler) screenshot(w http.ResponseWriter, r *http.Request) {
	page, err := h.getSessionPage(r)
	if err != nil {
		writeError(w, 404, "NOT_FOUND", err.Error())
		return
	}
	fullPage := r.URL.Query().Get("full_page") == "true"
	data, err := page.Screenshot(playwright.PageScreenshotOptions{
		FullPage: playwright.Bool(fullPage),
	})
	if err != nil {
		writeError(w, 500, "SCREENSHOT_FAILED", err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Write(data)
}

func (h *handler) content(w http.ResponseWriter, r *http.Request) {
	page, err := h.getSessionPage(r)
	if err != nil {
		writeError(w, 404, "NOT_FOUND", err.Error())
		return
	}
	selector := r.URL.Query().Get("selector")
	if selector != "" {
		text, err := page.Locator(selector).TextContent()
		if err != nil {
			writeError(w, 500, "CONTENT_FAILED", err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"data": text})
		return
	}
	html, err := page.Content()
	if err != nil {
		writeError(w, 500, "CONTENT_FAILED", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"data": html})
}

func (h *handler) waitFor(w http.ResponseWriter, r *http.Request) {
	page, err := h.getSessionPage(r)
	if err != nil {
		writeError(w, 404, "NOT_FOUND", err.Error())
		return
	}
	var req struct {
		Selector string  `json:"selector"`
		Timeout  float64 `json:"timeout,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "INVALID_BODY", err.Error())
		return
	}
	if req.Selector == "" {
		writeError(w, 400, "INVALID_SELECTOR", "selector is required")
		return
	}

	opts := playwright.PageWaitForSelectorOptions{}
	if req.Timeout > 0 {
		opts.Timeout = playwright.Float(req.Timeout)
	}

	_, err = page.WaitForSelector(req.Selector, opts)
	if err != nil {
		writeError(w, 408, "TIMEOUT", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"data": "found"})
}

func (h *handler) getCookies(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	sess, ok := h.mgr.GetSession(id)
	if !ok {
		writeError(w, 404, "NOT_FOUND", "session not found")
		return
	}
	cookies, err := sess.Context.Cookies()
	if err != nil {
		writeError(w, 500, "COOKIES_FAILED", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"data": cookies})
}

func (h *handler) setCookies(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	sess, ok := h.mgr.GetSession(id)
	if !ok {
		writeError(w, 404, "NOT_FOUND", "session not found")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, 400, "INVALID_BODY", err.Error())
		return
	}
	var cookies []playwright.OptionalCookie
	if err := json.Unmarshal(body, &cookies); err != nil {
		writeError(w, 400, "INVALID_BODY", err.Error())
		return
	}
	if err := sess.Context.AddCookies(cookies); err != nil {
		writeError(w, 500, "SET_COOKIES_FAILED", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"data": "cookies set"})
}

func (h *handler) playwrightEndpoint(w http.ResponseWriter, r *http.Request) {
	sessions := h.mgr.ListSessions()
	var endpoints []map[string]string
	for _, s := range sessions {
		if s.ConnectURL != "" {
			entry := map[string]string{
				"session_id": s.ID,
				"profile_id": s.ProfileID,
				"runtime_id": s.RuntimeID,
				"endpoint":   s.ConnectURL,
			}
			if h.cfg.Host != "127.0.0.1" {
				entry["proxy"] = fmt.Sprintf("ws://%s:%s/api/playwright/ws/%s", h.cfg.Host, h.cfg.Port, s.ID)
			}
			endpoints = append(endpoints, entry)
		}
	}
	writeJSON(w, 200, map[string]any{"data": endpoints})
}

// playwrightWSProxy proxies WebSocket connections to internal Playwright Bind endpoints.
// Client connects to ws://host:19280/api/playwright/ws/{session_id} with Bearer token.
// BrowseForge verifies auth then pipes to the internal dynamic-port WebSocket.
func (h *handler) playwrightWSProxy(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	session, ok := h.mgr.GetSession(sessionID)
	if !ok {
		http.Error(w, "session not found", 404)
		return
	}
	if session.ConnectURL == "" {
		http.Error(w, "no WebSocket endpoint for this session", 400)
		return
	}

	// Parse internal endpoint to get host:port and path
	internalURL := strings.Replace(session.ConnectURL, "ws://", "http://", 1)
	parsed, err := url.Parse(internalURL)
	if err != nil {
		http.Error(w, "invalid internal endpoint", 500)
		return
	}
	internalAddr := "127.0.0.1:" + parsed.Port()
	internalPath := parsed.Path

	// Hijack client connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", 500)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer clientConn.Close()

	// Dial internal Playwright WebSocket
	backendConn, err := net.Dial("tcp", internalAddr)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer backendConn.Close()

	// Forward client's upgrade request to backend (preserving all WebSocket headers)
	upgradeReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: %s\r\nSec-WebSocket-Key: %s\r\n",
		internalPath, internalAddr,
		r.Header.Get("Sec-WebSocket-Version"),
		r.Header.Get("Sec-WebSocket-Key"))
	if ext := r.Header.Get("Sec-WebSocket-Extensions"); ext != "" {
		upgradeReq += "Sec-WebSocket-Extensions: " + ext + "\r\n"
	}
	upgradeReq += "\r\n"
	backendConn.Write([]byte(upgradeReq))

	// Read backend upgrade response
	backendBuf := bufio.NewReader(backendConn)
	resp, err := http.ReadResponse(backendBuf, nil)
	if err != nil || resp.StatusCode != 101 {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// Forward ALL response headers to client (critical: includes Sec-WebSocket-Extensions)
	clientConn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n"))
	for key, vals := range resp.Header {
		for _, val := range vals {
			clientConn.Write([]byte(key + ": " + val + "\r\n"))
		}
	}
	clientConn.Write([]byte("\r\n"))

	// Bidirectional pipe (use backendBuf to not lose buffered data)
	done := make(chan struct{}, 2)
	go func() { io.Copy(backendConn, clientBuf); done <- struct{}{} }()
	go func() { io.Copy(clientConn, backendBuf); done <- struct{}{} }()
	<-done
}

// Backup/restore/shutdown are in backup.go
