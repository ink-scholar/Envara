package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/mxschmitt/playwright-go"
)

func (h *handler) sessionLinkIdentity(w http.ResponseWriter, r *http.Request) {
	identity, err := h.mgr.LinkIdentity(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, 409, "LINK_BROWSER_CHANGED", "selected browser launch is unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": identity})
}

func (h *handler) openSessionLink(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL         string `json:"url"`
		InstanceID  string `json:"instance_id"`
		RouteDigest string `json:"route_digest"`
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, 8193))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeError(w, 400, "INVALID_BODY", "invalid link request")
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		writeError(w, 400, "INVALID_BODY", "request must contain one JSON object")
		return
	}
	target, err := url.Parse(req.URL)
	if err != nil || len(req.URL) > 4096 || strings.ContainsAny(req.URL, "\x00\r\n") || target == nil || target.Host == "" || target.User != nil || (target.Scheme != "http" && target.Scheme != "https") {
		writeError(w, 400, "LINK_INVALID", "use an HTTP or HTTPS link without credentials")
		return
	}
	page, err := h.mgr.NewSessionLinkPage(chi.URLParam(r, "id"), req.InstanceID, req.RouteDigest)
	if err != nil {
		writeError(w, 409, "LINK_BROWSER_CHANGED", "selected browser launch or route has changed")
		return
	}
	// No registry/global lock spans navigation; Stop remains available. The page
	// belongs to the captured context, not a later lookup of a reusable ID.
	if _, err = page.Goto(req.URL, playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateDomcontentloaded, Timeout: playwright.Float(15000)}); err != nil {
		_ = page.Close()
		writeError(w, 502, "LINK_BROWSER_UNAVAILABLE", "link did not finish loading in the selected browser")
		return
	}
	_ = page.BringToFront()
	writeJSON(w, 200, map[string]any{"data": map[string]any{"opened": "tab"}})
}
