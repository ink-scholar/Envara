package api

// This endpoint deliberately does not use BrowserContext.ClearCookies with a
// filter: the pinned driver clears the entire context then recreates survivors.
// Chromium's targeted CDP operation preserves other sites and partition keys.
import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"browseforge/internal/browser"
	"github.com/go-chi/chi/v5"
	"github.com/playwright-community/playwright-go"
)

type siteCookie struct {
	Name           string  `json:"name"`
	Domain         string  `json:"domain"`
	Path           string  `json:"path"`
	Expires        float64 `json:"expires"`
	HTTPOnly       bool    `json:"httpOnly"`
	Secure         bool    `json:"secure"`
	SameSite       string  `json:"sameSite"`
	PartitionKey   string  `json:"partitionKey,omitempty"`
	PartitionState string  `json:"partitionState"`
}
type siteCookieRequest struct {
	InstanceID string `json:"instance_id"`
	Domain     string `json:"domain,omitempty"`
}
type rawSiteCookie struct {
	Name         string  `json:"name"`
	Domain       string  `json:"domain"`
	Path         string  `json:"path"`
	Expires      float64 `json:"expires"`
	HTTPOnly     bool    `json:"httpOnly"`
	Secure       bool    `json:"secure"`
	SameSite     string  `json:"sameSite"`
	PartitionKey *struct {
		TopLevelSite         string `json:"topLevelSite"`
		HasCrossSiteAncestor *bool  `json:"hasCrossSiteAncestor"`
	} `json:"partitionKey"`
	PartitionKeyOpaque bool `json:"partitionKeyOpaque"`
}

func cookieText(s string, max int) bool { return len(s) <= max && !strings.ContainsAny(s, "\x00\r\n") }
func cookieDomain(s string) bool {
	return s != "" && cookieText(s, 253) && !strings.ContainsAny(s, "/\\ @?#")
}

func (h *handler) siteCookieSession(w http.ResponseWriter, r *http.Request, clear bool) (*browser.Session, siteCookieRequest) {
	var req siteCookieRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, 2048))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil || decoder.Decode(new(any)) != io.EOF || len(req.InstanceID) != 32 || (clear && !cookieDomain(req.Domain)) || (!clear && req.Domain != "") {
		writeError(w, 400, "SITE_DATA_INVALID", "invalid cookie request")
		return nil, req
	}
	sess, ok := h.mgr.GetSession(chi.URLParam(r, "id"))
	if !ok || sess.Context == nil || sess.InstanceID != req.InstanceID {
		writeError(w, 409, "SITE_DATA_STALE", "selected browser launch changed")
		return nil, req
	}
	w.Header().Set("Cache-Control", "no-store")
	return sess, req
}

func chromiumCookieSession(sess *browser.Session) (playwright.CDPSession, []rawSiteCookie, error) {
	if sess.RuntimeID != "cloakbrowser" && sess.RuntimeID != "browseforge-chromium" {
		return nil, nil, fmt.Errorf("unsupported runtime")
	}
	var page playwright.Page
	for _, candidate := range sess.Context.Pages() {
		if !candidate.IsClosed() {
			page = candidate
			break
		}
	}
	if page == nil {
		return nil, nil, fmt.Errorf("no open page")
	}
	cdp, err := sess.Context.NewCDPSession(page)
	if err != nil {
		return nil, nil, err
	}
	result, err := cdp.Send("Network.getAllCookies", nil)
	if err != nil {
		_ = cdp.Detach()
		return nil, nil, err
	}
	data, err := json.Marshal(result)
	var envelope struct {
		Cookies []rawSiteCookie `json:"cookies"`
	}
	if err == nil {
		err = json.Unmarshal(data, &envelope)
	}
	if err != nil || envelope.Cookies == nil || len(envelope.Cookies) > 10000 {
		_ = cdp.Detach()
		return nil, nil, fmt.Errorf("invalid cookie inventory")
	}
	for _, c := range envelope.Cookies {
		if !cookieText(c.Name, 4096) || !cookieDomain(c.Domain) || !cookieText(c.Path, 4096) {
			_ = cdp.Detach()
			return nil, nil, fmt.Errorf("invalid cookie metadata")
		}
	}
	return cdp, envelope.Cookies, nil
}

func (h *handler) listSiteCookies(w http.ResponseWriter, r *http.Request) {
	sess, _ := h.siteCookieSession(w, r, false)
	if sess == nil {
		return
	}
	rows := []siteCookie{}
	supported := sess.RuntimeID == "cloakbrowser" || sess.RuntimeID == "browseforge-chromium"
	if supported {
		cdp, cookies, err := chromiumCookieSession(sess)
		if err != nil {
			writeError(w, 503, "SITE_DATA_UNAVAILABLE", "cookie inspection unavailable")
			return
		}
		defer cdp.Detach()
		for _, c := range cookies {
			row := siteCookie{Name: c.Name, Domain: c.Domain, Path: c.Path, Expires: c.Expires, HTTPOnly: c.HTTPOnly, Secure: c.Secure, SameSite: c.SameSite, PartitionState: "unpartitioned"}
			if c.PartitionKey != nil {
				row.PartitionKey = c.PartitionKey.TopLevelSite
				row.PartitionState = "partitioned"
			}
			if c.PartitionKeyOpaque || c.PartitionKey != nil && c.PartitionKey.HasCrossSiteAncestor == nil {
				row.PartitionState = "opaque"
			}
			rows = append(rows, row)
		}
	} else if sess.RuntimeID == "camoufox" {
		cookies, err := sess.Context.Cookies()
		if err != nil || len(cookies) > 10000 {
			writeError(w, 503, "SITE_DATA_UNAVAILABLE", "cookie inspection unavailable")
			return
		}
		for _, c := range cookies {
			if !cookieText(c.Name, 4096) || !cookieDomain(c.Domain) || !cookieText(c.Path, 4096) {
				writeError(w, 503, "SITE_DATA_UNAVAILABLE", "cookie inspection unavailable")
				return
			}
			sameSite := ""
			if c.SameSite != nil {
				sameSite = string(*c.SameSite)
			}
			rows = append(rows, siteCookie{Name: c.Name, Domain: c.Domain, Path: c.Path, Expires: c.Expires, HTTPOnly: c.HttpOnly, Secure: c.Secure, SameSite: sameSite, PartitionState: "unavailable"})
		}
	} else {
		writeError(w, 501, "SITE_DATA_UNSUPPORTED", "cookie inspection unsupported")
		return
	}
	writeJSON(w, 200, map[string]any{"data": map[string]any{"instanceId": sess.InstanceID, "runtime": sess.RuntimeID, "canClear": supported, "cookies": rows, "checkedAt": time.Now().UTC().Format(time.RFC3339)}})
}

func (h *handler) clearSiteCookies(w http.ResponseWriter, r *http.Request) {
	sess, req := h.siteCookieSession(w, r, true)
	if sess == nil {
		return
	}
	if sess.RuntimeID != "cloakbrowser" && sess.RuntimeID != "browseforge-chromium" {
		writeError(w, 501, "SITE_DATA_UNSUPPORTED", "targeted cookie removal unsupported")
		return
	}
	cdp, cookies, err := chromiumCookieSession(sess)
	if err != nil {
		writeError(w, 503, "SITE_DATA_UNAVAILABLE", "cookie inspection unavailable")
		return
	}
	defer cdp.Detach()
	selected := []rawSiteCookie{}
	for _, c := range cookies {
		if c.Domain != req.Domain {
			continue
		}
		if c.PartitionKeyOpaque || c.PartitionKey != nil && (c.PartitionKey.TopLevelSite == "" || c.PartitionKey.HasCrossSiteAncestor == nil) {
			writeError(w, 409, "SITE_DATA_PARTITION_UNSUPPORTED", "opaque partition cannot be removed safely")
			return
		}
		selected = append(selected, c)
	}
	for _, c := range selected {
		args := map[string]any{"name": c.Name, "domain": c.Domain, "path": c.Path}
		if c.PartitionKey != nil {
			args["partitionKey"] = map[string]any{"topLevelSite": c.PartitionKey.TopLevelSite, "hasCrossSiteAncestor": *c.PartitionKey.HasCrossSiteAncestor}
		}
		if _, err := cdp.Send("Network.deleteCookies", args); err != nil {
			writeError(w, 503, "SITE_DATA_CLEAR_INCOMPLETE", "cookie removal incomplete; refresh inventory")
			return
		}
	}
	// Sites can recreate cookies while open; report the operation, not a claim
	// that a still-running website can no longer store data.
	writeJSON(w, 200, map[string]any{"data": map[string]any{"removed": len(selected), "domain": req.Domain, "instanceId": sess.InstanceID}})
}
