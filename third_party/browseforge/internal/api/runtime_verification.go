package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"browseforge/internal/browser"

	"github.com/go-chi/chi/v5"
	"github.com/playwright-community/playwright-go"
)

// Retain a lease until exact-target cleanup finishes, even if the HTTP caller
// has timed out. Repeated clicks cannot accumulate workers behind a hung driver.
var runtimeVerificationInFlight sync.Map

type runtimeVerificationKey struct {
	manager           *browser.Manager
	session, instance string
}
type runtimeVerificationPage struct {
	page playwright.Page
	err  error
}

// This script runs inside an owned about:blank document in the real engine.
// A credential-free fixed fetch uses that browser's route. It does not navigate
// a user page, run a supplied script, accept a URL, or fall back to server HTTP.
// CORS, unsupported APIs, proxy errors and timeouts remain unobserved.
const runtimeVerificationScript = `(async () => {
  const result = { locale: navigator.language, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, ip: null };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetch('https://ipwho.is/', { credentials: 'omit', redirect: 'error', cache: 'no-store', referrerPolicy: 'no-referrer', signal: controller.signal });
    if (!response.ok || !response.body) return result;
    const reader = response.body.getReader();
    let size = 0; const chunks = [];
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 16384) { await reader.cancel(); return result; }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    const data = JSON.parse(new TextDecoder().decode(bytes));
    if (data.success !== false && typeof data.ip === 'string' && data.ip.length <= 45) result.ip = data.ip;
  } catch { /* no retry on another route or provider */ }
  finally { clearTimeout(timer); }
  return result;
})()`

type runtimeVerificationObservation struct {
	Locale   string `json:"locale"`
	Timezone string `json:"timezone"`
	IP       string `json:"ip"`
}

func (h *handler) runtimeVerification(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InstanceID  string `json:"instance_id"`
		RouteDigest string `json:"route_digest"`
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1025))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil || decoder.Decode(new(any)) != io.EOF || len(req.InstanceID) != 32 || len(req.RouteDigest) != 64 {
		writeError(w, 400, "RUNTIME_VERIFICATION_INVALID", "invalid runtime verification request")
		return
	}
	key := runtimeVerificationKey{h.mgr, chi.URLParam(r, "id"), req.InstanceID}
	if _, busy := runtimeVerificationInFlight.LoadOrStore(key, true); busy {
		writeError(w, 409, "RUNTIME_VERIFICATION_BUSY", "an observation is still finishing")
		return
	}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { runtimeVerificationInFlight.Delete(key) }) }
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	created := make(chan runtimeVerificationPage)
	go func() {
		page, err := h.mgr.NewRuntimeVerificationPage(key.session, req.InstanceID, req.RouteDigest, ctx)
		select {
		case created <- runtimeVerificationPage{page, err}: // handler now owns cleanup
		case <-ctx.Done():
			if page != nil {
				if closeErr := page.Close(); closeErr != nil && !page.IsClosed() {
					return
				}
			}
			release()
		}
	}()
	var page playwright.Page
	var err error
	select {
	case result := <-created:
		page, err = result.page, result.err
	case <-ctx.Done():
		writeError(w, 504, "RUNTIME_VERIFICATION_UNAVAILABLE", "browser observation timed out")
		return
	}
	if ctx.Err() != nil {
		if page != nil {
			go func() {
				err := page.Close()
				if err == nil || page.IsClosed() {
					release()
				}
			}()
		} else {
			release()
		}
		writeError(w, 504, "RUNTIME_VERIFICATION_UNAVAILABLE", "browser observation timed out")
		return
	}
	if errors.Is(err, browser.ErrRuntimeVerificationUnsupported) {
		release()
		writeError(w, 501, "RUNTIME_VERIFICATION_UNSUPPORTED", "background observation is unavailable for this runtime")
		return
	}
	if err != nil {
		release()
		writeError(w, 409, "RUNTIME_VERIFICATION_STALE", "selected browser launch or route changed")
		return
	}
	var closeOnce sync.Once
	cleanupDone := make(chan struct{})
	evaluationDone := make(chan struct{})
	var cleanupErr error
	closePage := func() {
		closeOnce.Do(func() {
			go func() {
				cleanupErr = page.Close()
				<-evaluationDone
				if cleanupErr == nil || page.IsClosed() {
					release()
				}
				close(cleanupDone)
			}()
		})
	}
	defer func() {
		closePage()
		select {
		case <-cleanupDone:
		case <-ctx.Done():
		}
	}()
	// Closing our owned page interrupts evaluation even when fetch/engine hangs.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			closePage()
		case <-done:
		}
	}()
	type evaluationResult struct {
		value any
		err   error
	}
	evaluated := make(chan evaluationResult, 1)
	go func() {
		var value any
		err := ctx.Err()
		if err == nil {
			value, err = page.Evaluate(runtimeVerificationScript)
		}
		evaluated <- evaluationResult{value, err}
		close(evaluationDone)
	}()
	var value any
	select {
	case result := <-evaluated:
		value, err = result.value, result.err
	case <-ctx.Done():
		writeError(w, 504, "RUNTIME_VERIFICATION_UNAVAILABLE", "browser observation timed out")
		return
	}
	if err != nil {
		writeError(w, 502, "RUNTIME_VERIFICATION_UNAVAILABLE", "browser observation unavailable")
		return
	}
	// Recheck exact ownership after evaluation; a reused ID is never accepted.
	identity, err := h.mgr.LinkIdentity(chi.URLParam(r, "id"))
	if err != nil || identity.InstanceID != req.InstanceID || identity.RouteDigest != req.RouteDigest {
		writeError(w, 409, "RUNTIME_VERIFICATION_STALE", "selected browser launch or route changed")
		return
	}
	encoded, err := json.Marshal(value)
	var result runtimeVerificationObservation
	if err != nil || len(encoded) > 1024 || json.Unmarshal(encoded, &result) != nil {
		writeError(w, 502, "RUNTIME_VERIFICATION_UNAVAILABLE", "browser observation unavailable")
		return
	}
	for _, field := range []*string{&result.Locale, &result.Timezone, &result.IP} {
		if len(*field) > 100 || strings.ContainsAny(*field, "\x00\r\n") {
			*field = ""
		}
	}
	closePage()
	select {
	case <-cleanupDone:
		if cleanupErr != nil {
			writeError(w, 502, "RUNTIME_VERIFICATION_UNAVAILABLE", "observation cleanup could not be confirmed")
			return
		}
	case <-ctx.Done():
		writeError(w, 504, "RUNTIME_VERIFICATION_UNAVAILABLE", "observation cleanup timed out")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"data": result})
}
