package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"browseforge/internal/browser"
	"browseforge/internal/config"
	"browseforge/internal/fingerprint"
	"browseforge/internal/groups"
	"browseforge/internal/humanize"
	"browseforge/internal/profile"
	bfruntime "browseforge/internal/runtime"
)

func NewRouter(cfg *config.Config, store *profile.Store, mgr *browser.Manager, fpPool *fingerprint.Pool, groupStores ...*groups.Store) (*chi.Mux, error) {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(corsLocal)

	token, err := loadOrCreateToken(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	cfg.APIToken = token

	hcfg := humanize.DefaultConfig()
	if cfg.Humanize != nil {
		hcfg = humanize.ConfigFromRaw(cfg.Humanize.Enabled, cfg.Humanize.MouseSpeed, cfg.Humanize.TypingCPM, cfg.Humanize.TypoRate, cfg.Humanize.ScrollStyle)
	}

	var groupStore *groups.Store
	if len(groupStores) > 0 {
		groupStore = groupStores[0]
	}
	h := &handler{cfg: cfg, store: store, groupStore: groupStore, mgr: mgr, token: token, fpPool: fpPool, hcfg: hcfg}

	r.Get("/api/status", h.status)
	r.Get("/api/health", h.health)
	r.Get("/", h.dashboard)

	r.Group(func(r chi.Router) {
		r.Use(h.authMiddleware)

		r.Post("/api/profiles", h.createProfile)
		r.Get("/api/runtimes", h.listRuntimes)
		r.Get("/api/profiles", h.listProfiles)
		r.Get("/api/profiles/{id}", h.getProfile)
		r.Put("/api/profiles/{id}", h.updateProfile)
		r.Delete("/api/profiles/{id}", h.deleteProfile)
		r.Post("/api/profiles/{id}/duplicate", h.duplicateProfile)
		r.Post("/api/profiles/{id}/export", h.exportProfile)
		r.Post("/api/profiles/import", h.importProfile)
		r.Get("/api/profiles/{id}/artifacts/*", h.artifact)
		r.Get("/api/groups", h.listGroups)
		r.Get("/api/groups/{name}", h.getGroup)
		r.Put("/api/groups/{name}", h.upsertGroup)
		r.Delete("/api/groups/{name}", h.deleteGroup)
		r.Delete("/api/groups/{name}/proxy", h.clearGroupProxy)

		r.Post("/api/sessions", h.createSession)
		r.Get("/api/sessions", h.listSessions)
		r.Delete("/api/sessions/{id}", h.deleteSession)
		r.Post("/api/sessions/{id}/focus", h.focusSession)

		r.Post("/api/sessions/{id}/navigate", h.navigate)
		r.Post("/api/sessions/{id}/click", h.click)
		r.Post("/api/sessions/{id}/type", h.typeText)
		r.Post("/api/sessions/{id}/eval", h.evaluate)
		r.Get("/api/sessions/{id}/screenshot", h.screenshot)
		r.Get("/api/sessions/{id}/content", h.content)
		r.Post("/api/sessions/{id}/wait", h.waitFor)
		r.Get("/api/sessions/{id}/cookies", h.getCookies)
		r.Post("/api/sessions/{id}/cookies", h.setCookies)

		r.Get("/api/playwright/endpoint", h.playwrightEndpoint)
		r.Get("/api/playwright/ws/{id}", h.playwrightWSProxy)
		r.Post("/api/backup", h.backup)
		r.Post("/api/restore", h.restore)
		r.Post("/api/shutdown", h.shutdown)
	})

	return r, nil
}

type handler struct {
	cfg        *config.Config
	store      *profile.Store
	groupStore *groups.Store
	mgr        *browser.Manager
	fpPool     *fingerprint.Pool
	hcfg       humanize.Config
	token      string
}

func (h *handler) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !validBearerToken(r.Header.Get("Authorization"), h.token) {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid or missing token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *handler) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version": h.cfg.Version,
		"status":  "ok",
	})
}

func (h *handler) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (h *handler) listRuntimes(w http.ResponseWriter, r *http.Request) {
	reg := h.mgr.RuntimeRegistry()
	writeJSON(w, http.StatusOK, map[string]any{"data": reg.List(), "default_runtime_id": reg.DefaultID()})
}

func requireEnabledRuntime(desc bfruntime.Descriptor) error {
	if !desc.Enabled {
		return fmt.Errorf("runtime %q is disabled", desc.ID)
	}
	return nil
}

func (h *handler) requireProfileRuntime(desc bfruntime.Descriptor) error {
	if h.cfg != nil && h.cfg.AllowEmptyRuntime {
		if !desc.PlatformSupported {
			return fmt.Errorf("runtime %q is unsupported on this platform: %s", desc.ID, desc.UnsupportedReason)
		}
		return nil
	}
	return requireEnabledRuntime(desc)
}

func (h *handler) focusSession(w http.ResponseWriter, r *http.Request) {
	if err := h.mgr.FocusSession(chi.URLParam(r, "id")); err != nil {
		if errors.Is(err, browser.ErrSessionNotFound) {
			writeError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
		} else {
			writeError(w, http.StatusInternalServerError, "FOCUS_FAILED", err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": "focused"})
}

func (h *handler) createProfile(w http.ResponseWriter, r *http.Request) {
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_BODY", err.Error())
		return
	}
	if _, ok := raw["engine"]; ok {
		writeError(w, http.StatusBadRequest, "DEPRECATED_FIELD", "engine was removed in v2; use runtime_id")
		return
	}
	data, err := json.Marshal(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_BODY", err.Error())
		return
	}
	var p profile.Profile
	if err := json.Unmarshal(data, &p); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_BODY", err.Error())
		return
	}
	if p.Name == "" {
		writeError(w, http.StatusBadRequest, "MISSING_NAME", "name is required")
		return
	}
	desc, err := h.mgr.RuntimeRegistry().ApplyProfileDefaults(&p)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_RUNTIME", err.Error())
		return
	}
	if err := h.requireProfileRuntime(desc); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_RUNTIME", err.Error())
		return
	}
	if err := h.validateBrowseForgeProfileProxy(desc.ID, &p); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_PROXY_REGION", err.Error())
		return
	}
	if err := h.prepareProfileIdentity(&p, desc); err != nil {
		writeError(w, http.StatusInternalServerError, "PREPARE_PROFILE_FAILED", err.Error())
		return
	}
	if err := h.store.Create(&p); err != nil {
		writeError(w, http.StatusInternalServerError, "CREATE_FAILED", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"data": p})
}

func (h *handler) prepareProfileIdentity(p *profile.Profile, desc bfruntime.Descriptor) error {
	if p.Fingerprint == nil && h.fpPool != nil && desc.FingerprintPoolKey != "" {
		fp, err := h.fpPool.Pick(desc.FingerprintPoolKey, "windows")
		if err != nil {
			fp, err = h.fpPool.Pick(desc.FingerprintPoolKey, "macos")
		}
		if err == nil {
			effectiveProxy := h.effectiveProxyForProfile(p)
			if effectiveProxy.Proxy != nil {
				proxy := effectiveProxy.Proxy
				tz, locale := fingerprint.DetectProxyGeoResult(proxy.Type, proxy.Host, proxy.Port, proxy.Username, proxy.Password)
				fp["timezone"] = tz
				fp["navigator.language"] = locale
			} else {
				fingerprint.AdjustToLocal(fp)
			}
			p.Fingerprint = fp
		}
	}
	if desc.Capabilities.SupportsSeedFingerprint && p.FingerprintSeed == 0 {
		b := make([]byte, 4)
		if _, err := rand.Read(b); err != nil {
			return fmt.Errorf("generate fingerprint seed: %w", err)
		}
		p.FingerprintSeed = uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	}
	return nil
}

func (h *handler) listProfiles(w http.ResponseWriter, r *http.Request) {
	group := r.URL.Query().Get("group")
	tag := r.URL.Query().Get("tag")
	profiles := h.store.List(group, tag)
	writeJSON(w, http.StatusOK, map[string]any{"data": profiles, "total": len(profiles)})
}

func (h *handler) getProfile(w http.ResponseWriter, r *http.Request) {
	p, err := h.store.Get(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": p})
}

func (h *handler) updateProfile(w http.ResponseWriter, r *http.Request) {
	var updates map[string]any
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_BODY", err.Error())
		return
	}
	if _, ok := updates["engine"]; ok {
		writeError(w, http.StatusBadRequest, "DEPRECATED_FIELD", "engine was removed in v2; use runtime_id")
		return
	}
	if _, runtimeChanged := updates["runtime_id"]; runtimeChanged || hasProxyUpdate(updates) || hasGroupUpdate(updates) {
		current, err := h.store.Get(chi.URLParam(r, "id"))
		if err != nil {
			writeError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
			return
		}
		draft := *current
		if runtimeChanged {
			v, ok := updates["runtime_id"].(string)
			if !ok {
				writeError(w, http.StatusBadRequest, "INVALID_RUNTIME", "runtime_id must be a string")
				return
			}
			draft.RuntimeID = v
		}
		if _, groupChanged := updates["group"]; groupChanged {
			v, ok := updates["group"].(string)
			if !ok {
				writeError(w, http.StatusBadRequest, "INVALID_BODY", "group must be a string")
				return
			}
			draft.Group = v
		}
		if _, proxyChanged := updates["proxy"]; proxyChanged {
			proxy, err := decodeProxyUpdate(updates["proxy"])
			if err != nil {
				writeError(w, http.StatusBadRequest, "INVALID_PROXY", err.Error())
				return
			}
			draft.Proxy = proxy
		}
		desc, err := h.mgr.RuntimeRegistry().ApplyProfileDefaults(&draft)
		if err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_RUNTIME", err.Error())
			return
		}
		if runtimeChanged {
			if err := h.requireProfileRuntime(desc); err != nil {
				writeError(w, http.StatusBadRequest, "INVALID_RUNTIME", err.Error())
				return
			}
		}
		if err := h.validateBrowseForgeProfileProxy(desc.ID, &draft); err != nil {
			writeError(w, http.StatusBadRequest, "INVALID_PROXY_REGION", err.Error())
			return
		}
		updates["runtime_id"] = draft.RuntimeID
		if _, proxyChanged := updates["proxy"]; proxyChanged {
			updates["proxy"] = draft.Proxy
		}
	}
	p, err := h.store.Update(chi.URLParam(r, "id"), updates)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": p})
}

func (h *handler) deleteProfile(w http.ResponseWriter, r *http.Request) {
	if err := h.store.Delete(chi.URLParam(r, "id")); err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": "deleted"})
}

func (h *handler) duplicateProfile(w http.ResponseWriter, r *http.Request) {
	src, err := h.store.Get(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
		return
	}
	desc, err := h.mgr.RuntimeRegistry().ApplyProfileDefaults(src)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_RUNTIME", err.Error())
		return
	}
	if err := h.requireProfileRuntime(desc); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_RUNTIME", err.Error())
		return
	}
	p, err := h.store.Duplicate(src.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"data": p})
}

// Session and browser operations are in sessions.go

func hasProxyUpdate(updates map[string]any) bool {
	_, ok := updates["proxy"]
	return ok
}
func hasGroupUpdate(updates map[string]any) bool {
	_, ok := updates["group"]
	return ok
}

func decodeProxyUpdate(raw any) (*profile.ProxyConfig, error) {
	if raw == nil {
		return nil, nil
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var proxy profile.ProxyConfig
	if err := json.Unmarshal(data, &proxy); err != nil {
		return nil, err
	}
	return &proxy, nil
}

func validateBrowseForgeProxyRegion(runtimeID bfruntime.ID, proxy *profile.ProxyConfig) error {
	if runtimeID != bfruntime.BrowseForgeChromium || proxy == nil {
		return nil
	}
	normalized, err := browser.NormalizeBrowseForgeProxyRegion(proxy.Region)
	if err != nil {
		return err
	}
	if normalized == "" {
		return fmt.Errorf("browseforge-chromium proxy_region is required when a proxy is configured; use a redacted geographic label such as %s", browser.BrowseForgeProxyRegionExamples)
	}
	proxy.Region = normalized
	return nil
}

func (h *handler) validateBrowseForgeProfileProxy(runtimeID bfruntime.ID, p *profile.Profile) error {
	if runtimeID != bfruntime.BrowseForgeChromium || p == nil {
		return nil
	}
	if p.Proxy != nil {
		if err := validateBrowseForgeProxyRegion(runtimeID, p.Proxy); err != nil {
			return err
		}
	}
	effective := h.effectiveProxyForProfile(p)
	if effective.Proxy == nil || effective.Source == "profile" {
		return nil
	}
	proxy := *effective.Proxy
	return validateBrowseForgeProxyRegion(runtimeID, &proxy)
}

// --- Helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

func validBearerToken(auth, token string) bool {
	if token == "" || !strings.HasPrefix(auth, "Bearer ") {
		return false
	}
	got := auth[len("Bearer "):]
	return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

func corsLocal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "moz-extension://*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func loadOrCreateToken(dataDir string) (string, error) {
	// Environment variable takes priority
	if envToken := os.Getenv("BROWSEFORGE_TOKEN"); envToken != "" {
		return envToken, nil
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return "", fmt.Errorf("create token directory: %w", err)
	}
	path := dataDir + "/.api-token"
	if data, err := os.ReadFile(path); err == nil {
		token := strings.TrimSpace(string(data))
		if token == "" {
			return "", fmt.Errorf("API token file is empty: %s", path)
		}
		return token, nil
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("read API token: %w", err)
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate API token: %w", err)
	}
	token := hex.EncodeToString(b)
	if err := os.WriteFile(path, []byte(token), 0600); err != nil {
		return "", fmt.Errorf("write API token: %w", err)
	}
	slog.Info("generated API token", "path", path)
	return token, nil
}
