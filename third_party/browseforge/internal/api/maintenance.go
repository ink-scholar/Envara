package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"browseforge/internal/browser"
)

func maintenanceBody(w http.ResponseWriter, r *http.Request, target any) bool {
	return maintenanceBodyWithCode(w, r, target, "CACHE_MAINTENANCE_INVALID")
}

func maintenanceBodyWithCode(w http.ResponseWriter, r *http.Request, target any, invalidCode string) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
		writeError(w, http.StatusBadRequest, invalidCode, "invalid maintenance request")
		return false
	}
	return true
}

func writeMaintenanceError(w http.ResponseWriter, err error) {
	code, status := browser.ErrorCode(err), http.StatusConflict
	switch {
	case code == "CACHE_MAINTENANCE_INVALID", code == "UPDATE_MAINTENANCE_INVALID":
		status = http.StatusBadRequest
	case errors.Is(err, browser.ErrManagerClosing):
		code, status = "APP_CLOSING", http.StatusServiceUnavailable
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		code, status = "CACHE_MAINTENANCE_CANCELLED", http.StatusRequestTimeout
	case code == "":
		code, status = "CACHE_MAINTENANCE_UNAVAILABLE", http.StatusServiceUnavailable
	}
	writeError(w, status, code, "profile maintenance request was refused")
}

func (h *handler) acquireProfileMaintenance(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProfileIDs []string `json:"profile_ids"`
	}
	if !maintenanceBody(w, r, &req) {
		return
	}
	if len(req.ProfileIDs) < 1 || len(req.ProfileIDs) > 500 {
		writeError(w, http.StatusBadRequest, "CACHE_MAINTENANCE_INVALID", "invalid profile maintenance request")
		return
	}
	for _, id := range req.ProfileIDs {
		if _, err := h.store.Get(id); err != nil {
			writeError(w, http.StatusNotFound, "PROFILE_NOT_FOUND", "selected profile is unavailable")
			return
		}
	}
	token, err := h.mgr.AcquireProfileMaintenance(r.Context(), req.ProfileIDs)
	if err != nil {
		writeMaintenanceError(w, err)
		return
	}
	// A delete may have completed while admission waited for its profile lock.
	// The installed Store guard now keeps this existence check stable until release.
	for _, id := range req.ProfileIDs {
		if _, err := h.store.Get(id); err != nil {
			_ = h.mgr.ReleaseProfileMaintenance(token)
			writeError(w, http.StatusNotFound, "PROFILE_NOT_FOUND", "selected profile is unavailable")
			return
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]string{"token": token}})
}

func (h *handler) releaseProfileMaintenance(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if !maintenanceBody(w, r, &req) {
		return
	}
	if err := h.mgr.ReleaseProfileMaintenance(req.Token); err != nil {
		writeMaintenanceError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]bool{"released": true}})
}

// Whole-request accounting covers handlers that continue after their last
// session closes. Maintenance control and explicit shutdown retain their own
// authorization paths and must not count themselves as active user operations.
func (h *handler) updateAdmissionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions || h.mgr == nil {
			next.ServeHTTP(w, r)
			return
		}
		switch r.URL.Path {
		case "/api/maintenance/acquire", "/api/maintenance/release", "/api/maintenance/update-acquire", "/api/maintenance/update-release", "/api/shutdown":
			next.ServeHTTP(w, r)
			return
		}
		release, err := h.mgr.ReserveUpdateOperation()
		if err != nil {
			writeMaintenanceError(w, err)
			return
		}
		defer release()
		next.ServeHTTP(w, r)
	})
}

func (h *handler) acquireUpdateMaintenance(w http.ResponseWriter, r *http.Request) {
	var req *struct{}
	if !maintenanceBodyWithCode(w, r, &req, "UPDATE_MAINTENANCE_INVALID") {
		return
	}
	if req == nil {
		writeError(w, http.StatusBadRequest, "UPDATE_MAINTENANCE_INVALID", "update admission requires an empty object")
		return
	}
	token, err := h.mgr.AcquireUpdateMaintenance(r.Context())
	if err != nil {
		writeMaintenanceError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]string{"token": token}})
}

func (h *handler) releaseUpdateMaintenance(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if !maintenanceBody(w, r, &req) {
		return
	}
	if err := h.mgr.ReleaseUpdateMaintenance(req.Token); err != nil {
		writeMaintenanceError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]bool{"released": true}})
}
