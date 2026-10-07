package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"browseforge/internal/groups"
	"browseforge/internal/profile"
	"browseforge/internal/runtime"

	"github.com/go-chi/chi/v5"
)

type groupRequest struct {
	ProxyMode string               `json:"proxy_mode"`
	Proxy     *profile.ProxyConfig `json:"proxy"`
}

func (h *handler) listGroups(w http.ResponseWriter, r *http.Request) {
	if h.groupStore == nil {
		writeError(w, http.StatusInternalServerError, "GROUPS_UNAVAILABLE", "group store is not initialized")
		return
	}
	items := h.groupStore.List()
	data := make([]map[string]any, 0, len(items))
	for _, g := range items {
		data = append(data, h.groupResponse(g))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": data, "total": len(data)})
}

func (h *handler) getGroup(w http.ResponseWriter, r *http.Request) {
	if h.groupStore == nil {
		writeError(w, http.StatusInternalServerError, "GROUPS_UNAVAILABLE", "group store is not initialized")
		return
	}
	name := chi.URLParam(r, "name")
	g, ok := h.groupStore.Get(name)
	if !ok {
		writeError(w, http.StatusNotFound, "GROUP_NOT_FOUND", "group not found: "+name)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": h.groupResponse(g)})
}

func (h *handler) upsertGroup(w http.ResponseWriter, r *http.Request) {
	if h.groupStore == nil {
		writeError(w, http.StatusInternalServerError, "GROUPS_UNAVAILABLE", "group store is not initialized")
		return
	}
	var req groupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_BODY", err.Error())
		return
	}
	if req.Proxy == nil {
		writeError(w, http.StatusBadRequest, "MISSING_PROXY", "proxy is required; use DELETE /api/groups/{name}/proxy to clear a group proxy policy")
		return
	}
	if err := h.validateGroupProxyRegion(chi.URLParam(r, "name"), req.Proxy); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_PROXY_REGION", err.Error())
		return
	}
	g, err := h.groupStore.Upsert(chi.URLParam(r, "name"), req.Proxy, req.ProxyMode)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_GROUP", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": h.groupResponse(g)})
}

func (h *handler) validateGroupProxyRegion(groupName string, proxy *profile.ProxyConfig) error {
	if proxy == nil || h.store == nil || h.mgr == nil {
		return nil
	}
	for _, p := range h.store.List(groupName, "") {
		draft := *p
		desc, err := h.mgr.RuntimeRegistry().ApplyProfileDefaults(&draft)
		if err == nil && desc.ID == runtime.BrowseForgeChromium {
			return validateBrowseForgeProxyRegion(desc.ID, proxy)
		}
	}
	return nil
}

func (h *handler) clearGroupProxy(w http.ResponseWriter, r *http.Request) {
	if h.groupStore == nil {
		writeError(w, http.StatusInternalServerError, "GROUPS_UNAVAILABLE", "group store is not initialized")
		return
	}
	g, err := h.groupStore.ClearProxy(chi.URLParam(r, "name"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_GROUP", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": h.groupResponse(g)})
}

func (h *handler) deleteGroup(w http.ResponseWriter, r *http.Request) {
	if h.groupStore == nil {
		writeError(w, http.StatusInternalServerError, "GROUPS_UNAVAILABLE", "group store is not initialized")
		return
	}
	name := strings.TrimSpace(chi.URLParam(r, "name"))
	if name == "" {
		writeError(w, http.StatusBadRequest, "INVALID_GROUP", "group name is required")
		return
	}
	active := h.activeSessionsForGroup(name)
	if active > 0 {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": map[string]any{
				"code":             "GROUP_HAS_ACTIVE_SESSIONS",
				"message":          "close active browsers in this group before deleting it",
				"active_sessions":  active,
				"restart_required": true,
			},
		})
		return
	}

	ungrouped := 0
	if h.store != nil {
		for _, p := range h.store.List("", "") {
			if strings.TrimSpace(p.Group) != name {
				continue
			}
			if _, err := h.store.Update(p.ID, map[string]any{"group": ""}); err != nil {
				writeError(w, http.StatusInternalServerError, "UNGROUP_FAILED", err.Error())
				return
			}
			ungrouped++
		}
	}
	g, err := h.groupStore.ClearProxy(name)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_GROUP", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
		"name":               g.Name,
		"profiles_ungrouped": ungrouped,
		"proxy_cleared":      g.Proxy == nil,
		"active_sessions":    0,
		"restart_required":   false,
	}})
}

func (h *handler) effectiveProxyForProfile(p *profile.Profile) groups.EffectiveProxy {
	if h.groupStore != nil {
		return h.groupStore.EffectiveProxy(p)
	}
	if p != nil && p.Proxy != nil && p.Proxy.Host != "" {
		return groups.EffectiveProxy{Proxy: p.Proxy, Source: "profile", Mode: groups.ProxyModeDefault}
	}
	return groups.EffectiveProxy{Source: "none", Mode: groups.ProxyModeDefault}
}

func (h *handler) groupResponse(g *groups.Group) map[string]any {
	active := h.activeSessionsForGroup(g.Name)
	return map[string]any{
		"name":             g.Name,
		"proxy_mode":       g.ProxyMode,
		"proxy":            g.Proxy,
		"created_at":       g.CreatedAt,
		"updated_at":       g.UpdatedAt,
		"active_sessions":  active,
		"restart_required": active > 0,
	}
}

func (h *handler) activeSessionsForGroup(groupName string) int {
	groupName = strings.TrimSpace(groupName)
	if h.mgr == nil || h.store == nil || groupName == "" {
		return 0
	}
	count := 0
	for _, sess := range h.mgr.ListSessions() {
		p, err := h.store.Get(sess.ProfileID)
		if err == nil && strings.TrimSpace(p.Group) == groupName {
			count++
		}
	}
	return count
}
