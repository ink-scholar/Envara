package api

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"browseforge/internal/profile"

	"github.com/go-chi/chi/v5"
)

func (h *handler) exportProfile(w http.ResponseWriter, r *http.Request) {
	p, err := h.store.Get(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, 404, "NOT_FOUND", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename="+p.ID+".zip")

	zw := zip.NewWriter(w)
	defer zw.Close()

	// Add profile.json
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return
	}
	f, err := zw.Create("profile.json")
	if err != nil {
		return
	}
	if _, err := f.Write(data); err != nil {
		return
	}

	// Add cookies backup if exists
	cookiePath := filepath.Join(p.ProfileDir, "cookies-backup.json")
	if raw, err := os.ReadFile(cookiePath); err == nil {
		f, err := zw.Create("cookies-backup.json")
		if err != nil {
			return
		}
		if _, err := f.Write(raw); err != nil {
			return
		}
	}
}

func (h *handler) importProfile(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		writeError(w, 400, "INVALID_FORM", err.Error())
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, 400, "NO_FILE", "file field required")
		return
	}
	defer file.Close()

	// Read zip into memory
	body, err := io.ReadAll(file)
	if err != nil {
		writeError(w, 400, "READ_FAILED", err.Error())
		return
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		writeError(w, 400, "INVALID_ZIP", err.Error())
		return
	}

	// Find profile.json
	var profileData []byte
	for _, f := range zr.File {
		if f.Name == "profile.json" {
			rc, err := f.Open()
			if err != nil {
				writeError(w, 400, "READ_FAILED", err.Error())
				return
			}
			profileData, err = io.ReadAll(rc)
			rc.Close()
			if err != nil {
				writeError(w, 400, "READ_FAILED", err.Error())
				return
			}
		}
	}
	if profileData == nil {
		writeError(w, 400, "NO_PROFILE", "profile.json not found in zip")
		return
	}

	var p profile.Profile
	if err := json.Unmarshal(profileData, &p); err != nil {
		writeError(w, 400, "INVALID_PROFILE", err.Error())
		return
	}
	p.ID = "" // generate new ID
	p.ContainerID = ""
	desc, err := h.mgr.RuntimeRegistry().ApplyProfileDefaults(&p)
	if err != nil {
		writeError(w, 400, "INVALID_RUNTIME", err.Error())
		return
	}
	if err := h.requireProfileRuntime(desc); err != nil {
		writeError(w, 400, "INVALID_RUNTIME", err.Error())
		return
	}

	if err := h.store.Create(&p); err != nil {
		writeError(w, 500, "IMPORT_FAILED", err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"data": p})
}

func (h *handler) backup(w http.ResponseWriter, r *http.Request) {
	profiles := h.store.List("", "")

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=backup-"+time.Now().Format("20060102")+".zip")

	zw := zip.NewWriter(w)
	defer zw.Close()

	for _, p := range profiles {
		data, err := json.MarshalIndent(p, "", "  ")
		if err != nil {
			return
		}
		f, err := zw.Create(p.ID + "/profile.json")
		if err != nil {
			return
		}
		if _, err := f.Write(data); err != nil {
			return
		}
	}
	if h.groupStore != nil {
		data, err := h.groupStore.Export()
		if err != nil {
			return
		}
		f, err := zw.Create("groups.json")
		if err != nil {
			return
		}
		if _, err := f.Write(data); err != nil {
			return
		}
	}
}

func (h *handler) restore(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(50 << 20); err != nil {
		writeError(w, 400, "INVALID_FORM", err.Error())
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, 400, "NO_FILE", err.Error())
		return
	}
	defer file.Close()

	body, err := io.ReadAll(file)
	if err != nil {
		writeError(w, 400, "READ_FAILED", err.Error())
		return
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		writeError(w, 400, "INVALID_ZIP", err.Error())
		return
	}

	var profilesToImport []profile.Profile
	for _, f := range zr.File {
		if filepath.Base(f.Name) != "profile.json" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			writeError(w, 400, "READ_FAILED", err.Error())
			return
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			writeError(w, 400, "READ_FAILED", err.Error())
			return
		}
		var p profile.Profile
		if err := json.Unmarshal(data, &p); err != nil {
			writeError(w, 400, "INVALID_PROFILE", err.Error())
			return
		}
		p.ID = ""
		p.ContainerID = ""
		desc, err := h.mgr.RuntimeRegistry().ApplyProfileDefaults(&p)
		if err != nil {
			writeError(w, 400, "INVALID_RUNTIME", err.Error())
			return
		}
		if err := h.requireProfileRuntime(desc); err != nil {
			writeError(w, 400, "INVALID_RUNTIME", err.Error())
			return
		}
		profilesToImport = append(profilesToImport, p)
	}

	imported := 0
	groupsImported := 0
	for _, f := range zr.File {
		if f.Name != "groups.json" || h.groupStore == nil {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			writeError(w, 400, "READ_FAILED", err.Error())
			return
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			writeError(w, 400, "READ_FAILED", err.Error())
			return
		}
		n, err := h.groupStore.Import(data)
		if err != nil {
			writeError(w, 400, "INVALID_GROUPS", err.Error())
			return
		}
		groupsImported = n
	}
	for i := range profilesToImport {
		if err := h.store.Create(&profilesToImport[i]); err != nil {
			writeError(w, 500, "RESTORE_FAILED", err.Error())
			return
		}
		imported++
	}
	writeJSON(w, 200, map[string]any{"data": map[string]any{"imported": imported, "groups_imported": groupsImported}})
}

func (h *handler) shutdown(w http.ResponseWriter, r *http.Request) {
	h.mgr.Close()
	writeJSON(w, 200, map[string]any{"data": "shutting down"})
	go func() { time.Sleep(500 * time.Millisecond); os.Exit(0) }()
}
