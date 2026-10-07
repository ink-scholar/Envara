package api

import (
	"fmt"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
)

func (h *handler) artifact(w http.ResponseWriter, r *http.Request) {
	profileID := chi.URLParam(r, "id")
	artifactPath := chi.URLParam(r, "*")
	if artifactPath == "" {
		writeError(w, http.StatusBadRequest, "INVALID_ARTIFACT", "artifact path is required")
		return
	}
	p, err := h.store.Get(profileID)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
		return
	}
	path, err := resolveProfileArtifactPath(p.ProfileDir, artifactPath)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_ARTIFACT", err.Error())
		return
	}
	file, err := os.Open(path)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ARTIFACT_FAILED", err.Error())
		return
	}
	if info.IsDir() {
		writeError(w, http.StatusBadRequest, "INVALID_ARTIFACT", "artifact path must name a file")
		return
	}
	mimeType := mime.TypeByExtension(filepath.Ext(path))
	if mimeType == "" {
		buf := make([]byte, 512)
		n, _ := file.Read(buf)
		mimeType = http.DetectContentType(buf[:n])
		if _, err := file.Seek(0, 0); err != nil {
			writeError(w, http.StatusInternalServerError, "ARTIFACT_FAILED", err.Error())
			return
		}
	}
	w.Header().Set("Content-Type", mimeType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, info.Name(), info.ModTime(), file)
}

func resolveProfileArtifactPath(profileDir, requested string) (string, error) {
	if strings.Contains(requested, "\x00") {
		return "", fmt.Errorf("artifact path contains invalid NUL byte")
	}
	clean := filepath.Clean(requested)
	if clean == "." || filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
		return "", fmt.Errorf("artifact path must stay within profile artifacts")
	}
	base := filepath.Join(profileDir, "artifacts")
	out := filepath.Join(base, clean)
	rel, err := filepath.Rel(base, out)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("artifact path must stay within profile artifacts")
	}
	return out, nil
}
