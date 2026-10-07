package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"browseforge/internal/profile"

	"github.com/go-chi/chi/v5"
)

func TestArtifactServesProfileArtifact(t *testing.T) {
	store, err := profile.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := &profile.Profile{ID: "prof_art", Name: "Artifact", RuntimeID: "camoufox"}
	if err := store.Create(p); err != nil {
		t.Fatal(err)
	}
	data := []byte("\x89PNG\r\n\x1a\nartifact")
	path := filepath.Join(p.ProfileDir, "artifacts", "shots", "home.png")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := artifactRequest("prof_art", "shots/home.png")
	(&handler{store: store}).artifact(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
	}
	if !bytes.Equal(rec.Body.Bytes(), data) {
		t.Fatalf("body = %q, want %q", rec.Body.Bytes(), data)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "image/png") {
		t.Fatalf("Content-Type = %q", got)
	}
}

func TestResolveProfileArtifactPathRejectsTraversal(t *testing.T) {
	if _, err := resolveProfileArtifactPath("/tmp/profile", "../secret.png"); err == nil {
		t.Fatal("expected traversal error")
	}
	if _, err := resolveProfileArtifactPath("/tmp/profile", "/tmp/secret.png"); err == nil {
		t.Fatal("expected absolute path error")
	}
}

func artifactRequest(profileID, artifactPath string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/profiles/"+profileID+"/artifacts/"+artifactPath, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", profileID)
	rctx.URLParams.Add("*", artifactPath)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}
