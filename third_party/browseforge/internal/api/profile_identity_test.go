package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"browseforge/internal/profile"
)

func createdIdentityProfile(t *testing.T, rec *httptest.ResponseRecorder) *profile.Profile {
	t.Helper()
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	var result struct {
		Data profile.Profile `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return &result.Data
}

func TestRESTFreshIdentityAndNamedDuplicateUseSharedGeneration(t *testing.T) {
	for _, provider := range []string{"cloakbrowser", "browseforge-chromium", "camoufox"} {
		t.Run(provider, func(t *testing.T) {
			h := newDesktopHandler(t)
			rec := httptest.NewRecorder()
			h.createProfile(rec, httptest.NewRequest(http.MethodPost, "/api/profiles", strings.NewReader(fmt.Sprintf(`{"name":"Fresh","runtime_id":%q}`, provider))))
			p := createdIdentityProfile(t, rec)
			if p.FingerprintGeneration == nil || len(p.FingerprintGeneration.GeneratedFields) == 0 || len(p.Fingerprint) == 0 {
				t.Fatal("REST creation bypassed generated identity persistence")
			}
			if provider != "camoufox" && p.FingerprintSeed == 0 {
				t.Fatal("REST creation lost its nonzero seed")
			}
			rec = httptest.NewRecorder()
			h.duplicateProfile(rec, requestWithProfileID(http.MethodPost, "/api/profiles/"+p.ID+"/duplicate", p.ID, strings.NewReader(`{"name":"Chosen clone name"}`)))
			clone := createdIdentityProfile(t, rec)
			if clone.Name != "Chosen clone name" || clone.ID == p.ID || clone.FingerprintGeneration == nil {
				t.Fatal("duplicate options or fresh generation were lost")
			}
			if provider != "camoufox" && (clone.FingerprintSeed == 0 || clone.FingerprintSeed == p.FingerprintSeed) {
				t.Fatal("REST duplicate retained the old seed")
			}
		})
	}
}

func TestRESTIdentityPreserveIsEphemeralAndKeepsLegacyZeroSeed(t *testing.T) {
	h := newDesktopHandler(t)
	rec := httptest.NewRecorder()
	h.createProfile(rec, httptest.NewRequest(http.MethodPost, "/api/profiles", strings.NewReader(`{"name":"Imported legacy","runtime_id":"cloakbrowser","identity_mode":"preserve","fingerprint":{"canvas:seed":17}}`)))
	p := createdIdentityProfile(t, rec)
	if p.FingerprintSeed != 0 || p.FingerprintGeneration != nil || p.Identity != nil || len(p.Fingerprint) != 1 || p.Fingerprint["canvas:seed"] != float64(17) {
		t.Fatal("preserve mode silently generated an identity")
	}
	if strings.Contains(rec.Body.String(), "identity_mode") {
		t.Fatal("one-shot preservation mode became a persistent profile field")
	}
	for _, body := range []string{`{"identity_mode":null}`, `{"identity_mode":true}`, `{"identity_mode":"fresh"}`} {
		var input map[string]any
		if err := json.Unmarshal([]byte(body), &input); err != nil {
			t.Fatal(err)
		}
		input["name"], input["runtime_id"] = "Invalid mode", "cloakbrowser"
		data, _ := json.Marshal(input)
		rec = httptest.NewRecorder()
		h.createProfile(rec, httptest.NewRequest(http.MethodPost, "/api/profiles", bytes.NewReader(data)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("invalid identity mode was accepted: %s", body)
		}
	}
}

func TestRESTExplicitImportAndRestoreSeedRemainUnchanged(t *testing.T) {
	h := newDesktopHandler(t)
	for _, seed := range []uint32{1, ^uint32(0)} {
		rec := httptest.NewRecorder()
		h.createProfile(rec, httptest.NewRequest(http.MethodPost, "/api/profiles", strings.NewReader(fmt.Sprintf(`{"name":"Explicit","runtime_id":"cloakbrowser","fingerprint_seed":%d}`, seed))))
		if p := createdIdentityProfile(t, rec); p.FingerprintSeed != seed {
			t.Fatal("REST creation changed an explicit seed")
		}
	}
	for _, route := range []string{"import", "restore"} {
		t.Run(route, func(t *testing.T) {
			entry := "profile.json"
			if route == "restore" {
				entry = "owned/profile.json"
			}
			body, contentType := multipartZipUpload(t, map[string][]byte{entry: []byte(`{"name":"Restored","runtime_id":"cloakbrowser","fingerprint_seed":425179,"fingerprint":{"canvas:seed":17}}`)})
			req := httptest.NewRequest(http.MethodPost, "/api/"+route, bytes.NewReader(body))
			req.Header.Set("Content-Type", contentType)
			rec := httptest.NewRecorder()
			if route == "import" {
				h.importProfile(rec, req)
			} else {
				h.restore(rec, req)
			}
			if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
				t.Fatalf("restore = %d %s", rec.Code, rec.Body.String())
			}
			for _, p := range h.store.List("", "") {
				if p.Name == "Restored" && (p.FingerprintSeed != 425179 || p.FingerprintGeneration != nil || len(p.Fingerprint) != 1) {
					t.Fatal("import or restore changed the saved identity")
				}
			}
		})
	}
}

func TestDuplicateNameValidationKeepsLegacyEmptyBody(t *testing.T) {
	for _, body := range []string{"", `{}`, `{"name":"Owned clone"}`} {
		if _, err := decodeDuplicateName(strings.NewReader(body)); err != nil {
			t.Fatalf("valid duplicate options = %q: %v", body, err)
		}
	}
	for _, body := range []string{`{"name":""}`, `{"name":"  "}`, `{"name":null}`, `{"name":1}`, `{"name":"line\nbreak"}`, `{"seed":12}`, `{} {}`, `null`, `[]`, `{"name":"` + strings.Repeat("a", 121) + `"}`} {
		if _, err := decodeDuplicateName(strings.NewReader(body)); err == nil {
			t.Fatalf("invalid duplicate options accepted: %q", body)
		}
	}
}
