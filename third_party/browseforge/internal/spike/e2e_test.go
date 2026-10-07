package spike_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestE2EFullFlow(t *testing.T) {
	camoufoxPath := os.Getenv("CAMOUFOX_PATH")
	if camoufoxPath == "" {
		t.Skip("CAMOUFOX_PATH not set")
	}

	// Write temp config
	config := fmt.Sprintf(`{
		"port": "19299",
		"profiles_dir": "/tmp/browseforge-test-profiles",
		"data_dir": "/tmp/browseforge-test-data",
		"log_file": "/tmp/browseforge-test.log",
		"default_runtime_id": "camoufox",
		"runtimes": {"camoufox": {"enabled": true, "binary_path": %q, "family": "firefox", "display_name": "Camoufox"}},
		"fingerprint_dir": "data"
	}`, camoufoxPath)
	os.WriteFile("/tmp/browseforge-test-config.json", []byte(config), 0644)
	os.MkdirAll("/tmp/browseforge-test-profiles", 0755)
	os.MkdirAll("/tmp/browseforge-test-data", 0755)
	defer os.RemoveAll("/tmp/browseforge-test-profiles")
	defer os.RemoveAll("/tmp/browseforge-test-data")

	// Start server
	cmd := exec.Command("go", "run", "./cmd/server", "--config", "/tmp/browseforge-test-config.json")
	cmd.Dir = os.Getenv("PROJECT_DIR")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	defer cmd.Process.Kill()

	// Wait for server
	base := "http://127.0.0.1:19299"
	for i := 0; i < 30; i++ {
		resp, err := http.Get(base + "/api/status")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			break
		}
		time.Sleep(time.Second)
		if i == 29 {
			t.Fatal("server didn't start in 30s")
		}
	}

	// Read token
	tokenBytes, _ := os.ReadFile("/tmp/browseforge-test-data/.api-token")
	token := strings.TrimSpace(string(tokenBytes))
	t.Logf("Token: %s", token[:8]+"...")

	doReq := func(method, path string, body any) (int, map[string]any) {
		var r io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			r = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, base+path, r)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		var result map[string]any
		json.NewDecoder(resp.Body).Decode(&result)
		return resp.StatusCode, result
	}

	// 1. Create profile
	status, result := doReq("POST", "/api/profiles", map[string]any{
		"name":       "Test Profile",
		"runtime_id": "camoufox",
	})
	if status != 201 {
		t.Fatalf("create profile: status %d, %v", status, result)
	}
	profileData := result["data"].(map[string]any)
	profileID := profileData["id"].(string)
	t.Logf("✅ Created profile: %s", profileID)

	// Check fingerprint was auto-assigned
	if profileData["fingerprint"] != nil {
		fp := profileData["fingerprint"].(map[string]any)
		t.Logf("✅ Fingerprint auto-assigned: UA=%v", fp["navigator.userAgent"])
	}

	// 2. List profiles
	status, result = doReq("GET", "/api/profiles", nil)
	if status != 200 {
		t.Fatalf("list profiles: %d", status)
	}
	t.Logf("✅ Listed profiles: total=%v", result["total"])

	// 3. Cleanup
	doReq("DELETE", "/api/profiles/"+profileID, nil)
	t.Log("✅ E2E profile CRUD flow complete")
}
