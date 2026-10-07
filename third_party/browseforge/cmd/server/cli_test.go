package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"browseforge/internal/browser"
)

func TestCLIHelpAndVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runCLI([]string{"--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("help exit = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "BrowseForge CLI") {
		t.Fatalf("help output missing title: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := runCLI([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("version exit = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "BrowseForge") {
		t.Fatalf("version output = %s", stdout.String())
	}
}

func TestCLISubcommandHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runCLI([]string{"serve", "--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("serve help exit = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "BrowseForge CLI") {
		t.Fatalf("serve help output = %s", stdout.String())
	}
}

func TestCLIUnknownCommandFails(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runCLI([]string{"nope"}, &stdout, &stderr); code == 0 {
		t.Fatalf("unknown command unexpectedly succeeded")
	}
	if !strings.Contains(stderr.String(), "Unknown command: nope") {
		t.Fatalf("stderr = %s", stderr.String())
	}
}

func TestCLIPlaywrightInstallDriverUsage(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runCLI([]string{"playwright"}, &stdout, &stderr); code != 2 {
		t.Fatalf("playwright usage exit = %d, stdout = %s, stderr = %s", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %s, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Usage: BrowseForge playwright install-driver") {
		t.Fatalf("stderr = %s", stderr.String())
	}
}

func TestCLIInitConfigTokenAndDoctorJSON(t *testing.T) {
	baseDir := t.TempDir()
	var stdout, stderr bytes.Buffer

	if code := runCLI([]string{"--base-dir", baseDir, "init", "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("init exit = %d, stdout = %s, stderr = %s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(baseDir, "config.json")); err != nil {
		t.Fatalf("config not created: %v", err)
	}
	configData, err := os.ReadFile(filepath.Join(baseDir, "config.json"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var generated map[string]any
	if err := json.Unmarshal(configData, &generated); err != nil {
		t.Fatalf("decode generated config: %v\n%s", err, string(configData))
	}
	if _, ok := generated["camoufox_path"]; ok {
		t.Fatalf("generated config includes legacy camoufox_path: %#v", generated)
	}
	if _, ok := generated["cloakbrowser_path"]; ok {
		t.Fatalf("generated config includes legacy cloakbrowser_path: %#v", generated)
	}
	if _, ok := generated["cloakbrowser"]; ok {
		t.Fatalf("generated config includes legacy root cloakbrowser settings: %#v", generated)
	}
	runtimes, ok := generated["runtimes"].(map[string]any)
	if !ok {
		t.Fatalf("generated config missing runtimes object: %#v", generated)
	}
	cloak, ok := runtimes["cloakbrowser"].(map[string]any)
	if !ok {
		t.Fatalf("generated config missing cloakbrowser runtime: %#v", runtimes)
	}
	if _, ok := cloak["settings"].(map[string]any); !ok {
		t.Fatalf("generated cloakbrowser runtime missing settings: %#v", cloak)
	}
	for _, dir := range []string{"profiles", "data", "logs"} {
		if _, err := os.Stat(filepath.Join(baseDir, dir)); err != nil {
			t.Fatalf("%s dir not created: %v", dir, err)
		}
	}

	stdout.Reset()
	stderr.Reset()
	if code := runCLI([]string{"--base-dir", baseDir, "config", "validate", "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("config validate exit = %d, stdout = %s, stderr = %s", code, stdout.String(), stderr.String())
	}
	var validation map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &validation); err != nil {
		t.Fatalf("decode config validate: %v\n%s", err, stdout.String())
	}
	if validation["ok"] != true {
		t.Fatalf("validation = %#v", validation)
	}

	tokenDir := filepath.Join(baseDir, "data")
	if err := os.WriteFile(filepath.Join(tokenDir, ".api-token"), []byte("test-token\n"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runCLI([]string{"--base-dir", baseDir, "token", "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("token exit = %d, stdout = %s, stderr = %s", code, stdout.String(), stderr.String())
	}
	var token map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &token); err != nil {
		t.Fatalf("decode token: %v\n%s", err, stdout.String())
	}
	if token["token"] != "test-token" {
		t.Fatalf("token output = %#v", token)
	}

	stdout.Reset()
	stderr.Reset()
	code := runCLI([]string{"--base-dir", baseDir, "doctor", "--json"}, &stdout, &stderr)
	if code != 0 && code != 1 {
		t.Fatalf("doctor exit = %d, stdout = %s, stderr = %s", code, stdout.String(), stderr.String())
	}
	var report doctorReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode doctor: %v\n%s", err, stdout.String())
	}
	if report.Version == "" || len(report.Checks) == 0 {
		t.Fatalf("doctor report = %#v", report)
	}
}

func TestCLICapabilitiesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runCLI([]string{"capabilities", "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("capabilities exit = %d, stderr = %s", code, stderr.String())
	}
	var caps map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &caps); err != nil {
		t.Fatalf("decode capabilities: %v\n%s", err, stdout.String())
	}
	commands, ok := caps["commands"].([]any)
	if !ok || len(commands) == 0 {
		t.Fatalf("commands missing: %#v", caps)
	}
}

func TestCLIStatusAndMCPConfigJSON(t *testing.T) {
	baseDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	if code := runCLI([]string{"--base-dir", baseDir, "init"}, &stdout, &stderr); code != 0 {
		t.Fatalf("init exit = %d, stderr = %s", code, stderr.String())
	}
	if err := os.WriteFile(filepath.Join(baseDir, "data", ".api-token"), []byte("test-token\n"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	if code := runCLI([]string{"--base-dir", baseDir, "status", "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("status exit = %d, stdout = %s, stderr = %s", code, stdout.String(), stderr.String())
	}
	var status map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		t.Fatalf("decode status: %v\n%s", err, stdout.String())
	}
	if status["mcp_url"] == "" || status["dashboard"] == "" {
		t.Fatalf("status missing URLs: %#v", status)
	}

	stdout.Reset()
	stderr.Reset()
	if code := runCLI([]string{"--base-dir", baseDir, "mcp-config", "http", "--url", "http://example.test/mcp", "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("mcp-config exit = %d, stdout = %s, stderr = %s", code, stdout.String(), stderr.String())
	}
	var cfg map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &cfg); err != nil {
		t.Fatalf("decode mcp config: %v\n%s", err, stdout.String())
	}
	if _, ok := cfg["browseforge"].(map[string]any); !ok {
		t.Fatalf("mcp config = %#v", cfg)
	}
}

func TestCollectBrowserStatesIncludesReadyBrowseForgeChromium(t *testing.T) {
	baseDir := t.TempDir()
	expectedVersion := browser.ExpectedBrowseForgeChromiumVersion()
	binPath := writeReadyBrowserRuntime(t, baseDir, browser.BrowseForgeChromiumRuntimeID, expectedVersion, "chrome")

	states := collectBrowserStates(baseDir)
	state := findBrowserState(t, states, browser.BrowseForgeChromiumRuntimeID)

	if state.Expected != expectedVersion {
		t.Fatalf("expected version = %q, want %q", state.Expected, expectedVersion)
	}
	if state.Installed != expectedVersion {
		t.Fatalf("installed version = %q, want %q", state.Installed, expectedVersion)
	}
	if state.Path != binPath {
		t.Fatalf("binary path = %q, want %q", state.Path, binPath)
	}
	if !state.Ready {
		t.Fatalf("browseforge-chromium state not ready: %#v", state)
	}
}

func TestCLIBrowsersRuntimesSelectionFiltersStatusAndInstall(t *testing.T) {
	baseDir := t.TempDir()
	expectedVersion := browser.ExpectedBrowseForgeChromiumVersion()
	binPath := writeReadyBrowserRuntime(t, baseDir, browser.BrowseForgeChromiumRuntimeID, expectedVersion, "chrome")

	tests := []struct {
		name string
		args []string
	}{
		{name: "status", args: []string{"status", "--json", "--runtimes", browser.BrowseForgeChromiumRuntimeID}},
		{name: "install", args: []string{"install", "--json", "--runtimes", browser.BrowseForgeChromiumRuntimeID}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append([]string{"--base-dir", baseDir, "browsers"}, tc.args...)
			if code := runCLI(args, &stdout, &stderr); code != 0 {
				t.Fatalf("browsers %s exit = %d, stdout = %s, stderr = %s", tc.name, code, stdout.String(), stderr.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("browsers %s wrote stderr despite ready selected runtime: %s", tc.name, stderr.String())
			}

			var result struct {
				OK       bool           `json:"ok"`
				Browsers []browserState `json:"browsers"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
				t.Fatalf("decode browsers %s: %v\n%s", tc.name, err, stdout.String())
			}
			if !result.OK {
				t.Fatalf("browsers %s result not ok: %#v", tc.name, result)
			}
			if len(result.Browsers) != 1 {
				t.Fatalf("browsers %s returned %d states, want only browseforge-chromium: %#v", tc.name, len(result.Browsers), result.Browsers)
			}
			state := result.Browsers[0]
			if state.Name != browser.BrowseForgeChromiumRuntimeID || state.Installed != expectedVersion || state.Path != binPath || !state.Ready {
				t.Fatalf("browsers %s state = %#v, want ready browseforge-chromium at %s", tc.name, state, binPath)
			}
		})
	}
}

func TestCLIBrowsersRuntimesSelectionRejectsUnknownRuntime(t *testing.T) {
	for _, subcmd := range []string{"status", "install"} {
		t.Run(subcmd, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runCLI([]string{
				"--base-dir", t.TempDir(),
				"browsers", subcmd,
				"--json",
				"--runtimes", browser.BrowseForgeChromiumRuntimeID + ",brave",
			}, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("browsers %s exit = %d, stdout = %s, stderr = %s", subcmd, code, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("browsers %s stdout = %s, want empty on selection error", subcmd, stdout.String())
			}
			if !strings.Contains(stderr.String(), `unsupported browser runtime "brave"`) {
				t.Fatalf("browsers %s stderr = %s, want unsupported runtime error", subcmd, stderr.String())
			}
		})
	}
}

func TestCLIFullBackupCreateAndRestore(t *testing.T) {
	baseDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(baseDir, "profiles", "prof_test"), 0755); err != nil {
		t.Fatalf("mkdir profile: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(baseDir, "data"), 0755); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}
	if err := os.WriteFile(filepath.Join(baseDir, "profiles", "prof_test", "profile.json"), []byte(`{"id":"prof_test"}`), 0644); err != nil {
		t.Fatalf("write profile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(baseDir, "data", ".api-token"), []byte("test-token"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(baseDir, "browsers", "camoufox"), 0755); err != nil {
		t.Fatalf("mkdir browser: %v", err)
	}
	if err := os.WriteFile(filepath.Join(baseDir, "browsers", "camoufox", "target.txt"), []byte("browser-data"), 0644); err != nil {
		t.Fatalf("write browser target: %v", err)
	}
	if err := os.Symlink("target.txt", filepath.Join(baseDir, "browsers", "camoufox", "link.txt")); err != nil {
		t.Fatalf("create browser symlink: %v", err)
	}

	backupDir := filepath.Join(t.TempDir(), "backups")
	var stdout, stderr bytes.Buffer
	if code := runCLI([]string{"--base-dir", baseDir, "backup", "create", "--full", "--output", backupDir, "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("backup create exit = %d, stdout = %s, stderr = %s", code, stdout.String(), stderr.String())
	}
	var created map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &created); err != nil {
		t.Fatalf("decode backup create: %v\n%s", err, stdout.String())
	}
	backupPath, _ := created["path"].(string)
	if backupPath == "" {
		t.Fatalf("backup path missing: %#v", created)
	}
	if filepath.Dir(backupPath) != backupDir {
		t.Fatalf("backup path = %s, want dir %s", backupPath, backupDir)
	}
	if _, err := os.Stat(backupPath); err != nil {
		t.Fatalf("backup not written: %v", err)
	}

	restoreDir := t.TempDir()
	stdout.Reset()
	stderr.Reset()
	if code := runCLI([]string{"--base-dir", restoreDir, "backup", "restore", "--full", "--json", backupPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("backup restore exit = %d, stdout = %s, stderr = %s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(restoreDir, "profiles", "prof_test", "profile.json")); err != nil {
		t.Fatalf("profile not restored: %v", err)
	}
	if _, err := os.Stat(filepath.Join(restoreDir, "data", ".api-token")); err != nil {
		t.Fatalf("token not restored: %v", err)
	}
	linkTarget, err := os.Readlink(filepath.Join(restoreDir, "browsers", "camoufox", "link.txt"))
	if err != nil {
		t.Fatalf("browser symlink not restored: %v", err)
	}
	if linkTarget != "target.txt" {
		t.Fatalf("browser symlink target = %q", linkTarget)
	}
}

func TestCLIMigrateProfilesApplyBacksUpRuntimeProfileWhenRemovingEngine(t *testing.T) {
	baseDir := t.TempDir()
	profilePath := filepath.Join(baseDir, "profiles", "prof_runtime", "profile.json")
	original := []byte(`{"id":"prof_runtime","name":"Has runtime","engine":"chromium","runtime_id":"cloakbrowser"}`)
	if err := os.MkdirAll(filepath.Dir(profilePath), 0755); err != nil {
		t.Fatalf("mkdir profile: %v", err)
	}
	if err := os.WriteFile(profilePath, original, 0644); err != nil {
		t.Fatalf("write profile: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if code := runCLI([]string{"--base-dir", baseDir, "migrate", "profiles", "--from", "v1", "--to", "v2", "--apply", "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("migrate exit = %d, stdout = %s, stderr = %s", code, stdout.String(), stderr.String())
	}

	backup, err := os.ReadFile(profilePath + ".v1.bak")
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(backup) != string(original) {
		t.Fatalf("backup = %s, want original %s", string(backup), string(original))
	}
	migrated, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatalf("read migrated profile: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(migrated, &got); err != nil {
		t.Fatalf("decode migrated profile: %v\n%s", err, string(migrated))
	}
	if _, ok := got["engine"]; ok {
		t.Fatalf("migrated profile still has engine: %#v", got)
	}
	if got["runtime_id"] != "cloakbrowser" {
		t.Fatalf("runtime_id = %v, want existing cloakbrowser", got["runtime_id"])
	}
}

func TestCLIMigrateProfilesApplyValidatesAllProfilesBeforeWriting(t *testing.T) {
	baseDir := t.TempDir()
	goodPath := filepath.Join(baseDir, "profiles", "01-good", "profile.json")
	badPath := filepath.Join(baseDir, "profiles", "02-bad", "profile.json")
	goodOriginal := []byte(`{"id":"prof_good","name":"Good","engine":"firefox"}`)
	badOriginal := []byte(`{"id":"prof_bad","name":"Bad","engine":"webkit"}`)
	for path, data := range map[string][]byte{
		goodPath: goodOriginal,
		badPath:  badOriginal,
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	var stdout, stderr bytes.Buffer
	code := runCLI([]string{"--base-dir", baseDir, "migrate", "profiles", "--from", "v1", "--to", "v2", "--apply", "--json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("migrate exit = %d, stdout = %s, stderr = %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), `unsupported v1 engine "webkit"`) {
		t.Fatalf("stderr missing unsupported engine: %s", stderr.String())
	}
	goodAfter, err := os.ReadFile(goodPath)
	if err != nil {
		t.Fatalf("read good profile: %v", err)
	}
	if string(goodAfter) != string(goodOriginal) {
		t.Fatalf("good profile was rewritten before later validation failed: %s", string(goodAfter))
	}
	if _, err := os.Stat(goodPath + ".v1.bak"); !os.IsNotExist(err) {
		t.Fatalf("good profile backup err = %v, want no backup before validation completes", err)
	}
	badAfter, err := os.ReadFile(badPath)
	if err != nil {
		t.Fatalf("read bad profile: %v", err)
	}
	if string(badAfter) != string(badOriginal) {
		t.Fatalf("bad profile = %s, want unchanged %s", string(badAfter), string(badOriginal))
	}
}

func TestCLIMigrateProfilesApplyRejectsMalformedProfileBeforeWriting(t *testing.T) {
	baseDir := t.TempDir()
	goodPath := filepath.Join(baseDir, "profiles", "01-good", "profile.json")
	badPath := filepath.Join(baseDir, "profiles", "02-bad", "profile.json")
	goodOriginal := []byte(`{"id":"prof_good","name":"Good","engine":"firefox"}`)
	badOriginal := []byte(`{"id":"prof_bad","name":"Bad","engine":`)
	for path, data := range map[string][]byte{
		goodPath: goodOriginal,
		badPath:  badOriginal,
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	var stdout, stderr bytes.Buffer
	code := runCLI([]string{"--base-dir", baseDir, "migrate", "profiles", "--from", "v1", "--to", "v2", "--apply", "--json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("migrate exit = %d, stdout = %s, stderr = %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), badPath) {
		t.Fatalf("stderr missing malformed profile path %s: %s", badPath, stderr.String())
	}
	goodAfter, err := os.ReadFile(goodPath)
	if err != nil {
		t.Fatalf("read good profile: %v", err)
	}
	if string(goodAfter) != string(goodOriginal) {
		t.Fatalf("good profile was rewritten before malformed profile failed validation: %s", string(goodAfter))
	}
	if _, err := os.Stat(goodPath + ".v1.bak"); !os.IsNotExist(err) {
		t.Fatalf("good profile backup err = %v, want no backup before validation completes", err)
	}
	badAfter, err := os.ReadFile(badPath)
	if err != nil {
		t.Fatalf("read bad profile: %v", err)
	}
	if string(badAfter) != string(badOriginal) {
		t.Fatalf("bad profile = %s, want unchanged %s", string(badAfter), string(badOriginal))
	}
}

func TestCLIInvalidConfigDoesNotPanic(t *testing.T) {
	baseDir := t.TempDir()
	configPath := filepath.Join(baseDir, "config.json")
	if err := os.WriteFile(configPath, []byte("{"), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := runCLI([]string{"--base-dir", baseDir, "smoke", "rest", "--json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("smoke exit = %d, stdout = %s, stderr = %s", code, stdout.String(), stderr.String())
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode smoke error: %v\n%s", err, stdout.String())
	}
	errMsg, _ := result["error"].(string)
	if result["ok"] != false || !strings.Contains(errMsg, "config error") {
		t.Fatalf("smoke result = %#v", result)
	}
}

func TestCLIAPIListReportsMissingToken(t *testing.T) {
	baseDir := t.TempDir()
	var stdout, stderr bytes.Buffer
	if code := runCLI([]string{"--base-dir", baseDir, "init"}, &stdout, &stderr); code != 0 {
		t.Fatalf("init exit = %d, stderr = %s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	code := runCLI([]string{"--base-dir", baseDir, "profiles", "list", "--base-url", "http://127.0.0.1:1", "--json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("profiles list exit = %d, stdout = %s, stderr = %s", code, stdout.String(), stderr.String())
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode profiles error: %v\n%s", err, stdout.String())
	}
	errMsg, _ := result["error"].(string)
	if result["ok"] != false || !strings.Contains(errMsg, "token error") {
		t.Fatalf("profiles result = %#v", result)
	}
}

func TestTokenPreviewShortToken(t *testing.T) {
	if got := tokenPreview("short"); got != "short" {
		t.Fatalf("tokenPreview short = %q", got)
	}
	if got := tokenPreview("1234567890abcdefX"); got != "1234567890abcdef" {
		t.Fatalf("tokenPreview long = %q", got)
	}
}

func TestFormatListenErrorIncludesPortGuidance(t *testing.T) {
	err := os.ErrInvalid
	if isPortInUseError(err) {
		t.Fatalf("os.ErrInvalid should not be treated as port-in-use")
	}

	for _, rawErr := range []string{
		"listen tcp 127.0.0.1:19280: bind: address already in use",
		"listen tcp 127.0.0.1:19280: bind: Only one usage of each socket address (protocol/network address/port) is normally permitted.",
	} {
		msg := formatListenError(
			&listenErrorString{rawErr},
			"127.0.0.1",
			"19280",
		)
		for _, want := range []string{
			"could not listen on 127.0.0.1:19280",
			"Port 19280 is already in use",
			"BrowseForge serve --port 19281",
		} {
			if !strings.Contains(msg, want) {
				t.Fatalf("listen error guidance missing %q for %q: %s", want, rawErr, msg)
			}
		}
	}
}

func TestNextPortSuggestion(t *testing.T) {
	tests := map[string]string{
		"19280": "19281",
		"19281": "19282",
		"65535": "19281",
		"port":  "19281",
	}
	for port, want := range tests {
		if got := nextPortSuggestion(port); got != want {
			t.Fatalf("nextPortSuggestion(%q) = %q, want %q", port, got, want)
		}
	}
}

func writeReadyBrowserRuntime(t *testing.T, baseDir, runtimeID, version, binaryRel string) string {
	t.Helper()
	runtimeDir := filepath.Join(baseDir, "browsers", runtimeID)
	binPath := filepath.Join(runtimeDir, binaryRel)
	if err := os.MkdirAll(filepath.Dir(binPath), 0755); err != nil {
		t.Fatalf("mkdir runtime binary dir: %v", err)
	}
	if err := os.WriteFile(binPath, []byte("browser binary"), 0755); err != nil {
		t.Fatalf("write runtime binary: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runtimeDir, ".version"), []byte(version+"\n"), 0644); err != nil {
		t.Fatalf("write runtime version: %v", err)
	}
	return binPath
}

func findBrowserState(t *testing.T, states []browserState, name string) browserState {
	t.Helper()
	for _, state := range states {
		if state.Name == name {
			return state
		}
	}
	t.Fatalf("browser state %q missing from %#v", name, states)
	return browserState{}
}

type listenErrorString struct {
	message string
}

func (e *listenErrorString) Error() string {
	return e.message
}
