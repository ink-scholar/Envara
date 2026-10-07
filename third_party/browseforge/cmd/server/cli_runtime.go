package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"browseforge/internal/browser"
	"browseforge/internal/config"
)

type browserState struct {
	Name              string `json:"name"`
	Expected          string `json:"expected"`
	Installed         string `json:"installed,omitempty"`
	Path              string `json:"path,omitempty"`
	Ready             bool   `json:"ready"`
	PlatformSupported bool   `json:"platform_supported"`
	UnsupportedReason string `json:"unsupported_reason,omitempty"`
}

type statusReport struct {
	Version     string         `json:"version"`
	BaseDir     string         `json:"base_dir"`
	Config      string         `json:"config"`
	RESTBaseURL string         `json:"rest_base_url"`
	MCPURL      string         `json:"mcp_url"`
	Dashboard   string         `json:"dashboard"`
	Token       map[string]any `json:"token"`
	Browsers    []browserState `json:"browsers"`
	Profiles    map[string]any `json:"profiles"`
	Server      map[string]any `json:"server"`
	OK          bool           `json:"ok"`
}

func runStatusCommand(args []string, global cliGlobal, stdout, stderr io.Writer) int {
	fs := newFlagSet("status", stderr)
	baseURL := fs.String("base-url", "", "BrowseForge base URL")
	token := fs.String("token", "", "Bearer token")
	jsonOut := fs.Bool("json", false, "Write JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "status does not accept positional arguments: %s\n", strings.Join(fs.Args(), " "))
		return 2
	}
	report := buildStatusReport(global, *baseURL, *token)
	if *jsonOut {
		_ = writeJSON(stdout, report)
	} else {
		printStatusReport(stdout, report)
	}
	if !report.OK {
		return 1
	}
	return 0
}

func buildStatusReport(global cliGlobal, baseURL, token string) statusReport {
	report := statusReport{
		Version:  Version,
		BaseDir:  global.baseDir,
		Config:   global.configPath,
		Token:    map[string]any{"configured": false},
		Profiles: map[string]any{"count": 0},
		Server:   map[string]any{"reachable": false},
		OK:       true,
	}
	cfg, err := config.Load(global.configPath)
	if err != nil {
		report.Server["config_error"] = err.Error()
		report.OK = false
		cfg = configDefaults()
	}
	report.RESTBaseURL = resolveBaseURL(baseURL, cfg)
	report.MCPURL = report.RESTBaseURL + "/mcp"
	report.Dashboard = report.RESTBaseURL
	if token == "" {
		token, path, err := readToken(global.configPath, global.baseDir)
		if err == nil {
			report.Token = map[string]any{"configured": true, "path": path, "preview": tokenPreview(token)}
		} else {
			report.Token = map[string]any{"configured": false, "error": err.Error()}
		}
	} else {
		report.Token = map[string]any{"configured": true, "source": "flag", "preview": tokenPreview(token)}
	}
	report.Browsers = collectBrowserStates(global.baseDir)
	profilesPath := resolvePath(global.baseDir, cfg.ProfilesDir)
	report.Profiles["path"] = profilesPath
	if count, err := countProfiles(profilesPath); err == nil {
		report.Profiles["count"] = count
	} else if !os.IsNotExist(err) {
		report.Profiles["error"] = err.Error()
	}
	if status, err := apiGET(report.RESTBaseURL+"/api/status", ""); err == nil {
		report.Server["reachable"] = true
		report.Server["status"] = status
	} else {
		report.Server["error"] = err.Error()
	}
	return report
}

func countProfiles(path string) (int, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(path, entry.Name(), "profile.json")); err == nil {
			count++
		}
	}
	return count, nil
}

func printStatusReport(w io.Writer, report statusReport) {
	fmt.Fprintf(w, "BrowseForge %s\n", report.Version)
	fmt.Fprintf(w, "Base dir:  %s\n", report.BaseDir)
	fmt.Fprintf(w, "Config:    %s\n", report.Config)
	fmt.Fprintf(w, "Dashboard: %s\n", report.Dashboard)
	fmt.Fprintf(w, "MCP HTTP:  %s\n", report.MCPURL)
	if configured, _ := report.Token["configured"].(bool); configured {
		fmt.Fprintf(w, "Token:     configured (%v)\n", report.Token["preview"])
	} else {
		fmt.Fprintf(w, "Token:     missing\n")
	}
	fmt.Fprintf(w, "Server:    reachable=%v\n", report.Server["reachable"])
	for _, b := range report.Browsers {
		fmt.Fprintf(w, "Browser:   %s ready=%v installed=%s expected=%s\n", b.Name, b.Ready, b.Installed, b.Expected)
	}
}

func runOpenCommand(args []string, global cliGlobal, stdout, stderr io.Writer) int {
	fs := newFlagSet("open", stderr)
	baseURL := fs.String("base-url", "", "BrowseForge base URL")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "open does not accept positional arguments: %s\n", strings.Join(fs.Args(), " "))
		return 2
	}
	cfg, err := config.Load(global.configPath)
	if err != nil && *baseURL == "" {
		fmt.Fprintf(stderr, "open failed: config error: %v\n", err)
		return 1
	}
	token, _, err := readToken(global.configPath, global.baseDir)
	if err != nil {
		fmt.Fprintf(stderr, "open failed: token error: %v\n", err)
		return 1
	}
	url := resolveBaseURL(*baseURL, cfg) + "#" + token
	openBrowser(url)
	fmt.Fprintf(stdout, "Opened %s\n", resolveBaseURL(*baseURL, cfg))
	return 0
}

func runMCPConfigCommand(args []string, global cliGlobal, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "mcp-config requires subcommand: stdio or http")
		return 2
	}
	mode := args[0]
	fs := newFlagSet("mcp-config "+mode, stderr)
	url := fs.String("url", "", "BrowseForge MCP base URL for HTTP mode")
	token := fs.String("token", "", "Bearer token for HTTP mode")
	jsonOut := fs.Bool("json", false, "Write JSON output")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "mcp-config %s does not accept positional arguments: %s\n", mode, strings.Join(fs.Args(), " "))
		return 2
	}
	cfg := map[string]any{}
	switch mode {
	case "stdio":
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintf(stderr, "mcp-config failed: %v\n", err)
			return 1
		}
		cfg = map[string]any{
			"browseforge": map[string]any{
				"command": exe,
				"args":    []string{"--base-dir", global.baseDir, "--config", global.configPath, "mcp-stdio"},
			},
		}
	case "http":
		resolvedURL := strings.TrimRight(*url, "/")
		if resolvedURL == "" {
			loaded, err := config.Load(global.configPath)
			if err != nil {
				fmt.Fprintf(stderr, "mcp-config failed: config error: %v\n", err)
				return 1
			}
			resolvedURL = resolveBaseURL("", loaded) + "/mcp"
		}
		resolvedToken := *token
		if resolvedToken == "" {
			var err error
			resolvedToken, _, err = readToken(global.configPath, global.baseDir)
			if err != nil {
				fmt.Fprintf(stderr, "mcp-config failed: token error: %v\n", err)
				return 1
			}
		}
		cfg = map[string]any{
			"browseforge": map[string]any{
				"url": resolvedURL,
				"headers": map[string]string{
					"Authorization": "Bearer " + resolvedToken,
				},
			},
		}
	default:
		fmt.Fprintf(stderr, "unknown mcp-config mode: %s\n", mode)
		return 2
	}
	if *jsonOut {
		_ = writeJSON(stdout, cfg)
	} else {
		_ = writeJSON(stdout, cfg)
	}
	return 0
}

func runBrowsersCommand(args []string, global cliGlobal, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "browsers requires subcommand: status or install")
		return 2
	}
	subcmd := args[0]
	fs := newFlagSet("browsers "+subcmd, stderr)
	jsonOut := fs.Bool("json", false, "Write JSON output")
	runtimesCSV := fs.String("runtimes", "", "Comma-separated browser runtimes to inspect/install: camoufox, cloakbrowser, browseforge-chromium")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "browsers %s does not accept positional arguments: %s\n", subcmd, strings.Join(fs.Args(), " "))
		return 2
	}
	if _, err := parseRuntimeSelection(*runtimesCSV); err != nil {
		fmt.Fprintf(stderr, "browsers %s failed: %v\n", subcmd, err)
		return 2
	}
	switch subcmd {
	case "status":
		states := selectBrowserStates(collectBrowserStates(global.baseDir), *runtimesCSV)
		if *jsonOut {
			_ = writeJSON(stdout, map[string]any{"ok": browsersReady(states), "browsers": states})
		} else {
			for _, state := range states {
				fmt.Fprintf(stdout, "%s ready=%v supported=%v installed=%s expected=%s path=%s reason=%s\n", state.Name, state.Ready, state.PlatformSupported, state.Installed, state.Expected, state.Path, state.UnsupportedReason)
			}
		}
		if !browsersReady(states) {
			return 1
		}
		return 0
	case "install":
		progress := stdout
		if *jsonOut {
			progress = stderr
		}
		var states []browserState
		var err error
		if *jsonOut {
			err = withStdoutRedirect(stderr, func() error {
				states, err = installBrowsers(global.baseDir, progress, *runtimesCSV)
				return err
			})
		} else {
			states, err = installBrowsers(global.baseDir, progress, *runtimesCSV)
		}
		if *jsonOut {
			result := map[string]any{"ok": err == nil, "browsers": states}
			if err != nil {
				result["error"] = err.Error()
			}
			_ = writeJSON(stdout, result)
		}
		if err != nil {
			fmt.Fprintf(stderr, "browsers install failed: %v\n", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(stderr, "unknown browsers subcommand: %s\n", subcmd)
		return 2
	}
}

func withStdoutRedirect(w io.Writer, fn func() error) error {
	old := os.Stdout
	r, pipeW, err := os.Pipe()
	if err != nil {
		return err
	}
	os.Stdout = pipeW
	defer func() { os.Stdout = old }()
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(w, r)
		close(done)
	}()
	runErr := fn()
	_ = pipeW.Close()
	<-done
	_ = r.Close()
	return runErr
}

func collectBrowserStates(baseDir string) []browserState {
	camoufoxInstalled := browser.InstalledVersion(baseDir, "camoufox")
	camoufoxSupport := browser.CurrentRuntimeSupport("camoufox")
	camoufoxPath := browser.FindBinary(baseDir, "camoufox")
	cloakSupport := browser.CurrentRuntimeSupport("cloakbrowser")
	cloakInstalled := browser.InstalledVersion(baseDir, "cloakbrowser")
	cloakPath := browser.FindBinary(baseDir, "cloakbrowser")
	browseForgeChromiumSupport := browser.CurrentRuntimeSupport(browser.BrowseForgeChromiumRuntimeID)
	browseForgeChromiumInstalled := browser.InstalledVersion(baseDir, browser.BrowseForgeChromiumRuntimeID)
	browseForgeChromiumPath := browser.FindBinary(baseDir, browser.BrowseForgeChromiumRuntimeID)
	return []browserState{
		{
			Name: "camoufox", Expected: browser.CamoufoxVersion, Installed: camoufoxInstalled,
			Path: camoufoxPath, Ready: camoufoxSupport.PlatformSupported && camoufoxInstalled == browser.CamoufoxVersion && camoufoxPath != "",
			PlatformSupported: camoufoxSupport.PlatformSupported, UnsupportedReason: camoufoxSupport.UnsupportedReason,
		},
		{
			Name: "cloakbrowser", Expected: cloakSupport.Version, Installed: cloakInstalled,
			Path: cloakPath, Ready: cloakSupport.PlatformSupported && cloakInstalled == cloakSupport.Version && cloakPath != "",
			PlatformSupported: cloakSupport.PlatformSupported, UnsupportedReason: cloakSupport.UnsupportedReason,
		},
		{
			Name: browser.BrowseForgeChromiumRuntimeID, Expected: browseForgeChromiumSupport.Version, Installed: browseForgeChromiumInstalled,
			Path: browseForgeChromiumPath, Ready: browseForgeChromiumSupport.PlatformSupported && browseForgeChromiumInstalled == browseForgeChromiumSupport.Version && browseForgeChromiumPath != "",
			PlatformSupported: browseForgeChromiumSupport.PlatformSupported, UnsupportedReason: browseForgeChromiumSupport.UnsupportedReason,
		},
	}
}

func parseRuntimeSelection(runtimesCSV string) (map[string]bool, error) {
	selection := map[string]bool{}
	if strings.TrimSpace(runtimesCSV) == "" {
		return selection, nil
	}
	for _, raw := range strings.Split(runtimesCSV, ",") {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		switch name {
		case "camoufox", "cloakbrowser", browser.BrowseForgeChromiumRuntimeID:
			selection[name] = true
		default:
			return nil, fmt.Errorf("unsupported browser runtime %q", name)
		}
	}
	return selection, nil
}

func selectBrowserStates(states []browserState, runtimesCSV string) []browserState {
	selection, err := parseRuntimeSelection(runtimesCSV)
	if err != nil || len(selection) == 0 {
		return states
	}
	out := make([]browserState, 0, len(selection))
	for _, state := range states {
		if selection[state.Name] {
			out = append(out, state)
		}
	}
	return out
}

func browsersReady(states []browserState) bool {
	for _, state := range states {
		if !state.Ready {
			return false
		}
	}
	return true
}

func installBrowsers(baseDir string, stdout io.Writer, runtimesCSV string) ([]browserState, error) {
	if err := os.MkdirAll(filepath.Join(baseDir, "browsers"), 0755); err != nil {
		return selectBrowserStates(collectBrowserStates(baseDir), runtimesCSV), err
	}
	selection, err := parseRuntimeSelection(runtimesCSV)
	if err != nil {
		return selectBrowserStates(collectBrowserStates(baseDir), runtimesCSV), err
	}
	shouldInstall := func(name string) bool {
		return len(selection) == 0 || selection[name]
	}
	for _, state := range collectBrowserStates(baseDir) {
		if !shouldInstall(state.Name) || state.Ready {
			continue
		}
		if !state.PlatformSupported {
			fmt.Fprintf(stdout, "Skipping %s: %s\n", state.Name, state.UnsupportedReason)
			if len(selection) == 1 && selection[state.Name] {
				return selectBrowserStates(collectBrowserStates(baseDir), runtimesCSV), fmt.Errorf("%s: %w", state.UnsupportedReason, browser.ErrUnsupportedRuntimePlatform)
			}
			continue
		}
		switch state.Name {
		case "camoufox":
			fmt.Fprintln(stdout, "Installing Camoufox...")
			if _, err := browser.DownloadCamoufox(baseDir); err != nil {
				return selectBrowserStates(collectBrowserStates(baseDir), runtimesCSV), err
			}
		case "cloakbrowser":
			fmt.Fprintln(stdout, "Installing CloakBrowser...")
			if _, err := browser.DownloadCloakBrowser(baseDir); err != nil {
				return selectBrowserStates(collectBrowserStates(baseDir), runtimesCSV), err
			}
		case browser.BrowseForgeChromiumRuntimeID:
			fmt.Fprintln(stdout, "Installing BrowseForge Chromium...")
			if _, err := browser.DownloadBrowseForgeChromium(baseDir); err != nil {
				return selectBrowserStates(collectBrowserStates(baseDir), runtimesCSV), err
			}
		}
	}
	return selectBrowserStates(collectBrowserStates(baseDir), runtimesCSV), nil
}

func runBackupCommand(args []string, global cliGlobal, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "backup requires subcommand: create or restore")
		return 2
	}
	subcmd := args[0]
	fs := newFlagSet("backup "+subcmd, stderr)
	full := fs.Bool("full", true, "Use filesystem backup including profiles, data, browsers, and logs")
	metadata := fs.Bool("metadata", false, "Use REST metadata backup")
	output := fs.String("output", "", "Output file or directory for backup create")
	baseURL := fs.String("base-url", "", "BrowseForge base URL for metadata backup")
	token := fs.String("token", "", "Bearer token for metadata backup")
	jsonOut := fs.Bool("json", false, "Write JSON output")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *metadata {
		*full = false
	}
	switch subcmd {
	case "create":
		if fs.NArg() != 0 {
			fmt.Fprintf(stderr, "backup create does not accept positional arguments: %s\n", strings.Join(fs.Args(), " "))
			return 2
		}
		path, err := createBackup(global, *full, *output, *baseURL, *token)
		if *jsonOut {
			_ = writeJSON(stdout, map[string]any{"ok": err == nil, "path": path, "full": *full, "error": errorString(err)})
		} else if err == nil {
			fmt.Fprintf(stdout, "Backup written: %s\n", path)
		}
		if err != nil {
			fmt.Fprintf(stderr, "backup create failed: %v\n", err)
			return 1
		}
		return 0
	case "restore":
		if fs.NArg() != 1 {
			fmt.Fprintln(stderr, "backup restore requires exactly one backup file")
			return 2
		}
		err := restoreBackup(global, fs.Arg(0), *full, *baseURL, *token)
		if *jsonOut {
			_ = writeJSON(stdout, map[string]any{"ok": err == nil, "path": fs.Arg(0), "full": *full, "error": errorString(err)})
		} else if err == nil {
			fmt.Fprintf(stdout, "Backup restored: %s\n", fs.Arg(0))
		}
		if err != nil {
			fmt.Fprintf(stderr, "backup restore failed: %v\n", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(stderr, "unknown backup subcommand: %s\n", subcmd)
		return 2
	}
}

func createBackup(global cliGlobal, full bool, output, baseURL, token string) (string, error) {
	if output == "" {
		output = filepath.Join(global.baseDir, "backups")
	}
	if full {
		path := backupOutputPath(output, "browseforge-runtime-", ".tgz")
		return path, createFullBackup(global.baseDir, path)
	}
	path := backupOutputPath(output, "browseforge-api-backup-", ".zip")
	return path, createMetadataBackup(global, path, baseURL, token)
}

func restoreBackup(global cliGlobal, path string, full bool, baseURL, token string) error {
	if full {
		return restoreFullBackup(global.baseDir, path)
	}
	return restoreMetadataBackup(global, path, baseURL, token)
}

func backupOutputPath(output, prefix, suffix string) string {
	name := prefix + time.Now().Format("20060102-150405") + suffix
	if output == "" {
		return filepath.Join("backups", name)
	}
	if info, err := os.Stat(output); err == nil && info.IsDir() {
		return filepath.Join(output, name)
	}
	if strings.HasSuffix(output, string(os.PathSeparator)) || filepath.Ext(output) == "" {
		return filepath.Join(output, name)
	}
	return output
}

func createFullBackup(baseDir, output string) error {
	if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
		return err
	}
	out, err := os.Create(output)
	if err != nil {
		return err
	}
	defer out.Close()
	gw := gzip.NewWriter(out)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()
	for _, name := range []string{"profiles", "data", "browsers", "logs"} {
		root := filepath.Join(baseDir, name)
		if _, err := os.Stat(root); os.IsNotExist(err) {
			continue
		}
		if err := addPathToTar(tw, baseDir, root); err != nil {
			return err
		}
	}
	return nil
}

func addPathToTar(tw *tar.Writer, baseDir, root string) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			header, err = tar.FileInfoHeader(info, link)
			if err != nil {
				return err
			}
		}
		rel, err := filepath.Rel(baseDir, path)
		if err != nil {
			return err
		}
		header.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if d.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		in, err := os.Open(path)
		if err != nil {
			return err
		}
		defer in.Close()
		_, err = io.Copy(tw, in)
		return err
	})
}

func restoreFullBackup(baseDir, path string) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()
	gr, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	allowed := map[string]bool{"profiles": true, "data": true, "browsers": true, "logs": true}
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		clean, err := safeBackupPath(header.Name)
		if err != nil {
			return fmt.Errorf("unsafe backup path: %s", header.Name)
		}
		first := strings.Split(clean, string(os.PathSeparator))[0]
		if !allowed[first] {
			return fmt.Errorf("unexpected backup path: %s", header.Name)
		}
		target := filepath.Join(baseDir, clean)
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			out.Close()
		case tar.TypeSymlink:
			if _, err := safeBackupPath(header.Linkname); err != nil {
				return fmt.Errorf("unsafe backup symlink target: %s", header.Linkname)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			_ = os.Remove(target)
			if err := os.Symlink(header.Linkname, target); err != nil {
				return err
			}
		}
	}
	return nil
}

func safeBackupPath(name string) (string, error) {
	clean := filepath.Clean(name)
	if clean == "." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) || clean == ".." || filepath.IsAbs(clean) {
		return "", fmt.Errorf("unsafe path")
	}
	return clean, nil
}

func createMetadataBackup(global cliGlobal, output, baseURL, token string) error {
	cfg, err := config.Load(global.configPath)
	if err != nil && baseURL == "" {
		return err
	}
	resolvedBase := resolveBaseURL(baseURL, cfg)
	resolvedToken := token
	if resolvedToken == "" {
		resolvedToken, _, err = readToken(global.configPath, global.baseDir)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequest(http.MethodPost, resolvedBase+"/api/backup", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+resolvedToken)
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
		return err
	}
	out, err := os.Create(output)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

func restoreMetadataBackup(global cliGlobal, path, baseURL, token string) error {
	cfg, err := config.Load(global.configPath)
	if err != nil && baseURL == "" {
		return err
	}
	resolvedBase := resolveBaseURL(baseURL, cfg)
	resolvedToken := token
	if resolvedToken == "" {
		resolvedToken, _, err = readToken(global.configPath, global.baseDir)
		if err != nil {
			return err
		}
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", filepath.Base(path))
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if _, err := part.Write(data); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, resolvedBase+"/api/restore", &body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+resolvedToken)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	_, err = doJSON(req)
	return err
}

func configDefaults() *config.Config {
	return &config.Config{Host: "127.0.0.1", Port: "19280", ProfilesDir: "profiles", DataDir: "data", LogFile: "logs/server.log", FingerprintDir: "data"}
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
