package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"browseforge/internal/api"
	"browseforge/internal/browser"
	"browseforge/internal/config"
	"browseforge/internal/fingerprint"
	"browseforge/internal/groups"
	"browseforge/internal/humanize"
	"browseforge/internal/mcp"
	"browseforge/internal/profile"
	"browseforge/internal/workflow"
)

var Version = "dev"

func main() {
	os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr))
}

// serveFlags holds CLI overrides for serve mode
type serveFlags struct {
	baseDir      string
	configPath   string
	host         string
	port         string
	noSandbox    bool
	noOpen       bool
	pauseOnError bool
}

func isDocker() bool {
	_, err := os.Stat("/.dockerenv")
	return err == nil
}

func runMCPStdio(opts mcpStdioOptions) {
	baseDir := opts.baseDir
	if err := os.Chdir(baseDir); err != nil {
		fmt.Fprintf(os.Stderr, "Chdir error: %v\n", err)
		os.Exit(1)
	}
	if err := os.MkdirAll("profiles", 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Create profiles dir error: %v\n", err)
		os.Exit(1)
	}
	if err := os.MkdirAll("data", 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Create data dir error: %v\n", err)
		os.Exit(1)
	}

	// Reuse existing config (don't download browsers in MCP mode)
	if _, err := os.Stat(opts.configPath); os.IsNotExist(err) {
		if err := writeDefaultConfig(opts.configPath, baseDir, false); err != nil {
			fmt.Fprintf(os.Stderr, "Config init error: %v\n", err)
			os.Exit(1)
		}
	}

	cfg, err := config.Load(opts.configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
		os.Exit(1)
	}
	cfg.Version = Version
	groupStore, err := groups.NewStore(cfg.DataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Group store error: %v\n", err)
		os.Exit(1)
	}
	profileStore, err := profile.NewStore(cfg.ProfilesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Profile store error: %v\n", err)
		os.Exit(1)
	}
	browserMgr, err := browser.NewManager(cfg, groupStore)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Browser manager error: %v\n", err)
		os.Exit(1)
	}
	defer browserMgr.Close()

	sessionPool, err := mcp.NewSessionPool(browserMgr, profileStore)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Web session pool warning: %v\n", err)
	}
	if sessionPool != nil {
		stopGC := sessionPool.StartGC(sessionPool.SweepInterval())
		defer stopGC()
		defer sessionPool.CloseAll()
	}

	mcpServer := mcp.NewServer(profileStore, browserMgr, buildHumanizeCfg(cfg), sessionPool, "", cfg.Version, groupStore)
	mcpServer.SetPublicBaseURL(cfg.PublicBaseURL)
	mcpServer.SetScreenshotArtifactDir(filepath.Join(cfg.DataDir, "screenshots"))
	mcpServer.RunStdio()
}

func runServer(flags *serveFlags) {
	if flags == nil {
		baseDir, err := defaultBaseDir()
		if err != nil {
			exitServerError(flags, "Executable path error: %v", err)
		}
		flags = &serveFlags{baseDir: baseDir, configPath: filepath.Join(baseDir, "config.json")}
	}
	// Auto-detect base directory (where the binary lives)
	baseDir := flags.baseDir
	if err := os.Chdir(baseDir); err != nil {
		exitServerError(flags, "Chdir error: %v", err)
	}

	// Auto-create directories
	if err := os.MkdirAll("profiles", 0755); err != nil {
		exitServerError(flags, "Create profiles dir error: %v", err)
	}
	if err := os.MkdirAll("data", 0755); err != nil {
		exitServerError(flags, "Create data dir error: %v", err)
	}
	if err := os.MkdirAll("logs", 0755); err != nil {
		exitServerError(flags, "Create logs dir error: %v", err)
	}

	// Load config once
	cfg, err := config.Load(flags.configPath)
	if err != nil {
		exitServerError(flags, "Config error: %v", err)
	}
	cfg.Version = Version
	groupStore, err := groups.NewStore(cfg.DataDir)
	if err != nil {
		exitServerError(flags, "Group store error: %v", err)
	}

	// Docker auto-detection
	if isDocker() {
		if cfg.Host == "127.0.0.1" {
			cfg.Host = "0.0.0.0"
		}
		if !cfg.NoSandbox {
			cfg.NoSandbox = true
		}
	}

	// CLI flags override config
	if flags != nil {
		if flags.host != "" {
			cfg.Host = flags.host
		}
		if flags.port != "" {
			cfg.Port = flags.port
		}
		if flags.noSandbox {
			cfg.NoSandbox = true
		}
	}

	// Setup logger (stdout in Docker, file otherwise)
	if isDocker() {
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	} else {
		logger := config.SetupLogger(cfg.LogFile)
		slog.SetDefault(logger)
	}

	// Find or download browser runtimes that are both configured and supported on
	// the current OS/architecture. A BrowseForge release can target more
	// platforms than a specific browser runtime release; unsupported runtimes are
	// disabled instead of blocking server startup.
	if cfg.Runtimes == nil {
		cfg.Runtimes = map[string]config.RuntimeConfig{}
	}
	runtimeEnabled := func(id string, fallback bool) bool {
		raw := cfg.Runtimes[id]
		if raw.Enabled != nil {
			return *raw.Enabled
		}
		return fallback || raw.BinaryPath != ""
	}
	runtimeSkipAutoUpdate := func(id string) bool {
		raw := cfg.Runtimes[id]
		if raw.SkipAutoUpdate {
			return true
		}
		if envBool("BROWSEFORGE_SKIP_BROWSER_AUTO_UPDATE") {
			return true
		}
		envName := "BROWSEFORGE_SKIP_" + strings.ToUpper(strings.NewReplacer("-", "_").Replace(id)) + "_AUTO_UPDATE"
		return envBool(envName)
	}
	ensureRuntime := func(id, label string, fallbackEnabled bool, download func(string) (string, error)) (string, bool) {
		support := browser.CurrentRuntimeSupport(id)
		enabled := runtimeEnabled(id, fallbackEnabled)
		if !support.PlatformSupported {
			if enabled {
				fmt.Printf("Skipping %s: %s\n", label, support.UnsupportedReason)
			}
			return "", false
		}
		if !enabled {
			return cfg.Runtimes[id].BinaryPath, false
		}
		path := ""
		installed := browser.InstalledVersion(baseDir, id)
		skipUpdate := runtimeSkipAutoUpdate(id)
		if installed == support.Version {
			path = existingRuntimeBinaryPath(cfg.Runtimes[id].BinaryPath)
			if path == "" {
				path = browser.FindBinary(baseDir, id)
			}
			if path != "" {
				return path, true
			}
			if skipUpdate {
				exitServerError(flags, "%s auto-update is disabled but no installed binary was found", label)
			}
		} else if skipUpdate {
			path = existingRuntimeBinaryPath(cfg.Runtimes[id].BinaryPath)
			if path == "" {
				path = browser.FindBinary(baseDir, id)
			}
			if path == "" {
				exitServerError(flags, "%s auto-update is disabled but no installed binary was found", label)
			}
			if installed == "" {
				fmt.Printf("%s version marker missing, but auto-update is disabled; using configured or discovered binary.\n", label)
			} else {
				fmt.Printf("%s update available (%s → %s), but auto-update is disabled; using installed binary.\n", label, installed, support.Version)
			}
			return path, true
		}
		if path != "" {
			return path, true
		}
		if installed == "" {
			fmt.Printf("%s not found. Downloading...\n", label)
		} else {
			fmt.Printf("%s update available (%s → %s). Downloading...\n", label, installed, support.Version)
		}
		var err error
		path, err = download(baseDir)
		if err != nil {
			slog.Error("download "+label, "error", err)
			exitServerError(flags, "Download %s error: %v", label, err)
		}
		return path, true
	}

	camoufoxPath, camoufoxEnabled := ensureRuntime("camoufox", "Camoufox", true, browser.DownloadCamoufox)
	cloakPath, cloakEnabled := ensureRuntime("cloakbrowser", "CloakBrowser", false, browser.DownloadCloakBrowser)
	browseForgeChromiumPath, browseForgeChromiumEnabled := ensureRuntime(browser.BrowseForgeChromiumRuntimeID, "BrowseForge Chromium", true, browser.DownloadBrowseForgeChromium)

	camoufoxRuntime := cfg.Runtimes["camoufox"]
	cloakRuntime := cfg.Runtimes["cloakbrowser"]
	browseForgeChromiumRuntime := cfg.Runtimes[browser.BrowseForgeChromiumRuntimeID]
	configChanged := false
	updateRuntime := func(id, path, family, display string, enabled bool, raw *config.RuntimeConfig) {
		if raw.BinaryPath != path || raw.Enabled == nil || *raw.Enabled != enabled || raw.Family != family || raw.DisplayName != display {
			raw.BinaryPath = path
			raw.Enabled = &enabled
			raw.Family = family
			raw.DisplayName = display
			cfg.Runtimes[id] = *raw
			configChanged = true
		}
	}
	updateRuntime("camoufox", camoufoxPath, "firefox", "Camoufox", camoufoxEnabled, &camoufoxRuntime)
	updateRuntime("cloakbrowser", cloakPath, "chromium", "CloakBrowser", cloakEnabled, &cloakRuntime)
	if browseForgeChromiumRuntime.Settings == nil {
		browseForgeChromiumRuntime.Settings = &config.CloakBrowserConfig{FingerprintPlatform: "auto", TargetPlatformPolicy: "warn", ExtraArgs: []string{}}
	}
	updateRuntime(browser.BrowseForgeChromiumRuntimeID, browseForgeChromiumPath, "chromium", "BrowseForge Chromium", browseForgeChromiumEnabled, &browseForgeChromiumRuntime)
	if cloakRuntime.Settings == nil {
		cloakRuntime.Settings = &config.CloakBrowserConfig{FingerprintPlatform: "auto", TargetPlatformPolicy: "warn", ExtraArgs: []string{}}
		cfg.Runtimes["cloakbrowser"] = cloakRuntime
		configChanged = true
	}
	defaultReady := func(id string) bool {
		raw, ok := cfg.Runtimes[id]
		return ok && raw.Enabled != nil && *raw.Enabled && raw.BinaryPath != ""
	}
	if !defaultReady(cfg.DefaultRuntimeID) {
		for _, id := range []string{browser.BrowseForgeChromiumRuntimeID, "camoufox", "cloakbrowser"} {
			if defaultReady(id) {
				cfg.DefaultRuntimeID = id
				configChanged = true
				break
			}
		}
	}
	if !defaultReady(cfg.DefaultRuntimeID) && !cfg.AllowEmptyRuntime {
		exitServerError(flags, "No supported browser runtime is available for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	if configChanged {
		cfgJSON, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			slog.Error("config encode", "error", err)
			exitServerError(flags, "Config encode error: %v", err)
		}
		if err := os.WriteFile(flags.configPath, cfgJSON, 0644); err != nil {
			slog.Error("config write", "error", err)
			exitServerError(flags, "Config write error: %v", err)
		}
	}

	profileStore, err := profile.NewStore(cfg.ProfilesDir)
	if err != nil {
		slog.Error("profile store", "error", err)
		exitServerError(flags, "Profile store error: %v", err)
	}

	fpPool, _ := fingerprint.NewPool(cfg.FingerprintDir)

	browserMgr, err := browser.NewManager(cfg, groupStore)
	if err != nil {
		slog.Error("browser manager", "error", err)
		exitServerError(flags, "Browser manager error: %v", err)
	}
	defer browserMgr.Close()

	router, err := api.NewRouter(cfg, profileStore, browserMgr, fpPool, groupStore)
	if err != nil {
		slog.Error("api router", "error", err)
		exitServerError(flags, "API router error: %v", err)
	}

	// Web Search & Explore agent sessions (profile browser + Playwright Bind + independent pages)
	sessionPool, err := mcp.NewSessionPool(browserMgr, profileStore)
	if err != nil {
		slog.Warn("web session pool not available", "error", err)
	} else {
		stopGC := sessionPool.StartGC(sessionPool.SweepInterval())
		defer stopGC()
		defer sessionPool.CloseAll()
	}

	// Workflow engine
	wfEngine := workflow.NewEngine("http://127.0.0.1:"+cfg.Port, cfg.APIToken)
	router.Post("/api/workflow/run", api.WorkflowHandler(wfEngine))

	// MCP Server (same HTTP service port, integrated with the main router)
	mcpServer := mcp.NewServer(profileStore, browserMgr, buildHumanizeCfg(cfg), sessionPool, cfg.APIToken, cfg.Version, groupStore)
	mcpServer.SetWorkflowEngine(wfEngine)
	mcpServer.SetPublicBaseURL(cfg.PublicBaseURL)
	mcpServer.SetScreenshotArtifactDir(filepath.Join(cfg.DataDir, "screenshots"))
	router.Post("/mcp", mcpServer.ServeHTTP)
	router.Get("/api/screenshots/{id}", mcpServer.ServeScreenshotArtifact)

	// HTTP Server with error channel (no os.Exit in goroutine)
	srv := &http.Server{Addr: cfg.Host + ":" + cfg.Port, Handler: router}
	serverErr := make(chan error, 1)

	go func() {
		slog.Info("server starting", "host", cfg.Host, "port", cfg.Port)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	// Wait for server ready, then show info
	go func() {
		for i := 0; i < 30; i++ {
			resp, err := http.Get("http://127.0.0.1:" + cfg.Port + "/api/status")
			if err == nil && resp.StatusCode == 200 {
				resp.Body.Close()
				token := cfg.APIToken
				fmt.Println("╔══════════════════════════════════════════╗")
				fmt.Printf("║        🦊 BrowseForge v%-16s║\n", Version)
				fmt.Println("╠══════════════════════════════════════════╣")
				fmt.Printf("║  Dashboard: http://%s:%-12s║\n", cfg.Host, cfg.Port)
				fmt.Printf("║  MCP:       http://%s:%-12s║\n", cfg.Host, cfg.Port+"/mcp")
				fmt.Printf("║  Token:     %s...  ║\n", tokenPreview(token))
				fmt.Println("╚══════════════════════════════════════════╝")
				if cfg.Host == "127.0.0.1" && !flags.noOpen {
					openBrowser(fmt.Sprintf("http://127.0.0.1:%s#%s", cfg.Port, token))
				}
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
	}()

	// Wait for shutdown signal or server error
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-quit:
		fmt.Println("\nShutting down...")
	case err := <-serverErr:
		exitServerError(flags, "%s", formatListenError(err, cfg.Host, cfg.Port))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}

func exitServerError(flags *serveFlags, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Server failed: "+format+"\n", args...)
	maybePauseAfterServerError(flags)
	os.Exit(1)
}

func maybePauseAfterServerError(flags *serveFlags) {
	if flags == nil || !flags.pauseOnError || runtime.GOOS != "windows" {
		return
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprint(os.Stderr, "Press Enter to close this window...")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}

func formatListenError(err error, host, port string) string {
	message := fmt.Sprintf("could not listen on %s:%s: %v", host, port, err)
	if isPortInUseError(err) {
		return fmt.Sprintf("%s\nPort %s is already in use. Close the other BrowseForge instance or start BrowseForge with a different port, for example: BrowseForge serve --port %s", message, port, nextPortSuggestion(port))
	}
	return message
}

func existingRuntimeBinaryPath(path string) string {
	if path == "" {
		return ""
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return ""
	}
	return path
}

func envBool(name string) bool {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return false
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false
	}
	return parsed
}

func nextPortSuggestion(port string) string {
	n, err := strconv.Atoi(port)
	if err != nil || n <= 0 || n >= 65535 {
		return "19281"
	}
	return strconv.Itoa(n + 1)
}

func isPortInUseError(err error) bool {
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "address already in use") ||
		strings.Contains(text, "only one usage of each socket address") ||
		strings.Contains(text, "bind: address already in use")
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func tokenPreview(token string) string {
	if len(token) <= 16 {
		return token
	}
	return token[:16]
}

// openBrowser opens URL in the default system browser
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	}
	if cmd != nil {
		cmd.Start()
	}
}

func buildHumanizeCfg(cfg *config.Config) humanize.Config {
	if cfg.Humanize == nil {
		return humanize.DefaultConfig()
	}
	return humanize.ConfigFromRaw(cfg.Humanize.Enabled, cfg.Humanize.MouseSpeed, cfg.Humanize.TypingCPM, cfg.Humanize.TypoRate, cfg.Humanize.ScrollStyle)
}
