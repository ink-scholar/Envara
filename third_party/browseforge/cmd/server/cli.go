package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"browseforge/internal/browser"
	"browseforge/internal/config"
	"browseforge/internal/workflow"
)

type cliGlobal struct {
	baseDir    string
	configPath string
}

type mcpStdioOptions struct {
	baseDir    string
	configPath string
}

type doctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

type doctorReport struct {
	Version string        `json:"version"`
	BaseDir string        `json:"base_dir"`
	Checks  []doctorCheck `json:"checks"`
	OK      bool          `json:"ok"`
}

const usageText = `BrowseForge CLI

Usage:
  BrowseForge [global flags] serve [--host HOST] [--port PORT] [--no-sandbox] [--no-open]
  BrowseForge [global flags] mcp-stdio
  BrowseForge --mcp
  BrowseForge [global flags] init [--force] [--json]
  BrowseForge [global flags] config show|validate [--json]
  BrowseForge [global flags] token [--json]
  BrowseForge [global flags] doctor [--strict] [--json]
  BrowseForge [global flags] status [--base-url URL] [--token TOKEN] [--json]
  BrowseForge [global flags] capabilities [--json]
  BrowseForge [global flags] open [--base-url URL]
  BrowseForge [global flags] mcp-config stdio|http [--url URL] [--token TOKEN] [--json]
  BrowseForge [global flags] browsers status|install [--json]
  BrowseForge [global flags] playwright install-driver
  BrowseForge [global flags] backup create|restore [--full|--metadata] [--output PATH] [--base-url URL] [--token TOKEN] [--json]
  BrowseForge [global flags] smoke rest|mcp [--base-url URL] [--token TOKEN] [--wait] [--timeout DURATION] [--json]
  BrowseForge [global flags] workflow run FILE [--base-url URL] [--token TOKEN] [--json]
  BrowseForge [global flags] profiles list [--base-url URL] [--token TOKEN] [--json]
  BrowseForge [global flags] sessions list [--base-url URL] [--token TOKEN] [--json]

Global flags:
  --base-dir DIR     Runtime directory for config, profiles, data, logs, and browsers.
  --config PATH     Config file path relative to base dir or absolute. Default: config.json.
  --help, -h        Show help.
  --version         Show version.
`

func runCLI(args []string, stdout, stderr io.Writer) int {
	global, rest, err := parseGlobalFlags(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprint(stderr, usageText)
		return 2
	}
	if len(rest) == 0 {
		runServer(&serveFlags{baseDir: global.baseDir, configPath: global.configPath, pauseOnError: true})
		return 0
	}
	if hasHelpFlag(rest[1:]) {
		fmt.Fprint(stdout, usageText)
		return 0
	}

	switch rest[0] {
	case "--help", "-h", "help":
		fmt.Fprint(stdout, usageText)
		return 0
	case "--version", "version":
		fmt.Fprintf(stdout, "BrowseForge %s\n", Version)
		return 0
	case "--mcp", "mcp-stdio":
		opts, err := parseMCPStdioFlags(rest[1:], global)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		runMCPStdio(opts)
		return 0
	case "serve":
		flags, err := parseServeFlags(rest[1:], global)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		runServer(flags)
		return 0
	case "init":
		return runInitCommand(rest[1:], global, stdout, stderr)
	case "config":
		return runConfigCommand(rest[1:], global, stdout, stderr)
	case "token":
		return runTokenCommand(rest[1:], global, stdout, stderr)
	case "doctor":
		return runDoctorCommand(rest[1:], global, stdout, stderr)
	case "status":
		return runStatusCommand(rest[1:], global, stdout, stderr)
	case "capabilities":
		return runCapabilitiesCommand(rest[1:], stdout, stderr)
	case "open":
		return runOpenCommand(rest[1:], global, stdout, stderr)
	case "mcp-config":
		return runMCPConfigCommand(rest[1:], global, stdout, stderr)
	case "browsers":
		return runBrowsersCommand(rest[1:], global, stdout, stderr)
	case "playwright":
		return runPlaywrightCommand(rest[1:], stdout, stderr)
	case "backup":
		return runBackupCommand(rest[1:], global, stdout, stderr)
	case "smoke":
		return runSmokeCommand(rest[1:], global, stdout, stderr)
	case "migrate":
		return runMigrateCommand(rest[1:], global, stdout, stderr)
	case "workflow":
		return runWorkflowCommand(rest[1:], global, stdout, stderr)
	case "profiles":
		return runAPIListCommand("profiles", rest[1:], global, stdout, stderr)
	case "sessions":
		return runAPIListCommand("sessions", rest[1:], global, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "Unknown command: %s\n", rest[0])
		fmt.Fprint(stderr, usageText)
		return 2
	}
}

func hasHelpFlag(args []string) bool {
	for _, arg := range args {
		if arg == "--help" || arg == "-h" {
			return true
		}
	}
	return false
}

func parseGlobalFlags(args []string) (cliGlobal, []string, error) {
	baseDir, err := defaultBaseDir()
	if err != nil {
		return cliGlobal{}, nil, err
	}
	global := cliGlobal{baseDir: baseDir, configPath: "config.json"}
	var rest []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--base-dir":
			i++
			if i >= len(args) {
				return global, nil, errors.New("--base-dir requires a value")
			}
			global.baseDir = args[i]
		case strings.HasPrefix(arg, "--base-dir="):
			global.baseDir = strings.TrimPrefix(arg, "--base-dir=")
		case arg == "--config":
			i++
			if i >= len(args) {
				return global, nil, errors.New("--config requires a value")
			}
			global.configPath = args[i]
		case strings.HasPrefix(arg, "--config="):
			global.configPath = strings.TrimPrefix(arg, "--config=")
		default:
			rest = args[i:]
			i = len(args)
		}
	}
	if global.baseDir == "" {
		return global, nil, errors.New("--base-dir cannot be empty")
	}
	if !filepath.IsAbs(global.baseDir) {
		abs, err := filepath.Abs(global.baseDir)
		if err != nil {
			return global, nil, err
		}
		global.baseDir = abs
	}
	global.configPath = resolvePath(global.baseDir, global.configPath)
	return global, rest, nil
}

func defaultBaseDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("executable path error: %w", err)
	}
	return filepath.Dir(exe), nil
}

func resolvePath(baseDir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

func parseServeFlags(args []string, global cliGlobal) (*serveFlags, error) {
	fs := newFlagSet("serve", io.Discard)
	f := &serveFlags{baseDir: global.baseDir, configPath: global.configPath}
	fs.StringVar(&f.host, "host", "", "Listen address")
	fs.StringVar(&f.port, "port", "", "API port")
	fs.BoolVar(&f.noSandbox, "no-sandbox", false, "Disable Chromium sandbox")
	fs.BoolVar(&f.noOpen, "no-open", false, "Do not open the dashboard browser")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, fmt.Errorf("serve does not accept positional arguments: %s", strings.Join(fs.Args(), " "))
	}
	return f, nil
}

func parseMCPStdioFlags(args []string, global cliGlobal) (mcpStdioOptions, error) {
	fs := newFlagSet("mcp-stdio", io.Discard)
	opts := mcpStdioOptions{baseDir: global.baseDir, configPath: global.configPath}
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	if fs.NArg() != 0 {
		return opts, fmt.Errorf("mcp-stdio does not accept positional arguments: %s", strings.Join(fs.Args(), " "))
	}
	return opts, nil
}

func runInitCommand(args []string, global cliGlobal, stdout, stderr io.Writer) int {
	fs := newFlagSet("init", stderr)
	force := fs.Bool("force", false, "Overwrite existing config")
	jsonOut := fs.Bool("json", false, "Write JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "init does not accept positional arguments: %s\n", strings.Join(fs.Args(), " "))
		return 2
	}
	if err := ensureRuntimeDirs(global.baseDir); err != nil {
		fmt.Fprintf(stderr, "init failed: %v\n", err)
		return 1
	}
	if err := writeDefaultConfig(global.configPath, global.baseDir, *force); err != nil {
		fmt.Fprintf(stderr, "init failed: %v\n", err)
		return 1
	}
	result := map[string]any{"ok": true, "config": global.configPath, "base_dir": global.baseDir}
	if *jsonOut {
		_ = writeJSON(stdout, result)
	} else {
		fmt.Fprintf(stdout, "Initialized BrowseForge runtime at %s\nConfig: %s\n", global.baseDir, global.configPath)
	}
	return 0
}

func runConfigCommand(args []string, global cliGlobal, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "config requires subcommand: show or validate")
		return 2
	}
	subcmd := args[0]
	fs := newFlagSet("config "+subcmd, stderr)
	jsonOut := fs.Bool("json", false, "Write JSON output")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "config %s does not accept positional arguments: %s\n", subcmd, strings.Join(fs.Args(), " "))
		return 2
	}

	cfg, err := config.Load(global.configPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return 1
	}
	switch subcmd {
	case "show":
		if *jsonOut {
			_ = writeJSON(stdout, cfg)
		} else {
			_ = writeJSON(stdout, cfg)
		}
		return 0
	case "validate":
		if err := validateConfig(cfg); err != nil {
			if *jsonOut {
				_ = writeJSON(stdout, map[string]any{"ok": false, "error": err.Error(), "config": global.configPath})
			} else {
				fmt.Fprintf(stderr, "Config invalid: %v\n", err)
			}
			return 1
		}
		if *jsonOut {
			_ = writeJSON(stdout, map[string]any{"ok": true, "config": global.configPath})
		} else {
			fmt.Fprintf(stdout, "Config valid: %s\n", global.configPath)
		}
		return 0
	default:
		fmt.Fprintf(stderr, "unknown config subcommand: %s\n", subcmd)
		return 2
	}
}

func runTokenCommand(args []string, global cliGlobal, stdout, stderr io.Writer) int {
	fs := newFlagSet("token", stderr)
	jsonOut := fs.Bool("json", false, "Write JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "token does not accept positional arguments: %s\n", strings.Join(fs.Args(), " "))
		return 2
	}
	token, path, err := readToken(global.configPath, global.baseDir)
	if err != nil {
		if *jsonOut {
			_ = writeJSON(stdout, map[string]any{"ok": false, "error": err.Error(), "path": path})
		} else {
			fmt.Fprintln(stderr, "Token not found. Start the server first.")
		}
		return 1
	}
	if *jsonOut {
		_ = writeJSON(stdout, map[string]any{"ok": true, "token": token, "path": path})
	} else {
		fmt.Fprintln(stdout, token)
	}
	return 0
}

func runDoctorCommand(args []string, global cliGlobal, stdout, stderr io.Writer) int {
	fs := newFlagSet("doctor", stderr)
	strict := fs.Bool("strict", false, "Treat missing runtime dependencies as failures")
	jsonOut := fs.Bool("json", false, "Write JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "doctor does not accept positional arguments: %s\n", strings.Join(fs.Args(), " "))
		return 2
	}
	report := buildDoctorReport(global, *strict)
	if *jsonOut {
		_ = writeJSON(stdout, report)
	} else {
		printDoctorReport(stdout, report)
	}
	if !report.OK {
		return 1
	}
	return 0
}
func runPlaywrightCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || args[0] != "install-driver" {
		fmt.Fprintln(stderr, "Usage: BrowseForge playwright install-driver")
		return 2
	}
	if err := browser.InstallPlaywrightDriver(); err != nil {
		fmt.Fprintf(stderr, "playwright install-driver: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "Playwright driver installed")
	return 0
}

func runCapabilitiesCommand(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("capabilities", stderr)
	jsonOut := fs.Bool("json", false, "Write JSON output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "capabilities does not accept positional arguments: %s\n", strings.Join(fs.Args(), " "))
		return 2
	}
	caps := map[string]any{
		"version": Version,
		"transports": []string{
			"rest",
			"mcp-http",
			"mcp-stdio",
			"playwright-proxy",
		},
		"commands": []string{
			"serve", "mcp-stdio", "init", "config", "token", "doctor",
			"status", "capabilities", "open", "mcp-config", "browsers",
			"backup", "smoke", "workflow", "profiles", "sessions", "migrate",
		},
		"browser_runtimes": []string{"camoufox", "cloakbrowser"},
		"machine_readable": []string{"token --json", "doctor --json", "status --json", "config validate --json", "capabilities --json", "smoke --json"},
	}
	if *jsonOut {
		_ = writeJSON(stdout, caps)
	} else {
		fmt.Fprintf(stdout, "BrowseForge %s\n", Version)
		fmt.Fprintln(stdout, "Transports: REST, MCP HTTP, MCP stdio, Playwright proxy")
		fmt.Fprintln(stdout, "Browser runtimes: camoufox, cloakbrowser")
		fmt.Fprintln(stdout, "Agent-ready commands: init, config, token, doctor, status, capabilities, open, mcp-config, browsers, backup, smoke, workflow, profiles, sessions, migrate")
	}
	return 0
}

func runSmokeCommand(args []string, global cliGlobal, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "smoke requires target: rest or mcp")
		return 2
	}
	target := args[0]
	fs := newFlagSet("smoke "+target, stderr)
	baseURL := fs.String("base-url", "", "BrowseForge base URL")
	token := fs.String("token", "", "Bearer token")
	wait := fs.Bool("wait", false, "Wait until smoke check succeeds")
	timeout := fs.Duration("timeout", 60*time.Second, "Maximum wait duration")
	interval := fs.Duration("interval", 2*time.Second, "Wait retry interval")
	jsonOut := fs.Bool("json", false, "Write JSON output")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "smoke %s does not accept positional arguments: %s\n", target, strings.Join(fs.Args(), " "))
		return 2
	}
	cfg, err := config.Load(global.configPath)
	if err != nil && *baseURL == "" {
		result := map[string]any{"ok": false, "target": target, "error": "config error: " + err.Error(), "config": global.configPath}
		if *jsonOut {
			_ = writeJSON(stdout, result)
		} else {
			fmt.Fprintf(stderr, "Smoke %s failed: config error: %v\n", target, err)
		}
		return 1
	}
	resolvedBase := resolveBaseURL(*baseURL, cfg)
	resolvedToken := *token
	if target == "mcp" && resolvedToken == "" {
		var err error
		resolvedToken, _, err = readToken(global.configPath, global.baseDir)
		if err != nil {
			result := map[string]any{"ok": false, "target": target, "base_url": resolvedBase, "error": "token error: " + err.Error()}
			if *jsonOut {
				_ = writeJSON(stdout, result)
			} else {
				fmt.Fprintf(stderr, "Smoke %s failed: token error: %v\n", target, err)
			}
			return 1
		}
	}
	var result map[string]any
	runCheck := func() (map[string]any, error) {
		switch target {
		case "rest":
			return smokeREST(resolvedBase)
		case "mcp":
			return smokeMCP(resolvedBase, resolvedToken)
		default:
			return nil, fmt.Errorf("unknown smoke target: %s", target)
		}
	}
	if target != "rest" && target != "mcp" {
		fmt.Fprintf(stderr, "unknown smoke target: %s\n", target)
		return 2
	}
	if *wait {
		deadline := time.Now().Add(*timeout)
		for {
			result, err = runCheck()
			if err == nil || time.Now().After(deadline) {
				break
			}
			time.Sleep(*interval)
		}
	} else {
		result, err = runCheck()
	}
	if err != nil {
		result = map[string]any{"ok": false, "target": target, "base_url": resolvedBase, "error": err.Error()}
	}
	if *jsonOut {
		_ = writeJSON(stdout, result)
	} else if err != nil {
		fmt.Fprintf(stderr, "Smoke %s failed: %v\n", target, err)
	} else {
		fmt.Fprintf(stdout, "Smoke %s OK: %s\n", target, resolvedBase)
	}
	if err != nil {
		return 1
	}
	return 0
}

func runMigrateCommand(args []string, global cliGlobal, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "profiles" {
		fmt.Fprintln(stderr, "migrate requires subcommand: profiles --from v1 --to v2 [--apply]")
		return 2
	}
	fs := newFlagSet("migrate profiles", stderr)
	from := fs.String("from", "", "Source schema version")
	to := fs.String("to", "", "Target schema version")
	apply := fs.Bool("apply", false, "Write migrated profile files")
	jsonOut := fs.Bool("json", false, "Write JSON output")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *from != "v1" || *to != "v2" {
		fmt.Fprintln(stderr, "only --from v1 --to v2 is supported")
		return 2
	}
	cfg, err := config.Load(global.configPath)
	if err != nil {
		fmt.Fprintf(stderr, "migrate config error: %v\n", err)
		return 1
	}
	profilesDir := resolvePath(global.baseDir, cfg.ProfilesDir)
	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		fmt.Fprintf(stderr, "migrate read profiles failed: %v\n", err)
		return 1
	}
	type migratedProfile struct {
		ID         string `json:"id"`
		FromEngine string `json:"from_engine,omitempty"`
		RuntimeID  string `json:"runtime_id"`
		Status     string `json:"status"`
	}
	type migrationPlan struct {
		path   string
		data   []byte
		out    []byte
		result migratedProfile
	}
	var migrated []migratedProfile
	var plans []migrationPlan
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		path := filepath.Join(profilesDir, entry.Name(), "profile.json")
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			fmt.Fprintf(stderr, "migrate read %s failed: %v\n", path, err)
			return 1
		}
		var raw map[string]any
		if err := json.Unmarshal(data, &raw); err != nil {
			fmt.Fprintf(stderr, "migrate decode %s failed: %v\n", path, err)
			return 1
		}
		id, _ := raw["id"].(string)
		engine, _ := raw["engine"].(string)
		runtimeID, _ := raw["runtime_id"].(string)
		status := "migrated"
		if runtimeID != "" {
			if engine == "" {
				continue
			}
			status = "removed_engine"
		} else {
			switch engine {
			case "firefox", "":
				runtimeID = "camoufox"
			case "chromium":
				runtimeID = "cloakbrowser"
			default:
				fmt.Fprintf(stderr, "unsupported v1 engine %q in %s\n", engine, path)
				return 1
			}
			raw["runtime_id"] = runtimeID
		}
		delete(raw, "engine")
		out, err := json.MarshalIndent(raw, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "migrate encode %s failed: %v\n", path, err)
			return 1
		}
		result := migratedProfile{ID: id, FromEngine: engine, RuntimeID: runtimeID, Status: status}
		plans = append(plans, migrationPlan{path: path, data: data, out: append(out, '\n'), result: result})
		migrated = append(migrated, result)
	}
	if *apply {
		for _, plan := range plans {
			backup := plan.path + ".v1.bak"
			if _, err := os.Stat(backup); os.IsNotExist(err) {
				if err := os.WriteFile(backup, plan.data, 0644); err != nil {
					fmt.Fprintf(stderr, "migrate backup %s failed: %v\n", plan.path, err)
					return 1
				}
			}
			if err := os.WriteFile(plan.path, plan.out, 0644); err != nil {
				fmt.Fprintf(stderr, "migrate write %s failed: %v\n", plan.path, err)
				return 1
			}
		}
	}
	result := map[string]any{"ok": true, "apply": *apply, "profiles_dir": profilesDir, "profiles": migrated, "count": len(migrated)}
	if *jsonOut {
		_ = writeJSON(stdout, result)
	} else {
		mode := "dry-run"
		if *apply {
			mode = "applied"
		}
		fmt.Fprintf(stdout, "v1-to-v2 profile migration %s: %d profile(s)\n", mode, len(migrated))
	}
	return 0
}

func runWorkflowCommand(args []string, global cliGlobal, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "run" {
		fmt.Fprintln(stderr, "workflow requires subcommand: run FILE")
		return 2
	}
	fs := newFlagSet("workflow run", stderr)
	baseURL := fs.String("base-url", "", "BrowseForge base URL")
	token := fs.String("token", "", "Bearer token")
	jsonOut := fs.Bool("json", false, "Write JSON output")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "workflow run requires exactly one workflow file")
		return 2
	}
	cfg, err := config.Load(global.configPath)
	if err != nil && *baseURL == "" {
		fmt.Fprintf(stderr, "workflow config error: %v\n", err)
		return 1
	}
	resolvedBase := resolveBaseURL(*baseURL, cfg)
	resolvedToken := *token
	if resolvedToken == "" {
		var err error
		resolvedToken, _, err = readToken(global.configPath, global.baseDir)
		if err != nil {
			fmt.Fprintf(stderr, "workflow token error: %v\n", err)
			return 1
		}
	}
	engine := workflow.NewEngine(resolvedBase, resolvedToken)
	wf, err := engine.LoadFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "workflow load failed: %v\n", err)
		return 1
	}
	results := engine.Execute(wf)
	if *jsonOut {
		_ = writeJSON(stdout, map[string]any{"ok": workflowResultsOK(results), "workflow": wf.Name, "results": results})
	} else {
		for _, result := range results {
			status := "ok"
			if !result.Success {
				status = "failed"
			}
			fmt.Fprintf(stdout, "%s\t%s\t%s\n", status, result.Action, result.Step)
		}
	}
	if !workflowResultsOK(results) {
		return 1
	}
	return 0
}

func runAPIListCommand(resource string, args []string, global cliGlobal, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "list" {
		fmt.Fprintf(stderr, "%s requires subcommand: list\n", resource)
		return 2
	}
	fs := newFlagSet(resource+" list", stderr)
	baseURL := fs.String("base-url", "", "BrowseForge base URL")
	token := fs.String("token", "", "Bearer token")
	jsonOut := fs.Bool("json", false, "Write JSON output")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "%s list does not accept positional arguments: %s\n", resource, strings.Join(fs.Args(), " "))
		return 2
	}
	cfg, err := config.Load(global.configPath)
	if err != nil && *baseURL == "" {
		if *jsonOut {
			_ = writeJSON(stdout, map[string]any{"ok": false, "resource": resource, "error": "config error: " + err.Error(), "config": global.configPath})
		} else {
			fmt.Fprintf(stderr, "%s list failed: config error: %v\n", resource, err)
		}
		return 1
	}
	resolvedBase := resolveBaseURL(*baseURL, cfg)
	resolvedToken := *token
	if resolvedToken == "" {
		var err error
		resolvedToken, _, err = readToken(global.configPath, global.baseDir)
		if err != nil {
			if *jsonOut {
				_ = writeJSON(stdout, map[string]any{"ok": false, "resource": resource, "error": "token error: " + err.Error()})
			} else {
				fmt.Fprintf(stderr, "%s list failed: token error: %v\n", resource, err)
			}
			return 1
		}
	}
	result, err := apiGET(resolvedBase+"/api/"+resource, resolvedToken)
	if err != nil {
		if *jsonOut {
			_ = writeJSON(stdout, map[string]any{"ok": false, "resource": resource, "error": err.Error()})
		} else {
			fmt.Fprintf(stderr, "%s list failed: %v\n", resource, err)
		}
		return 1
	}
	if *jsonOut {
		_ = writeJSON(stdout, result)
	} else {
		_ = writeJSON(stdout, result)
	}
	return 0
}

func ensureRuntimeDirs(baseDir string) error {
	for _, name := range []string{"profiles", "data", "logs", "browsers"} {
		if err := os.MkdirAll(filepath.Join(baseDir, name), 0755); err != nil {
			return err
		}
	}
	return nil
}

func writeDefaultConfig(path, baseDir string, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("config already exists: %s", path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	cfg := defaultConfig(baseDir)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0644)
}

func defaultConfig(baseDir string) *config.Config {
	camoufoxPath := browser.FindBinary(baseDir, "camoufox")
	cloakBrowserPath := browser.FindBinary(baseDir, "cloakbrowser")
	camoufoxEnabled := camoufoxPath != ""
	cloakBrowserEnabled := cloakBrowserPath != ""
	return &config.Config{
		Host:             "127.0.0.1",
		Port:             "19280",
		ProfilesDir:      "profiles",
		DataDir:          "data",
		LogFile:          "logs/server.log",
		DefaultRuntimeID: "camoufox",
		FingerprintDir:   "data",
		Runtimes: map[string]config.RuntimeConfig{
			"camoufox": {
				Enabled:     &camoufoxEnabled,
				BinaryPath:  camoufoxPath,
				Family:      "firefox",
				DisplayName: "Camoufox",
			},
			"cloakbrowser": {
				Enabled:     &cloakBrowserEnabled,
				BinaryPath:  cloakBrowserPath,
				Family:      "chromium",
				DisplayName: "CloakBrowser",
				Settings: &config.CloakBrowserConfig{
					FingerprintPlatform:  "auto",
					TargetPlatformPolicy: "warn",
					ExtraArgs:            []string{},
				},
			},
		},
	}
}

func validateConfig(cfg *config.Config) error {
	if cfg.Port == "" {
		return errors.New("port is required")
	}
	if cfg.ProfilesDir == "" {
		return errors.New("profiles_dir is required")
	}
	if cfg.DataDir == "" {
		return errors.New("data_dir is required")
	}
	if cfg.LogFile == "" {
		return errors.New("log_file is required")
	}
	if cfg.FingerprintDir == "" {
		return errors.New("fingerprint_dir is required")
	}
	return nil
}

func readToken(configPath, baseDir string) (string, string, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return "", "", err
	}
	tokenPath := filepath.Join(resolvePath(baseDir, cfg.DataDir), ".api-token")
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", tokenPath, err
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", tokenPath, errors.New("token file is empty")
	}
	return token, tokenPath, nil
}

func buildDoctorReport(global cliGlobal, strict bool) doctorReport {
	report := doctorReport{Version: Version, BaseDir: global.baseDir, OK: true}
	add := func(name, status, message string) {
		report.Checks = append(report.Checks, doctorCheck{Name: name, Status: status, Message: message})
		if status == "fail" {
			report.OK = false
		}
	}
	warn := func(name, message string) {
		status := "warn"
		if strict {
			status = "fail"
		}
		add(name, status, message)
	}

	if isDocker() {
		add("docker", "ok", "detected")
	} else {
		add("docker", "ok", "native environment")
	}
	if display := os.Getenv("DISPLAY"); display != "" {
		add("display", "ok", display)
	} else {
		warn("display", "DISPLAY is not set; browser launch needs a display server in non-headless deployments")
	}
	cfg, err := config.Load(global.configPath)
	if err != nil {
		add("config", "fail", err.Error())
	} else if err := validateConfig(cfg); err != nil {
		add("config", "fail", err.Error())
	} else {
		add("config", "ok", global.configPath)
	}
	if ver := browser.InstalledVersion(global.baseDir, "camoufox"); ver != "" {
		add("camoufox", "ok", ver+" "+browser.FindBinary(global.baseDir, "camoufox"))
	} else {
		warn("camoufox", "not installed; serve will download it on first run")
	}
	if ver := browser.InstalledVersion(global.baseDir, "cloakbrowser"); ver != "" {
		add("cloakbrowser", "ok", ver+" "+browser.FindBinary(global.baseDir, "cloakbrowser"))
	} else {
		warn("cloakbrowser", "not installed; serve will download it on first run")
	}
	if _, _, err := readToken(global.configPath, global.baseDir); err == nil {
		add("api_token", "ok", "configured")
	} else {
		warn("api_token", "will be generated on first server start")
	}
	if isDocker() {
		if cfg != nil && cfg.NoSandbox {
			add("sandbox", "ok", "Docker detected and no_sandbox is enabled")
		} else if strict {
			add("sandbox", "fail", "Docker detected; use serve --no-sandbox or config no_sandbox=true")
		} else {
			add("sandbox", "warn", "Docker detected; use serve --no-sandbox or config no_sandbox=true")
		}
	} else {
		add("sandbox", "ok", "native sandbox should work")
	}
	return report
}

func printDoctorReport(w io.Writer, report doctorReport) {
	fmt.Fprintf(w, "BrowseForge %s Environment Check\n\n", report.Version)
	for _, check := range report.Checks {
		fmt.Fprintf(w, "[%s] %s", check.Status, check.Name)
		if check.Message != "" {
			fmt.Fprintf(w, ": %s", check.Message)
		}
		fmt.Fprintln(w)
	}
}

func resolveBaseURL(baseURL string, cfg *config.Config) string {
	if baseURL != "" {
		return strings.TrimRight(baseURL, "/")
	}
	if cfg == nil {
		return "http://127.0.0.1:19280"
	}
	host := cfg.Host
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	port := cfg.Port
	if port == "" {
		port = "19280"
	}
	return "http://" + host + ":" + port
}

func smokeREST(baseURL string) (map[string]any, error) {
	result, err := apiGET(baseURL+"/api/status", "")
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "target": "rest", "base_url": baseURL, "response": result}, nil
}

func smokeMCP(baseURL, token string) (map[string]any, error) {
	body := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params":  map[string]any{},
	}
	result, err := apiPOST(baseURL+"/mcp", token, body)
	if err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "target": "mcp", "base_url": baseURL, "response": result}, nil
}

func apiGET(url, token string) (map[string]any, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return doJSON(req)
}

func apiPOST(url, token string, body any) (map[string]any, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return doJSON(req)
}

func doJSON(req *http.Request) (map[string]any, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		if errObj, ok := result["error"].(map[string]any); ok {
			return nil, fmt.Errorf("%v", errObj["message"])
		}
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return result, nil
}

func workflowResultsOK(results []workflow.Result) bool {
	if len(results) == 0 {
		return true
	}
	for _, result := range results {
		if !result.Success {
			return false
		}
	}
	return true
}
