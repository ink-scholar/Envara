package config

import (
	"encoding/json"
	"log/slog"
	"os"
	"strings"
)

type Config struct {
	Host          string `json:"host,omitempty"`
	Port          string `json:"port"`
	PublicBaseURL string `json:"public_base_url,omitempty"`
	NoSandbox     bool   `json:"no_sandbox,omitempty"`
	// AllowEmptyRuntime lets a desktop host manage profiles before installing a browser.
	// The default remains false; launch always requires an enabled runtime.
	AllowEmptyRuntime bool                     `json:"allow_empty_runtime,omitempty"`
	ProfilesDir       string                   `json:"profiles_dir"`
	DataDir           string                   `json:"data_dir"`
	LogFile           string                   `json:"log_file"`
	DefaultRuntimeID  string                   `json:"default_runtime_id,omitempty"`
	Runtimes          map[string]RuntimeConfig `json:"runtimes,omitempty"`
	FingerprintDir    string                   `json:"fingerprint_dir"`
	Humanize          *HumanizeConfig          `json:"humanize,omitempty"`
	// EnforceHTTPProxyBridge is enabled by the desktop serve flag, never by saved JSON.
	EnforceHTTPProxyBridge bool   `json:"-"`
	APIToken               string `json:"-"` // generated at runtime
	Version                string `json:"-"` // set from main
}

// CloakBrowserConfig controls Chromium/CloakBrowser launch compatibility.
// Stability settings keep fragile VM/container launches alive. Fingerprint
// settings describe the browser identity BrowseForge owns and should not be
// smuggled through ExtraArgs, where they are harder to audit.
type CloakBrowserConfig struct {
	SafeGPU                             bool     `json:"safe_gpu"`
	AutoSafeGPUFallback                 bool     `json:"auto_safe_gpu_fallback"`
	IsolatedRuntimeCache                bool     `json:"isolated_runtime_cache"`
	RepairTransientCacheOnLaunchFailure bool     `json:"repair_transient_cache_on_launch_failure"`
	FingerprintPlatform                 string   `json:"fingerprint_platform,omitempty"` // auto | macos | windows | linux
	FontsDir                            string   `json:"fonts_dir,omitempty"`
	StorageQuotaMB                      int64    `json:"storage_quota_mb,omitempty"`
	TargetPlatformPolicy                string   `json:"target_platform_policy,omitempty"` // strict | warn | allow
	NativeMode                          string   `json:"native_mode,omitempty"`
	PluginsPDF                          string   `json:"plugins_pdf,omitempty"`
	ExtraArgs                           []string `json:"extra_args"`
}

// RuntimeConfig is the generic provider config used by runtime-agnostic code.
type RuntimeConfig struct {
	Enabled        *bool               `json:"enabled,omitempty"`
	BinaryPath     string              `json:"binary_path,omitempty"`
	SkipAutoUpdate bool                `json:"skip_auto_update,omitempty"`
	Family         string              `json:"family,omitempty"`
	DisplayName    string              `json:"display_name,omitempty"`
	Settings       *CloakBrowserConfig `json:"settings,omitempty"`
}

// HumanizeConfig controls human-like behavior simulation.
type HumanizeConfig struct {
	Enabled     *bool    `json:"enabled,omitempty"`
	MouseSpeed  string   `json:"mouse_speed,omitempty"`
	TypingCPM   int      `json:"typing_cpm,omitempty"`
	TypoRate    *float64 `json:"typo_rate,omitempty"`
	ScrollStyle string   `json:"scroll_style,omitempty"`
}

func (cfg *Config) Runtime(id string) RuntimeConfig {
	if cfg == nil || cfg.Runtimes == nil {
		return RuntimeConfig{}
	}
	return cfg.Runtimes[id]
}

func (cfg *Config) ChromiumRuntimeSettings(id string) *CloakBrowserConfig {
	raw := cfg.Runtime(id)
	return raw.Settings
}

func (cfg *Config) CloakBrowserSettings() *CloakBrowserConfig {
	return cfg.ChromiumRuntimeSettings("cloakbrowser")
}

func Load(path string) (*Config, error) {
	cfg := &Config{
		Host:             "127.0.0.1",
		Port:             "19280",
		ProfilesDir:      "profiles",
		DataDir:          "data",
		LogFile:          "logs/server.log",
		DefaultRuntimeID: "camoufox",
		FingerprintDir:   "data",
	}

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			applyPublicBaseURL(cfg)
			return cfg, nil
		}
		return nil, err
	}
	defer f.Close()

	var raw struct {
		Config
		CamoufoxPath     string              `json:"camoufox_path,omitempty"`
		CloakBrowserPath string              `json:"cloakbrowser_path,omitempty"`
		CloakBrowser     *CloakBrowserConfig `json:"cloakbrowser,omitempty"`
	}
	raw.Config = *cfg
	if err := json.NewDecoder(f).Decode(&raw); err != nil {
		return nil, err
	}
	cfg = &raw.Config
	applyLegacyRuntimeConfig(cfg, raw.CamoufoxPath, raw.CloakBrowserPath, raw.CloakBrowser)
	applyPublicBaseURL(cfg)
	return cfg, nil
}

func applyPublicBaseURL(cfg *Config) {
	if env := strings.TrimSpace(os.Getenv("BROWSEFORGE_PUBLIC_BASE_URL")); env != "" {
		cfg.PublicBaseURL = strings.TrimRight(env, "/")
	} else {
		cfg.PublicBaseURL = strings.TrimRight(strings.TrimSpace(cfg.PublicBaseURL), "/")
	}
}

func applyLegacyRuntimeConfig(cfg *Config, camoufoxPath, cloakBrowserPath string, cloakBrowser *CloakBrowserConfig) {
	if cfg.Runtimes == nil {
		cfg.Runtimes = map[string]RuntimeConfig{}
	}
	if camoufoxPath != "" {
		rt := cfg.Runtimes["camoufox"]
		if rt.BinaryPath == "" {
			enabled := true
			rt.BinaryPath = camoufoxPath
			if rt.Enabled == nil {
				rt.Enabled = &enabled
			}
			if rt.Family == "" {
				rt.Family = "firefox"
			}
			if rt.DisplayName == "" {
				rt.DisplayName = "Camoufox"
			}
			cfg.Runtimes["camoufox"] = rt
		}
	}
	if cloakBrowserPath != "" || cloakBrowser != nil {
		rt := cfg.Runtimes["cloakbrowser"]
		if rt.BinaryPath == "" && cloakBrowserPath != "" {
			enabled := true
			rt.BinaryPath = cloakBrowserPath
			if rt.Enabled == nil {
				rt.Enabled = &enabled
			}
		}
		if rt.Family == "" {
			rt.Family = "chromium"
		}
		if rt.DisplayName == "" {
			rt.DisplayName = "CloakBrowser"
		}
		if rt.Settings == nil && cloakBrowser != nil {
			rt.Settings = cloakBrowser
		}
		cfg.Runtimes["cloakbrowser"] = rt
	}
}

func SetupLogger(logFile string) *slog.Logger {
	os.MkdirAll("logs", 0755)
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return slog.New(slog.NewJSONHandler(os.Stdout, nil))
	}
	return slog.New(slog.NewJSONHandler(f, nil))
}
