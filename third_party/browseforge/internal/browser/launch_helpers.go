package browser

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// splitLocale splits "en-US" into ["en", "US"], fallback to ["en", "US"].
func splitLocale(locale string) [2]string {
	if i := strings.IndexByte(locale, '-'); i > 0 {
		return [2]string{locale[:i], locale[i+1:]}
	}
	return [2]string{"en", "US"}
}

// humanizeError wraps Playwright errors into user-friendly messages.
func humanizeError(err error) error {
	msg := err.Error()
	switch {
	case isChromiumGPUOrCacheLaunchFailure(err):
		return fmt.Errorf("CloakBrowser/Chromium 啟動時 GPU 或暫存 cache 初始化失敗。Windows VM 可在 config.json 的 runtimes.cloakbrowser.settings 啟用 safe_gpu、isolated_runtime_cache 與 repair_transient_cache_on_launch_failure。原始錯誤: %w", err)
	case shouldRetryLaunch(err):
		return fmt.Errorf("瀏覽器啟動時 Playwright protocol 連線中斷。BrowseForge 會自動重試一次；若仍失敗，請重啟服務或容器。原始錯誤: %w", err)
	case strings.Contains(msg, "sandboxing failed") || strings.Contains(msg, "sandbox"):
		return fmt.Errorf("Chromium sandbox 失敗。Docker 中請使用 --no-sandbox 或 'serve --no-sandbox'。原始錯誤: %w", err)
	case strings.Contains(msg, "XServer") || strings.Contains(msg, "DISPLAY"):
		return fmt.Errorf("找不到 X 顯示器。請設定 DISPLAY 環境變數或使用 xvfb-run。原始錯誤: %w", err)
	case strings.Contains(msg, "profile appears to be in use"):
		return fmt.Errorf("Profile 被鎖定（上次未正常關閉）。請重啟服務或刪除 profiles/*/browser-data/SingletonLock。原始錯誤: %w", err)
	case strings.Contains(msg, "executable doesn't exist") || strings.Contains(msg, "not found"):
		return fmt.Errorf("瀏覽器執行檔不存在。請重新啟動讓 BrowseForge 自動下載。原始錯誤: %w", err)
	default:
		return err
	}
}

func shouldRetryLaunch(err error) bool {
	if err == nil {
		return false
	}
	var noManagerRetry noManagerRetryError
	if errors.As(err, &noManagerRetry) {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "could not read protocol padding") ||
		strings.Contains(msg, "target closed") ||
		isChromiumGPUOrCacheLaunchFailure(err) ||
		strings.Contains(msg, "EOF")
}

type codedError struct {
	code string
	err  error
}

func (e codedError) Error() string {
	return e.err.Error()
}

func (e codedError) Unwrap() error {
	return e.err
}

func (e codedError) ErrorCode() string {
	return e.code
}

type errorCoder interface {
	ErrorCode() string
}

func ErrorCode(err error) string {
	var coded errorCoder
	if errors.As(err, &coded) {
		return coded.ErrorCode()
	}
	return ""
}

func shouldRetryLaunchAttempt(err error) bool {
	if shouldRetryLaunch(err) {
		return true
	}
	switch ErrorCode(err) {
	case "BROWSER_BIND_FAILED", "BROWSER_CONNECT_TIMEOUT", "BROWSER_PROCESS_EXITED", "ENDPOINT_UNHEALTHY":
		return true
	default:
		return false
	}
}

func classifyEndpointHealthError(err error) string {
	if err == nil {
		return "ENDPOINT_UNHEALTHY"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "timed out") || strings.Contains(msg, "deadline exceeded"):
		return "BROWSER_CONNECT_TIMEOUT"
	case strings.Contains(msg, "process exited") || strings.Contains(msg, "target closed") || strings.Contains(msg, "browser has been closed"):
		return "BROWSER_PROCESS_EXITED"
	default:
		return "ENDPOINT_UNHEALTHY"
	}
}

type noManagerRetryError struct {
	err error
}

func (e noManagerRetryError) Error() string {
	return e.err.Error()
}

func (e noManagerRetryError) Unwrap() error {
	return e.err
}

func cleanProfileLocks(userDataDir string) {
	for _, name := range []string{"SingletonLock", "SingletonCookie", "SingletonSocket"} {
		path := filepath.Join(userDataDir, name)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			slog.Warn("remove stale profile lock failed", "path", path, "error", err)
		}
	}
}

func isChromiumGPUOrCacheLaunchFailure(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "gpu process isn't usable") ||
		strings.Contains(msg, "gpu process launch failed") ||
		strings.Contains(msg, "gpu cache creation failed") ||
		strings.Contains(msg, "unable to create cache") ||
		strings.Contains(msg, "unable to move the cache") ||
		strings.Contains(msg, "cache_util_win") ||
		strings.Contains(msg, "存取被拒")
}

func sanitizeExtraChromiumArgs(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	blockedPrefixes := []string{
		"--user-data-dir",
		"--remote-debugging-pipe",
		"--remote-debugging-port",
		"--profile-directory",
		"--disk-cache-dir",
		"--proxy-server",
		"--enable-automation",
		"--disable-blink-features",
		"--force-webrtc-ip-handling-policy",
		"--webrtc-ip-handling-policy",
		"--fingerprint",
		"--fingerprint-platform",
		"--fingerprint-timezone",
		"--fingerprint-locale",
		"--fingerprint-webrtc-ip",
		"--fingerprint-accept-language",
		"--fingerprint-user-agent",
		"--fingerprint-ua-full-version",
		"--fingerprint-ua-platform",
		"--fingerprint-ua-platform-version",
		"--fingerprint-ua-architecture",
		"--fingerprint-ua-bitness",
		"--fingerprint-ua-mobile",
		"--fingerprint-ua-model",
		"--fingerprint-ua-form-factors",
		"--fingerprint-sec-ch-ua",
		"--fingerprint-sec-ch-ua-full-version-list",
		"--fingerprint-fonts-dir",
		"--fingerprint-fonts-list",
		"--fingerprint-storage-quota",
		"--fingerprint-screen-width",
		"--fingerprint-screen-height",
		"--fingerprint-hardware-concurrency",
		"--fingerprint-device-memory",
		"--fingerprint-screen-avail-width",
		"--fingerprint-screen-avail-height",
		"--fingerprint-audio-noise",
		"--fingerprint-canvas-noise",
		"--fingerprint-webgl-vendor",
		"--fingerprint-webgl-renderer",
		"--force-device-scale-factor",
		"--window-position",
		"--window-size",
		"--browseforge-stealth-config",
		"--browseforge-stealth-mode",
	}
	out := make([]string, 0, len(args))
	seen := map[string]bool{}
	for _, arg := range args {
		arg = strings.TrimSpace(arg)
		if arg == "" {
			continue
		}
		blocked := false
		for _, prefix := range blockedPrefixes {
			if arg == prefix || strings.HasPrefix(arg, prefix+"=") {
				slog.Warn("ignored unsafe extra chromium arg", "arg", arg)
				blocked = true
				break
			}
		}
		if blocked || seen[arg] {
			continue
		}
		seen[arg] = true
		out = append(out, arg)
	}
	return out
}

func repairTransientChromiumData(userDataDir string) {
	for _, rel := range []string{
		filepath.Join("Default", "Cache"),
		filepath.Join("Default", "Code Cache"),
		filepath.Join("Default", "GPUCache"),
		"BrowseForgeRuntimeCache",
		"ShaderCache",
		"GrShaderCache",
		"component_crx_cache",
	} {
		path := filepath.Join(userDataDir, rel)
		if err := os.RemoveAll(path); err != nil {
			slog.Warn("remove transient chromium cache failed", "path", path, "error", err)
		}
	}
}
