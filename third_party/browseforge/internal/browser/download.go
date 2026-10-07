package browser

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	bfruntime "browseforge/internal/runtime"
)

// Downloader handles first-run browser binary downloads

// Version constants — bump these in internal/runtime/support.go to trigger auto-update.
const (
	CamoufoxVersion              = bfruntime.CamoufoxVersion
	CloakBrowserVersion          = bfruntime.CloakBrowserVersion
	BrowseForgeChromiumVersion   = bfruntime.BrowseForgeChromiumVersion
	BrowseForgeChromiumRelease   = "https://github.com/nczz/browseforge-runtime-chromium/releases/download"
	BrowseForgeChromiumRuntimeID = bfruntime.BrowseForgeChromiumRuntimeID
)

var ErrUnsupportedRuntimePlatform = bfruntime.ErrUnsupportedRuntimePlatform

type UnsupportedRuntimePlatformError = bfruntime.UnsupportedRuntimePlatformError
type RuntimeSupport = bfruntime.RuntimeSupport

func CurrentRuntimeSupport(runtimeID string) RuntimeSupport {
	return bfruntime.CurrentRuntimeSupport(runtimeID)
}

func RuntimeSupportFor(runtimeID, goos, goarch string) RuntimeSupport {
	return bfruntime.RuntimeSupportFor(runtimeID, goos, goarch)
}

// ExpectedCloakBrowserVersion returns the expected version for the current platform.
func ExpectedCloakBrowserVersion() string {
	return bfruntime.ExpectedCloakBrowserVersion()
}

type BrowserInfo struct {
	Name    string
	Exists  bool
	Path    string
	Version string
}

func CheckBrowsers(camoufoxPath, cloakPath string) (camoufox, cloak BrowserInfo) {
	camoufox = BrowserInfo{Name: "Camoufox (Firefox)"}
	if camoufoxPath != "" {
		if info, err := os.Stat(camoufoxPath); err == nil && !info.IsDir() {
			camoufox.Exists = true
			camoufox.Path = camoufoxPath
		}
	}

	cloak = BrowserInfo{Name: "CloakBrowser (Chromium)"}
	if cloakPath != "" {
		if info, err := os.Stat(cloakPath); err == nil && !info.IsDir() {
			cloak.Exists = true
			cloak.Path = cloakPath
		}
	}
	return
}

// InstalledVersion reads the .version marker file in a browser directory.
// Returns empty string if not installed.
func InstalledVersion(baseDir, browserName string) string {
	data, err := os.ReadFile(filepath.Join(baseDir, "browsers", browserName, ".version"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func writeVersionMarker(dir, version string) {
	os.WriteFile(filepath.Join(dir, ".version"), []byte(version), 0644)
}

// FindBinary searches a browser directory for a known executable.
// Checks exact candidate paths first, then scans one level of subdirectories.
func FindBinary(baseDir, browserName string) string {
	dir := filepath.Join(baseDir, "browsers", browserName)

	var candidates []string
	var exeNames []string
	switch browserName {
	case "camoufox":
		candidates = []string{
			filepath.Join("Camoufox.app", "Contents", "MacOS", "camoufox"),
			"camoufox.exe",
			"camoufox",
		}
		exeNames = []string{"camoufox.exe", "camoufox"}
	case "cloakbrowser", "browseforge-chromium":
		candidates = []string{
			filepath.Join("Chromium.app", "Contents", "MacOS", "Chromium"),
			"chrome.exe",
			"chrome",
			"chromium",
		}
		exeNames = []string{"chrome.exe", "chrome", "chromium"}
	}

	// Check known candidate paths
	for _, c := range candidates {
		p := filepath.Join(dir, c)
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}

	// Fallback: scan one level of subdirectories for known exe names
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		for _, c := range candidates {
			p := filepath.Join(dir, entry.Name(), c)
			if info, err := os.Stat(p); err == nil && !info.IsDir() {
				return p
			}
		}
		for _, name := range exeNames {
			p := filepath.Join(dir, entry.Name(), name)
			if info, err := os.Stat(p); err == nil && !info.IsDir() {
				return p
			}
		}
	}
	return ""
}

func ExpectedBrowseForgeChromiumVersion() string {
	return bfruntime.ExpectedBrowseForgeChromiumVersion()
}

func BrowseForgeChromiumSupportFor(goos, goarch string) RuntimeSupport {
	return bfruntime.BrowseForgeChromiumSupportFor(goos, goarch)
}

func browseForgeChromiumPlatform() (string, error) {
	return browseForgeChromiumPlatformFor(runtime.GOOS, runtime.GOARCH)
}

func browseForgeChromiumPlatformFor(goos, goarch string) (string, error) {
	return bfruntime.BrowseForgeChromiumPlatformFor(goos, goarch)
}

func CamoufoxSupportFor(goos, goarch string) RuntimeSupport {
	return bfruntime.CamoufoxSupportFor(goos, goarch)
}

func camoufoxDownloadFilenameFor(version, goos, goarch string) (string, error) {
	return bfruntime.CamoufoxDownloadFilenameFor(version, goos, goarch)
}

func camoufoxDownloadURLFor(version, goos, goarch string) (string, string, error) {
	filename, err := camoufoxDownloadFilenameFor(version, goos, goarch)
	if err != nil {
		return "", "", err
	}
	return fmt.Sprintf("https://github.com/daijro/camoufox/releases/download/%s/%s", version, filename), filename, nil
}

func BrowseForgeChromiumDownloadURL(version string) (string, string, error) {
	return browseForgeChromiumDownloadURLFor(version, runtime.GOOS, runtime.GOARCH)
}

func browseForgeChromiumDownloadURLFor(version, goos, goarch string) (string, string, error) {
	platform, err := browseForgeChromiumPlatformFor(goos, goarch)
	if err != nil {
		return "", "", err
	}
	filename := fmt.Sprintf("browseforge-runtime-chromium-%s-%s.zip", version, platform)
	baseURL := strings.TrimRight(os.Getenv("BROWSEFORGE_CHROMIUM_RELEASE_BASE_URL"), "/")
	if baseURL == "" {
		baseURL = BrowseForgeChromiumRelease
	}
	return fmt.Sprintf("%s/%s/%s", baseURL, version, filename), filename, nil
}

func DownloadBrowseForgeChromium(baseDir string) (string, error) {
	version := BrowseForgeChromiumVersion
	url, filename, err := BrowseForgeChromiumDownloadURL(version)
	if err != nil {
		return "", err
	}
	destDir := filepath.Join(baseDir, "browsers", BrowseForgeChromiumRuntimeID)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return "", err
	}

	tmpFile := filepath.Join(os.TempDir(), filename)
	slog.Info("downloading BrowseForge Chromium", "url", url)
	fmt.Printf("📥 Downloading BrowseForge Chromium (%s)...\n", filename)

	if err := download(url, tmpFile); err != nil {
		return "", err
	}

	fmt.Println("📦 Extracting...")
	if err := extract(tmpFile, destDir); err != nil {
		return "", err
	}
	os.Remove(tmpFile)

	// Flatten: if the archive extracted into a single subdirectory, hoist its
	// contents up so the binary lives directly under destDir (e.g. chrome is at
	// browsers/browseforge-chromium/chrome instead of .../subdir/chrome).
	if err := flattenSingleSubdir(destDir); err != nil {
		slog.Warn("flatten after extract failed", "err", err)
	}

	if runtime.GOOS == "darwin" {
		exec.Command("xattr", "-cr", destDir).Run()
	}

	binPath := FindBinary(baseDir, BrowseForgeChromiumRuntimeID)
	if binPath == "" {
		return "", fmt.Errorf("binary not found after extract in %s", destDir)
	}
	os.Chmod(binPath, 0755)

	fmt.Println("✅ BrowseForge Chromium installed")
	writeVersionMarker(destDir, version)
	return binPath, nil
}

func DownloadCamoufox(baseDir string) (string, error) {
	url, filename, err := camoufoxDownloadURLFor(CamoufoxVersion, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return "", err
	}
	destDir := filepath.Join(baseDir, "browsers", "camoufox")
	os.MkdirAll(destDir, 0755)

	tmpFile := filepath.Join(os.TempDir(), filename)
	slog.Info("downloading Camoufox", "url", url)
	fmt.Printf("📥 Downloading Camoufox (%s)...\n", filename)

	if err := download(url, tmpFile); err != nil {
		return "", err
	}

	fmt.Println("📦 Extracting...")
	if err := extract(tmpFile, destDir); err != nil {
		return "", err
	}
	os.Remove(tmpFile)

	if runtime.GOOS == "darwin" {
		exec.Command("xattr", "-cr", destDir).Run()
	}

	binPath := FindBinary(baseDir, "camoufox")
	if binPath == "" {
		return "", fmt.Errorf("binary not found after extract in %s", destDir)
	}
	os.Chmod(binPath, 0755)

	fmt.Println("✅ Camoufox installed")
	writeVersionMarker(destDir, CamoufoxVersion)
	return binPath, nil
}

func CloakBrowserSupportFor(goos, goarch string) RuntimeSupport {
	return bfruntime.CloakBrowserSupportFor(goos, goarch)
}

func DownloadCloakBrowser(baseDir string) (string, error) {
	version, filename, err := bfruntime.CloakBrowserArchiveFilenameFor(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("https://github.com/CloakHQ/CloakBrowser/releases/download/%s/%s", version, filename)
	destDir := filepath.Join(baseDir, "browsers", "cloakbrowser")
	os.MkdirAll(destDir, 0755)

	tmpFile := filepath.Join(os.TempDir(), filename)
	slog.Info("downloading CloakBrowser", "url", url)
	fmt.Printf("📥 Downloading CloakBrowser (%s)...\n", filename)

	if err := download(url, tmpFile); err != nil {
		return "", err
	}

	fmt.Println("📦 Extracting...")
	if err := extract(tmpFile, destDir); err != nil {
		return "", err
	}
	os.Remove(tmpFile)

	if runtime.GOOS == "darwin" {
		exec.Command("xattr", "-cr", destDir).Run()
	}

	binPath := FindBinary(baseDir, "cloakbrowser")
	if binPath == "" {
		return "", fmt.Errorf("binary not found after extract in %s", destDir)
	}
	os.Chmod(binPath, 0755)

	fmt.Println("✅ CloakBrowser installed")
	writeVersionMarker(destDir, version)
	return binPath, nil
}

// flattenSingleSubdir hoists the contents of a lone subdirectory up into dir.
// This handles archives that wrap everything in a version-named folder, e.g.
// browseforge-runtime-chromium-v0.1.6-alpha.0-linux-x64/chrome → chrome.
// Files already at the top level (like .version) are preserved.
func flattenSingleSubdir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	// Count subdirectories and top-level files (ignoring .version marker).
	var dirs []os.DirEntry
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e)
		}
	}

	// Only flatten when there is exactly one subdirectory.
	if len(dirs) != 1 {
		return nil
	}

	subdir := filepath.Join(dir, dirs[0].Name())
	subEntries, err := os.ReadDir(subdir)
	if err != nil {
		return err
	}

	// Move each entry from the subdirectory up to dir.
	for _, e := range subEntries {
		src := filepath.Join(subdir, e.Name())
		dst := filepath.Join(dir, e.Name())
		if err := os.Rename(src, dst); err != nil {
			return fmt.Errorf("flatten: rename %s → %s: %w", src, dst, err)
		}
	}

	// Remove the now-empty subdirectory.
	return os.Remove(subdir)
}

func download(dlURL, dest string) error {
	resp, err := http.Get(dlURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	total := resp.ContentLength
	var written int64
	buf := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, err := out.Write(buf[:n]); err != nil {
				return err
			}
			written += int64(n)
			if total > 0 {
				fmt.Fprintf(os.Stderr, "\r  %d / %d MB (%.0f%%)", written>>20, total>>20, float64(written)/float64(total)*100)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	fmt.Fprintln(os.Stderr)
	return nil
}

func extract(file, destDir string) error {
	if strings.HasSuffix(file, ".zip") {
		return extractZip(file, destDir)
	}
	if strings.HasSuffix(file, ".tar.gz") {
		return extractTarGz(file, destDir)
	}
	return fmt.Errorf("unknown archive format: %s", file)
}

func extractZip(zipFile, destDir string) error {
	r, err := zip.OpenReader(zipFile)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		target := filepath.Join(destDir, f.Name)
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(destDir)+string(os.PathSeparator)) {
			continue // skip zip slip
		}
		if f.FileInfo().IsDir() {
			os.MkdirAll(target, 0755)
			continue
		}
		os.MkdirAll(filepath.Dir(target), 0755)
		mode := f.Mode() | 0644 // ensure writable on Windows (mode 0 = read-only)
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
		if err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			out.Close()
			return err
		}
		_, err = io.Copy(out, rc)
		rc.Close()
		out.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func extractTarGz(tarFile, destDir string) error {
	f, err := os.Open(tarFile)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		target := filepath.Join(destDir, hdr.Name)
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(destDir)+string(os.PathSeparator)) {
			continue // skip path traversal
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(target, 0755)
		case tar.TypeReg:
			os.MkdirAll(filepath.Dir(target), 0755)
			mode := os.FileMode(hdr.Mode) | 0644 // ensure writable on Windows
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			_, err = io.Copy(out, tr)
			out.Close()
			if err != nil {
				return err
			}
		case tar.TypeSymlink:
			os.MkdirAll(filepath.Dir(target), 0755)
			os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				// Windows: symlink needs admin/dev-mode — copy the target instead
				src := filepath.Join(filepath.Dir(target), hdr.Linkname)
				if data, readErr := os.ReadFile(src); readErr == nil {
					os.WriteFile(target, data, 0755)
				}
			}
		}
	}
	return nil
}
