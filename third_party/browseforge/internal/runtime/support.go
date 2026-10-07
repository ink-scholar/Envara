package runtime

import (
	"errors"
	"fmt"
	goruntime "runtime"
	"strings"
)

// Version constants define the browser runtime artifacts BrowseForge installs.
// Keep platform filenames and support checks in this package so startup, CLI,
// downloads, and runtime registry all read from one compatibility source.
const (
	CamoufoxVersion              = "v135.0.1-beta.24"
	CloakBrowserVersion          = "chromium-v146.0.7680.177.4"
	CloakBrowserDarwinVersion    = "chromium-v145.0.7632.109.2"
	BrowseForgeChromiumVersion   = "v0.1.6-alpha.0"
	BrowseForgeChromiumRuntimeID = string(BrowseForgeChromium)
)

var ErrUnsupportedRuntimePlatform = errors.New("unsupported runtime platform")

type UnsupportedRuntimePlatformError struct {
	Runtime string
	Version string
	GOOS    string
	GOARCH  string
}

func (e UnsupportedRuntimePlatformError) Error() string {
	return fmt.Sprintf("%s %s is not available for %s/%s", e.Runtime, e.Version, e.GOOS, e.GOARCH)
}

func (e UnsupportedRuntimePlatformError) Unwrap() error {
	return ErrUnsupportedRuntimePlatform
}

type RuntimeSupport struct {
	RuntimeID         string
	DisplayName       string
	Version           string
	GOOS              string
	GOARCH            string
	PlatformSupported bool
	UnsupportedReason string
}

func unsupportedRuntime(runtimeID, displayName, version, goos, goarch string) RuntimeSupport {
	err := UnsupportedRuntimePlatformError{Runtime: displayName, Version: version, GOOS: goos, GOARCH: goarch}
	return RuntimeSupport{
		RuntimeID:         runtimeID,
		DisplayName:       displayName,
		Version:           version,
		GOOS:              goos,
		GOARCH:            goarch,
		PlatformSupported: false,
		UnsupportedReason: err.Error(),
	}
}

func supportedRuntime(runtimeID, displayName, version, goos, goarch string) RuntimeSupport {
	return RuntimeSupport{
		RuntimeID:         runtimeID,
		DisplayName:       displayName,
		Version:           version,
		GOOS:              goos,
		GOARCH:            goarch,
		PlatformSupported: true,
	}
}

func CurrentRuntimeSupport(runtimeID string) RuntimeSupport {
	return RuntimeSupportFor(runtimeID, goruntime.GOOS, goruntime.GOARCH)
}

func RuntimeSupportFor(runtimeID, goos, goarch string) RuntimeSupport {
	switch ID(runtimeID) {
	case Camoufox:
		return CamoufoxSupportFor(goos, goarch)
	case CloakBrowser:
		return CloakBrowserSupportFor(goos, goarch)
	case BrowseForgeChromium:
		return BrowseForgeChromiumSupportFor(goos, goarch)
	default:
		return unsupportedRuntime(runtimeID, runtimeID, "", goos, goarch)
	}
}

func ExpectedCloakBrowserVersionFor(goos string) string {
	if goos == "darwin" {
		return CloakBrowserDarwinVersion
	}
	return CloakBrowserVersion
}

func ExpectedCloakBrowserVersion() string {
	return ExpectedCloakBrowserVersionFor(goruntime.GOOS)
}

func ExpectedBrowseForgeChromiumVersion() string {
	return BrowseForgeChromiumVersion
}

func BrowseForgeChromiumSupportFor(goos, goarch string) RuntimeSupport {
	if _, err := BrowseForgeChromiumPlatformFor(goos, goarch); err != nil {
		return unsupportedRuntime(BrowseForgeChromiumRuntimeID, "BrowseForge Chromium", BrowseForgeChromiumVersion, goos, goarch)
	}
	return supportedRuntime(BrowseForgeChromiumRuntimeID, "BrowseForge Chromium", BrowseForgeChromiumVersion, goos, goarch)
}

func BrowseForgeChromiumPlatformFor(goos, goarch string) (string, error) {
	switch goos {
	case "darwin":
		switch goarch {
		case "arm64":
			return "macos-arm64", nil
		case "amd64":
			return "macos-x64", nil
		}
	case "linux":
		switch goarch {
		case "amd64":
			return "linux-x64", nil
		case "arm64":
			return "linux-arm64", nil
		}
	case "windows":
		if goarch == "amd64" {
			return "windows-x64", nil
		}
	}
	return "", fmt.Errorf("unsupported BrowseForge Chromium platform: %s/%s", goos, goarch)
}

func CamoufoxSupportFor(goos, goarch string) RuntimeSupport {
	if _, err := CamoufoxDownloadFilenameFor(CamoufoxVersion, goos, goarch); err != nil {
		return unsupportedRuntime(string(Camoufox), "Camoufox", CamoufoxVersion, goos, goarch)
	}
	return supportedRuntime(string(Camoufox), "Camoufox", CamoufoxVersion, goos, goarch)
}

func CamoufoxDownloadFilenameFor(version, goos, goarch string) (string, error) {
	releaseVersion := strings.TrimPrefix(version, "v")
	suffix := ""
	switch goos {
	case "darwin":
		switch goarch {
		case "amd64":
			suffix = "mac.x86_64"
		case "arm64":
			suffix = "mac.arm64"
		}
	case "linux":
		switch goarch {
		case "amd64":
			suffix = "lin.x86_64"
		case "arm64":
			suffix = "lin.arm64"
		}
	case "windows":
		if goarch == "amd64" {
			suffix = "win.x86_64"
		}
	}
	if suffix == "" {
		return "", UnsupportedRuntimePlatformError{Runtime: "Camoufox", Version: version, GOOS: goos, GOARCH: goarch}
	}
	return fmt.Sprintf("camoufox-%s-%s.zip", releaseVersion, suffix), nil
}

func CloakBrowserSupportFor(goos, goarch string) RuntimeSupport {
	version, _, err := CloakBrowserArchiveFilenameFor(goos, goarch)
	if err != nil {
		return unsupportedRuntime(string(CloakBrowser), "CloakBrowser", version, goos, goarch)
	}
	return supportedRuntime(string(CloakBrowser), "CloakBrowser", version, goos, goarch)
}

func CloakBrowserArchiveFilenameFor(goos, goarch string) (version, filename string, err error) {
	version = ExpectedCloakBrowserVersionFor(goos)
	switch goos {
	case "darwin":
		switch goarch {
		case "amd64":
			return version, "cloakbrowser-darwin-x64.tar.gz", nil
		case "arm64":
			return version, "cloakbrowser-darwin-arm64.tar.gz", nil
		}
	case "linux":
		switch goarch {
		case "amd64":
			return version, "cloakbrowser-linux-x64.tar.gz", nil
		case "arm64":
			return version, "cloakbrowser-linux-arm64.tar.gz", nil
		}
	case "windows":
		if goarch == "amd64" {
			return version, "cloakbrowser-windows-x64.zip", nil
		}
	}
	return version, "", UnsupportedRuntimePlatformError{Runtime: "CloakBrowser", Version: version, GOOS: goos, GOARCH: goarch}
}
