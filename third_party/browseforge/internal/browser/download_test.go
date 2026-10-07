package browser

import (
	"archive/zip"
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindBinaryLocatesBrowseForgeChromiumArtifactLayouts(t *testing.T) {
	tests := []struct {
		name      string
		binaryRel string
	}{
		{
			name:      "direct app bundle",
			binaryRel: filepath.Join("Chromium.app", "Contents", "MacOS", "Chromium"),
		},
		{
			name:      "direct chrome executable",
			binaryRel: "chrome",
		},
		{
			name:      "direct windows executable",
			binaryRel: "chrome.exe",
		},
		{
			name:      "extracted artifact root with app bundle",
			binaryRel: filepath.Join("browseforge-runtime-chromium-v0.1.5-alpha.0-macos-x64", "Chromium.app", "Contents", "MacOS", "Chromium"),
		},
		{
			name:      "extracted artifact root with linux executable",
			binaryRel: filepath.Join("browseforge-runtime-chromium-v0.1.5-alpha.0-linux-x64", "chrome"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			baseDir := t.TempDir()
			wantPath := filepath.Join(baseDir, "browsers", BrowseForgeChromiumRuntimeID, tc.binaryRel)
			if err := os.MkdirAll(filepath.Dir(wantPath), 0755); err != nil {
				t.Fatalf("mkdir binary dir: %v", err)
			}
			if err := os.WriteFile(wantPath, []byte("chromium binary"), 0755); err != nil {
				t.Fatalf("write binary: %v", err)
			}

			if got := FindBinary(baseDir, BrowseForgeChromiumRuntimeID); got != wantPath {
				t.Fatalf("FindBinary() = %q, want %q", got, wantPath)
			}
		})
	}
}

func TestBrowseForgeChromiumPlatformFor(t *testing.T) {
	tests := []struct {
		name       string
		goos       string
		goarch     string
		want       string
		wantErr    bool
		wantErrMsg string
	}{
		{name: "macOS arm64", goos: "darwin", goarch: "arm64", want: "macos-arm64"},
		{name: "macOS x64", goos: "darwin", goarch: "amd64", want: "macos-x64"},
		{name: "Linux x64", goos: "linux", goarch: "amd64", want: "linux-x64"},
		{name: "Linux arm64", goos: "linux", goarch: "arm64", want: "linux-arm64"},
		{name: "Windows x64", goos: "windows", goarch: "amd64", want: "windows-x64"},
		{name: "Windows arm64 unsupported", goos: "windows", goarch: "arm64", wantErr: true, wantErrMsg: "unsupported BrowseForge Chromium platform: windows/arm64"},
		{name: "Linux 386 unsupported", goos: "linux", goarch: "386", wantErr: true, wantErrMsg: "unsupported BrowseForge Chromium platform: linux/386"},
		{name: "FreeBSD amd64 unsupported", goos: "freebsd", goarch: "amd64", wantErr: true, wantErrMsg: "unsupported BrowseForge Chromium platform: freebsd/amd64"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := browseForgeChromiumPlatformFor(tc.goos, tc.goarch)
			if tc.wantErr {
				if err == nil {
					t.Fatal("browseForgeChromiumPlatformFor() error = nil, want error")
				}
				if err.Error() != tc.wantErrMsg {
					t.Fatalf("browseForgeChromiumPlatformFor() error = %q, want %q", err.Error(), tc.wantErrMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("browseForgeChromiumPlatformFor() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("browseForgeChromiumPlatformFor() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBrowseForgeChromiumDownloadURLForLinuxArm64(t *testing.T) {
	t.Setenv("BROWSEFORGE_CHROMIUM_RELEASE_BASE_URL", "https://runtime.example/releases/")

	gotURL, gotFilename, err := browseForgeChromiumDownloadURLFor(BrowseForgeChromiumVersion, "linux", "arm64")
	if err != nil {
		t.Fatalf("browseForgeChromiumDownloadURLFor() error = %v", err)
	}

	wantFilename := "browseforge-runtime-chromium-" + BrowseForgeChromiumVersion + "-linux-arm64.zip"
	if gotFilename != wantFilename {
		t.Fatalf("filename = %q, want %q", gotFilename, wantFilename)
	}

	wantURL := "https://runtime.example/releases/" + BrowseForgeChromiumVersion + "/" + wantFilename
	if gotURL != wantURL {
		t.Fatalf("url = %q, want %q", gotURL, wantURL)
	}
}

func TestCamoufoxDownloadURLForSupportedPlatforms(t *testing.T) {
	tests := []struct {
		name         string
		goos         string
		goarch       string
		wantFilename string
	}{
		{name: "macOS x64", goos: "darwin", goarch: "amd64", wantFilename: "camoufox-135.0.1-beta.24-mac.x86_64.zip"},
		{name: "macOS arm64", goos: "darwin", goarch: "arm64", wantFilename: "camoufox-135.0.1-beta.24-mac.arm64.zip"},
		{name: "Linux x64", goos: "linux", goarch: "amd64", wantFilename: "camoufox-135.0.1-beta.24-lin.x86_64.zip"},
		{name: "Linux arm64", goos: "linux", goarch: "arm64", wantFilename: "camoufox-135.0.1-beta.24-lin.arm64.zip"},
		{name: "Windows x64", goos: "windows", goarch: "amd64", wantFilename: "camoufox-135.0.1-beta.24-win.x86_64.zip"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotURL, gotFilename, err := camoufoxDownloadURLFor(CamoufoxVersion, tc.goos, tc.goarch)
			if err != nil {
				t.Fatalf("camoufoxDownloadURLFor() error = %v", err)
			}
			if gotFilename != tc.wantFilename {
				t.Fatalf("filename = %q, want %q", gotFilename, tc.wantFilename)
			}
			wantURL := "https://github.com/daijro/camoufox/releases/download/" + CamoufoxVersion + "/" + tc.wantFilename
			if gotURL != wantURL {
				t.Fatalf("url = %q, want %q", gotURL, wantURL)
			}
		})
	}
}

func TestCamoufoxDownloadURLForUnsupportedPlatforms(t *testing.T) {
	for _, tc := range []struct {
		goos   string
		goarch string
	}{
		{goos: "windows", goarch: "arm64"},
		{goos: "linux", goarch: "386"},
		{goos: "freebsd", goarch: "amd64"},
	} {
		_, _, err := camoufoxDownloadURLFor(CamoufoxVersion, tc.goos, tc.goarch)
		if !errors.Is(err, ErrUnsupportedRuntimePlatform) {
			t.Fatalf("camoufoxDownloadURLFor(%s/%s) error = %v, want ErrUnsupportedRuntimePlatform", tc.goos, tc.goarch, err)
		}
	}
}

func TestDownloadBrowseForgeChromiumExtractsFlattenedExecutable(t *testing.T) {
	platform, err := browseForgeChromiumPlatform()
	if err != nil {
		t.Skipf("BrowseForge Chromium runtime is not available on this test platform: %v", err)
	}

	filename := "browseforge-runtime-chromium-" + BrowseForgeChromiumVersion + "-" + platform + ".zip"
	exeName := "chrome"
	if platform == "windows-x64" {
		exeName = "chrome.exe"
	}
	archiveRoot := strings.TrimSuffix(filename, ".zip")
	archive := zipArchive(t, filepath.Join(archiveRoot, exeName), []byte("chromium binary"), 0755)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wantPath := "/" + BrowseForgeChromiumVersion + "/" + filename
		if r.URL.Path != wantPath {
			http.NotFound(w, r)
			t.Errorf("download path = %q, want %q", r.URL.Path, wantPath)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(archive)
	}))
	defer server.Close()

	t.Setenv("BROWSEFORGE_CHROMIUM_RELEASE_BASE_URL", server.URL)
	baseDir := t.TempDir()
	gotPath, err := DownloadBrowseForgeChromium(baseDir)
	if err != nil {
		t.Fatalf("DownloadBrowseForgeChromium() error = %v", err)
	}

	wantPath := filepath.Join(baseDir, "browsers", BrowseForgeChromiumRuntimeID, exeName)
	if gotPath != wantPath {
		t.Fatalf("DownloadBrowseForgeChromium() path = %q, want %q", gotPath, wantPath)
	}

	info, err := os.Stat(wantPath)
	if err != nil {
		t.Fatalf("stat extracted executable: %v", err)
	}
	if info.IsDir() {
		t.Fatalf("extracted executable is a directory: %s", wantPath)
	}
	if info.Mode().Perm()&0111 == 0 {
		t.Fatalf("extracted executable mode = %v, want executable bit set", info.Mode().Perm())
	}

	if gotVersion := InstalledVersion(baseDir, BrowseForgeChromiumRuntimeID); gotVersion != BrowseForgeChromiumVersion {
		t.Fatalf("installed version = %q, want %q", gotVersion, BrowseForgeChromiumVersion)
	}

	if _, err := os.Stat(filepath.Join(baseDir, "browsers", BrowseForgeChromiumRuntimeID, archiveRoot)); !os.IsNotExist(err) {
		t.Fatalf("archive wrapper directory still exists after flatten: err=%v", err)
	}
}

func zipArchive(t *testing.T, name string, data []byte, mode os.FileMode) []byte {
	t.Helper()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	hdr := &zip.FileHeader{Name: name, Method: zip.Deflate}
	hdr.SetMode(mode)
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		t.Fatalf("create zip header: %v", err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("write zip payload: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}
