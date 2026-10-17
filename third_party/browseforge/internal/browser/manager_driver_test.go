package browser

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/playwright-community/playwright-go"
)

func TestStartPlaywrightDriverRequiresExplicitBundledMode(t *testing.T) {
	for _, mode := range []string{"", "0", "true", " 1", "1 ", "bundled", "1"} {
		t.Run("mode="+mode, func(t *testing.T) {
			t.Setenv("ENVARA_DESKTOP_BUNDLED_DRIVER", mode)
			// Driver paths alone do not opt a standalone CLI into bundled mode.
			t.Setenv("PLAYWRIGHT_DRIVER_PATH", t.TempDir())
			t.Setenv("PLAYWRIGHT_CLI_PATH", filepath.Join(t.TempDir(), "cli.js"))
			t.Setenv("PLAYWRIGHT_NODEJS_PATH", filepath.Join(t.TempDir(), "node"))
			var calls []string
			want := &playwright.Playwright{}
			got, err := startPlaywrightDriver(func() error {
				calls = append(calls, "install")
				return nil
			}, func() (*playwright.Playwright, error) {
				calls = append(calls, "run")
				return want, nil
			})
			if err != nil || got != want {
				t.Fatalf("result = %p, %v; want %p, nil", got, err, want)
			}
			wantCalls := []string{"install", "run"}
			if mode == "1" {
				wantCalls = []string{"run"}
			}
			if !reflect.DeepEqual(calls, wantCalls) {
				t.Fatalf("calls = %v, want %v", calls, wantCalls)
			}
		})
	}
}

func TestStartPlaywrightDriverPreservesErrorsWithoutFallback(t *testing.T) {
	failure := errors.New("owned driver failure")
	t.Run("standalone install", func(t *testing.T) {
		t.Setenv("ENVARA_DESKTOP_BUNDLED_DRIVER", "")
		got, err := startPlaywrightDriver(func() error { return failure }, func() (*playwright.Playwright, error) {
			t.Fatal("run must not follow a failed install")
			return nil, nil
		})
		if got != nil || !errors.Is(err, failure) || !strings.HasPrefix(err.Error(), "playwright.Install: ") {
			t.Fatalf("result = %p, %v", got, err)
		}
	})
	for _, mode := range []string{"", "1"} {
		t.Run("run mode="+mode, func(t *testing.T) {
			t.Setenv("ENVARA_DESKTOP_BUNDLED_DRIVER", mode)
			installs, runs := 0, 0
			got, err := startPlaywrightDriver(func() error { installs++; return nil }, func() (*playwright.Playwright, error) {
				runs++
				return nil, failure
			})
			wantInstalls := 1
			if mode == "1" {
				wantInstalls = 0
			}
			if got != nil || !errors.Is(err, failure) || !strings.HasPrefix(err.Error(), "playwright.Run: ") || installs != wantInstalls || runs != 1 {
				t.Fatalf("result = %p, %v; installs=%d, runs=%d", got, err, installs, runs)
			}
		})
	}
}

func TestBundledPlaywrightDriverRejectsMissingResourcesWithoutInstall(t *testing.T) {
	t.Setenv("ENVARA_DESKTOP_BUNDLED_DRIVER", "1")
	directory := t.TempDir()
	t.Setenv("PLAYWRIGHT_DRIVER_PATH", directory)
	t.Setenv("PLAYWRIGHT_CLI_PATH", filepath.Join(directory, "missing-cli.js"))
	t.Setenv("PLAYWRIGHT_NODEJS_PATH", filepath.Join(directory, "missing-node"))
	got, err := startPlaywrightDriver(func() error {
		t.Fatal("a missing bundled driver must not trigger install or download")
		return nil
	}, func() (*playwright.Playwright, error) { return playwright.Run() })
	if got != nil || err == nil || !strings.Contains(err.Error(), "please install the driver") {
		t.Fatalf("result = %p, %v; want missing-driver rejection", got, err)
	}
	entries, readErr := os.ReadDir(directory)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("missing bundle was modified: entries=%v, error=%v", entries, readErr)
	}
}

func TestBundledPlaywrightDriverRejectsWrongVersionBeforeRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("owned executable fixture uses a POSIX shell")
	}
	t.Setenv("ENVARA_DESKTOP_BUNDLED_DRIVER", "1")
	directory := t.TempDir()
	cli := filepath.Join(directory, "package", "cli.js")
	if err := os.Mkdir(filepath.Dir(cli), 0o700); err != nil {
		t.Fatal(err)
	}
	node := filepath.Join(directory, "node")
	logFile := filepath.Join(directory, "calls")
	if err := os.WriteFile(cli, []byte("owned unused CLI fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const script = "#!/bin/sh\nif [ \"$2\" = \"--version\" ]; then\n  printf 'version\\n' >> \"$ENVARA_TEST_DRIVER_LOG\"\n  printf 'Version 0.0.0\\n'\nelse\n  printf 'unexpected\\n' >> \"$ENVARA_TEST_DRIVER_LOG\"\n  exit 2\nfi\n"
	if err := os.WriteFile(node, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PLAYWRIGHT_DRIVER_PATH", directory)
	t.Setenv("PLAYWRIGHT_CLI_PATH", cli)
	t.Setenv("PLAYWRIGHT_NODEJS_PATH", node)
	t.Setenv("ENVARA_TEST_DRIVER_LOG", logFile)
	got, err := startPlaywrightDriver(func() error {
		t.Fatal("an incompatible bundled driver must not trigger install or download")
		return nil
	}, func() (*playwright.Playwright, error) { return playwright.Run() })
	if got != nil || err == nil || !strings.Contains(err.Error(), "driver exists but version not") {
		t.Fatalf("result = %p, %v; want incompatible-driver rejection", got, err)
	}
	calls, readErr := os.ReadFile(logFile)
	if readErr != nil || string(calls) != "version\n" {
		t.Fatalf("calls = %q, %v; must check version once and never start run-driver", calls, readErr)
	}
	contents, readErr := os.ReadFile(cli)
	if readErr != nil || string(contents) != "owned unused CLI fixture\n" {
		t.Fatalf("bundled CLI was modified: %q, %v", contents, readErr)
	}
}
