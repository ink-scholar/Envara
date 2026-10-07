package host

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"

	"envara.io/windows-app-routing/internal/protocol"
)

func captureManifestFixture(t *testing.T) []byte {
	t.Helper()
	digest := sha256.Sum256([]byte("test artifact"))
	manifest := captureManifest{
		Schema: 1, CaptureABI: 1, Engine: "windivert", Architecture: "x64",
		Files: []captureArtifact{
			{Name: "EnvaraCapture.dll", SHA256: hex.EncodeToString(digest[:])},
			{Name: "WinDivert.dll", SHA256: hex.EncodeToString(digest[:])},
			{Name: "WinDivert64.sys", SHA256: hex.EncodeToString(digest[:])},
		},
	}
	manifest.Upstream.Project = "basil00/WinDivert"
	manifest.Upstream.Version = "2.2.2"
	manifest.Upstream.Commit = "1789526ecfb9ff5397c94f9f54c1a3dc2fb60440"
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestCaptureManifestRequiresPinnedArtifactsAndExactContract(t *testing.T) {
	valid := captureManifestFixture(t)
	manifest, err := decodeCaptureManifest(append(valid, []byte(" \n\t")...))
	if err != nil || len(manifest.Files) != 3 || manifest.CaptureABI != 1 {
		t.Fatalf("valid pinned manifest rejected: %v", err)
	}
	for _, mutation := range []struct{ name, from, to string }{
		{"wrong schema", `"schema":1`, `"schema":2`},
		{"wrong ABI", `"captureAbi":1`, `"captureAbi":2`},
		{"wrong engine", `"engine":"windivert"`, `"engine":"other"`},
		{"wrong architecture", `"architecture":"x64"`, `"architecture":"arm64"`},
		{"wrong project", `"project":"basil00/WinDivert"`, `"project":"other/WinDivert"`},
		{"wrong version", `"version":"2.2.2"`, `"version":"2.2.3"`},
		{"wrong commit", `1789526ecfb9ff5397c94f9f54c1a3dc2fb60440`, strings.Repeat("0", 40)},
		{"unknown root field", `"schema":1`, `"schema":1,"ready":true`},
		{"unknown upstream field", `"project":"basil00/WinDivert"`, `"project":"basil00/WinDivert","trusted":true`},
		{"unknown file field", `"name":"EnvaraCapture.dll"`, `"name":"EnvaraCapture.dll","signed":true`},
		{"missing schema", `"schema":1,`, ""},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			data := strings.Replace(string(valid), mutation.from, mutation.to, 1)
			if data == string(valid) {
				t.Fatal("fixture mutation did not apply")
			}
			if _, err := decodeCaptureManifest([]byte(data)); err == nil {
				t.Fatal("untrusted manifest accepted")
			}
		})
	}
}

func TestCaptureManifestRejectsArtifactPathsDuplicatesAndInvalidHashes(t *testing.T) {
	valid := captureManifestFixture(t)
	for _, name := range []string{
		"../EnvaraCapture.dll", "subdir/EnvaraCapture.dll", "/tmp/EnvaraCapture.dll",
		`C:\EnvaraCapture.dll`, `..\EnvaraCapture.dll`, "envaracapture.dll",
		"WinDivert.dll", "EnvaraCapture.dll\x00", "EnvaraCapture.dll:stream",
	} {
		t.Run(name, func(t *testing.T) {
			var candidate captureManifest
			if err := json.Unmarshal(valid, &candidate); err != nil {
				t.Fatal(err)
			}
			candidate.Files[0].Name = name
			data, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeCaptureManifest(data); err == nil {
				t.Fatal("path or duplicate artifact accepted")
			}
		})
	}
	var manifest captureManifest
	if err := json.Unmarshal(valid, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, hash := range []string{"", strings.Repeat("0", 62), strings.Repeat("0", 66), strings.Repeat("z", 64), strings.ToUpper(manifest.Files[0].SHA256)} {
		t.Run("hash "+hash, func(t *testing.T) {
			candidate := manifest
			candidate.Files = append([]captureArtifact(nil), manifest.Files...)
			candidate.Files[0].SHA256 = hash
			data, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeCaptureManifest(data); err == nil {
				t.Fatal("noncanonical artifact hash accepted")
			}
		})
	}
	for _, count := range []int{0, 2, 4} {
		candidate := manifest
		candidate.Files = append([]captureArtifact(nil), manifest.Files...)
		if count == 0 {
			candidate.Files = nil
		} else if count == 4 {
			candidate.Files = append(candidate.Files, manifest.Files[0])
		} else {
			candidate.Files = candidate.Files[:count]
		}
		data, err := json.Marshal(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeCaptureManifest(data); err == nil {
			t.Fatalf("accepted %d artifacts", count)
		}
	}
}

func TestCaptureManifestRejectsTrailingAndOversizeInput(t *testing.T) {
	valid := captureManifestFixture(t)
	boundary := append(append([]byte(nil), valid...), bytes.Repeat([]byte(" "), 32768-len(valid))...)
	if _, err := decodeCaptureManifest(boundary); err != nil {
		t.Fatalf("valid manifest at size limit rejected: %v", err)
	}
	for _, data := range [][]byte{
		nil, []byte("null"), []byte("{"), append(append([]byte(nil), valid...), valid...),
		append(append([]byte(nil), valid...), []byte(" null")...),
		append(append([]byte(nil), valid...), []byte(" garbage")...),
		append(boundary, ' '),
	} {
		if _, err := decodeCaptureManifest(data); err == nil {
			t.Fatal("ambiguous or invalid provenance accepted")
		}
	}
}

type captureErrorReader struct{}

func (captureErrorReader) Read([]byte) (int, error) { return 0, errors.New("test read failure") }

type captureZeroReader struct{}

func (captureZeroReader) Read(buffer []byte) (int, error) {
	clear(buffer)
	return len(buffer), nil
}

func TestCaptureHashRejectsTamperingReadFailureAndOversizeArtifact(t *testing.T) {
	contents := []byte("test artifact")
	digest := sha256.Sum256(contents)
	expected := hex.EncodeToString(digest[:])
	if err := verifyCaptureHash(bytes.NewReader(contents), expected); err != nil {
		t.Fatal(err)
	}
	if err := verifyCaptureHash(bytes.NewReader([]byte("tampered artifact")), expected); err == nil {
		t.Fatal("tampered artifact accepted")
	}
	emptyDigest := sha256.Sum256(nil)
	if err := verifyCaptureHash(captureErrorReader{}, hex.EncodeToString(emptyDigest[:])); err == nil {
		t.Fatal("artifact reader failure ignored")
	}
	oversizeHash := sha256.New()
	if _, err := io.Copy(oversizeHash, io.LimitReader(captureZeroReader{}, 64*1024*1024+1)); err != nil {
		t.Fatal(err)
	}
	if err := verifyCaptureHash(io.LimitReader(captureZeroReader{}, 64*1024*1024+1), hex.EncodeToString(oversizeHash.Sum(nil))); err == nil {
		t.Fatal("correctly hashed oversized artifact accepted")
	}
	if err := verifyCaptureHash(bytes.NewReader(contents), strings.ToUpper(expected)); err == nil {
		t.Fatal("noncanonical expected hash accepted")
	}
}

func TestPortableCaptureStatusAndSetupNeverActivateOrAuthorize(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("portable boundary test; never calls the Windows host")
	}
	for _, method := range []string{"status", "setup"} {
		response := Call(protocol.Request{Protocol: protocol.Name, Version: protocol.Version, ID: "capture-portable", Method: method})
		status, ok := response.Result.(protocol.Status)
		if response.Error != nil || !ok {
			t.Fatalf("%s did not return a portable missing status: %#v", method, response)
		}
		if status.CanLaunch() || status.Installed || status.Authorized || status.Ready || status.Capture != nil || status.Verification.Passed || status.Verification.Version != "windows-windivert-v1" || len(status.Sessions) != 0 {
			t.Fatalf("%s implied activation or native acceptance: %#v", method, status)
		}
	}
	response := Call(protocol.Request{Protocol: protocol.Name, Version: protocol.Version, ID: "capture-portable", Method: "launch"})
	if response.Error == nil || response.Error.Code != "PLATFORM_UNSUPPORTED" || response.Result != nil {
		t.Fatal("portable host did not reject launch")
	}
}
