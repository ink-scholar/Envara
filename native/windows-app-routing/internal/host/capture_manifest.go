package host

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

const captureManifestName = "capture-provenance.json"
const captureABI = 1

type captureArtifact struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}
type captureManifest struct {
	Schema       uint32 `json:"schema"`
	CaptureABI   uint32 `json:"captureAbi"`
	Engine       string `json:"engine"`
	Architecture string `json:"architecture"`
	Upstream     struct {
		Project string `json:"project"`
		Version string `json:"version"`
		Commit  string `json:"commit"`
	} `json:"upstream"`
	Files []captureArtifact `json:"files"`
}

// Provenance is accepted only from the administrator-protected installation.
// This decoder cannot activate a DLL or a driver, and names are not paths.
func decodeCaptureManifest(data []byte) (captureManifest, error) {
	var result captureManifest
	if len(data) == 0 || len(data) > 32768 {
		return result, errors.New("capture provenance size invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil {
		return result, errors.New("capture provenance invalid")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || result.Schema != 1 || result.CaptureABI != captureABI || result.Engine != "windivert" || result.Architecture != "x64" || result.Upstream.Project != "basil00/WinDivert" || result.Upstream.Version != "2.2.2" || result.Upstream.Commit != "1789526ecfb9ff5397c94f9f54c1a3dc2fb60440" || len(result.Files) != 3 {
		return result, errors.New("capture provenance contract invalid")
	}
	wanted := map[string]bool{"EnvaraCapture.dll": true, "WinDivert.dll": true, "WinDivert64.sys": true}
	for _, file := range result.Files {
		hash, err := hex.DecodeString(file.SHA256)
		if !wanted[file.Name] || err != nil || len(hash) != sha256.Size || hex.EncodeToString(hash) != file.SHA256 {
			return result, errors.New("capture artifact invalid")
		}
		delete(wanted, file.Name)
	}
	return result, nil
}

func verifyCaptureHash(reader io.Reader, expected string) error {
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(reader, 64*1024*1024+1))
	if err != nil || n > 64*1024*1024 || hex.EncodeToString(hash.Sum(nil)) != expected {
		return errors.New("capture artifact hash mismatch")
	}
	return nil
}
