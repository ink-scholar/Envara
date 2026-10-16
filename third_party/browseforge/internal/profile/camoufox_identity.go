package profile

import (
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"sync"
)

// CamoufoxIdentityVersion identifies the generated, OS-matched native tuples.
// The small catalog is built ahead of time; users need no Python or model fetch.
const CamoufoxIdentityVersion = "camoufox-135.0.1-beta.24/browserforge-1.2.1/catalog-v1"

//go:embed camoufox-data/catalog.json
var camoufoxIdentityCatalog []byte

type camoufoxIdentityTuple struct {
	ID          string         `json:"id"`
	TargetOS    string         `json:"targetOS"`
	Fingerprint map[string]any `json:"fingerprint"`
}

var camoufoxCatalogCache struct {
	sync.Once
	byOS map[string][]camoufoxIdentityTuple
	err  error
}

func loadCamoufoxIdentityCatalog() (map[string][]camoufoxIdentityTuple, error) {
	camoufoxCatalogCache.Do(func() {
		var catalog struct {
			SchemaVersion int                     `json:"schemaVersion"`
			Provider      string                  `json:"provider"`
			FirefoxMajor  int                     `json:"firefoxMajor"`
			Templates     []camoufoxIdentityTuple `json:"templates"`
		}
		if err := json.Unmarshal(camoufoxIdentityCatalog, &catalog); err != nil {
			camoufoxCatalogCache.err = fmt.Errorf("read built-in Camoufox identity catalog: %w", err)
			return
		}
		if catalog.SchemaVersion != 1 || catalog.Provider != "camoufox" || catalog.FirefoxMajor != 135 {
			camoufoxCatalogCache.err = fmt.Errorf("unsupported built-in Camoufox identity catalog")
			return
		}
		byOS := make(map[string][]camoufoxIdentityTuple)
		for _, tuple := range catalog.Templates {
			if tuple.ID == "" || len(tuple.Fingerprint) == 0 {
				camoufoxCatalogCache.err = fmt.Errorf("incomplete built-in Camoufox identity tuple")
				return
			}
			byOS[tuple.TargetOS] = append(byOS[tuple.TargetOS], tuple)
		}
		for _, targetOS := range []string{"macos", "windows", "linux"} {
			if len(byOS[targetOS]) == 0 {
				camoufoxCatalogCache.err = fmt.Errorf("built-in Camoufox identity catalog is missing %s", targetOS)
				return
			}
		}
		camoufoxCatalogCache.byOS = byOS
	})
	return camoufoxCatalogCache.byOS, camoufoxCatalogCache.err
}

// NewCamoufoxIdentity generates only a new environment's identity. Callers must
// persist it once and preserve it on load/import. Every tuple keeps a complete
// official sampled WebGL family and same-OS browser/device/font parameters.
// Language, timezone, geolocation and route addresses belong to session context.
func NewCamoufoxIdentity(targetOS string) (tupleID string, fields map[string]any, err error) {
	return newCamoufoxIdentity(rand.Reader, targetOS)
}

func newCamoufoxIdentity(source io.Reader, targetOS string) (string, map[string]any, error) {
	if targetOS != "macos" && targetOS != "windows" && targetOS != "linux" {
		return "", nil, fmt.Errorf("Camoufox identity requires macos, windows or linux")
	}
	catalog, err := loadCamoufoxIdentityCatalog()
	if err != nil {
		return "", nil, err
	}
	index, err := rand.Int(source, big.NewInt(int64(len(catalog[targetOS]))))
	if err != nil {
		return "", nil, fmt.Errorf("select Camoufox identity: %w", err)
	}
	tuple := catalog[targetOS][index.Int64()]
	// Copy nested maps and arrays, so one profile edit cannot mutate another
	// profile or the cached source tuple.
	encoded, err := json.Marshal(tuple.Fingerprint)
	if err != nil {
		return "", nil, fmt.Errorf("copy Camoufox identity: %w", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return "", nil, fmt.Errorf("copy Camoufox identity: %w", err)
	}
	spacing, err := rand.Int(source, big.NewInt(1<<30))
	if err != nil {
		return "", nil, fmt.Errorf("generate Camoufox font spacing: %w", err)
	}
	aliasing, err := rand.Int(source, big.NewInt(101))
	if err != nil {
		return "", nil, fmt.Errorf("generate Camoufox canvas parameter: %w", err)
	}
	// Exactly the supported ranges used by the pinned official Python wrapper.
	fields["fonts:spacing_seed"] = spacing.Int64()
	fields["canvas:aaOffset"] = aliasing.Int64() - 50
	fields["canvas:aaCapOffset"] = true
	return tuple.ID, fields, nil
}
