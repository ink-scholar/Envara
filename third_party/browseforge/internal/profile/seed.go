package profile

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Camoufox owns a structured fingerprint rather than Chromium's seed contract.
func usesFingerprintSeed(runtimeID string) bool {
	return runtimeID == "cloakbrowser" || runtimeID == "browseforge-chromium"
}

func randomFingerprintSeed(source io.Reader, previous uint32) (uint32, error) {
	var bytes [4]byte
	for {
		if _, err := io.ReadFull(source, bytes[:]); err != nil {
			return 0, fmt.Errorf("generate fingerprint seed: %w", err)
		}
		seed := binary.BigEndian.Uint32(bytes[:])
		if seed != 0 && seed != previous {
			return seed, nil
		}
	}
}
