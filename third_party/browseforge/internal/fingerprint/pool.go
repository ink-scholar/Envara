package fingerprint

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
)

type Pool struct {
	mu   sync.Mutex
	data map[string][]map[string]any // "firefox-windows" → []fingerprint
	used map[string]bool             // fingerprint hash → used
}

func NewPool(dir string) (*Pool, error) {
	p := &Pool{
		data: make(map[string][]map[string]any),
		used: make(map[string]bool),
	}
	files, _ := filepath.Glob(filepath.Join(dir, "fingerprints-*.json"))
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var fps []map[string]any
		if err := json.Unmarshal(raw, &fps); err != nil {
			continue
		}
		// Extract key from filename: fingerprints-firefox-windows.json → firefox-windows
		base := filepath.Base(f)
		key := base[len("fingerprints-") : len(base)-len(".json")]
		p.data[key] = fps
	}
	return p, nil
}

// Pick returns a random unused fingerprint for the given engine and OS
func (p *Pool) Pick(engine, os string) (map[string]any, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	key := engine + "-" + os
	fps, ok := p.data[key]
	if !ok || len(fps) == 0 {
		// Fallback: try any available pool for this engine
		for k, v := range p.data {
			if len(k) > len(engine) && k[:len(engine)] == engine && len(v) > 0 {
				fps = v
				key = k
				break
			}
		}
		if fps == nil {
			return nil, fmt.Errorf("no fingerprints available for %s-%s", engine, os)
		}
	}

	// Find unused fingerprint
	for i := 0; i < len(fps); i++ {
		idx := rand.Intn(len(fps))
		fp := fps[idx]
		hash := fmt.Sprintf("%s-%d", key, idx)
		if !p.used[hash] {
			p.used[hash] = true
			// Deep copy
			data, _ := json.Marshal(fp)
			var copy map[string]any
			json.Unmarshal(data, &copy)
			delete(copy, "_meta")
			return copy, nil
		}
	}

	return nil, fmt.Errorf("fingerprint pool exhausted for %s", key)
}

func (p *Pool) Available(engine, os string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := engine + "-" + os
	fps := p.data[key]
	count := 0
	for i := range fps {
		hash := fmt.Sprintf("%s-%d", key, i)
		if !p.used[hash] {
			count++
		}
	}
	return count
}
