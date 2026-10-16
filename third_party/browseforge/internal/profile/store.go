package profile

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Profile struct {
	ID                    string                 `json:"id"`
	Name                  string                 `json:"name"`
	RuntimeID             string                 `json:"runtime_id"` // concrete runtime provider, e.g. "camoufox" | "cloakbrowser"
	Identity              *IdentityConfig        `json:"identity,omitempty"`
	LaunchOverrides       *LaunchOverrides       `json:"launch_overrides,omitempty"`
	Group                 string                 `json:"group,omitempty"`
	Tags                  []string               `json:"tags,omitempty"`
	CreatedAt             time.Time              `json:"created_at"`
	LastUsed              time.Time              `json:"last_used"`
	Fingerprint           map[string]any         `json:"fingerprint,omitempty"`
	FingerprintSeed       uint32                 `json:"fingerprint_seed,omitempty"` // Seed-based provider identity
	FingerprintGeneration *FingerprintGeneration `json:"fingerprint_generation,omitempty"`
	Proxy                 *ProxyConfig           `json:"proxy,omitempty"`
	ManagedProxyRequired  bool                   `json:"managed_proxy_required,omitempty"`
	ContainerID           string                 `json:"container_id,omitempty"`
	ProfileDir            string                 `json:"profile_dir"`
	// SessionProxy is an ephemeral managed bridge selected for one launch. It
	// cannot be imported, exported, or written into profile.json.
	SessionProxy       *ProxyConfig   `json:"-"`
	SessionPrivacy     *PrivacyConfig `json:"-"`
	SessionGeolocation *Geolocation   `json:"-"`
	SessionCountryCode string         `json:"-"`
}

type IdentityConfig struct {
	TargetOS     string `json:"target_os,omitempty"` // macos | windows | linux
	BrowserMajor int    `json:"browser_major,omitempty"`
	GPUVendor    string `json:"gpu_vendor,omitempty"`
	GPURenderer  string `json:"gpu_renderer,omitempty"`
	FontPack     string `json:"font_pack,omitempty"`
	RiskAccepted bool   `json:"risk_accepted,omitempty"`
}

type ProxyConfig struct {
	Type     string `json:"type"` // "socks5" | "http"
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Region   string `json:"region,omitempty"`
}

type Store struct {
	dir      string
	mu       sync.RWMutex
	profiles map[string]*Profile
}

func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, profiles: make(map[string]*Profile)}
	return s, s.loadAll()
}

func (s *Store) loadAll() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(s.dir, e.Name(), "profile.json")
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var p Profile
		if err := json.Unmarshal(data, &p); err != nil {
			continue
		}
		if err := validateV2Profile(&p, path); err != nil {
			return err
		}
		s.profiles[p.ID] = &p
	}
	return nil
}
func (s *Store) Create(p *Profile) error {
	return s.create(p, false)
}

// CreatePreservingIdentity restores an imported identity without regenerating
// missing fields or migrating its saved seed, including legacy zero seeds.
func (s *Store) CreatePreservingIdentity(p *Profile) error {
	return s.create(p, true)
}

func (s *Store) create(p *Profile, preserveIdentity bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if p.ID == "" {
		id, err := generateID()
		if err != nil {
			return err
		}
		p.ID = id
	}
	if err := validateV2Profile(p, "new profile"); err != nil {
		return err
	}
	if !preserveIdentity && usesFingerprintSeed(p.RuntimeID) && p.FingerprintSeed == 0 {
		seed, err := randomFingerprintSeed(rand.Reader, 0)
		if err != nil {
			return err
		}
		p.FingerprintSeed = seed
	}
	if !preserveIdentity {
		if err := generateProfileFingerprint(p); err != nil {
			return err
		}
	}
	p.CreatedAt = time.Now()
	p.LastUsed = p.CreatedAt
	p.ProfileDir = filepath.Join(s.dir, p.ID)

	if err := os.MkdirAll(p.ProfileDir, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(p.ProfileDir, "browser-data"), 0755); err != nil {
		return err
	}

	if err := s.save(p); err != nil {
		return err
	}
	s.profiles[p.ID] = p
	return nil
}

func validateV2Profile(p *Profile, source string) error {
	if p == nil {
		return fmt.Errorf("%s is nil", source)
	}
	if p.RuntimeID == "" {
		return fmt.Errorf("%s uses v1 profile schema: runtime_id is required; run BrowseForge migrate profiles --from v1 --to v2", source)
	}
	return ValidateLaunchOverrides(p.LaunchOverrides)
}

func (s *Store) Get(id string) (*Profile, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.profiles[id]
	if !ok {
		return nil, fmt.Errorf("profile not found: %s", id)
	}
	return p, nil
}

func (s *Store) List(group, tag string) []*Profile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Profile
	for _, p := range s.profiles {
		if group != "" && p.Group != group {
			continue
		}
		if tag != "" && !contains(p.Tags, tag) {
			continue
		}
		result = append(result, p)
	}
	return result
}

func (s *Store) Update(id string, updates map[string]any) (*Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.profiles[id]
	if !ok {
		return nil, fmt.Errorf("profile not found: %s", id)
	}

	data, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	for k, v := range updates {
		m[k] = v
	}
	merged, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var candidate Profile
	if err := json.Unmarshal(merged, &candidate); err != nil {
		return nil, err
	}
	if err := validateV2Profile(&candidate, "updated profile"); err != nil {
		return nil, err
	}
	if _, supplied := updates["fingerprint_generation"]; !supplied && candidate.FingerprintGeneration != nil {
		if _, supplied := updates["fingerprint"]; supplied {
			for key := range candidate.Fingerprint {
				delete(candidate.FingerprintGeneration.GeneratedFields, key)
			}
		}
	}
	if err := s.save(&candidate); err != nil {
		return nil, err
	}
	*p = candidate
	return p, nil
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.profiles[id]
	if !ok {
		return fmt.Errorf("profile not found: %s", id)
	}
	os.RemoveAll(p.ProfileDir)
	delete(s.profiles, id)
	return nil
}

func (s *Store) Duplicate(id string, names ...string) (*Profile, error) {
	s.mu.RLock()
	src, ok := s.profiles[id]
	if !ok {
		s.mu.RUnlock()
		return nil, fmt.Errorf("profile not found: %s", id)
	}

	data, err := json.Marshal(src)
	s.mu.RUnlock()
	if err != nil {
		return nil, err
	}
	var dup Profile
	if err := json.Unmarshal(data, &dup); err != nil {
		return nil, err
	}
	dup.ID = ""
	dup.Name += " (copy)"
	if len(names) > 0 {
		dup.Name = names[0]
	}
	dup.ContainerID = ""
	resetGeneratedFingerprint(&dup)
	if usesFingerprintSeed(dup.RuntimeID) {
		seed, err := randomFingerprintSeed(rand.Reader, dup.FingerprintSeed)
		if err != nil {
			return nil, err
		}
		dup.FingerprintSeed = seed
	}
	return &dup, s.Create(&dup)
}

func (s *Store) save(p *Profile) error {
	path := filepath.Join(p.ProfileDir, "profile.json")
	tmp := path + ".tmp"
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func generateID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "prof_" + hex.EncodeToString(b), nil
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
