package groups

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"browseforge/internal/profile"
)

const (
	ProxyModeDefault  = "default"
	ProxyModeEnforced = "enforced"
)

type Group struct {
	Name      string               `json:"name"`
	ProxyMode string               `json:"proxy_mode,omitempty"`
	Proxy     *profile.ProxyConfig `json:"proxy,omitempty"`
	CreatedAt time.Time            `json:"created_at"`
	UpdatedAt time.Time            `json:"updated_at"`
}

type EffectiveProxy struct {
	Proxy  *profile.ProxyConfig
	Source string
	Mode   string
}

type Store struct {
	path   string
	mu     sync.RWMutex
	groups map[string]*Group
}

func NewStore(dataDir string) (*Store, error) {
	if dataDir == "" {
		dataDir = "data"
	}
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dataDir, "groups.json"), groups: make(map[string]*Group)}
	return s, s.load()
}

func (s *Store) List() []*Group {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.groups))
	for name := range s.groups {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]*Group, 0, len(names))
	for _, name := range names {
		out = append(out, cloneGroup(s.groups[name]))
	}
	return out
}

func (s *Store) Get(name string) (*Group, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.groups[normalizeName(name)]
	if !ok {
		return nil, false
	}
	return cloneGroup(g), true
}

func (s *Store) Upsert(name string, proxy *profile.ProxyConfig, mode string) (*Group, error) {
	name = normalizeName(name)
	if name == "" {
		return nil, fmt.Errorf("group name is required")
	}
	if proxy == nil {
		return nil, fmt.Errorf("proxy is required")
	}
	mode = normalizeMode(mode)
	if err := validateProxyMode(mode); err != nil {
		return nil, err
	}
	proxy = cloneProxy(proxy)
	if err := validateProxy(proxy); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	g, ok := s.groups[name]
	if !ok {
		g = &Group{Name: name, CreatedAt: now}
		s.groups[name] = g
	}
	g.Proxy = proxy
	g.ProxyMode = mode
	g.UpdatedAt = now
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return cloneGroup(g), nil
}

func (s *Store) ClearProxy(name string) (*Group, error) {
	name = normalizeName(name)
	if name == "" {
		return nil, fmt.Errorf("group name is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	g, ok := s.groups[name]
	if !ok {
		g = &Group{Name: name, ProxyMode: ProxyModeDefault, CreatedAt: now, UpdatedAt: now}
		return cloneGroup(g), nil
	}
	delete(s.groups, name)
	g = &Group{Name: name, ProxyMode: ProxyModeDefault, CreatedAt: g.CreatedAt, UpdatedAt: now}
	if err := s.saveLocked(); err != nil {
		return nil, err
	}
	return cloneGroup(g), nil
}

func (s *Store) Export() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.groups))
	for name := range s.groups {
		names = append(names, name)
	}
	sort.Strings(names)
	file := groupFile{Groups: make([]Group, 0, len(names))}
	for _, name := range names {
		file.Groups = append(file.Groups, *cloneGroup(s.groups[name]))
	}
	return json.MarshalIndent(file, "", "  ")
}

func (s *Store) Import(data []byte) (int, error) {
	var file groupFile
	if err := json.Unmarshal(data, &file); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for i := range file.Groups {
		g := file.Groups[i]
		g.Name = normalizeName(g.Name)
		if g.Name == "" {
			continue
		}
		g.ProxyMode = normalizeMode(g.ProxyMode)
		if err := validateProxyMode(g.ProxyMode); err != nil {
			continue
		}
		if g.Proxy == nil {
			continue
		}
		g.Proxy = cloneProxy(g.Proxy)
		if err := validateProxy(g.Proxy); err != nil {
			continue
		}
		if g.CreatedAt.IsZero() {
			g.CreatedAt = time.Now()
		}
		if g.UpdatedAt.IsZero() {
			g.UpdatedAt = g.CreatedAt
		}
		s.groups[g.Name] = cloneGroup(&g)
		count++
	}
	if err := s.saveLocked(); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Store) EffectiveProxy(p *profile.Profile) EffectiveProxy {
	if p == nil {
		return EffectiveProxy{Source: "none", Mode: ProxyModeDefault}
	}

	var group *Group
	if p.Group != "" {
		s.mu.RLock()
		group = cloneGroup(s.groups[normalizeName(p.Group)])
		s.mu.RUnlock()
	}

	profileProxy := normalizeProxy(p.Proxy)
	groupProxy := normalizeProxy(nil)
	mode := ProxyModeDefault
	if group != nil {
		mode = normalizeMode(group.ProxyMode)
		groupProxy = normalizeProxy(group.Proxy)
	}

	if mode == ProxyModeEnforced && groupProxy != nil {
		return EffectiveProxy{Proxy: groupProxy, Source: "group", Mode: mode}
	}
	if profileProxy != nil {
		return EffectiveProxy{Proxy: profileProxy, Source: "profile", Mode: mode}
	}
	if groupProxy != nil {
		return EffectiveProxy{Proxy: groupProxy, Source: "group", Mode: mode}
	}
	return EffectiveProxy{Source: "none", Mode: mode}
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var file groupFile
	if err := json.Unmarshal(data, &file); err != nil {
		return err
	}
	for i := range file.Groups {
		g := file.Groups[i]
		g.Name = normalizeName(g.Name)
		if g.Name == "" {
			continue
		}
		g.ProxyMode = normalizeMode(g.ProxyMode)
		if err := validateProxyMode(g.ProxyMode); err != nil {
			continue
		}
		if g.Proxy == nil {
			continue
		}
		g.Proxy = cloneProxy(g.Proxy)
		if err := validateProxy(g.Proxy); err != nil {
			continue
		}
		s.groups[g.Name] = cloneGroup(&g)
	}
	return nil
}

func (s *Store) saveLocked() error {
	names := make([]string, 0, len(s.groups))
	for name := range s.groups {
		names = append(names, name)
	}
	sort.Strings(names)
	file := groupFile{Groups: make([]Group, 0, len(names))}
	for _, name := range names {
		file.Groups = append(file.Groups, *cloneGroup(s.groups[name]))
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

type groupFile struct {
	Groups []Group `json:"groups"`
}

func normalizeName(name string) string {
	return strings.TrimSpace(name)
}

func normalizeMode(mode string) string {
	mode = strings.TrimSpace(strings.ToLower(mode))
	if mode == "" {
		return ProxyModeDefault
	}
	return mode
}

func validateProxyMode(mode string) error {
	switch mode {
	case ProxyModeDefault, ProxyModeEnforced:
		return nil
	default:
		return fmt.Errorf("unsupported proxy mode %q (supported: %s, %s)", mode, ProxyModeDefault, ProxyModeEnforced)
	}
}

func validateProxy(proxy *profile.ProxyConfig) error {
	if proxy == nil {
		return nil
	}
	if proxy.Type != "socks5" && proxy.Type != "http" {
		return fmt.Errorf("unsupported proxy type %q", proxy.Type)
	}
	if strings.TrimSpace(proxy.Host) == "" {
		return fmt.Errorf("proxy host is required")
	}
	if proxy.Port <= 0 || proxy.Port > 65535 {
		return fmt.Errorf("proxy port must be between 1 and 65535")
	}
	return nil
}

func normalizeProxy(proxy *profile.ProxyConfig) *profile.ProxyConfig {
	if proxy == nil || strings.TrimSpace(proxy.Host) == "" {
		return nil
	}
	return cloneProxy(proxy)
}

func cloneGroup(g *Group) *Group {
	if g == nil {
		return nil
	}
	out := *g
	out.Proxy = cloneProxy(g.Proxy)
	return &out
}

func cloneProxy(proxy *profile.ProxyConfig) *profile.ProxyConfig {
	if proxy == nil {
		return nil
	}
	out := *proxy
	out.Type = strings.TrimSpace(strings.ToLower(out.Type))
	out.Host = strings.TrimSpace(out.Host)
	out.Region = strings.TrimSpace(out.Region)
	return &out
}
