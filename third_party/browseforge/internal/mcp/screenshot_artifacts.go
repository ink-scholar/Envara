package mcp

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const defaultScreenshotURLTTL = 10 * time.Minute

type screenshotArtifact struct {
	data      []byte
	mimeType  string
	ext       string
	expiresAt time.Time
}

type screenshotArtifactDiskRecord struct {
	MIMEType  string    `json:"mime_type"`
	Ext       string    `json:"ext"`
	ExpiresAt time.Time `json:"expires_at"`
}

type screenshotArtifactStore struct {
	mu    sync.Mutex
	items map[string]screenshotArtifact
	dir   string
}

func newScreenshotArtifactStore(dirs ...string) *screenshotArtifactStore {
	dir := ""
	if len(dirs) > 0 {
		dir = strings.TrimSpace(dirs[0])
	}
	return &screenshotArtifactStore{items: map[string]screenshotArtifact{}, dir: dir}
}

func (s *screenshotArtifactStore) setDir(dir string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dir = strings.TrimSpace(dir)
}

func (s *screenshotArtifactStore) save(data []byte, mimeType, ext string, ttl time.Duration) (string, time.Time, error) {
	id, err := randomHex(16)
	if err != nil {
		return "", time.Time{}, err
	}
	now := time.Now()
	expiresAt := now.Add(ttl)
	item := screenshotArtifact{data: data, mimeType: mimeType, ext: ext, expiresAt: expiresAt}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupExpiredLocked(now)
	if s.dir != "" {
		if err := s.writeDiskArtifactLocked(id, item); err != nil {
			return "", time.Time{}, err
		}
	}
	s.items[id] = item
	return id, expiresAt, nil
}

func (s *screenshotArtifactStore) get(id string) (screenshotArtifact, bool) {
	if !validScreenshotArtifactID(id) {
		return screenshotArtifact{}, false
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[id]
	if ok {
		if item.expiresAt.After(now) {
			return item, true
		}
		delete(s.items, id)
		s.removeDiskArtifactLocked(id)
		return screenshotArtifact{}, false
	}
	if s.dir == "" {
		return screenshotArtifact{}, false
	}
	item, ok = s.readDiskArtifactLocked(id, now)
	if !ok {
		return screenshotArtifact{}, false
	}
	s.items[id] = item
	return item, true
}

func (s *screenshotArtifactStore) cleanupExpiredLocked(now time.Time) {
	for id, item := range s.items {
		if !item.expiresAt.After(now) {
			delete(s.items, id)
			s.removeDiskArtifactLocked(id)
		}
	}
	if s.dir == "" {
		return
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		if !validScreenshotArtifactID(id) {
			continue
		}
		meta, err := s.readDiskRecordLocked(id)
		if err != nil || !meta.ExpiresAt.After(now) {
			s.removeDiskArtifactLocked(id)
		}
	}
}

func (s *screenshotArtifactStore) writeDiskArtifactLocked(id string, item screenshotArtifact) error {
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return err
	}
	dataPath := s.diskDataPath(id)
	dataTmp := dataPath + ".tmp"
	if err := os.WriteFile(dataTmp, item.data, 0600); err != nil {
		return err
	}
	if err := os.Rename(dataTmp, dataPath); err != nil {
		_ = os.Remove(dataTmp)
		return err
	}

	record := screenshotArtifactDiskRecord{MIMEType: item.mimeType, Ext: item.ext, ExpiresAt: item.expiresAt}
	meta, err := json.Marshal(record)
	if err != nil {
		_ = os.Remove(dataPath)
		return err
	}
	metaPath := s.diskMetaPath(id)
	metaTmp := metaPath + ".tmp"
	if err := os.WriteFile(metaTmp, meta, 0600); err != nil {
		_ = os.Remove(dataPath)
		return err
	}
	if err := os.Rename(metaTmp, metaPath); err != nil {
		_ = os.Remove(metaTmp)
		_ = os.Remove(dataPath)
		return err
	}
	return nil
}

func (s *screenshotArtifactStore) readDiskArtifactLocked(id string, now time.Time) (screenshotArtifact, bool) {
	meta, err := s.readDiskRecordLocked(id)
	if err != nil {
		return screenshotArtifact{}, false
	}
	if !meta.ExpiresAt.After(now) {
		s.removeDiskArtifactLocked(id)
		return screenshotArtifact{}, false
	}
	data, err := os.ReadFile(s.diskDataPath(id))
	if err != nil {
		return screenshotArtifact{}, false
	}
	return screenshotArtifact{data: data, mimeType: meta.MIMEType, ext: meta.Ext, expiresAt: meta.ExpiresAt}, true
}

func (s *screenshotArtifactStore) readDiskRecordLocked(id string) (screenshotArtifactDiskRecord, error) {
	data, err := os.ReadFile(s.diskMetaPath(id))
	if err != nil {
		return screenshotArtifactDiskRecord{}, err
	}
	var meta screenshotArtifactDiskRecord
	if err := json.Unmarshal(data, &meta); err != nil {
		return screenshotArtifactDiskRecord{}, err
	}
	return meta, nil
}

func (s *screenshotArtifactStore) removeDiskArtifactLocked(id string) {
	if s.dir == "" {
		return
	}
	_ = os.Remove(s.diskDataPath(id))
	_ = os.Remove(s.diskMetaPath(id))
}

func (s *screenshotArtifactStore) diskDataPath(id string) string {
	return filepath.Join(s.dir, id+".bin")
}

func (s *screenshotArtifactStore) diskMetaPath(id string) string {
	return filepath.Join(s.dir, id+".json")
}

func validScreenshotArtifactID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, r := range id {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func (s *Server) ServeScreenshotArtifact(w http.ResponseWriter, r *http.Request) {
	id := path.Base(strings.TrimSuffix(r.URL.Path, "/"))
	if !validScreenshotArtifactID(id) {
		http.NotFound(w, r)
		return
	}
	store := s.screenshotArtifactStore()
	item, ok := store.get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", item.mimeType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	filename := "screenshot-" + id + item.ext
	w.Header().Set("Content-Disposition", `inline; filename="`+filename+`"`)
	http.ServeContent(w, r, filename, item.expiresAt, bytes.NewReader(item.data))
}

func (s *Server) screenshotArtifactStore() *screenshotArtifactStore {
	if s.screenshotArtifacts == nil {
		s.screenshotArtifacts = newScreenshotArtifactStore()
	}
	return s.screenshotArtifacts
}

func (s *Server) SetScreenshotArtifactDir(dir string) {
	s.screenshotArtifactStore().setDir(dir)
}

func parseScreenshotTTL(args map[string]any) time.Duration {
	seconds := 600.0
	if raw, ok := args["url_ttl_seconds"].(float64); ok && raw > 0 {
		seconds = raw
	}
	if seconds < 30 {
		seconds = 30
	}
	if seconds > 3600 {
		seconds = 3600
	}
	return time.Duration(seconds * float64(time.Second))
}

func randomHex(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
