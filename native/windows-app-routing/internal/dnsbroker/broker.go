// Package dnsbroker provides a per-route resolver for a future owned Windows
// resolver adapter. It is not an interception mechanism for Windows dnscache.
package dnsbroker

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"time"
)

const maxWire = 65535
const maxCache = 256

type Exchange interface {
	Exchange(context.Context, []byte) ([]byte, error)
	Close()
}
type Request struct {
	ID   uint16
	Name string
	Type uint16
}
type entry struct {
	wire    []byte
	offsets []int
	stored  time.Time
	expires time.Time
}
type Broker struct {
	mu        sync.Mutex
	transport Exchange
	cache     map[string]entry
	now       func() time.Time
	ctx       context.Context
	cancel    context.CancelFunc
	closed    bool
}

func New(transport Exchange) *Broker {
	ctx, cancel := context.WithCancel(context.Background())
	return &Broker{transport: transport, cache: map[string]entry{}, now: time.Now, ctx: ctx, cancel: cancel}
}

func (broker *Broker) Close() {
	broker.mu.Lock()
	defer broker.mu.Unlock()
	if broker.closed {
		return
	}
	broker.closed = true
	broker.cancel()
	broker.cache = map[string]entry{}
	broker.transport.Close()
}

func (broker *Broker) Resolve(ctx context.Context, request Request) ([]byte, error) {
	name, err := canonicalName(request.Name)
	if err != nil || request.Type == 0 || request.Type == 255 {
		return nil, errors.New("DNS question invalid")
	}
	key := name + ":" + string([]byte{byte(request.Type >> 8), byte(request.Type)})
	broker.mu.Lock()
	if broker.closed {
		broker.mu.Unlock()
		return nil, errors.New("DNS route revoked")
	}
	now := broker.now()
	if cached, ok := broker.cache[key]; ok && now.Before(cached.expires) {
		data := append([]byte{}, cached.wire...)
		binary.BigEndian.PutUint16(data, request.ID)
		elapsed := uint32(now.Sub(cached.stored) / time.Second)
		for _, offset := range cached.offsets {
			ttl := binary.BigEndian.Uint32(data[offset:])
			if elapsed >= ttl {
				ttl = 0
			} else {
				ttl -= elapsed
			}
			binary.BigEndian.PutUint32(data[offset:], ttl)
		}
		broker.mu.Unlock()
		return data, nil
	}
	broker.mu.Unlock()
	var nonce [2]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, errors.New("DNS transaction unavailable")
	}
	id := binary.BigEndian.Uint16(nonce[:])
	query := makeQuery(name, request.Type, id)
	operation, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stop := context.AfterFunc(broker.ctx, cancel)
	defer stop()
	response, err := broker.transport.Exchange(operation, query)
	if err != nil {
		return nil, errors.New("Managed DNS route failed")
	}
	ttl, offsets, err := validateResponse(response, name, request.Type, id)
	if err != nil {
		return nil, errors.New("Managed DNS response invalid")
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	if broker.closed {
		return nil, errors.New("DNS route revoked")
	}
	if ttl > 0 {
		if len(broker.cache) >= maxCache {
			for old := range broker.cache {
				delete(broker.cache, old)
				break
			}
		}
		stored := broker.now()
		broker.cache[key] = entry{wire: append([]byte{}, response...), offsets: offsets, stored: stored, expires: stored.Add(time.Duration(ttl) * time.Second)}
	}
	result := append([]byte{}, response...)
	binary.BigEndian.PutUint16(result, request.ID)
	return result, nil
}

func canonicalName(name string) (string, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if len(name) == 0 || len(name) > 253 {
		return "", errors.New("DNS name invalid")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("DNS name invalid")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-' && c != '_' {
				return "", errors.New("DNS name invalid")
			}
		}
	}
	return name, nil
}

func makeQuery(name string, qtype uint16, id uint16) []byte {
	data := make([]byte, 12)
	binary.BigEndian.PutUint16(data, id)
	binary.BigEndian.PutUint16(data[2:], 0x0100)
	binary.BigEndian.PutUint16(data[4:], 1)
	for _, label := range strings.Split(name, ".") {
		data = append(data, byte(len(label)))
		data = append(data, label...)
	}
	return append(data, 0, byte(qtype>>8), byte(qtype), 0, 1)
}

func readName(data []byte, start int) (string, int, error) {
	position := start
	end := -1
	var labels []string
	seen := map[int]bool{}
	total := 0
	for steps := 0; steps < 128; steps++ {
		if position < 0 || position >= len(data) || seen[position] {
			return "", 0, errors.New("DNS name compression invalid")
		}
		seen[position] = true
		length := int(data[position])
		position++
		if length == 0 {
			if end < 0 {
				end = position
			}
			return strings.ToLower(strings.Join(labels, ".")), end, nil
		}
		if length&0xc0 == 0xc0 {
			if position >= len(data) {
				return "", 0, errors.New("DNS pointer truncated")
			}
			if end < 0 {
				end = position + 1
			}
			position = (length&0x3f)<<8 | int(data[position])
			continue
		}
		if length > 63 || position+length > len(data) {
			return "", 0, errors.New("DNS label invalid")
		}
		total += length + 1
		if total > 254 {
			return "", 0, errors.New("DNS name too long")
		}
		labels = append(labels, string(data[position:position+length]))
		position += length
	}
	return "", 0, errors.New("DNS name compression too deep")
}

func validateResponse(data []byte, name string, qtype uint16, id uint16) (uint32, []int, error) {
	if len(data) < 12 || len(data) > maxWire || binary.BigEndian.Uint16(data) != id {
		return 0, nil, errors.New("DNS transaction invalid")
	}
	flags := binary.BigEndian.Uint16(data[2:])
	rcode := flags & 15
	if flags&0x8000 == 0 || flags&0x7800 != 0 || flags&0x0200 != 0 || binary.BigEndian.Uint16(data[4:]) != 1 || (rcode != 0 && rcode != 3) {
		return 0, nil, errors.New("DNS response flags invalid")
	}
	question, pos, err := readName(data, 12)
	if err != nil || pos+4 > len(data) || question != name || binary.BigEndian.Uint16(data[pos:]) != qtype || binary.BigEndian.Uint16(data[pos+2:]) != 1 {
		return 0, nil, errors.New("DNS question mismatch")
	}
	pos += 4
	answers := int(binary.BigEndian.Uint16(data[6:]))
	records := answers + int(binary.BigEndian.Uint16(data[8:])) + int(binary.BigEndian.Uint16(data[10:]))
	if records > 2048 {
		return 0, nil, errors.New("DNS records invalid")
	}
	ttl := uint32(3600)
	var offsets []int
	for i := 0; i < records; i++ {
		_, next, err := readName(data, pos)
		if err != nil || next+10 > len(data) {
			return 0, nil, errors.New("DNS record invalid")
		}
		typeID := binary.BigEndian.Uint16(data[next:])
		class := binary.BigEndian.Uint16(data[next+2:])
		recordTTL := binary.BigEndian.Uint32(data[next+4:])
		size := int(binary.BigEndian.Uint16(data[next+8:]))
		pos = next + 10 + size
		if pos > len(data) {
			return 0, nil, errors.New("DNS record truncated")
		}
		if typeID != 41 { // OPT's TTL bytes contain flags and must never be decremented.
			offsets = append(offsets, next+4)
			if i < answers && class == 1 && recordTTL < ttl {
				ttl = recordTTL
			}
		}
	}
	if pos != len(data) {
		return 0, nil, errors.New("DNS trailing data invalid")
	}
	if answers == 0 || rcode != 0 {
		ttl = 0
	} // No shared or negative caching.
	return ttl, offsets, nil
}
