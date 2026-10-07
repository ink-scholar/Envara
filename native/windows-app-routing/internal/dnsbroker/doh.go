package dnsbroker

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"envara.io/windows-app-routing/internal/socks5"
)

// There is no system resolver, ProxyFromEnvironment, no-auth fallback, redirect
// following, or direct-destination dial in this transport. Literal upstream IP
// avoids bootstrap DNS through the shared Windows DNS Client service.
type DoH struct {
	client    *http.Client
	transport *http.Transport
}

func NewManagedDoH(route socks5.Route) (*DoH, error) {
	if err := route.Validate(); err != nil {
		return nil, err
	}
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "cloudflare-dns.com"},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "cloudflare-dns.com:443" {
				return nil, errors.New("DNS transport target invalid")
			}
			conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", route.Address())
			if err != nil {
				return nil, errors.New("DNS core unavailable")
			}
			stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
			defer stop()
			if err = socks5.Connect(conn, route, net.IPv4(1, 1, 1, 1), 443); err != nil {
				conn.Close()
				return nil, errors.New("DNS proxy refused")
			}
			if ctx.Err() != nil {
				conn.Close()
				return nil, errors.New("DNS route cancelled")
			}
			return conn, nil
		}}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &DoH{client: client, transport: transport}, nil
}

func (doh *DoH) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, "POST", "https://cloudflare-dns.com/dns-query", bytes.NewReader(query))
	if err != nil {
		return nil, errors.New("DNS request invalid")
	}
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")
	response, err := doh.client.Do(request)
	if err != nil {
		return nil, errors.New("DNS managed transport failed")
	}
	defer response.Body.Close()
	contentType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || response.StatusCode != http.StatusOK || contentType != "application/dns-message" {
		return nil, errors.New("DNS transport response invalid")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxWire+1))
	if err != nil || len(data) > maxWire {
		return nil, errors.New("DNS response too large")
	}
	// RFC 8484 section 5.1: a cached HTTP response's Age is already elapsed
	// lifetime, so it must not restart the DNS TTL or our private route cache.
	age, err := responseAge(response.Header)
	if err != nil {
		return nil, err
	}
	if len(query) < 12 || binary.BigEndian.Uint16(query[4:]) != 1 {
		return nil, errors.New("DNS request invalid")
	}
	name, end, err := readName(query, 12)
	if err != nil || end+4 != len(query) || binary.BigEndian.Uint16(query[end+2:]) != 1 {
		return nil, errors.New("DNS request invalid")
	}
	_, offsets, err := validateResponse(data, name, binary.BigEndian.Uint16(query[end:]), binary.BigEndian.Uint16(query))
	if err != nil {
		return nil, errors.New("DNS transport response invalid")
	}
	for _, offset := range offsets {
		ttl := uint64(binary.BigEndian.Uint32(data[offset:]))
		if age >= ttl {
			ttl = 0
		} else {
			ttl -= age
		}
		binary.BigEndian.PutUint32(data[offset:], uint32(ttl))
	}
	return data, nil
}

func responseAge(header http.Header) (uint64, error) {
	values := header.Values("Age")
	if len(values) == 0 {
		return 0, nil
	}
	if len(values) != 1 {
		return 0, errors.New("DNS HTTP age invalid")
	}
	value := strings.Trim(values[0], " \t")
	if len(value) == 0 {
		return 0, errors.New("DNS HTTP age invalid")
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return 0, errors.New("DNS HTTP age invalid")
		}
	}
	age, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, errors.New("DNS HTTP age invalid")
	}
	return age, nil
}

func (doh *DoH) Close() { doh.transport.CloseIdleConnections() }
