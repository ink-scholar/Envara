package dnsbroker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"envara.io/windows-app-routing/internal/socks5"
)

// All sockets in these fixtures are loopback. The SOCKS server verifies the
// production CONNECT destination before forwarding it into the fixture TLS
// server; the certificate is trusted only by the test's transport instance.
func managedTLSFixture(t *testing.T) (*DoH, *x509.CertPool, *atomic.Int32, <-chan error) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"cloudflare-dns.com"}, BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	calls := &atomic.Int32{}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Method != "POST" || request.URL.Path != "/dns-query" || request.Host != "cloudflare-dns.com" || request.Header.Get("Content-Type") != "application/dns-message" || request.TLS.ServerName != "cloudflare-dns.com" {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		query, err := io.ReadAll(io.LimitReader(request.Body, maxWire+1))
		if err != nil || len(query) > maxWire {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		response, err := (&fixtureExchange{}).Exchange(request.Context(), query)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/dns-message")
		writer.Header().Set("Age", "120")
		_, _ = writer.Write(response)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}, MinVersion: tls.VersionTLS12}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 8)
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer client.Close()
				_ = client.SetDeadline(time.Now().Add(3 * time.Second))
				var greeting [3]byte
				if _, err := io.ReadFull(client, greeting[:]); err != nil || greeting != [3]byte{5, 1, 2} {
					results <- errors.New("fixture requires SOCKS authentication")
					return
				}
				if _, err := client.Write([]byte{5, 2}); err != nil {
					results <- err
					return
				}
				var authHeader [2]byte
				if _, err := io.ReadFull(client, authHeader[:]); err != nil || authHeader[0] != 1 {
					results <- errors.New("fixture auth header invalid")
					return
				}
				username := make([]byte, int(authHeader[1]))
				if _, err := io.ReadFull(client, username); err != nil {
					results <- err
					return
				}
				var length [1]byte
				if _, err := io.ReadFull(client, length[:]); err != nil {
					results <- err
					return
				}
				password := make([]byte, int(length[0]))
				if _, err := io.ReadFull(client, password); err != nil || string(username) != "fixture-user" || string(password) != "fixture-password" {
					results <- errors.New("fixture credentials invalid")
					return
				}
				if _, err := client.Write([]byte{1, 0}); err != nil {
					results <- err
					return
				}
				var connect [10]byte
				if _, err := io.ReadFull(client, connect[:]); err != nil || connect != [10]byte{5, 1, 0, 1, 1, 1, 1, 1, 1, 187} {
					results <- errors.New("DNS CONNECT used a hostname or unexpected destination")
					return
				}
				upstream, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
				if err != nil {
					results <- err
					return
				}
				defer upstream.Close()
				_ = upstream.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err := client.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
					results <- err
					return
				}
				results <- nil
				copied := make(chan struct{})
				go func() { _, _ = io.Copy(upstream, client); _ = upstream.Close(); close(copied) }()
				_, _ = io.Copy(client, upstream)
				_ = client.Close()
				<-copied
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); workers.Wait() })
	port := listener.Addr().(*net.TCPAddr).Port
	doh, err := NewManagedDoH(socks5.Route{Protocol: "socks5", Host: "127.0.0.1", Port: uint16(port), Username: "fixture-user", Password: "fixture-password", UDPPolicy: "block"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(doh.Close)
	return doh, roots, calls, results
}

func TestAuthenticatedSOCKSTLSDoHSuccessSubtractsAgeAndCacheElapsed(t *testing.T) {
	doh, roots, calls, connected := managedTLSFixture(t)
	doh.transport.TLSClientConfig.RootCAs = roots // Test-only CA; production uses OS verification.
	broker := New(doh)
	t.Cleanup(broker.Close)
	now := time.Unix(1000, 0)
	broker.now = func() time.Time { return now }
	request := Request{ID: 42, Name: "example.test", Type: 1}
	response, err := broker.Resolve(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-connected; err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(response) != 42 || binary.BigEndian.Uint32(response[len(response)-10:]) != 180 || calls.Load() != 1 {
		t.Fatal("DoH did not subtract HTTP Age from TTL")
	}
	now = now.Add(time.Minute)
	response, err = broker.Resolve(context.Background(), request)
	if err != nil || binary.BigEndian.Uint32(response[len(response)-10:]) != 120 || calls.Load() != 1 {
		t.Fatal("route cache restarted aged TTL")
	}
	now = now.Add(2 * time.Minute)
	if _, err := broker.Resolve(context.Background(), request); err != nil || calls.Load() != 2 {
		t.Fatal("aged DNS TTL failed to expire")
	}
}

func TestAuthenticatedSOCKSDoesNotDisableTLSCertificateVerification(t *testing.T) {
	doh, _, calls, connected := managedTLSFixture(t)
	doh.transport.TLSClientConfig.RootCAs = x509.NewCertPool() // No fixture CA trusted.
	if _, err := doh.Exchange(context.Background(), makeQuery("example.test", 1, 7)); err == nil {
		t.Fatal("untrusted DoH certificate accepted")
	}
	if err := <-connected; err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 || doh.transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("DNS request sent without verified TLS")
	}
}

func TestDoHAgeSaturatesAndRejectsAmbiguousValues(t *testing.T) {
	for _, age := range []string{"0", "120", "300", "18446744073709551615", "-1", "+1", "1, 2", "", "18446744073709551616"} {
		t.Run(age, func(t *testing.T) {
			doh, err := NewManagedDoH(socks5.Route{Protocol: "socks5", Host: "127.0.0.1", Port: 1080, Username: "fixture-user", Password: "fixture-password", UDPPolicy: "block"})
			if err != nil {
				t.Fatal(err)
			}
			defer doh.Close()
			query := makeQuery("example.test", 1, 7)
			doh.client.Transport = responseTransport(func(request *http.Request) (*http.Response, error) {
				data, _ := (&fixtureExchange{}).Exchange(request.Context(), query)
				// OPT flags occupy the TTL position and must remain intact.
				binary.BigEndian.PutUint16(data[10:], 1)
				data = append(data, 0, 0, 41, 16, 0, 0, 0, 128, 0, 0, 0)
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/dns-message"}, "Age": {age}}, Body: io.NopCloser(strings.NewReader(string(data))), Request: request}, nil
			})
			response, err := doh.Exchange(context.Background(), query)
			expected := map[string]uint32{"0": 300, "120": 180, "300": 0, "18446744073709551615": 0}
			if ttl, valid := expected[age]; valid {
				if err != nil || binary.BigEndian.Uint32(response[len(query)+6:]) != ttl || binary.BigEndian.Uint32(response[len(response)-6:]) != 32768 {
					t.Fatal("Age adjusted TTL incorrectly or changed OPT flags")
				}
			} else if err == nil {
				t.Fatal("invalid HTTP Age accepted")
			}
		})
	}
	if _, err := responseAge(http.Header{"Age": {"1", "2"}}); err == nil {
		t.Fatal("duplicate HTTP Age accepted")
	}
}
