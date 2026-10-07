package dnsbroker

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"envara.io/windows-app-routing/internal/socks5"
)

type fixtureExchange struct {
	mu    sync.Mutex
	calls int
	fail  bool
	wait  bool
}

func (fixture *fixtureExchange) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	fixture.mu.Lock()
	fixture.calls++
	fail, wait := fixture.fail, fixture.wait
	fixture.mu.Unlock()
	if wait {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if fail {
		return nil, errors.New("fixture network failure")
	}
	response := append([]byte{}, query...)
	binary.BigEndian.PutUint16(response[2:], 0x8180)
	binary.BigEndian.PutUint16(response[6:], 1)
	return append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 192, 0, 2, 7), nil
}
func (*fixtureExchange) Close() {}

func TestRouteCacheNeverSharedExpiresAndDecrementsTTL(t *testing.T) {
	transport := &fixtureExchange{}
	one, two := New(transport), New(transport)
	defer one.Close()
	defer two.Close()
	now := time.Unix(1000, 0)
	one.now = func() time.Time { return now }
	request := Request{ID: 7, Name: "EXAMPLE.TEST.", Type: 1}
	if _, err := one.Resolve(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	request.ID = 11
	response, err := one.Resolve(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint16(response) != 11 || binary.BigEndian.Uint32(response[len(response)-10:]) != 240 {
		t.Fatal("cached transaction/TTL invalid")
	}
	if transport.calls != 1 {
		t.Fatal("cache missed")
	}
	if _, err := two.Resolve(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if transport.calls != 2 {
		t.Fatal("cache crossed routes")
	}
	now = now.Add(5 * time.Minute)
	if _, err := one.Resolve(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if transport.calls != 3 {
		t.Fatal("expired cache reused")
	}
	transport.fail = true
	one.Close()
	if _, err := one.Resolve(context.Background(), request); err == nil {
		t.Fatal("revoked route served cache")
	}
}

func TestFailureAndRevocationNeverUseSystemDNSOrStaleCache(t *testing.T) {
	transport := &fixtureExchange{fail: true}
	broker := New(transport)
	if _, err := broker.Resolve(context.Background(), Request{ID: 1, Name: "example.test", Type: 1}); err == nil {
		t.Fatal("transport failure ignored")
	}
	transport.fail = false
	transport.wait = true
	done := make(chan error, 1)
	go func() {
		_, err := broker.Resolve(context.Background(), Request{ID: 2, Name: "other.test", Type: 1})
		done <- err
	}()
	time.Sleep(10 * time.Millisecond)
	broker.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("revocation returned DNS")
		}
	case <-time.After(time.Second):
		t.Fatal("revocation did not cancel in-flight lookup")
	}
}

func TestRejectsMalformedNameQuestionAndCompressionCycles(t *testing.T) {
	for _, name := range []string{"", "bad..test", "bad\x00.test", "你好.test", strings.Repeat("x", 64) + ".test"} {
		if _, err := canonicalName(name); err == nil {
			t.Fatal("invalid name accepted")
		}
	}
	query := makeQuery("example.test", 1, 7)
	response, _ := (&fixtureExchange{}).Exchange(context.Background(), query)
	for _, change := range []func([]byte){func(w []byte) { w[0] = 1 }, func(w []byte) { w[2] = 0 }, func(w []byte) { w[12] = 0xc0; w[13] = 12 }, func(w []byte) { w[len(w)-5] = 9 }} {
		invalid := append([]byte{}, response...)
		change(invalid)
		if _, _, err := validateResponse(invalid, "example.test", 1, 7); err == nil {
			t.Fatal("malformed response accepted")
		}
	}
}

func TestDoHRequiresManagedAuthenticationAndIgnoresAmbientProxy(t *testing.T) {
	trap, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer trap.Close()
	t.Setenv("HTTPS_PROXY", "http://"+trap.Addr().String())
	t.Setenv("HTTP_PROXY", "http://"+trap.Addr().String())
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	result := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		var greeting [3]byte
		_, err = io.ReadFull(conn, greeting[:])
		if greeting != [3]byte{5, 1, 2} {
			result <- errors.New("proxy auth not required")
			return
		}
		_, _ = conn.Write([]byte{5, 0})
		result <- err
	}()
	address := listener.Addr().(*net.TCPAddr)
	doh, err := NewManagedDoH(socks5.Route{Protocol: "socks5", Host: "127.0.0.1", Port: uint16(address.Port), Username: "fixture-user", Password: "fixture-password", UDPPolicy: "block"})
	if err != nil {
		t.Fatal(err)
	}
	defer doh.Close()
	_, err = doh.Exchange(context.Background(), makeQuery("example.test", 1, 1))
	if err == nil {
		t.Fatal("no-auth proxy accepted")
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	_ = trap.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Millisecond))
	if connection, err := trap.Accept(); err == nil {
		connection.Close()
		t.Fatal("ambient proxy contacted")
	}
	if _, err := doh.transport.DialContext(context.Background(), "tcp", "unexpected.test:443"); err == nil {
		t.Fatal("unexpected DNS transport target allowed")
	}
}

type responseTransport func(*http.Request) (*http.Response, error)

func (f responseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestDoHRejectsRedirectInsteadOfContactingAnotherNetwork(t *testing.T) {
	doh, err := NewManagedDoH(socks5.Route{Protocol: "socks5", Host: "127.0.0.1", Port: 1080, Username: "fixture-user", Password: "fixture-password", UDPPolicy: "block"})
	if err != nil {
		t.Fatal(err)
	}
	defer doh.Close()
	calls := 0
	doh.client.Transport = responseTransport(func(request *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://unexpected.test/dns-query"}}, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	})
	if _, err := doh.Exchange(context.Background(), makeQuery("example.test", 1, 1)); err == nil {
		t.Fatal("redirect accepted")
	}
	if calls != 1 {
		t.Fatal("followed redirect")
	}
}
