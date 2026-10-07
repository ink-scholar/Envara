package socks5

import (
	"io"
	"net"
	"testing"
)

func TestRequiresOwnedAuthenticatedLoopbackAndExplicitUDPPolicy(t *testing.T) {
	valid := Route{Protocol: "socks5", Host: "127.0.0.1", Port: 1080, Username: "fixture-user", Password: "fixture-secret", UDPPolicy: "block"}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Route){func(r *Route) { r.Host = "example.invalid" }, func(r *Route) { r.Password = "" }, func(r *Route) { r.UDPPolicy = "" }, func(r *Route) { r.Protocol = "http" }} {
		bad := valid
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("unsafe route accepted")
		}
	}
}

func TestNegotiatesAuthenticatedIPv6AndRejectsNoAuthFallback(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		client, server := net.Pipe()
		done := make(chan error, 1)
		go func() {
			defer server.Close()
			var greeting [3]byte
			_, err := io.ReadFull(server, greeting[:])
			if err != nil {
				done <- err
				return
			}
			if greeting != [3]byte{5, 1, 2} {
				t.Error("authentication not required")
			}
			if refuse {
				_, err = server.Write([]byte{5, 0})
				done <- err
				return
			}
			_, _ = server.Write([]byte{5, 2})
			var prefix [2]byte
			_, _ = io.ReadFull(server, prefix[:])
			user := make([]byte, prefix[1])
			_, _ = io.ReadFull(server, user)
			var length [1]byte
			_, _ = io.ReadFull(server, length[:])
			secret := make([]byte, length[0])
			_, _ = io.ReadFull(server, secret)
			if string(user) != "u" || string(secret) != "p" {
				t.Error("wrong fixture auth")
			}
			_, _ = server.Write([]byte{1, 0})
			request := make([]byte, 22)
			_, err = io.ReadFull(server, request)
			if request[3] != 4 || request[20] != 1 || request[21] != 187 {
				t.Error("wrong IPv6/port")
			}
			_, _ = server.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
			done <- err
		}()
		err := Connect(client, Route{Protocol: "socks5", Host: "127.0.0.1", Port: 1080, Username: "u", Password: "p", UDPPolicy: "block"}, net.ParseIP("2001:db8::7"), 443)
		client.Close()
		if (err != nil) != refuse {
			t.Fatalf("refuse=%v err=%v", refuse, err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}
