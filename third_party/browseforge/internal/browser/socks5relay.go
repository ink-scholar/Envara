package browser

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"golang.org/x/net/proxy"
)

// SOCKS5Relay is a local no-auth SOCKS5 proxy that forwards through an
// upstream authenticated SOCKS5 proxy. This works around Chromium's lack
// of SOCKS5 authentication support.
type SOCKS5Relay struct {
	ln     net.Listener
	dialer proxy.Dialer
	done   chan struct{}
	wg     sync.WaitGroup
}

// StartSOCKS5Relay starts a local SOCKS5 relay on a random port.
// Returns the relay and the "host:port" string to point Chromium at.
func StartSOCKS5Relay(upstreamAddr, username, password string) (*SOCKS5Relay, string, error) {
	auth := &proxy.Auth{User: username, Password: password}
	dialer, err := proxy.SOCKS5("tcp", upstreamAddr, auth, proxy.Direct)
	if err != nil {
		return nil, "", fmt.Errorf("socks5 dialer: %w", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}

	r := &SOCKS5Relay{ln: ln, dialer: dialer, done: make(chan struct{})}
	r.wg.Add(1)
	go r.serve()

	addr := ln.Addr().String()
	slog.Info("socks5 relay started", "local", addr, "upstream", upstreamAddr)
	return r, addr, nil
}

func (r *SOCKS5Relay) Close() {
	close(r.done)
	r.ln.Close()
	r.wg.Wait()
}

func (r *SOCKS5Relay) serve() {
	defer r.wg.Done()
	for {
		conn, err := r.ln.Accept()
		if err != nil {
			select {
			case <-r.done:
				return
			default:
				continue
			}
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.handle(conn)
		}()
	}
}

func (r *SOCKS5Relay) handle(conn net.Conn) {
	defer conn.Close()

	// --- SOCKS5 greeting (no auth) ---
	// client: VER NMETHODS METHODS...
	buf := make([]byte, 258)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil || buf[0] != 0x05 {
		return
	}
	nm := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nm]); err != nil {
		return
	}
	// reply: no auth required
	conn.Write([]byte{0x05, 0x00})

	// --- SOCKS5 request ---
	// VER CMD RSV ATYP DST.ADDR DST.PORT
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	if buf[1] != 0x01 { // only CONNECT
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var target string
	switch buf[3] { // ATYP
	case 0x01: // IPv4
		if _, err := io.ReadFull(conn, buf[:6]); err != nil {
			return
		}
		target = fmt.Sprintf("%d.%d.%d.%d:%d", buf[0], buf[1], buf[2], buf[3], binary.BigEndian.Uint16(buf[4:6]))
	case 0x03: // Domain
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		dlen := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:dlen+2]); err != nil {
			return
		}
		target = fmt.Sprintf("%s:%d", string(buf[:dlen]), binary.BigEndian.Uint16(buf[dlen:dlen+2]))
	case 0x04: // IPv6
		if _, err := io.ReadFull(conn, buf[:18]); err != nil {
			return
		}
		ip := net.IP(buf[:16])
		target = fmt.Sprintf("[%s]:%d", ip, binary.BigEndian.Uint16(buf[16:18]))
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Dial through upstream authenticated SOCKS5
	remote, err := r.dialer.Dial("tcp", target)
	if err != nil {
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	// Success reply
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0})

	// Relay
	var wg sync.WaitGroup
	wg.Add(2)
	relay := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}
	go relay(remote, conn)
	go relay(conn, remote)
	wg.Wait()
}
