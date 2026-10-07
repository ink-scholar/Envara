// Package socks5 is a small authenticated transport to the application-owned core.
// It never dials an original destination directly and has no fallback transport.
package socks5

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

type Route struct {
	Protocol  string `json:"protocol"`
	Host      string `json:"host"`
	Port      uint16 `json:"port"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	UDP       bool   `json:"udp"`
	UDPPolicy string `json:"udpPolicy"`
}

func (r Route) Validate() error {
	ip := net.ParseIP(r.Host)
	if r.Protocol != "socks5" || ip == nil || !ip.IsLoopback() || r.Port == 0 ||
		len(r.Username) == 0 || len(r.Username) > 255 || len(r.Password) == 0 || len(r.Password) > 255 {
		return errors.New("authenticated managed loopback SOCKS5 route required")
	}
	if r.UDPPolicy != "block" && r.UDPPolicy != "proxy" {
		return errors.New("explicit UDP policy required")
	}
	return nil
}

// Connect uses an already-open socket so the Windows relay can copy WFP redirect
// records onto that socket before connect(), as required to avoid proxy loops.
func Connect(conn net.Conn, route Route, destination net.IP, port uint16) error {
	if err := route.Validate(); err != nil {
		return err
	}
	if destination == nil || port == 0 {
		return errors.New("destination invalid")
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{})
	if err := Authenticate(conn, route); err != nil {
		return err
	}
	request := []byte{5, 1, 0}
	if v4 := destination.To4(); v4 != nil {
		request = append(request, 1)
		request = append(request, v4...)
	} else {
		v6 := destination.To16()
		if v6 == nil {
			return errors.New("destination invalid")
		}
		request = append(request, 4)
		request = append(request, v6...)
	}
	request = append(request, byte(port>>8), byte(port))
	if err := writeAll(conn, request); err != nil {
		return err
	}
	_, _, err := readReply(conn)
	return err
}

func Authenticate(conn io.ReadWriter, route Route) error {
	if err := writeAll(conn, []byte{5, 1, 2}); err != nil {
		return err
	}
	var selection [2]byte
	if _, err := io.ReadFull(conn, selection[:]); err != nil {
		return err
	}
	if selection != [2]byte{5, 2} {
		return errors.New("proxy refused required authentication")
	}
	credentials := []byte{1, byte(len(route.Username))}
	credentials = append(credentials, route.Username...)
	credentials = append(credentials, byte(len(route.Password)))
	credentials = append(credentials, route.Password...)
	err := writeAll(conn, credentials)
	for i := range credentials {
		credentials[i] = 0
	}
	if err != nil {
		return err
	}
	var auth [2]byte
	if _, err = io.ReadFull(conn, auth[:]); err != nil {
		return err
	}
	if auth != [2]byte{1, 0} {
		return errors.New("proxy authentication refused")
	}
	return nil
}

func readReply(reader io.Reader) (net.IP, uint16, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, 0, err
	}
	if header[0] != 5 || header[1] != 0 || header[2] != 0 {
		return nil, 0, errors.New("proxy connection refused")
	}
	var size int
	switch header[3] {
	case 1:
		size = 4
	case 4:
		size = 16
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return nil, 0, err
		}
		size = int(length[0])
	default:
		return nil, 0, errors.New("proxy reply invalid")
	}
	data := make([]byte, size+2)
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, 0, err
	}
	return net.IP(data[:size]), binary.BigEndian.Uint16(data[size:]), nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func (r Route) Address() string { return net.JoinHostPort(r.Host, strconv.Itoa(int(r.Port))) }
