package protocol

import (
	"encoding/binary"
	"testing"
)

func TestDriverStatusNeverTreatsHeartbeatOrRestartAsFilterProof(t *testing.T) {
	data := make([]byte, DriverStatusSize)
	binary.LittleEndian.PutUint32(data, DriverABI)
	binary.LittleEndian.PutUint32(data[4:], 15)
	binary.LittleEndian.PutUint32(data[16:], 3)
	binary.LittleEndian.PutUint64(data[24:], 7)
	status, err := DecodeDriverStatus(data)
	if err != nil {
		t.Fatal(err)
	}
	if status.Enforcement.FilteringReady || status.Capabilities.DNS {
		t.Fatal("running alone proved filtering or DNS")
	}
	binary.LittleEndian.PutUint32(data[20:], 1)
	status, err = DecodeDriverStatus(data)
	if err != nil || !status.Enforcement.FilteringReady {
		t.Fatal("verified running filter state rejected")
	}
	for _, offset := range []int{16, 24} {
		invalid := append([]byte{}, data...)
		for i := 0; i < 4; i++ {
			invalid[offset+i] = 0
		}
		if _, err := DecodeDriverStatus(invalid); err == nil {
			t.Fatal("inconsistent ready state accepted")
		}
	}
	invalid := append([]byte{}, data...)
	binary.LittleEndian.PutUint32(invalid, 1)
	if _, err := DecodeDriverStatus(invalid); err == nil {
		t.Fatal("old ABI accepted")
	}
}
