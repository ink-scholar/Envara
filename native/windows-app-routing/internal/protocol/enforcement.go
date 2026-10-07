package protocol

import (
	"encoding/binary"
	"errors"
)

const DriverABI = 2
const DriverStatusSize = 40

type Enforcement struct {
	BFEState       uint32 `json:"bfeState"`
	FilteringReady bool   `json:"filteringReady"`
	Generation     uint64 `json:"generation"`
	LastFailure    uint32 `json:"lastFailure"`
}

type DriverStatus struct {
	Capabilities Capabilities
	Enforcement  Enforcement
	Routes       uint32
	Processes    uint32
}

func DecodeDriverStatus(data []byte) (DriverStatus, error) {
	if len(data) != DriverStatusSize || binary.LittleEndian.Uint32(data) != DriverABI || binary.LittleEndian.Uint32(data[36:]) != 0 {
		return DriverStatus{}, errors.New("driver ABI invalid")
	}
	flags := binary.LittleEndian.Uint32(data[4:])
	state := binary.LittleEndian.Uint32(data[16:])
	ready := binary.LittleEndian.Uint32(data[20:])
	epoch := binary.LittleEndian.Uint64(data[24:])
	if flags&^uint32(31) != 0 || state > 3 || ready > 1 || (ready == 1 && (state != 3 || epoch == 0)) || binary.LittleEndian.Uint32(data[8:]) > 64 || binary.LittleEndian.Uint32(data[12:]) > 4096 {
		return DriverStatus{}, errors.New("driver state invalid")
	}
	return DriverStatus{Capabilities: Capabilities{TCP: flags&1 != 0, UDP: flags&2 != 0, ChildProcesses: flags&4 != 0, FailClosed: flags&8 != 0, DNS: flags&16 != 0},
		Enforcement: Enforcement{BFEState: state, FilteringReady: ready == 1, Generation: epoch, LastFailure: binary.LittleEndian.Uint32(data[32:])},
		Routes:      binary.LittleEndian.Uint32(data[8:]), Processes: binary.LittleEndian.Uint32(data[12:])}, nil
}
