package protocol

import (
	"encoding/binary"
	"errors"
)

const CaptureABI = 1
const CaptureStatusSize = 104

// Artifact provenance and capture setup are separate from native acceptance.
// No field here authorizes protected launch or asserts DNS isolation.
type CaptureStatus struct {
	Engine             string `json:"engine"`
	ABI                uint32 `json:"abi"`
	Architecture       string `json:"architecture"`
	ProvenanceVerified bool   `json:"provenanceVerified"`
	ActivationStarted  bool   `json:"activationStarted"`
	Running            bool   `json:"running"`
	SocketReady        bool   `json:"socketReady"`
	NetworkReady       bool   `json:"networkReady"`
	TCPCapture         bool   `json:"tcpCapture"`
	UDPBlocking        bool   `json:"udpBlocking"`
	IdentityCallback   bool   `json:"identityCallback"`
	Ready              bool   `json:"ready"`
	DNS                bool   `json:"dns"`
	FailClosed         bool   `json:"failClosed"`
	VerificationPassed bool   `json:"verificationPassed"`
	Intercepted        uint64 `json:"intercepted"`
	Reinjected         uint64 `json:"reinjected"`
	Blocked            uint64 `json:"blocked"`
	UnknownDropped     uint64 `json:"unknownDropped"`
	UnsupportedDropped uint64 `json:"unsupportedDropped"`
	ActiveFlows        uint32 `json:"activeFlows"`
	ActiveIdentities   uint32 `json:"activeIdentities"`
	LastError          uint32 `json:"lastError"`
	Reason             string `json:"reason,omitempty"`
}

func DecodeCaptureStatus(data []byte) (CaptureStatus, error) {
	invalid := func() (CaptureStatus, error) {
		return CaptureStatus{}, errors.New("capture ABI or acceptance claim invalid")
	}
	if len(data) != CaptureStatusSize || binary.LittleEndian.Uint32(data) != CaptureStatusSize || binary.LittleEndian.Uint32(data[4:]) != CaptureABI || binary.LittleEndian.Uint32(data[100:]) != 0 {
		return invalid()
	}
	for offset := 8; offset < 48; offset += 4 {
		if binary.LittleEndian.Uint32(data[offset:]) > 1 {
			return invalid()
		}
	}
	// The present implementation has no DNS adapter/native acceptance. Reject a
	// DLL that claims otherwise rather than allowing its wire flags to override.
	for offset := 32; offset < 48; offset += 4 {
		if binary.LittleEndian.Uint32(data[offset:]) != 0 {
			return invalid()
		}
	}
	if binary.LittleEndian.Uint32(data[88:]) > 2048 || binary.LittleEndian.Uint32(data[92:]) > 1024 {
		return invalid()
	}
	flag := func(offset int) bool { return binary.LittleEndian.Uint32(data[offset:]) != 0 }
	return CaptureStatus{Engine: "windivert", ABI: CaptureABI, Architecture: "x64", ActivationStarted: flag(8) || flag(12) || flag(16),
		Running: flag(8), SocketReady: flag(12), NetworkReady: flag(16), TCPCapture: flag(20), UDPBlocking: flag(24), IdentityCallback: flag(28),
		Intercepted: binary.LittleEndian.Uint64(data[48:]), Reinjected: binary.LittleEndian.Uint64(data[56:]), Blocked: binary.LittleEndian.Uint64(data[64:]), UnknownDropped: binary.LittleEndian.Uint64(data[72:]), UnsupportedDropped: binary.LittleEndian.Uint64(data[80:]),
		ActiveFlows: binary.LittleEndian.Uint32(data[88:]), ActiveIdentities: binary.LittleEndian.Uint32(data[92:]), LastError: binary.LittleEndian.Uint32(data[96:])}, nil
}
