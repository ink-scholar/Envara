package protocol

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func captureStatusFixture() []byte {
	data := make([]byte, CaptureStatusSize)
	binary.LittleEndian.PutUint32(data, CaptureStatusSize)
	binary.LittleEndian.PutUint32(data[4:], CaptureABI)
	return data
}

func TestCaptureStatusPreservesTelemetryWithoutGrantingAcceptance(t *testing.T) {
	data := captureStatusFixture()
	for offset := 8; offset < 32; offset += 4 {
		binary.LittleEndian.PutUint32(data[offset:], 1)
	}
	for index, value := range []uint64{1<<40 + 1, 1<<41 + 2, 1<<42 + 3, 1<<43 + 4, 1<<44 + 5} {
		binary.LittleEndian.PutUint64(data[48+index*8:], value)
	}
	binary.LittleEndian.PutUint32(data[88:], 2048)
	binary.LittleEndian.PutUint32(data[92:], 1024)
	binary.LittleEndian.PutUint32(data[96:], 5)
	capture, err := DecodeCaptureStatus(data)
	if err != nil {
		t.Fatal(err)
	}
	if capture.Engine != "windivert" || capture.ABI != 1 || capture.Architecture != "x64" || !capture.ActivationStarted || !capture.Running || !capture.SocketReady || !capture.NetworkReady || !capture.TCPCapture || !capture.UDPBlocking || !capture.IdentityCallback {
		t.Fatalf("valid capture telemetry rejected: %#v", capture)
	}
	if capture.Intercepted != 1<<40+1 || capture.Reinjected != 1<<41+2 || capture.Blocked != 1<<42+3 || capture.UnknownDropped != 1<<43+4 || capture.UnsupportedDropped != 1<<44+5 || capture.ActiveFlows != 2048 || capture.ActiveIdentities != 1024 || capture.LastError != 5 {
		t.Fatalf("capture counters decoded incorrectly: %#v", capture)
	}
	if capture.Ready || capture.DNS || capture.FailClosed || capture.VerificationPassed || capture.ProvenanceVerified {
		t.Fatal("capture wire data asserted unverified acceptance")
	}
	status := MissingStatus("capture telemetry only")
	status.Installed = true
	status.Authorized = true
	status.Capture = &capture
	if status.CanLaunch() {
		t.Fatal("capture telemetry authorized protected launch")
	}
}

func TestIdleCaptureStatusDoesNotClaimActivation(t *testing.T) {
	capture, err := DecodeCaptureStatus(captureStatusFixture())
	if err != nil {
		t.Fatal(err)
	}
	if capture.ActivationStarted || capture.Running || capture.Ready || capture.DNS || capture.FailClosed || capture.VerificationPassed {
		t.Fatal("idle telemetry asserted activation or acceptance")
	}
}

func TestCaptureStatusRejectsClaimsMissingFromNativeAcceptance(t *testing.T) {
	for _, field := range []struct {
		name   string
		offset int
	}{
		{"ready", 32}, {"DNS", 36}, {"fail closed", 40}, {"verified", 44},
	} {
		t.Run(field.name, func(t *testing.T) {
			data := captureStatusFixture()
			binary.LittleEndian.PutUint32(data[field.offset:], 1)
			capture, err := DecodeCaptureStatus(data)
			if err == nil || capture != (CaptureStatus{}) {
				t.Fatalf("unverified %s claim was accepted: %#v, %v", field.name, capture, err)
			}
		})
	}
}

func TestCaptureStatusRejectsMalformedAndIncompatibleABI(t *testing.T) {
	for _, size := range []int{0, CaptureStatusSize - 1, CaptureStatusSize + 1} {
		if _, err := DecodeCaptureStatus(make([]byte, size)); err == nil {
			t.Fatalf("accepted %d-byte wire status", size)
		}
	}
	for _, mutation := range []struct {
		name   string
		offset int
		value  uint32
	}{
		{"wrong reported size", 0, CaptureStatusSize - 1},
		{"zero ABI", 4, 0}, {"future ABI", 4, CaptureABI + 1},
		{"too many flows", 88, 2049}, {"too many identities", 92, 1025},
		{"reserved data", 100, 1},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			data := captureStatusFixture()
			binary.LittleEndian.PutUint32(data[mutation.offset:], mutation.value)
			if _, err := DecodeCaptureStatus(data); err == nil {
				t.Fatal("incompatible capture status accepted")
			}
		})
	}
	for offset := 8; offset < 48; offset += 4 {
		t.Run(fmt.Sprintf("nonboolean at %d", offset), func(t *testing.T) {
			data := captureStatusFixture()
			binary.LittleEndian.PutUint32(data[offset:], 2)
			if _, err := DecodeCaptureStatus(data); err == nil {
				t.Fatal("nonboolean capture flag accepted")
			}
		})
	}
}
