package protocol

import (
	"strings"
	"testing"
)

func TestRPCBoundaryRejectsAmbiguousAndOversizeMessages(t *testing.T) {
	valid := `{"protocol":"envara.application-routing","version":1,"id":"a-b","method":"status","params":{}}`
	if _, err := Read(strings.NewReader(valid)); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{valid + valid, strings.Replace(valid, `"version":1`, `"version":2`, 1),
		strings.Replace(valid, `"status"`, `"execute"`, 1), strings.Replace(valid, `"params":{}`, `"password":"do-not-log"`, 1),
		strings.Repeat(" ", MaxMessage+1)} {
		if _, err := Read(strings.NewReader(invalid)); err == nil {
			t.Fatal("accepted invalid envelope")
		}
	}
}

func TestSourceBuiltAndPartialCapabilityNeverAuthorizeLaunch(t *testing.T) {
	all := Capabilities{true, true, true, true, true}
	ready := Status{Installed: true, Authorized: true, Ready: true, Capabilities: all,
		Verification: Verification{Passed: true, Version: "acceptance-1", Checks: all}}
	if !ready.CanLaunch() {
		t.Fatal("complete verified status rejected")
	}
	for i := 0; i < 5; i++ {
		candidate := ready
		switch i {
		case 0:
			candidate.Capabilities.DNS = false
		case 1:
			candidate.Verification.Passed = false
		case 2:
			candidate.Verification.Checks.UDP = false
		case 3:
			candidate.Authorized = false
		case 4:
			candidate.Verification.Version = ""
		}
		if candidate.CanLaunch() {
			t.Fatal("partial/unverified status authorized spawn")
		}
	}
}
