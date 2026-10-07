//go:build !windows

package host

import (
	"envara.io/windows-app-routing/internal/protocol"
	"errors"
)

func Call(request protocol.Request) protocol.Response {
	if request.Method == "status" || request.Method == "setup" {
		return protocol.Success(request, protocol.MissingStatus("Windows native routing is unavailable on this platform."))
	}
	return protocol.Failure(request, "PLATFORM_UNSUPPORTED", "Windows native routing is unavailable on this platform.")
}

func RunService() error { return errors.New("Windows service unavailable") }
