package main

import (
	"encoding/json"
	"os"

	"envara.io/windows-app-routing/internal/host"
	"envara.io/windows-app-routing/internal/protocol"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--service" {
		// Never print service requests or arguments: they can contain secrets.
		if host.RunService() != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 2 || os.Args[1] != "--rpc" {
		os.Exit(2)
	}
	request, err := protocol.Read(os.Stdin)
	var response protocol.Response
	if err != nil {
		response = protocol.Failure(protocol.Request{}, "INVALID_REQUEST", "Invalid native request.")
	} else {
		response = host.Call(request)
	}
	if json.NewEncoder(os.Stdout).Encode(response) != nil {
		os.Exit(1)
	}
}
