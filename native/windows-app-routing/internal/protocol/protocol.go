// Package protocol defines the private, credential-bearing native RPC boundary.
// Requests must only travel over stdin and the local authenticated named pipe.
package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

const Name = "envara.application-routing"
const Version = 1
const MaxMessage = 1024 * 1024

var requestID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,80}$`)

type Request struct {
	Protocol string          `json:"protocol"`
	Version  int             `json:"version"`
	ID       string          `json:"id"`
	Method   string          `json:"method"`
	Params   json.RawMessage `json:"params"`
}

type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Response struct {
	Protocol string `json:"protocol"`
	Version  int    `json:"version"`
	ID       string `json:"id"`
	Result   any    `json:"result,omitempty"`
	Error    *Error `json:"error,omitempty"`
}

type Capabilities struct {
	TCP            bool `json:"tcp"`
	UDP            bool `json:"udp"`
	DNS            bool `json:"dns"`
	ChildProcesses bool `json:"childProcesses"`
	FailClosed     bool `json:"failClosed"`
}

func (c Capabilities) Complete() bool {
	return c.TCP && c.UDP && c.DNS && c.ChildProcesses && c.FailClosed
}

type Verification struct {
	Passed  bool         `json:"passed"`
	Version string       `json:"version"`
	Checks  Capabilities `json:"checks"`
}

type Session struct {
	SessionID string `json:"sessionId"`
	PID       uint32 `json:"pid"`
	Status    string `json:"status"`
	ExitCode  *int   `json:"exitCode,omitempty"`
}

type Status struct {
	Platform     string       `json:"platform"`
	Installed    bool         `json:"installed"`
	Authorized   bool         `json:"authorized"`
	Ready        bool         `json:"ready"`
	Capabilities Capabilities `json:"capabilities"`
	Verification Verification `json:"verification"`
	Sessions     []Session    `json:"sessions"`
	Reason       string       `json:"reason,omitempty"`
	Enforcement  *Enforcement `json:"enforcement,omitempty"`
}

func (s Status) CanLaunch() bool {
	return s.Installed && s.Authorized && s.Ready && s.Capabilities.Complete() &&
		s.Verification.Passed && s.Verification.Version != "" && s.Verification.Checks.Complete()
}

func Read(r io.Reader) (Request, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxMessage+1))
	if err != nil || len(data) > MaxMessage {
		return Request{}, errors.New("request size invalid")
	}
	return Decode(data)
}

func Decode(data []byte) (Request, error) {
	var request Request
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return Request{}, errors.New("request invalid")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || request.Protocol != Name || request.Version != Version || !requestID.MatchString(request.ID) {
		return Request{}, errors.New("request envelope invalid")
	}
	switch request.Method {
	case "status", "setup", "prepareRoute", "launch", "stop", "revoke":
	default:
		return Request{}, errors.New("method invalid")
	}
	return request, nil
}

func Success(request Request, result any) Response {
	return Response{Protocol: Name, Version: Version, ID: request.ID, Result: result}
}

func Failure(request Request, code, message string) Response {
	return Response{Protocol: Name, Version: Version, ID: request.ID, Error: &Error{Code: code, Message: message}}
}

func MissingStatus(reason string) Status {
	return Status{Platform: "win32", Sessions: []Session{}, Reason: reason,
		Verification: Verification{Version: "windows-wfp-v1"}}
}
