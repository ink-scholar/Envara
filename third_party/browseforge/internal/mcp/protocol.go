package mcp

import (
	"encoding/json"
	"net/http"
)

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func newError(code int, msg string) *mcpError { return &mcpError{Code: code, Message: msg} }

func newErrorData(code int, msg string, data any) *mcpError {
	return &mcpError{Code: code, Message: msg, Data: data}
}

func writeJSONRPC(w http.ResponseWriter, id any, err *mcpError, result ...any) {
	writeJSONRPCStatus(w, http.StatusOK, id, err, result...)
}

func writeJSONRPCStatus(w http.ResponseWriter, status int, id any, err *mcpError, result ...any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := map[string]any{"jsonrpc": "2.0", "id": id}
	if err != nil {
		resp["error"] = err
	} else if len(result) > 0 {
		resp["result"] = result[0]
	}
	json.NewEncoder(w).Encode(resp)
}

func mustJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}
