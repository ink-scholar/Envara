package mcp

import (
	"math"
	"testing"

	"browseforge/internal/browser"
)

func TestTabToolsRejectMalformedIndexBeforeLookingUpSession(t *testing.T) {
	server := &Server{}
	for name, tool := range map[string]func(map[string]any) (any, *mcpError){
		"switch": server.toolSwitchTab,
		"close":  server.toolCloseTab,
	} {
		for label, input := range map[string]any{
			"missing": nil, "string": "1", "boolean": true, "negative": float64(-1),
			"fraction": 0.5, "nan": math.NaN(), "infinity": math.Inf(1), "overflow": math.MaxFloat64,
		} {
			t.Run(name+"/"+label, func(t *testing.T) {
				result, failure := tool(map[string]any{"profile_id": "owned-inactive", "index": input})
				if result != nil || failure == nil || failure.Code != -32602 {
					t.Fatalf("malformed index must return invalid params, got result=%v failure=%v", result, failure)
				}
			})
		}
	}
}

func TestTabToolsAcceptWholeIndexAndReachTheActualSessionCheck(t *testing.T) {
	server := &Server{mgr: &browser.Manager{}}
	for name, tool := range map[string]func(map[string]any) (any, *mcpError){
		"switch": server.toolSwitchTab,
		"close":  server.toolCloseTab,
	} {
		t.Run(name, func(t *testing.T) {
			_, failure := tool(map[string]any{"profile_id": "owned-inactive", "index": float64(0)})
			if failure == nil || failure.Code != -32000 || failure.Message != "no active session" {
				t.Fatalf("valid index must reach session lookup, got %v", failure)
			}
		})
	}
}
