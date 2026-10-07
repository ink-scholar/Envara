package api

import (
	"encoding/json"
	"net/http"

	"browseforge/internal/workflow"
)

func WorkflowHandler(engine *workflow.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var wf workflow.Workflow
		if err := json.NewDecoder(r.Body).Decode(&wf); err != nil {
			writeError(w, 400, "INVALID_BODY", err.Error())
			return
		}
		if wf.Name == "" {
			wf.Name = "unnamed"
		}
		results := engine.Execute(&wf)
		writeJSON(w, 200, map[string]any{"data": results})
	}
}
