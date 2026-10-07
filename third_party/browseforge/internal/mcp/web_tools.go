package mcp

import "fmt"

func (s *Server) toolWebSearch(args map[string]any) (any, *mcpError) {
	query, _ := args["query"].(string)
	if query == "" {
		return nil, newError(-32602, "query is required")
	}
	profileID, _ := args["profile_id"].(string)
	sessionID, _ := args["session_id"].(string)
	engine, _ := args["engine"].(string)
	if profileID == "" && sessionID == "" {
		if s.sessionPool == nil {
			return nil, newError(-32000, "web search is not available (session pool not initialized)")
		}
		defaultID, err := s.sessionPool.GetOrCreateDefaultProfile()
		if err != nil {
			return nil, newError(-32000, "auto-create default profile: "+err.Error())
		}
		profileID = defaultID
	}

	maxResults := 10
	if mr, ok := args["max_results"].(float64); ok && mr > 0 {
		maxResults = int(mr)
	}

	if s.sessionPool == nil {
		return nil, newError(-32000, "web search is not available (session pool not initialized)")
	}

	sess, created, err := s.sessionPool.GetOrCreateSession(profileID, sessionID)
	if err != nil {
		return nil, newError(-32000, err.Error())
	}

	searchResp, err := sess.WebSearch(query, engine, maxResults)
	if err != nil {
		return nil, newError(-32000, err.Error())
	}

	return buildWebSearchMCPResult(query, searchResp, sess.ID, sess.ProfileID, created), nil
}

func buildWebSearchMCPResult(query string, searchResp *SearchResponse, sessionID, profileID string, created bool) map[string]any {
	if searchResp == nil {
		searchResp = &SearchResponse{ExtractionMode: "structured"}
	}
	if searchResp.Engine == "" {
		searchResp.Engine = defaultSearchProviderName
	}
	if searchResp.ExtractionMode == "" {
		searchResp.ExtractionMode = "structured"
	}
	items := make([]map[string]string, len(searchResp.Results))
	for i, r := range searchResp.Results {
		items[i] = map[string]string{"title": r.Title, "url": r.URL, "snippet": r.Snippet}
	}

	payload := map[string]any{
		"engine":          searchResp.Engine,
		"query":           query,
		"extraction_mode": searchResp.ExtractionMode,
		"results":         items,
	}
	if searchResp.RawFallback != nil {
		payload["raw_fallback"] = searchResp.RawFallback
	}

	res := textResult(fmt.Sprintf("Found %d %s results for \"%s\" (mode: %s):\n%s", len(searchResp.Results), searchResp.Engine, query, searchResp.ExtractionMode, mustJSON(payload)))
	res["session_id"] = sessionID
	res["profile_id"] = profileID
	res["session_created"] = created
	res["engine"] = searchResp.Engine
	res["extraction_mode"] = searchResp.ExtractionMode
	res["results"] = items
	if searchResp.RawFallback != nil {
		res["raw_fallback"] = searchResp.RawFallback
	}
	return res
}

func (s *Server) toolWebExplore(args map[string]any) (any, *mcpError) {
	url, _ := args["url"].(string)
	if url == "" {
		return nil, newError(-32602, "url is required")
	}
	profileID, _ := args["profile_id"].(string)
	sessionID, _ := args["session_id"].(string)
	if profileID == "" && sessionID == "" {
		if s.sessionPool == nil {
			return nil, newError(-32000, "web explore is not available (session pool not initialized)")
		}
		defaultID, err := s.sessionPool.GetOrCreateDefaultProfile()
		if err != nil {
			return nil, newError(-32000, "auto-create default profile: "+err.Error())
		}
		profileID = defaultID
	}

	maxTextLength := 3000
	if mtl, ok := args["max_text_length"].(float64); ok && mtl > 0 {
		maxTextLength = int(mtl)
	}
	maxLinks := 50
	if ml, ok := args["max_links"].(float64); ok && ml > 0 {
		maxLinks = int(ml)
	}

	if s.sessionPool == nil {
		return nil, newError(-32000, "web explore is not available (session pool not initialized)")
	}

	sess, created, err := s.sessionPool.GetOrCreateSession(profileID, sessionID)
	if err != nil {
		return nil, newError(-32000, err.Error())
	}

	result, err := sess.WebExplore(url, maxTextLength, maxLinks)
	if err != nil {
		return nil, newError(-32000, err.Error())
	}

	output := map[string]any{
		"url":   result.URL,
		"title": result.Title,
		"text":  result.Text,
		"links": result.Links,
	}
	if result.Description != "" {
		output["description"] = result.Description
	}

	res := textResult(mustJSON(output))
	res["session_id"] = sess.ID
	res["profile_id"] = sess.ProfileID
	res["session_created"] = created
	return res, nil
}

func (s *Server) toolCreateSession(args map[string]any) (any, *mcpError) {
	profileID, _ := args["profile_id"].(string)
	if profileID == "" {
		return nil, newError(-32602, "profile_id is required")
	}
	if s.sessionPool == nil {
		return nil, newError(-32000, "web sessions are not available (session pool not initialized)")
	}
	sess, err := s.sessionPool.CreateSession(profileID)
	if err != nil {
		return nil, newError(-32000, err.Error())
	}
	res := textResult(fmt.Sprintf("Session created: %s (profile: %s, browser: %s)", sess.ID, sess.ProfileID, sess.BrowserID))
	res["session_id"] = sess.ID
	res["profile_id"] = sess.ProfileID
	return res, nil
}

func (s *Server) toolDestroySession(args map[string]any) (any, *mcpError) {
	sessionID, _ := args["session_id"].(string)
	if sessionID == "" {
		return nil, newError(-32602, "session_id is required")
	}
	if s.sessionPool == nil {
		return nil, newError(-32000, "web sessions are not available (session pool not initialized)")
	}
	if err := s.sessionPool.DestroySession(sessionID); err != nil {
		return nil, newError(-32000, err.Error())
	}
	res := textResult("Session destroyed: " + sessionID)
	res["session_id"] = sessionID
	return res, nil
}

func (s *Server) toolListSessions(args map[string]any) (any, *mcpError) {
	profileID, _ := args["profile_id"].(string)
	if s.sessionPool == nil {
		return nil, newError(-32000, "web sessions are not available (session pool not initialized)")
	}
	return textResult(mustJSON(s.sessionPool.ListSessions(profileID))), nil
}

func (s *Server) toolGCSessions(args map[string]any) (any, *mcpError) {
	if s.sessionPool == nil {
		return nil, newError(-32000, "web sessions are not available (session pool not initialized)")
	}
	closed := s.sessionPool.GC()
	return textResult(fmt.Sprintf("GC completed: closed %d sessions", closed)), nil
}
