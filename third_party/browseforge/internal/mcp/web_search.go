package mcp

import (
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/playwright-community/playwright-go"
)

// WebSearch performs a provider-backed web search in this session's dedicated page.
func (s *WebSession) WebSearch(query string, engine string, maxResults int) (*SearchResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if query == "" {
		return nil, fmt.Errorf("query is required")
	}
	if maxResults <= 0 || maxResults > 30 {
		maxResults = 10
	}
	provider, err := getSearchProvider(engine)
	if err != nil {
		return nil, err
	}
	if err := s.ensurePageOpenLocked(); err != nil {
		return nil, err
	}

	s.LastAccessed = time.Now()
	searchURL := provider.SearchURL(query)
	_, err = s.Page.Goto(searchURL, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateDomcontentloaded,
		Timeout:   playwright.Float(30000),
	})
	if err != nil {
		return nil, fmt.Errorf("navigate to search: %w", err)
	}

	if err = provider.WaitForResults(s.Page); err != nil {
		slog.Warn("search results selector not found, trying extraction anyway", "session", s.ID, "engine", provider.Name(), "error", err)
	}

	resp, err := provider.Extract(s.Page, maxResults)
	if err != nil {
		logSearchInterstitial(s.ID, s.ProfileID, provider, err)
		return nil, fmt.Errorf("extract search results: %w", err)
	}
	if resp == nil {
		resp = &SearchResponse{Engine: provider.Name(), ExtractionMode: "structured"}
	}
	if resp.Engine == "" {
		resp.Engine = provider.Name()
	}
	if resp.ExtractionMode == "" {
		resp.ExtractionMode = "structured"
	}
	if len(resp.Results) == 0 {
		fallback, err := s.extractSearchRawFallback(provider, maxResults)
		if err != nil {
			return nil, fmt.Errorf("extract raw search fallback: %w", err)
		}
		resp.ExtractionMode = "raw_fallback"
		resp.RawFallback = fallback
		slog.Info("web search raw fallback extracted", "session", s.ID, "profile", s.ProfileID, "engine", provider.Name(), "query", query, "text_chars", len(fallback.Text), "candidate_links", len(fallback.CandidateLinks))
	}

	rawLinks := 0
	if resp.RawFallback != nil {
		rawLinks = len(resp.RawFallback.CandidateLinks)
	}
	slog.Info("web search completed", "session", s.ID, "profile", s.ProfileID, "engine", provider.Name(), "query", query, "results", len(resp.Results), "mode", resp.ExtractionMode, "raw_links", rawLinks)
	return resp, nil
}

// WebExplore navigates this session's dedicated page and extracts structured content.
func (s *WebSession) WebExplore(url string, maxTextLength int, maxLinks int) (*ExploreResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if url == "" {
		return nil, fmt.Errorf("url is required")
	}
	if maxTextLength <= 0 || maxTextLength > 10000 {
		maxTextLength = 3000
	}
	if maxLinks <= 0 || maxLinks > 200 {
		maxLinks = 50
	}
	if err := s.ensurePageOpenLocked(); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	s.LastAccessed = time.Now()
	_, err := s.Page.Goto(url, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateNetworkidle,
		Timeout:   playwright.Float(30000),
	})
	if err != nil {
		return nil, fmt.Errorf("navigate to url: %w", err)
	}

	result, err := s.extractPageContent(maxTextLength, maxLinks)
	if err != nil {
		return nil, fmt.Errorf("extract page content: %w", err)
	}

	result.URL = url
	slog.Info("web explore completed", "session", s.ID, "profile", s.ProfileID, "url", url, "textLen", len(result.Text), "links", len(result.Links))
	return result, nil
}

// SearchResponse represents a web_search extraction result.
type SearchResponse struct {
	Engine         string             `json:"engine"`
	Results        []SearchResult     `json:"results"`
	ExtractionMode string             `json:"extraction_mode"`
	RawFallback    *SearchRawFallback `json:"raw_fallback,omitempty"`
}

// SearchResult represents a single structured search result entry.
type SearchResult struct {
	Title   string `json:"title"`
	URL     string `json:"url"`
	Snippet string `json:"snippet"`
}

// SearchRawFallback is an LLM-friendly SERP snapshot used when structured selectors fail.
type SearchRawFallback struct {
	PageTitle      string    `json:"page_title"`
	Text           string    `json:"text"`
	CandidateLinks []LinkRef `json:"candidate_links"`
}

// ExploreResult represents the extracted content of a single page.
type ExploreResult struct {
	URL         string    `json:"url,omitempty"`
	Title       string    `json:"title"`
	Description string    `json:"description,omitempty"`
	Text        string    `json:"text"`
	Links       []LinkRef `json:"links"`
	Errors      []string  `json:"errors,omitempty"`
}

// LinkRef represents a hyperlink found on a page.
type LinkRef struct {
	Text string `json:"text"`
	URL  string `json:"url"`
}

func (s *WebSession) extractSearchRawFallback(provider SearchProvider, maxLinks int) (*SearchRawFallback, error) {
	data, err := s.Page.Evaluate(`() => {
		const normalizeSearchURL = (rawHref) => {
			if (!rawHref) return '';
			const u = new URL(rawHref, window.location.href);
			if (u.pathname === '/url' && u.searchParams.has('q')) {
				return u.searchParams.get('q') || '';
			}
			if (u.hostname.endsWith('bing.com') && u.searchParams.has('u')) {
				const encoded = u.searchParams.get('u') || '';
				try {
					const payload = encoded.startsWith('a1') ? encoded.slice(2) : encoded;
					const decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
					if (decoded.startsWith('http://') || decoded.startsWith('https://')) return decoded;
				} catch (_) {}
			}
			if (u.pathname.includes('/l/') && u.searchParams.has('uddg')) {
				return decodeURIComponent(u.searchParams.get('uddg') || '');
			}
			return u.href;
		};
		const isUsefulHref = (href) => {
			if (!href || href.startsWith('javascript:') || href.startsWith('#') || href.startsWith('mailto:')) return false;
			const u = new URL(href, window.location.href);
			if (u.hostname.endsWith('google.com') && ['/search', '/preferences', '/advanced_search', '/maps', '/imghp', '/webhp'].includes(u.pathname)) return false;
			return true;
		};
		const body = document.body;
		let text = body && body.innerText ? body.innerText.replace(/[\s]+/g, ' ').trim() : '';
		const links = [];
		const seen = new Set();
		for (const a of document.querySelectorAll('a[href]')) {
			const href = normalizeSearchURL(a.getAttribute('href') || a.href);
			if (!isUsefulHref(href) || seen.has(href)) continue;
			const linkText = (a.innerText || a.textContent || '').replace(/[\s]+/g, ' ').trim();
			if (!linkText && !href) continue;
			seen.add(href);
			links.push({ text: linkText, url: href });
			if (links.length >= 30) break;
		}
		return { page_title: document.title || '', text, candidate_links: links };
	}`)
	if err != nil {
		return nil, err
	}
	raw, ok := data.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected raw fallback type")
	}
	fallback := &SearchRawFallback{
		PageTitle:      asString(raw["page_title"]),
		Text:           truncateString(asString(raw["text"]), 4000),
		CandidateLinks: []LinkRef{},
	}
	if rawLinks, ok := raw["candidate_links"].([]any); ok {
		for i, item := range rawLinks {
			if i >= maxLinks {
				break
			}
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			linkURL := asString(m["url"])
			if !provider.UsefulFallbackLink(linkURL) {
				continue
			}
			fallback.CandidateLinks = append(fallback.CandidateLinks, LinkRef{Text: asString(m["text"]), URL: linkURL})
		}
	}
	return fallback, nil
}

func (s *WebSession) extractPageContent(maxTextLength, maxLinks int) (*ExploreResult, error) {
	data, err := s.Page.Evaluate(`() => {
		const result = { title: document.title || '', description: '', text: '', links: [] };
		const metaDesc = document.querySelector('meta[name="description"]');
		if (metaDesc) result.description = metaDesc.getAttribute('content') || '';
		const body = document.body;
		if (body) {
			const scripts = body.querySelectorAll('script, style, noscript, iframe');
			scripts.forEach(s => s.remove());
			let text = body.innerText || '';
			text = text.replace(/[\s]+/g, ' ').trim();
			result.text = text;
		}
		const links = document.querySelectorAll('a[href]');
		for (const a of links) {
			const href = a.getAttribute('href');
			if (!href || href.startsWith('javascript:') || href.startsWith('#') || href.startsWith('mailto:')) continue;
			const text = a.innerText ? a.innerText.trim() : '';
			if (!text && !href) continue;
			result.links.push({ text, url: href });
		}
		return result;
	}`)
	if err != nil {
		return nil, err
	}

	raw, ok := data.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected page content type")
	}

	er := &ExploreResult{
		Title:       asString(raw["title"]),
		Description: asString(raw["description"]),
		Text:        asString(raw["text"]),
	}
	er.Text = truncateString(er.Text, maxTextLength)

	if rawLinks, ok := raw["links"].([]any); ok {
		for i, item := range rawLinks {
			if i >= maxLinks {
				break
			}
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			er.Links = append(er.Links, LinkRef{Text: asString(m["text"]), URL: asString(m["url"])})
		}
	}
	return er, nil
}

func truncateString(s string, maxRunes int) string {
	if maxRunes <= 0 || utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	r := []rune(s)
	return string(r[:maxRunes]) + "\n… (truncated)"
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return fmt.Sprintf("%g", t)
	case nil:
		return ""
	default:
		s := fmt.Sprintf("%v", t)
		if utf8.RuneCountInString(s) > 5000 {
			return s[:5000] + "…"
		}
		return s
	}
}
