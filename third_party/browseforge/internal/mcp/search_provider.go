package mcp

import (
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"

	"github.com/mxschmitt/playwright-go"
)

const defaultSearchProviderName = "google"

// SearchProvider encapsulates search-engine-specific navigation and SERP parsing.
type SearchProvider interface {
	Name() string
	SearchURL(query string) string
	WaitForResults(page playwright.Page) error
	Extract(page playwright.Page, maxResults int) (*SearchResponse, error)
	UsefulFallbackLink(href string) bool
}

var searchProviders = map[string]SearchProvider{
	"google":     googleSearchProvider{},
	"bing":       bingSearchProvider{},
	"duckduckgo": duckDuckGoSearchProvider{},
	"ddg":        duckDuckGoSearchProvider{},
}

func getSearchProvider(name string) (SearchProvider, error) {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if normalized == "" {
		normalized = defaultSearchProviderName
	}
	provider, ok := searchProviders[normalized]
	if !ok {
		names := make([]string, 0, len(searchProviders))
		for name := range searchProviders {
			names = append(names, name)
		}
		sort.Strings(names)
		return nil, fmt.Errorf("unsupported search engine %q (supported: %s)", name, strings.Join(names, ", "))
	}
	return provider, nil
}

func supportedSearchProviderNames() []string {
	names := make([]string, 0, len(searchProviders))
	for name := range searchProviders {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

type googleSearchProvider struct{}

func (googleSearchProvider) Name() string { return "google" }

func (googleSearchProvider) SearchURL(query string) string {
	return "https://www.google.com/search?hl=en&q=" + url.QueryEscape(query)
}

func (googleSearchProvider) WaitForResults(page playwright.Page) error {
	_, err := page.WaitForSelector("#search", playwright.PageWaitForSelectorOptions{
		Timeout: playwright.Float(15000),
	})
	return err
}

func (googleSearchProvider) Extract(page playwright.Page, maxResults int) (*SearchResponse, error) {
	data, err := page.Evaluate(`() => {
		const href = window.location.href.toLowerCase();
		const bodyText = (document.body && document.body.innerText ? document.body.innerText : '').toLowerCase();
		if (href.includes('/sorry/') || bodyText.includes('unusual traffic') || bodyText.includes('our systems have detected unusual traffic')) {
			return { error: 'google_unusual_traffic_interstitial' };
		}
		if (document.querySelector('form[action*="/sorry/"]') || document.querySelector('iframe[src*="recaptcha"]') || bodyText.includes('not a robot')) {
			return { error: 'google_captcha_interstitial' };
		}
		if ((href.includes('consent.google.') || href.includes('/consent')) && (bodyText.includes('before you continue') || bodyText.includes('accept all'))) {
			return { error: 'google_consent_interstitial' };
		}

		const results = [];
		const seen = new Set();
		const normalizeURL = (rawHref) => {
			if (!rawHref) return '';
			const u = new URL(rawHref, window.location.href);
			if (u.pathname === '/url' && u.searchParams.has('q')) {
				return u.searchParams.get('q') || '';
			}
			return u.href;
		};
		const addResult = (titleEl, linkEl, snippetEl) => {
			if (!titleEl || !linkEl) return;
			const title = (titleEl.innerText || titleEl.textContent || '').trim();
			const href = normalizeURL(linkEl.getAttribute('href') || linkEl.href);
			if (!title || !href || seen.has(href)) return;
			const parsed = new URL(href, window.location.href);
			if (parsed.hostname.endsWith('google.com') && ['/search', '/preferences', '/advanced_search', '/maps'].includes(parsed.pathname)) return;
			const snippet = snippetEl ? (snippetEl.innerText || snippetEl.textContent || '').trim() : '';
			seen.add(href);
			results.push({title, url: href, snippet});
		};

		const items = document.querySelectorAll('div.g, div.MjjYud, div.TzMi6d');
		for (const item of items) {
			addResult(item.querySelector('h3'), item.querySelector('a'), item.querySelector('[data-sncf], .VwiC3b, .yXK5lf, [style*="-webkit-line-clamp"]'));
			if (results.length >= 30) break;
		}

		if (results.length === 0) {
			for (const linkEl of document.querySelectorAll('a:has(h3), a[jsname][href], a[data-ved][href]')) {
				const titleEl = linkEl.querySelector('h3') || linkEl;
				const container = linkEl.closest('div[data-ved], div[jscontroller], div');
				const snippetEl = container ? container.querySelector('[data-sncf], .VwiC3b, .yXK5lf, [style*="-webkit-line-clamp"]') : null;
				addResult(titleEl, linkEl, snippetEl);
				if (results.length >= 30) break;
			}
		}
		return results;
	}`)
	if err != nil {
		return nil, err
	}
	if marker, ok := data.(map[string]any); ok {
		if markerErr := asString(marker["error"]); markerErr != "" {
			return nil, fmt.Errorf("%s", markerErr)
		}
	}
	results, err := searchResultsFromEvaluate(data, maxResults)
	if err != nil {
		return nil, err
	}
	return &SearchResponse{Engine: "google", Results: results, ExtractionMode: "structured"}, nil
}

func (googleSearchProvider) UsefulFallbackLink(href string) bool {
	u, err := url.Parse(href)
	if err != nil {
		return false
	}
	if strings.HasSuffix(u.Hostname(), "google.com") {
		switch u.Path {
		case "/search", "/preferences", "/advanced_search", "/maps", "/imghp", "/webhp":
			return false
		}
	}
	return true
}

type bingSearchProvider struct{}

func (bingSearchProvider) Name() string { return "bing" }

func (bingSearchProvider) SearchURL(query string) string {
	return "https://www.bing.com/search?setlang=en-US&mkt=en-US&q=" + url.QueryEscape(query)
}

func (bingSearchProvider) WaitForResults(page playwright.Page) error {
	_, err := page.WaitForSelector("#b_results", playwright.PageWaitForSelectorOptions{
		Timeout: playwright.Float(15000),
	})
	return err
}

func (bingSearchProvider) Extract(page playwright.Page, maxResults int) (*SearchResponse, error) {
	data, err := page.Evaluate(`() => {
		const bodyText = (document.body && document.body.innerText ? document.body.innerText : '').toLowerCase();
		if (bodyText.includes('unusual traffic') || bodyText.includes('verify you are human')) {
			return { error: 'bing_verification_interstitial' };
		}
		const normalizeBingURL = (rawHref) => {
			if (!rawHref) return '';
			const u = new URL(rawHref, window.location.href);
			if (u.hostname.endsWith('bing.com') && u.searchParams.has('u')) {
				const encoded = u.searchParams.get('u') || '';
				try {
					const payload = encoded.startsWith('a1') ? encoded.slice(2) : encoded;
					const decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
					if (decoded.startsWith('http://') || decoded.startsWith('https://')) return decoded;
				} catch (_) {}
			}
			return u.href;
		};
		const results = [];
		const seen = new Set();
		const addResult = (item) => {
			const linkEl = item.querySelector('h2 a[href], a[href] h2')?.closest('a[href]') || item.querySelector('a[href]');
			const titleEl = item.querySelector('h2') || linkEl;
			if (!linkEl || !titleEl) return;
			const title = (titleEl.innerText || titleEl.textContent || '').trim();
			const href = normalizeBingURL(linkEl.getAttribute('href') || linkEl.href);
			if (!title || !href || seen.has(href)) return;
			const parsed = new URL(href, window.location.href);
			if (parsed.hostname.endsWith('bing.com')) return;
			const snippetEl = item.querySelector('.b_caption p, .b_snippet, p');
			const snippet = snippetEl ? (snippetEl.innerText || snippetEl.textContent || '').trim() : '';
			seen.add(href);
			results.push({title, url: href, snippet});
		};
		for (const item of document.querySelectorAll('#b_results > li.b_algo')) {
			addResult(item);
			if (results.length >= 30) break;
		}
		if (results.length === 0) {
			for (const item of document.querySelectorAll('li.b_algo, article, .b_results li')) {
				addResult(item);
				if (results.length >= 30) break;
			}
		}
		return results;
	}`)
	if err != nil {
		return nil, err
	}
	if marker, ok := data.(map[string]any); ok {
		if markerErr := asString(marker["error"]); markerErr != "" {
			return nil, fmt.Errorf("%s", markerErr)
		}
	}
	results, err := searchResultsFromEvaluate(data, maxResults)
	if err != nil {
		return nil, err
	}
	return &SearchResponse{Engine: "bing", Results: results, ExtractionMode: "structured"}, nil
}

func (bingSearchProvider) UsefulFallbackLink(href string) bool {
	u, err := url.Parse(href)
	if err != nil {
		return false
	}
	return !strings.HasSuffix(u.Hostname(), "bing.com")
}

type duckDuckGoSearchProvider struct{}

func (duckDuckGoSearchProvider) Name() string { return "duckduckgo" }

func (duckDuckGoSearchProvider) SearchURL(query string) string {
	return "https://duckduckgo.com/html/?kl=us-en&q=" + url.QueryEscape(query)
}

func (duckDuckGoSearchProvider) WaitForResults(page playwright.Page) error {
	_, err := page.WaitForSelector(".results, #links, .result", playwright.PageWaitForSelectorOptions{
		Timeout: playwright.Float(15000),
	})
	return err
}

func (duckDuckGoSearchProvider) Extract(page playwright.Page, maxResults int) (*SearchResponse, error) {
	data, err := page.Evaluate(`() => {
		const bodyText = (document.body && document.body.innerText ? document.body.innerText : '').toLowerCase();
		if (bodyText.includes('anomaly') && bodyText.includes('traffic')) {
			return { error: 'duckduckgo_anomaly_interstitial' };
		}
		const results = [];
		const seen = new Set();
		const normalizeDDGURL = (rawHref) => {
			if (!rawHref) return '';
			const u = new URL(rawHref, window.location.href);
			if (u.hostname.endsWith('duckduckgo.com') && u.pathname.includes('/l/') && u.searchParams.has('uddg')) {
				return decodeURIComponent(u.searchParams.get('uddg') || '');
			}
			return u.href;
		};
		const addResult = (item) => {
			const linkEl = item.querySelector('a.result__a[href], .result__title a[href], a[href]');
			if (!linkEl) return;
			const title = (linkEl.innerText || linkEl.textContent || '').trim();
			const href = normalizeDDGURL(linkEl.getAttribute('href') || linkEl.href);
			if (!title || !href || seen.has(href)) return;
			const parsed = new URL(href, window.location.href);
			if (parsed.hostname.endsWith('duckduckgo.com') && !parsed.pathname.includes('/l/')) return;
			const snippetEl = item.querySelector('.result__snippet, .result__body, .snippet');
			const snippet = snippetEl ? (snippetEl.innerText || snippetEl.textContent || '').trim() : '';
			seen.add(href);
			results.push({title, url: href, snippet});
		};
		for (const item of document.querySelectorAll('.result, .web-result')) {
			addResult(item);
			if (results.length >= 30) break;
		}
		return results;
	}`)
	if err != nil {
		return nil, err
	}
	if marker, ok := data.(map[string]any); ok {
		if markerErr := asString(marker["error"]); markerErr != "" {
			return nil, fmt.Errorf("%s", markerErr)
		}
	}
	results, err := searchResultsFromEvaluate(data, maxResults)
	if err != nil {
		return nil, err
	}
	return &SearchResponse{Engine: "duckduckgo", Results: results, ExtractionMode: "structured"}, nil
}

func (duckDuckGoSearchProvider) UsefulFallbackLink(href string) bool {
	u, err := url.Parse(href)
	if err != nil {
		return false
	}
	return !strings.HasSuffix(u.Hostname(), "duckduckgo.com")
}

func searchResultsFromEvaluate(data any, maxResults int) ([]SearchResult, error) {
	raw, ok := data.([]any)
	if !ok {
		return nil, fmt.Errorf("unexpected result type from page.evaluate")
	}
	var searchResults []SearchResult
	for i, item := range raw {
		if i >= maxResults {
			break
		}
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		title := asString(m["title"])
		resultURL := asString(m["url"])
		if title == "" || resultURL == "" {
			continue
		}
		searchResults = append(searchResults, SearchResult{
			Title:   title,
			URL:     resultURL,
			Snippet: asString(m["snippet"]),
		})
	}
	return searchResults, nil
}

func logSearchInterstitial(sessionID, profileID string, provider SearchProvider, err error) {
	if err == nil {
		return
	}
	msg := err.Error()
	if strings.Contains(msg, "interstitial") || strings.Contains(msg, "verification") || strings.Contains(msg, "anomaly") {
		slog.Warn("web search interstitial detected", "session", sessionID, "profile", profileID, "engine", provider.Name(), "error", msg)
	}
}
