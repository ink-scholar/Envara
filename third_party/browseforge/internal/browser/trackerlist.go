package browser

import (
	"bufio"
	"embed"
	"encoding/json"
	"net"
	"net/url"
	"path"
	"strings"
	"sync"

	"golang.org/x/net/publicsuffix"
)

// EasyPrivacy, bundled byte for byte at one pinned commit by
// scripts/update-tracker-list.mjs; trackerlists/easyprivacy/NOTICE.md carries
// its licence and attribution. Only a strict subset of the filter syntax is
// used: a rule with anything the matcher does not understand is skipped, so the
// list can only ever block less than upstream intends, never more.
//
//go:embed trackerlists/easyprivacy/*.txt trackerlists/easyprivacy/provenance.json
var easyPrivacyFiles embed.FS

// Request kinds, as filter-list resource types.
const (
	kindScript uint16 = 1 << iota
	kindImage
	kindStylesheet
	kindXHR
	kindSubdocument
	kindPing
	kindMedia
	kindFont
	kindWebsocket
	kindOther
	kindDocument
)

// Rules without a type option apply to every kind except a top-level page.
const kindDefault = kindScript | kindImage | kindStylesheet | kindXHR | kindSubdocument | kindPing | kindMedia | kindFont | kindWebsocket | kindOther

var filterKinds = map[string]uint16{
	"script": kindScript, "image": kindImage, "stylesheet": kindStylesheet, "css": kindStylesheet,
	"xmlhttprequest": kindXHR, "xhr": kindXHR, "subdocument": kindSubdocument, "frame": kindSubdocument,
	"ping": kindPing, "media": kindMedia, "font": kindFont, "websocket": kindWebsocket, "other": kindOther,
}

type trackerRule struct {
	tail       string // the pattern after the host anchor; empty: the whole host
	kinds      uint16
	domains    []string // the page must be on one of these, when set
	notDomains []string
}

type trackerList struct {
	commit        string
	block, allow  map[string][]trackerRule
	blockRules    int
	allowRules    int
	skippedRules  int
	sourceFiles   int
	sourcePresent bool
}

var (
	easyPrivacyOnce sync.Once
	easyPrivacy     *trackerList
)

// loadedEasyPrivacy parses the bundled list once, on first use.
func loadedEasyPrivacy() *trackerList {
	easyPrivacyOnce.Do(func() { easyPrivacy = parseTrackerList(easyPrivacyFiles) })
	return easyPrivacy
}

func parseTrackerList(files embed.FS) *trackerList {
	list := &trackerList{block: map[string][]trackerRule{}, allow: map[string][]trackerRule{}}
	if data, err := files.ReadFile("trackerlists/easyprivacy/provenance.json"); err == nil {
		var provenance struct {
			Commit string `json:"commit"`
		}
		if json.Unmarshal(data, &provenance) == nil {
			list.commit = provenance.Commit
		}
	}
	entries, err := files.ReadDir("trackerlists/easyprivacy")
	if err != nil {
		return list
	}
	for _, entry := range entries {
		if entry.IsDir() || path.Ext(entry.Name()) != ".txt" {
			continue
		}
		data, err := files.ReadFile("trackerlists/easyprivacy/" + entry.Name())
		if err != nil {
			continue
		}
		list.sourceFiles++
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || line[0] == '!' || line[0] == '[' {
				continue
			}
			anchor, rule, allow, ok := parseTrackerRule(line)
			if !ok {
				list.skippedRules++
				continue
			}
			if allow {
				list.allow[anchor] = append(list.allow[anchor], rule)
				list.allowRules++
			} else {
				list.block[anchor] = append(list.block[anchor], rule)
				list.blockRules++
			}
		}
	}
	list.sourcePresent = list.blockRules > 0
	return list
}

func validFilterHost(host string) bool {
	if host == "" || !strings.Contains(host, ".") || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") || strings.HasPrefix(host, "-") {
		return false
	}
	for _, character := range host {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '.' || character == '-') {
			return false
		}
	}
	return true
}

// parseTrackerRule reads one network rule of the supported subset:
//
//	||host^  ||host/path*^...  [@@ for an exception]  [$options]
//
// Options: third-party, resource types (and their negations), domain=.
// Anything else (cosmetic rules, regular expressions, unanchored patterns,
// first-party-only rules, modifiers such as redirect or important) is refused.
func parseTrackerRule(line string) (anchor string, rule trackerRule, allow bool, ok bool) {
	if strings.Contains(line, "##") || strings.Contains(line, "#@#") || strings.Contains(line, "#?#") || strings.Contains(line, "#$#") {
		return "", rule, false, false
	}
	if strings.HasPrefix(line, "@@") {
		allow, line = true, line[2:]
	}
	if !strings.HasPrefix(line, "||") {
		return "", rule, allow, false
	}
	body, options := strings.ToLower(line[2:]), ""
	if index := strings.LastIndexByte(body, '$'); index >= 0 {
		body, options = body[:index], body[index+1:]
	}
	end := strings.IndexAny(body, "^/*:?|")
	if end < 0 {
		end = len(body)
	}
	anchor, rule.tail = body[:end], body[end:]
	if !validFilterHost(anchor) {
		return "", rule, allow, false
	}
	// The host must be followed by a separator: `||example.c*` style prefixes
	// would match unrelated hosts that merely start the same way.
	if rule.tail != "" && rule.tail[0] != '^' && rule.tail[0] != '/' && rule.tail[0] != ':' {
		return "", rule, allow, false
	}
	if rule.tail == "^" {
		rule.tail = ""
	}
	var include, exclude uint16
	if options != "" {
		for _, option := range strings.Split(options, ",") {
			option = strings.TrimSpace(option)
			switch {
			case option == "third-party" || option == "3p" || option == "~first-party" || option == "~1p":
				// Every rule is applied to third-party requests only.
			case strings.HasPrefix(option, "domain="):
				for _, domain := range strings.Split(option[len("domain="):], "|") {
					negated := strings.HasPrefix(domain, "~")
					domain = strings.TrimPrefix(domain, "~")
					if !validFilterHost(domain) {
						return "", rule, allow, false
					}
					if negated {
						rule.notDomains = append(rule.notDomains, domain)
					} else {
						rule.domains = append(rule.domains, domain)
					}
				}
			default:
				negated := strings.HasPrefix(option, "~")
				kind, known := filterKinds[strings.TrimPrefix(option, "~")]
				if !known {
					return "", rule, allow, false
				}
				if negated {
					exclude |= kind
				} else {
					include |= kind
				}
			}
		}
	}
	if include != 0 {
		rule.kinds = include &^ exclude
	} else {
		rule.kinds = kindDefault &^ exclude
	}
	if rule.kinds == 0 {
		return "", rule, allow, false
	}
	return anchor, rule, allow, true
}

func filterSeparator(character byte) bool {
	return !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' ||
		character == '_' || character == '-' || character == '.' || character == '%')
}

// matchFilterTail matches the rest of a rule against the rest of a URL, both
// starting right after the host: `*` is any run, `^` a separator or the end,
// and a final `|` the end. Without that, the rest of the URL is free.
func matchFilterTail(pattern, value string) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			pattern = strings.TrimLeft(pattern, "*")
			if pattern == "" {
				return true
			}
			for index := 0; index <= len(value); index++ {
				if matchFilterTail(pattern, value[index:]) {
					return true
				}
			}
			return false
		case '^':
			if value == "" {
				pattern = pattern[1:]
				continue
			}
			if !filterSeparator(value[0]) {
				return false
			}
		case '|':
			return len(pattern) == 1 && value == ""
		default:
			if value == "" || value[0] != pattern[0] {
				return false
			}
		}
		pattern, value = pattern[1:], value[1:]
	}
	return true
}

func (rule trackerRule) applies(tail string, kind uint16, pageHost string) bool {
	if rule.kinds&kind == 0 {
		return false
	}
	if len(rule.domains) > 0 {
		found := false
		for _, domain := range rule.domains {
			if pageHost != "" && matchingHost(pageHost, domain) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	for _, domain := range rule.notDomains {
		if pageHost != "" && matchingHost(pageHost, domain) {
			return false
		}
	}
	return rule.tail == "" || matchFilterTail(rule.tail, tail)
}

func matchingRules(rules map[string][]trackerRule, host, tail string, kind uint16, pageHost string) bool {
	for current := host; current != ""; {
		for _, rule := range rules[current] {
			if rule.applies(tail, kind, pageHost) {
				return true
			}
		}
		index := strings.IndexByte(current, '.')
		if index < 0 {
			break
		}
		current = current[index+1:]
	}
	return false
}

// blocks reports whether the list blocks a request, after its exceptions.
func (list *trackerList) blocks(host, tail string, kind uint16, pageHost string) bool {
	if list == nil || !matchingRules(list.block, host, tail, kind, pageHost) {
		return false
	}
	return !matchingRules(list.allow, host, tail, kind, pageHost)
}

// sameSite compares registrable domains with the Public Suffix List, so a
// site's own subdomains are first party and unrelated hosts on a shared suffix
// are not.
func sameSite(host, pageHost string) bool {
	if host == "" || pageHost == "" {
		return false
	}
	if host == pageHost {
		return true
	}
	if net.ParseIP(host) != nil || net.ParseIP(pageHost) != nil {
		return false
	}
	first, errFirst := publicsuffix.EffectiveTLDPlusOne(host)
	second, errSecond := publicsuffix.EffectiveTLDPlusOne(pageHost)
	if errFirst != nil || errSecond != nil {
		return matchingHost(host, pageHost) || matchingHost(pageHost, host)
	}
	return first == second
}

// urlTail is what follows the host in a URL, as a filter rule sees it.
func urlTail(target *url.URL) string {
	tail := ""
	if port := target.Port(); port != "" {
		tail = ":" + port
	}
	tail += target.EscapedPath()
	if target.RawQuery != "" || target.ForceQuery {
		tail += "?" + target.RawQuery
	}
	return strings.ToLower(tail)
}

// requestKindFor maps a Playwright resource type to a filter-list kind.
func requestKindFor(resourceType string, subframe bool) uint16 {
	switch resourceType {
	case "document":
		if subframe {
			return kindSubdocument
		}
		return kindDocument
	case "script":
		return kindScript
	case "image":
		return kindImage
	case "stylesheet":
		return kindStylesheet
	case "xhr", "fetch":
		return kindXHR
	case "ping", "beacon":
		return kindPing
	case "media":
		return kindMedia
	case "font":
		return kindFont
	case "websocket":
		return kindWebsocket
	case "":
		return kindDefault
	default:
		return kindOther
	}
}

// trackerListLabel names the bundled list for the privacy snapshot.
func trackerListLabel() string {
	list := loadedEasyPrivacy()
	if list == nil || !list.sourcePresent {
		return ""
	}
	commit := list.commit
	if len(commit) > 7 {
		commit = commit[:7]
	}
	return "EasyPrivacy " + commit
}
