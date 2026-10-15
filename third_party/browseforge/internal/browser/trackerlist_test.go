package browser

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestBundledEasyPrivacyIsUnmodifiedAndLoads(t *testing.T) {
	data, err := easyPrivacyFiles.ReadFile("trackerlists/easyprivacy/provenance.json")
	if err != nil {
		t.Fatal(err)
	}
	var provenance struct {
		Commit string `json:"commit"`
		Files  []struct {
			Name   string `json:"name"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
	}
	if err := json.Unmarshal(data, &provenance); err != nil || len(provenance.Commit) != 40 || len(provenance.Files) == 0 {
		t.Fatalf("provenance unreadable: %v", err)
	}
	for _, file := range provenance.Files {
		bytes, err := easyPrivacyFiles.ReadFile("trackerlists/easyprivacy/" + file.Name)
		if err != nil {
			t.Fatalf("%s missing: %v", file.Name, err)
		}
		sum := sha256.Sum256(bytes)
		if hex.EncodeToString(sum[:]) != file.SHA256 {
			t.Fatalf("%s differs from the pinned upstream file", file.Name)
		}
	}
	list := loadedEasyPrivacy()
	if list.sourceFiles != len(provenance.Files) {
		t.Fatalf("parsed %d files, provenance names %d", list.sourceFiles, len(provenance.Files))
	}
	// Thousands of host rules and their exceptions; a parser regression that
	// silently dropped most of them would show here.
	if list.blockRules < 8000 || list.allowRules < 300 {
		t.Fatalf("too few rules: %d block, %d allow, %d skipped", list.blockRules, list.allowRules, list.skippedRules)
	}
	t.Logf("EasyPrivacy %s: %d block rules, %d exceptions, %d skipped", list.commit[:7], list.blockRules, list.allowRules, list.skippedRules)
	if label := trackerListLabel(); label != "EasyPrivacy "+provenance.Commit[:7] {
		t.Fatalf("label = %q", label)
	}
}

func TestFilterRuleSubsetIsStrict(t *testing.T) {
	for _, line := range []string{
		"example.com##.banner", "/tracker.js", "|https://example.com/", "/ads[0-9]+/", "||exa*mple.com^",
		"||example.c*", "||example.com^$important", "||example.com^$redirect=noop.js", "||example.com^$~third-party",
		"||example.com^$1p", "||example.com^$document", "||example.com^$domain=*.example", "||localhost^",
	} {
		if _, _, _, ok := parseTrackerRule(line); ok {
			t.Fatalf("unsupported rule accepted: %s", line)
		}
	}
	anchor, rule, allow, ok := parseTrackerRule("@@||Cdn.Example.com/Track/*.js^$script,domain=site.com|~shop.site.com")
	if !ok || !allow || anchor != "cdn.example.com" || rule.tail != "/track/*.js^" || rule.kinds != kindScript ||
		len(rule.domains) != 1 || rule.domains[0] != "site.com" || len(rule.notDomains) != 1 {
		t.Fatalf("exception parsed wrong: %q %+v %t %t", anchor, rule, allow, ok)
	}
	if _, rule, _, ok := parseTrackerRule("||metrics.example.com^$third-party,~image"); !ok || rule.tail != "" || rule.kinds != kindDefault&^kindImage {
		t.Fatalf("host rule parsed wrong: %+v %t", rule, ok)
	}
}

func TestFilterTailMatching(t *testing.T) {
	for _, check := range []struct {
		pattern, value string
		want           bool
	}{
		{"/track", "/track/pixel.gif", true},
		{"/track", "/tracking", true},
		{"/track^", "/tracking", false},
		{"/track^", "/track?id=1", true},
		{"/track^", "/track", true},
		{"/*/pixel.gif", "/a/b/pixel.gif?x", true},
		{"/pixel.gif|", "/pixel.gif?x", false},
		{"/pixel.gif|", "/pixel.gif", true},
		{"^*/collect", ":8443/g/collect", true},
		{"/g/collect", "/x/g/collect", false},
	} {
		if got := matchFilterTail(check.pattern, check.value); got != check.want {
			t.Fatalf("matchFilterTail(%q, %q) = %t, want %t", check.pattern, check.value, got, check.want)
		}
	}
}

func TestEasyPrivacyBlocksThirdPartyTrackersOnly(t *testing.T) {
	list := loadedEasyPrivacy()
	// A host the list names as a third-party tracker, chosen from the list
	// itself so the test follows list updates.
	tracker := ""
	for anchor, rules := range list.block {
		for _, rule := range rules {
			if rule.tail == "" && rule.kinds == kindDefault && len(rule.domains) == 0 && len(rule.notDomains) == 0 &&
				!matchingRules(list.allow, anchor, "/", kindScript, "news.example") && builtinTrackerDomain(anchor, "strict") == "" {
				blocked := false
				for _, domain := range strictTrackerDomains {
					if matchingHost(anchor, domain) {
						blocked = true
					}
				}
				if !blocked {
					tracker = anchor
				}
			}
			if tracker != "" {
				break
			}
		}
		if tracker != "" {
			break
		}
	}
	if tracker == "" {
		t.Fatal("no plain host rule found")
	}
	target := "https://" + tracker + "/collect?v=1"
	for _, mode := range []string{"standard", "strict"} {
		if !blockTrackerRequest(target, "https://news.example/article", mode, kindScript) {
			t.Fatalf("%s: third-party %s not blocked", mode, tracker)
		}
		if blockTrackerRequest(target, "https://"+tracker+"/dashboard", mode, kindScript) {
			t.Fatalf("%s: first-party %s blocked", mode, tracker)
		}
		if blockTrackerRequest(target, "https://news.example/article", mode, kindDocument) {
			t.Fatalf("%s: a page the user navigates to was blocked", mode)
		}
	}
	if blockTrackerRequest(target, "https://news.example/article", "off", kindScript) {
		t.Fatal("off still blocks")
	}
	// A subdomain on the same registrable domain is first party.
	if !sameSite("metrics.example.co.uk", "www.example.co.uk") || sameSite("a.github.io", "b.github.io") || sameSite("tracker.net", "site.net") {
		t.Fatal("site comparison wrong")
	}
}

func TestEasyPrivacyKeepsSignInAndStandardTierPromises(t *testing.T) {
	signIn := []string{
		"https://accounts.google.com/o/oauth2/v2/auth?client_id=x", "https://accounts.google.com/gsi/client",
		"https://appleid.apple.com/auth/authorize", "https://www.facebook.com/login.php", "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		"https://github.com/login/oauth/authorize", "https://claude.ai/api/organizations", "https://api.anthropic.com/v1/messages",
		"https://www.notion.so/api/v3/getSpaces", "https://challenges.cloudflare.com/turnstile/v0/api.js", "https://www.google.com/recaptcha/api.js",
		"https://www.gstatic.com/recaptcha/releases/x/recaptcha__en.js", "https://js.stripe.com/v3/", "https://cdn.jsdelivr.net/npm/x",
		"https://fonts.googleapis.com/css2?family=Inter", "https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js",
	}
	for _, raw := range signIn {
		for _, kind := range []uint16{kindScript, kindXHR, kindSubdocument, kindImage} {
			if blockTrackerRequest(raw, "https://some-site.example/", "strict", kind) {
				t.Fatalf("sign-in or site infrastructure blocked: %s (kind %d)", raw, kind)
			}
		}
	}
	// What the strict tier holds back stays strict-only even when EasyPrivacy
	// would block it.
	for _, raw := range []string{"https://www.googletagmanager.com/gtag/js?id=G-1", "https://connect.facebook.net/en_US/sdk.js", "https://o1.ingest.sentry.io/api/1/envelope/"} {
		if blockTrackerRequest(raw, "https://some-site.example/", "standard", kindScript) {
			t.Fatalf("standard blocked a strict-only host: %s", raw)
		}
		if !blockTrackerRequest(raw, "https://some-site.example/", "strict", kindScript) {
			t.Fatalf("strict did not block %s", raw)
		}
	}
}

func TestEasyPrivacyExceptionsAreHonoured(t *testing.T) {
	list := loadedEasyPrivacy()
	// Every exception that names a host the list also blocks must win for a
	// request it describes; checked on the list itself, not a hand-picked case.
	checked := 0
	for anchor, exceptions := range list.allow {
		if _, blocked := list.block[anchor]; !blocked {
			continue
		}
		for _, exception := range exceptions {
			if exception.tail != "" && (strings.ContainsAny(exception.tail, "*^|") || len(exception.domains) == 0) {
				continue
			}
			page := "https://unrelated.example/"
			if len(exception.domains) > 0 {
				page = "https://" + exception.domains[0] + "/"
			}
			kind := exception.kinds & -exception.kinds // one request type the exception covers
			tail := exception.tail
			if tail == "" {
				tail = "/"
			}
			if list.blocks(anchor, tail, kind, strings.TrimSuffix(strings.TrimPrefix(page, "https://"), "/")) {
				t.Fatalf("exception for %s%s on %s did not win", anchor, tail, page)
			}
			checked++
		}
	}
	t.Logf("%d exceptions over blocked hosts checked", checked)
}
