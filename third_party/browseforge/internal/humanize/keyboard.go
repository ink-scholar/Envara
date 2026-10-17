package humanize

import (
	"math"
	"math/rand/v2"
	"time"
	"unicode"

	"github.com/playwright-community/playwright-go"
)

var adjacentKeys = map[rune][]rune{
	'a': {'s', 'q', 'z'}, 'b': {'v', 'n', 'g'}, 'c': {'x', 'v', 'd'},
	'd': {'s', 'f', 'e'}, 'e': {'w', 'r', 'd'}, 'f': {'d', 'g', 'r'},
	'g': {'f', 'h', 't'}, 'h': {'g', 'j', 'y'}, 'i': {'u', 'o', 'k'},
	'j': {'h', 'k', 'u'}, 'k': {'j', 'l', 'i'}, 'l': {'k', 'o', 'p'},
	'm': {'n', 'j'}, 'n': {'b', 'm', 'h'}, 'o': {'i', 'p', 'l'},
	'p': {'o', 'l'}, 'q': {'w', 'a'}, 'r': {'e', 't', 'f'},
	's': {'a', 'd', 'w'}, 't': {'r', 'y', 'g'}, 'u': {'y', 'i', 'j'},
	'v': {'c', 'b', 'f'}, 'w': {'q', 'e', 's'}, 'x': {'z', 'c', 's'},
	'y': {'t', 'u', 'h'}, 'z': {'x', 'a'},
}

// Type types text into an element with human-like keystroke dynamics.
func Type(page playwright.Page, selector, text string, cfg Config) error {
	if !cfg.Enabled {
		return page.Fill(selector, text)
	}

	// Focus the element
	if err := Click(page, selector, cfg); err != nil {
		// Fallback: use Playwright's click to focus, then still type humanly
		page.Click(selector)
	}
	time.Sleep(time.Duration(randRangeInt(80, 200)) * time.Millisecond)

	// Always type character by character with human timing
	kb := page.Keyboard()
	mu := math.Log(60000.0 / float64(cfg.TypingCPM))
	sigma := 0.3

	var prev rune
	for _, ch := range text {
		delay := logNormalDelay(mu, sigma)

		if ch == prev {
			delay *= 0.7
		}
		if prev == ' ' || unicode.IsPunct(prev) {
			delay += randRange(50, 150)
		}

		time.Sleep(time.Duration(delay) * time.Millisecond)

		// Typo simulation
		if cfg.TypoRate > 0 && rand.Float64() < cfg.TypoRate {
			if typo := pickTypo(ch); typo != 0 {
				pressChar(kb, typo)
				time.Sleep(time.Duration(randRangeInt(100, 300)) * time.Millisecond)
				kb.Press("Backspace")
				time.Sleep(time.Duration(randRangeInt(50, 120)) * time.Millisecond)
			}
		}

		pressChar(kb, ch)
		prev = ch
	}
	return nil
}

func pressChar(kb playwright.Keyboard, ch rune) {
	delay := randRange(80, 140)
	kb.Press(string(ch), playwright.KeyboardPressOptions{
		Delay: playwright.Float(delay),
	})
}

func pickTypo(ch rune) rune {
	lower := unicode.ToLower(ch)
	adj := adjacentKeys[lower]
	if len(adj) == 0 {
		return 0
	}
	return adj[rand.IntN(len(adj))]
}
