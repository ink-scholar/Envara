package humanize

import (
	"fmt"
	"math"
	"time"

	"github.com/playwright-community/playwright-go"
)

// ScrollIntoView scrolls the page so the element is visible, with smooth easing.
func ScrollIntoView(page playwright.Page, selector string, cfg Config) error {
	if !cfg.Enabled || cfg.ScrollStyle == "instant" {
		_, err := page.Evaluate(fmt.Sprintf(
			`document.querySelector(%q)?.scrollIntoView({block:"center"})`, selector))
		return err
	}

	// Get element position and viewport info
	info, err := page.Evaluate(fmt.Sprintf(`(() => {
		const el = document.querySelector(%q);
		if (!el) return null;
		const r = el.getBoundingClientRect();
		return {top: r.top, bottom: r.bottom, vh: window.innerHeight};
	})()`, selector))
	if err != nil || info == nil {
		return err
	}

	m, ok := info.(map[string]interface{})
	if !ok {
		return nil
	}
	top, _ := m["top"].(float64)
	bottom, _ := m["bottom"].(float64)
	vh, _ := m["vh"].(float64)

	// Already in viewport
	if top >= 0 && bottom <= vh {
		return nil
	}

	// Calculate scroll delta to center the element
	delta := top - vh/2 + (bottom-top)/2
	if math.Abs(delta) < 10 {
		return nil
	}

	// Smooth scroll with ease-out deceleration
	steps := 15 + int(math.Min(math.Abs(delta)/50, 30))
	mouse := page.Mouse()
	for i := 1; i <= steps; i++ {
		// Ease-out: larger steps at start, smaller at end
		progress := float64(i) / float64(steps)
		eased := 1 - math.Pow(1-progress, 3) // cubic ease-out
		prevEased := 1 - math.Pow(1-float64(i-1)/float64(steps), 3)
		stepDelta := (eased - prevEased) * delta

		if err := mouse.Wheel(0, stepDelta); err != nil {
			return err
		}
		time.Sleep(time.Duration(randRangeInt(15, 30)) * time.Millisecond)
	}

	// Brief pause after scrolling
	time.Sleep(time.Duration(randRangeInt(100, 300)) * time.Millisecond)
	return nil
}
