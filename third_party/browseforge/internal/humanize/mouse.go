package humanize

import (
	"math/rand/v2"
	"time"

	"github.com/playwright-community/playwright-go"
)

const (
	overshootThreshold = 500.0
	overshootRadius    = 120.0
	microPauseProb     = 0.08
)

var mousePos = vec2{X: 0, Y: 0}

// Click moves the mouse to the element in a human-like path, then clicks.
func Click(page playwright.Page, selector string, cfg Config) error {
	if !cfg.Enabled {
		return page.Click(selector)
	}

	loc := page.Locator(selector)
	if err := ScrollIntoView(page, selector, cfg); err != nil {
		// Scroll failed — still try to click with delay
		return clickWithDelay(page, selector)
	}

	box, err := loc.BoundingBox()
	if err != nil || box == nil {
		return clickWithDelay(page, selector)
	}

	target := vec2{
		X: box.X + rand.Float64()*box.Width,
		Y: box.Y + rand.Float64()*box.Height,
	}

	if err := moveMouse(page, target, box.Width, cfg); err != nil {
		return clickWithDelay(page, selector)
	}

	// Human-like click: down → random delay → up
	mouse := page.Mouse()
	if err := mouse.Down(); err != nil {
		return clickWithDelay(page, selector)
	}
	time.Sleep(time.Duration(randRangeInt(60, 140)) * time.Millisecond)
	return mouse.Up()
}

// clickWithDelay is the fallback — uses Playwright's Click but with human-like delay.
func clickWithDelay(page playwright.Page, selector string) error {
	delay := randRange(60, 140)
	return page.Click(selector, playwright.PageClickOptions{
		Delay: playwright.Float(delay),
	})
}

func moveMouse(page playwright.Page, target vec2, targetWidth float64, cfg Config) error {
	mouse := page.Mouse()
	minSteps, maxSteps, pauseMs := cfg.mouseParams()

	start := mousePos
	dist := target.sub(start).length()
	steps := fittsSteps(dist, targetWidth, minSteps, maxSteps)

	if dist > overshootThreshold {
		ovPt := overshootPoint(target, overshootRadius)
		ovSteps := fittsSteps(dist, targetWidth, minSteps, maxSteps)
		if err := traversePath(mouse, bezierPath(start, ovPt, ovSteps), pauseMs); err != nil {
			return err
		}
		corrSteps := max(minSteps/2, 15)
		return traversePath(mouse, bezierPath(ovPt, target, corrSteps), pauseMs)
	}

	return traversePath(mouse, bezierPath(start, target, steps), pauseMs)
}

func traversePath(mouse playwright.Mouse, pts []vec2, pauseMs [2]int) error {
	for _, pt := range pts {
		if err := mouse.Move(pt.X, pt.Y); err != nil {
			return err
		}
		mousePos = pt

		if rand.Float64() < microPauseProb {
			time.Sleep(time.Duration(randRangeInt(pauseMs[0], pauseMs[1])) * time.Millisecond)
		} else {
			time.Sleep(time.Duration(randRangeInt(6, 14)) * time.Millisecond)
		}
	}
	return nil
}
